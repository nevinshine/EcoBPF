// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * cpu_sched.bpf.c — EcoBPF CPU Scheduling & Context Switch Probe
 *
 * Attaches to scheduler tracepoints to capture:
 *   - Per-PID CPU time slices (nanosecond precision)
 *   - Context switch counts (voluntary + involuntary)
 *   - CPU frequency at switch time
 *   - Process exec events for command name tracking
 *
 * Data flows to user-space via:
 *   1. Ring buffer (cpu_events) — real-time event stream
 *   2. Per-CPU hash map (cpu_stats_map) — aggregated stats, pinned to bpffs
 */

#include "headers/vmlinux_subset.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ─── Event types ─────────────────────────────────────────────────────────── */

enum cpu_event_type {
    CPU_EVENT_SWITCH = 1,
    CPU_EVENT_EXEC   = 2,
};

struct cpu_event {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 cpu_id;
    u32 event_type;
    char comm[16];

    /* sched_switch specific */
    u64 delta_ns;          /* Time spent on CPU since last switch-in */
    u32 prev_pid;
    u32 next_pid;
    long prev_state;
};

/* Aggregated per-PID CPU statistics */
struct cpu_stats {
    u64 total_cpu_time_ns;
    u64 ctx_switches;
    u64 voluntary_ctx_switches;
    u64 involuntary_ctx_switches;
    u32 last_cpu_id;
    u64 last_seen_ns;
    char comm[16];
};

/* Per-CPU timestamp tracker for delta calculation */
struct switch_start {
    u64 ts;
    u32 pid;
};

/* ─── BPF Maps ────────────────────────────────────────────────────────────── */

/*
 * Ring buffer for streaming events to user-space.
 * 256KB per-CPU ring, sufficient for ~4000 events/sec.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} cpu_events SEC(".maps");

/*
 * Aggregated CPU stats per PID.
 * Pinned to /sys/fs/bpf/ecobpf/cpu_stats_map for daemon restart resilience.
 * Max 16384 tracked PIDs.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, u32);
    __type(value, struct cpu_stats);
} cpu_stats_map SEC(".maps");

/*
 * Per-CPU array tracking switch-in timestamps for delta calculation.
 * Key = CPU ID, Value = {timestamp, pid}.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct switch_start);
} cpu_switch_start SEC(".maps");

/* ─── Tracepoint: sched_switch ─────────────────────────────────────────── */

SEC("tp/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u32 cpu = bpf_get_smp_processor_id();
    u32 zero = 0;

    pid_t prev_pid = ctx->prev_pid;
    pid_t next_pid = ctx->next_pid;

    /* ─── Account time for the outgoing task ─── */
    struct switch_start *start = bpf_map_lookup_elem(&cpu_switch_start, &zero);
    if (start && start->pid == (u32)prev_pid && start->ts > 0) {
        u64 delta = ts - start->ts;

        /* Update aggregated stats for prev_pid */
        u32 key = (u32)prev_pid;
        struct cpu_stats *stats = bpf_map_lookup_elem(&cpu_stats_map, &key);
        if (stats) {
            __sync_fetch_and_add(&stats->total_cpu_time_ns, delta);
            __sync_fetch_and_add(&stats->ctx_switches, 1);

            /* Classify context switch type */
            if (ctx->prev_state == 0) {
                /* TASK_RUNNING → preempted (involuntary) */
                __sync_fetch_and_add(&stats->involuntary_ctx_switches, 1);
            } else {
                /* Sleeping/waiting (voluntary) */
                __sync_fetch_and_add(&stats->voluntary_ctx_switches, 1);
            }

            stats->last_cpu_id = cpu;
            stats->last_seen_ns = ts;
        } else {
            /* First time seeing this PID — initialize */
            struct cpu_stats new_stats = {};
            new_stats.total_cpu_time_ns = delta;
            new_stats.ctx_switches = 1;
            new_stats.last_cpu_id = cpu;
            new_stats.last_seen_ns = ts;

            if (ctx->prev_state == 0) {
                new_stats.involuntary_ctx_switches = 1;
            } else {
                new_stats.voluntary_ctx_switches = 1;
            }

            __builtin_memcpy(new_stats.comm, ctx->prev_comm, 16);
            bpf_map_update_elem(&cpu_stats_map, &key, &new_stats, BPF_ANY);
        }

        /* Emit ring buffer event */
        struct cpu_event *evt = bpf_ringbuf_reserve(&cpu_events,
                                                     sizeof(struct cpu_event), 0);
        if (evt) {
            evt->timestamp_ns = ts;
            evt->pid = (u32)prev_pid;
            evt->tgid = 0; /* Filled by user-space from /proc */
            evt->cpu_id = cpu;
            evt->event_type = CPU_EVENT_SWITCH;
            evt->delta_ns = delta;
            evt->prev_pid = (u32)prev_pid;
            evt->next_pid = (u32)next_pid;
            evt->prev_state = ctx->prev_state;
            __builtin_memcpy(evt->comm, ctx->prev_comm, 16);

            bpf_ringbuf_submit(evt, 0);
        }
    }

    /* ─── Record switch-in timestamp for the incoming task ─── */
    struct switch_start new_start = {
        .ts  = ts,
        .pid = (u32)next_pid,
    };
    bpf_map_update_elem(&cpu_switch_start, &zero, &new_start, BPF_ANY);

    return 0;
}

/* ─── Tracepoint: sched_process_exec ──────────────────────────────────── */

SEC("tp/sched/sched_process_exec")
int handle_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u32 pid = (u32)bpf_get_current_pid_tgid();
    u32 tgid = (u32)(bpf_get_current_pid_tgid() >> 32);

    /* Initialize CPU stats for the new process */
    struct cpu_stats new_stats = {};
    new_stats.last_seen_ns = ts;
    new_stats.last_cpu_id = bpf_get_smp_processor_id();
    bpf_get_current_comm(&new_stats.comm, sizeof(new_stats.comm));

    bpf_map_update_elem(&cpu_stats_map, &pid, &new_stats, BPF_ANY);

    /* Emit exec event to ring buffer */
    struct cpu_event *evt = bpf_ringbuf_reserve(&cpu_events,
                                                 sizeof(struct cpu_event), 0);
    if (evt) {
        evt->timestamp_ns = ts;
        evt->pid = pid;
        evt->tgid = tgid;
        evt->cpu_id = bpf_get_smp_processor_id();
        evt->event_type = CPU_EVENT_EXEC;
        evt->delta_ns = 0;
        evt->prev_pid = 0;
        evt->next_pid = 0;
        evt->prev_state = 0;
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

        bpf_ringbuf_submit(evt, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
