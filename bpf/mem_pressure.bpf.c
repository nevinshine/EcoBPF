// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * mem_pressure.bpf.c — EcoBPF Memory Pressure & Page Fault Probe
 *
 * Attaches to memory subsystem tracepoints to capture:
 *   - Major and minor page faults per PID
 *   - Direct reclaim events (memory pressure indicator)
 *   - RSS approximation via fault accounting
 *
 * Data flows to user-space via:
 *   1. Ring buffer (mem_events) — real-time event stream
 *   2. Per-PID hash map (mem_stats_map) — aggregated stats, pinned to bpffs
 */

#include "headers/vmlinux_subset.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ─── Event types ─────────────────────────────────────────────────────────── */

enum mem_event_type {
    MEM_EVENT_PAGE_FAULT_USER   = 1,
    MEM_EVENT_PAGE_FAULT_KERNEL = 2,
    MEM_EVENT_DIRECT_RECLAIM    = 3,
};

struct mem_event {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 event_type;
    u32 cpu_id;
    char comm[16];

    /* Page fault specific */
    u64 address;
    u64 ip;               /* Instruction pointer at fault */
    u64 error_code;

    /* Reclaim specific */
    u32 reclaim_order;
    u64 gfp_flags;
};

/* Aggregated per-PID memory statistics */
struct mem_stats {
    u64 major_faults;
    u64 minor_faults;
    u64 total_faults;
    u64 direct_reclaim_count;
    u64 last_fault_ns;
    u64 estimated_rss_pages;   /* Approximation based on fault delta */
    char comm[16];
};

/* ─── BPF Maps ────────────────────────────────────────────────────────────── */

/* Ring buffer for streaming memory events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} mem_events SEC(".maps");

/*
 * Aggregated memory stats per PID.
 * Pinned to /sys/fs/bpf/ecobpf/mem_stats_map for restart resilience.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, u32);
    __type(value, struct mem_stats);
} mem_stats_map SEC(".maps");

/* ─── Helpers ─────────────────────────────────────────────────────────────── */

static __always_inline void update_fault_stats(u32 pid, bool is_major,
                                                u64 ts, const char *comm)
{
    struct mem_stats *stats = bpf_map_lookup_elem(&mem_stats_map, &pid);
    if (stats) {
        if (is_major) {
            __sync_fetch_and_add(&stats->major_faults, 1);
        } else {
            __sync_fetch_and_add(&stats->minor_faults, 1);
            /* Minor faults approximate new page allocations → RSS growth */
            __sync_fetch_and_add(&stats->estimated_rss_pages, 1);
        }
        __sync_fetch_and_add(&stats->total_faults, 1);
        stats->last_fault_ns = ts;
    } else {
        struct mem_stats new_stats = {};
        if (is_major) {
            new_stats.major_faults = 1;
        } else {
            new_stats.minor_faults = 1;
            new_stats.estimated_rss_pages = 1;
        }
        new_stats.total_faults = 1;
        new_stats.last_fault_ns = ts;
        __builtin_memcpy(new_stats.comm, comm, 16);

        bpf_map_update_elem(&mem_stats_map, &pid, &new_stats, BPF_ANY);
    }
}

/* ─── Tracepoint: page_fault_user ─────────────────────────────────────── */

SEC("tp/exceptions/page_fault_user")
int handle_page_fault_user(struct trace_event_raw_page_fault *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pidtgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)pidtgid;
    u32 tgid = (u32)(pidtgid >> 32);

    /*
     * Classify fault: bit 0 of error_code indicates protection fault (major)
     * vs. not-present fault (minor).
     */
    bool is_major = (ctx->error_code & 0x1) != 0;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    update_fault_stats(pid, is_major, ts, comm);

    /* Emit event to ring buffer */
    struct mem_event *evt = bpf_ringbuf_reserve(&mem_events,
                                                 sizeof(struct mem_event), 0);
    if (evt) {
        evt->timestamp_ns = ts;
        evt->pid = pid;
        evt->tgid = tgid;
        evt->event_type = MEM_EVENT_PAGE_FAULT_USER;
        evt->cpu_id = bpf_get_smp_processor_id();
        evt->address = ctx->address;
        evt->ip = ctx->ip;
        evt->error_code = ctx->error_code;
        evt->reclaim_order = 0;
        evt->gfp_flags = 0;
        __builtin_memcpy(evt->comm, comm, 16);

        bpf_ringbuf_submit(evt, 0);
    }

    return 0;
}

/* ─── Tracepoint: page_fault_kernel ───────────────────────────────────── */

SEC("tp/exceptions/page_fault_kernel")
int handle_page_fault_kernel(struct trace_event_raw_page_fault *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pidtgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)pidtgid;
    u32 tgid = (u32)(pidtgid >> 32);

    /* Kernel page faults are typically major faults */
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    update_fault_stats(pid, true, ts, comm);

    struct mem_event *evt = bpf_ringbuf_reserve(&mem_events,
                                                 sizeof(struct mem_event), 0);
    if (evt) {
        evt->timestamp_ns = ts;
        evt->pid = pid;
        evt->tgid = tgid;
        evt->event_type = MEM_EVENT_PAGE_FAULT_KERNEL;
        evt->cpu_id = bpf_get_smp_processor_id();
        evt->address = ctx->address;
        evt->ip = ctx->ip;
        evt->error_code = ctx->error_code;
        evt->reclaim_order = 0;
        evt->gfp_flags = 0;
        __builtin_memcpy(evt->comm, comm, 16);

        bpf_ringbuf_submit(evt, 0);
    }

    return 0;
}

/* ─── Tracepoint: mm_vmscan_direct_reclaim_begin ──────────────────────── */

SEC("tp/vmscan/mm_vmscan_direct_reclaim_begin")
int handle_direct_reclaim(struct trace_event_raw_mm_vmscan_direct_reclaim_begin *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pidtgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)pidtgid;
    u32 tgid = (u32)(pidtgid >> 32);

    /* Update reclaim counter */
    struct mem_stats *stats = bpf_map_lookup_elem(&mem_stats_map, &pid);
    if (stats) {
        __sync_fetch_and_add(&stats->direct_reclaim_count, 1);
    } else {
        struct mem_stats new_stats = {};
        new_stats.direct_reclaim_count = 1;
        new_stats.last_fault_ns = ts;
        bpf_get_current_comm(&new_stats.comm, sizeof(new_stats.comm));
        bpf_map_update_elem(&mem_stats_map, &pid, &new_stats, BPF_ANY);
    }

    struct mem_event *evt = bpf_ringbuf_reserve(&mem_events,
                                                 sizeof(struct mem_event), 0);
    if (evt) {
        evt->timestamp_ns = ts;
        evt->pid = pid;
        evt->tgid = tgid;
        evt->event_type = MEM_EVENT_DIRECT_RECLAIM;
        evt->cpu_id = bpf_get_smp_processor_id();
        evt->address = 0;
        evt->ip = 0;
        evt->error_code = 0;
        evt->reclaim_order = (u32)ctx->order;
        evt->gfp_flags = ctx->gfp_flags;
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

        bpf_ringbuf_submit(evt, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
