// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * gpu_activity.bpf.c — EcoBPF GPU Activity Probe
 *
 * Attaches to DRM scheduler tracepoints to capture GPU workload activity.
 * Gracefully degrades on hosts without GPU or without supported tracepoints.
 *
 * Supported tracepoints (when available):
 *   - tp/gpu/gpu_sched_job        (generic GPU scheduler)
 *   - tp/drm/drm_sched_job        (DRM subsystem scheduler)
 *
 * On hosts without these tracepoints, the probe loads but produces no events.
 * The user-space daemon detects this via empty ring buffer reads and reports
 * GPU metrics as zero (graceful degradation).
 *
 * Data flows via:
 *   1. Ring buffer (gpu_events) — real-time GPU job events
 *   2. Hash map (gpu_stats_map) — per-PID GPU activity aggregates, pinned
 */

#include "headers/vmlinux_subset.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ─── Event / Stats structures ────────────────────────────────────────────── */

enum gpu_event_type {
    GPU_EVENT_JOB_SUBMIT = 1,
    GPU_EVENT_JOB_COMPLETE = 2,
};

struct gpu_event {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 event_type;
    u32 cpu_id;
    char comm[16];

    u64 job_id;
    u64 fence_id;
    u32 ring_id;         /* GPU ring/engine index */
    u32 hw_job_count;    /* Number of HW jobs queued */
};

struct gpu_stats {
    u64 total_jobs_submitted;
    u64 total_gpu_active_ns;    /* Estimated GPU busy time */
    u64 last_submit_ns;
    u64 last_complete_ns;
    u32 active_jobs;            /* Currently inflight jobs */
    char comm[16];
};

/* ─── BPF Maps ────────────────────────────────────────────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 1024);
} gpu_events SEC(".maps");

/*
 * Per-PID GPU statistics.
 * Pinned to /sys/fs/bpf/ecobpf/gpu_stats_map for restart resilience.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __type(key, u32);
    __type(value, struct gpu_stats);
} gpu_stats_map SEC(".maps");

/*
 * Per-PID job start timestamps for duration calculation.
 * Tracks the latest job submission time per PID.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u64);
} gpu_job_start SEC(".maps");

/* ─── Tracepoint: DRM scheduler job submission ────────────────────────── */

/*
 * This probe handles both gpu_sched_job and drm_sched_job tracepoints.
 * The tracepoint argument structure is compatible for both.
 *
 * Note: Uses SEC("tp/drm/drm_sched_job") which is the more widely
 * available tracepoint. If the tracepoint doesn't exist on the host,
 * the probe attachment will silently fail, and the daemon falls back
 * to reporting zero GPU activity.
 */
SEC("tp/drm/drm_sched_job")
int handle_gpu_job_submit(struct trace_event_raw_gpu_sched *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pidtgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)pidtgid;
    u32 tgid = (u32)(pidtgid >> 32);

    /* Record job start time for duration tracking */
    bpf_map_update_elem(&gpu_job_start, &pid, &ts, BPF_ANY);

    /* Update aggregated GPU stats */
    struct gpu_stats *stats = bpf_map_lookup_elem(&gpu_stats_map, &pid);
    if (stats) {
        __sync_fetch_and_add(&stats->total_jobs_submitted, 1);
        __sync_fetch_and_add(&stats->active_jobs, 1);
        stats->last_submit_ns = ts;
    } else {
        struct gpu_stats new_stats = {};
        new_stats.total_jobs_submitted = 1;
        new_stats.active_jobs = 1;
        new_stats.last_submit_ns = ts;
        bpf_get_current_comm(&new_stats.comm, sizeof(new_stats.comm));
        bpf_map_update_elem(&gpu_stats_map, &pid, &new_stats, BPF_ANY);
    }

    /* Emit event to ring buffer */
    struct gpu_event *evt = bpf_ringbuf_reserve(&gpu_events,
                                                 sizeof(struct gpu_event), 0);
    if (evt) {
        evt->timestamp_ns = ts;
        evt->pid = pid;
        evt->tgid = tgid;
        evt->event_type = GPU_EVENT_JOB_SUBMIT;
        evt->cpu_id = bpf_get_smp_processor_id();
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

        /* Read tracepoint fields with bounds checking */
        evt->job_id = 0;
        evt->fence_id = 0;
        evt->ring_id = 0;
        evt->hw_job_count = 0;

        /*
         * Safe reads: these fields may not be present in all kernel versions.
         * bpf_probe_read_kernel returns 0 on success, negative on failure.
         */
        bpf_probe_read_kernel(&evt->fence_id, sizeof(evt->fence_id),
                              &ctx->fence_id);
        bpf_probe_read_kernel(&evt->job_id, sizeof(evt->job_id),
                              &ctx->job_id);
        bpf_probe_read_kernel(&evt->ring_id, sizeof(evt->ring_id),
                              &ctx->ring);
        bpf_probe_read_kernel(&evt->hw_job_count, sizeof(evt->hw_job_count),
                              &ctx->hw_job_count);

        bpf_ringbuf_submit(evt, 0);
    }

    return 0;
}

/*
 * Generic tracepoint fallback for gpu_sched_job (if drm_sched_job unavailable).
 * Identical logic, different tracepoint path.
 */
SEC("tp/gpu/gpu_sched_job")
int handle_gpu_sched_job(struct trace_event_raw_gpu_sched *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pidtgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)pidtgid;
    u32 tgid = (u32)(pidtgid >> 32);

    bpf_map_update_elem(&gpu_job_start, &pid, &ts, BPF_ANY);

    struct gpu_stats *stats = bpf_map_lookup_elem(&gpu_stats_map, &pid);
    if (stats) {
        __sync_fetch_and_add(&stats->total_jobs_submitted, 1);
        __sync_fetch_and_add(&stats->active_jobs, 1);
        stats->last_submit_ns = ts;
    } else {
        struct gpu_stats new_stats = {};
        new_stats.total_jobs_submitted = 1;
        new_stats.active_jobs = 1;
        new_stats.last_submit_ns = ts;
        bpf_get_current_comm(&new_stats.comm, sizeof(new_stats.comm));
        bpf_map_update_elem(&gpu_stats_map, &pid, &new_stats, BPF_ANY);
    }

    struct gpu_event *evt = bpf_ringbuf_reserve(&gpu_events,
                                                 sizeof(struct gpu_event), 0);
    if (evt) {
        evt->timestamp_ns = ts;
        evt->pid = pid;
        evt->tgid = tgid;
        evt->event_type = GPU_EVENT_JOB_SUBMIT;
        evt->cpu_id = bpf_get_smp_processor_id();
        bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
        evt->job_id = 0;
        evt->fence_id = 0;
        evt->ring_id = 0;
        evt->hw_job_count = 0;

        bpf_probe_read_kernel(&evt->fence_id, sizeof(evt->fence_id),
                              &ctx->fence_id);
        bpf_probe_read_kernel(&evt->job_id, sizeof(evt->job_id),
                              &ctx->job_id);

        bpf_ringbuf_submit(evt, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
