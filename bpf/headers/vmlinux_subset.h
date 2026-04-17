/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * vmlinux_subset.h — Minimal BTF-derived kernel type definitions for EcoBPF.
 *
 * This file provides a portable subset of kernel types needed by EcoBPF probes.
 * For CO-RE (Compile Once – Run Everywhere) portability, regenerate with:
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux_full.h
 * Then extract only the structures referenced by the probes.
 *
 * This subset targets kernels >= 5.8 with BTF support enabled.
 */

#ifndef __VMLINUX_SUBSET_H__
#define __VMLINUX_SUBSET_H__

typedef unsigned char       __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;
typedef signed char         __s8;
typedef signed short        __s16;
typedef signed int          __s32;
typedef signed long long    __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_DEVMAP = 14,
    BPF_MAP_TYPE_SOCKMAP = 15,
    BPF_MAP_TYPE_CPUMAP = 16,
    BPF_MAP_TYPE_XSKMAP = 17,
    BPF_MAP_TYPE_SOCKHASH = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
    BPF_MAP_TYPE_QUEUE = 22,
    BPF_MAP_TYPE_STACK = 23,
    BPF_MAP_TYPE_SK_STORAGE = 24,
    BPF_MAP_TYPE_DEVMAP_HASH = 25,
    BPF_MAP_TYPE_STRUCT_OPS = 26,
    BPF_MAP_TYPE_RINGBUF = 27,
    BPF_MAP_TYPE_INODE_STORAGE = 28,
};

#define BPF_ANY 0
#define BPF_NOEXIST 1
#define BPF_EXIST 2

typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;

typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;

/* Boolean type */
typedef _Bool bool;
#define true  1
#define false 0

/* Null */
#define NULL ((void *)0)

/*
 * Task state (scheduler) — CO-RE relocated fields.
 * Only fields accessed by our probes are defined.
 */
struct task_struct {
    int                     pid;
    int                     tgid;
    char                    comm[16];
    unsigned int            flags;
    volatile long           state;
    int                     on_cpu;
    unsigned int            cpu;
    u64                     utime;
    u64                     stime;
    unsigned long           nvcsw;
    unsigned long           nivcsw;
    struct mm_struct        *mm;
    struct css_set          *cgroups;
} __attribute__((preserve_access_index));

struct mm_struct {
    unsigned long           total_vm;
    unsigned long           locked_vm;
    unsigned long           pinned_vm;
    unsigned long           data_vm;
    unsigned long           exec_vm;
    unsigned long           stack_vm;
} __attribute__((preserve_access_index));

/*
 * Tracepoint argument structures for sched events.
 * These match the kernel tracepoint format.
 */

/* tp/sched/sched_switch */
struct trace_event_raw_sched_switch {
    /* Common tracepoint fields (skipped by BPF) */
    unsigned short          common_type;
    unsigned char           common_flags;
    unsigned char           common_preempt_count;
    int                     common_pid;

    /* sched_switch specific fields */
    char                    prev_comm[16];
    pid_t                   prev_pid;
    int                     prev_prio;
    long                    prev_state;
    char                    next_comm[16];
    pid_t                   next_pid;
    int                     next_prio;
} __attribute__((preserve_access_index));

/* tp/sched/sched_process_exec */
struct trace_event_raw_sched_process_exec {
    unsigned short          common_type;
    unsigned char           common_flags;
    unsigned char           common_preempt_count;
    int                     common_pid;

    int                     old_pid;
    /* filename is a dynamic string, accessed via bpf_probe_read */
} __attribute__((preserve_access_index));

/*
 * Memory / VM event argument structures
 */

/* Page fault tracepoint args (tp/exceptions/page_fault_user, page_fault_kernel) */
struct trace_event_raw_page_fault {
    unsigned short          common_type;
    unsigned char           common_flags;
    unsigned char           common_preempt_count;
    int                     common_pid;

    unsigned long           address;
    unsigned long           ip;
    unsigned long           error_code;
} __attribute__((preserve_access_index));

/* tp/vmscan/mm_vmscan_direct_reclaim_begin */
struct trace_event_raw_mm_vmscan_direct_reclaim_begin {
    unsigned short          common_type;
    unsigned char           common_flags;
    unsigned char           common_preempt_count;
    int                     common_pid;

    int                     order;
    unsigned long           gfp_flags;
} __attribute__((preserve_access_index));

/*
 * GPU / DRM scheduler tracepoint (when available)
 */
struct trace_event_raw_gpu_sched {
    unsigned short          common_type;
    unsigned char           common_flags;
    unsigned char           common_preempt_count;
    int                     common_pid;

    u64                     fence_id;
    u64                     job_id;
    u32                     ring;
    u32                     hw_job_count;
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_SUBSET_H__ */
