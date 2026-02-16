/*
 * scx_fifo.bpf.c - A FIFO scheduler with Statistics (API Fixed)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

struct task_stats {
    u64 total_run_ns;
    u64 total_wait_ns;
    u64 nr_switches;
    u64 last_enq_ts;
    u64 last_run_ts;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct task_stats);
} stats_map SEC(".maps");

// 5 seconds slice to ensure strict FIFO
const volatile u64 fifo_slice_ns = 5000000000ULL; 

void BPF_STRUCT_OPS(fifo_enable, struct task_struct *p)
{
    u32 pid = p->pid;
    struct task_stats stats = {};
    bpf_probe_read_kernel_str(stats.comm, sizeof(stats.comm), p->comm);
    bpf_map_update_elem(&stats_map, &pid, &stats, BPF_NOEXIST);
}

void BPF_STRUCT_OPS(fifo_enqueue, struct task_struct *p, u64 enq_flags)
{
    u32 pid = p->pid;
    struct task_stats *stats = bpf_map_lookup_elem(&stats_map, &pid);
    
    if (stats) {
        stats->last_enq_ts = bpf_ktime_get_ns();
    }
    
    //  scx_bpf_dsq_insert instead of scx_bpf_dispatch
    scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, fifo_slice_ns, enq_flags);
}

void BPF_STRUCT_OPS(fifo_running, struct task_struct *p)
{
    u32 pid = p->pid;
    struct task_stats *stats = bpf_map_lookup_elem(&stats_map, &pid);
    u64 now = bpf_ktime_get_ns();

    if (stats) {
        if (stats->last_enq_ts) {
            stats->total_wait_ns += (now - stats->last_enq_ts);
        }
        stats->nr_switches++;
        stats->last_run_ts = now;
    }
}

void BPF_STRUCT_OPS(fifo_stopping, struct task_struct *p, bool runnable)
{
    u32 pid = p->pid;
    struct task_stats *stats = bpf_map_lookup_elem(&stats_map, &pid);
    u64 now = bpf_ktime_get_ns();

    if (stats && stats->last_run_ts) {
        stats->total_run_ns += (now - stats->last_run_ts);
    }
}

SEC(".struct_ops.link")
struct sched_ext_ops fifo_ops = {
    .enable     = (void *)fifo_enable,
    .enqueue    = (void *)fifo_enqueue,
    .running    = (void *)fifo_running,
    .stopping   = (void *)fifo_stopping,
    .name       = "scx_fifo_stats",
};
