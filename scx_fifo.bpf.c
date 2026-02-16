/*
 * scx_fifo.bpf.c - A simple FIFO scheduler using sched-ext
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile u64 fifo_slice_ns = SCX_SLICE_DFL;

void BPF_STRUCT_OPS(fifo_enqueue, struct task_struct *p, u64 enq_flags)
{

    scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, fifo_slice_ns, enq_flags);
}

SEC(".struct_ops.link")
struct sched_ext_ops fifo_ops = {
    .enqueue    = (void *)fifo_enqueue,
    .name       = "scx_fifo_demo", 
};
