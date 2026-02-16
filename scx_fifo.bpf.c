#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);
} stats SEC(".maps");

static __always_inline void stat_inc(u32 idx)
{
	u64 *cnt = bpf_map_lookup_elem(&stats, &idx);
	if (cnt)
		(*cnt)++;
}

s32 BPF_STRUCT_OPS(fifo_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	if (is_idle) {
		stat_inc(0);
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_INF, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(fifo_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);
	scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_INF, enq_flags);
}

void BPF_STRUCT_OPS(fifo_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_consume(SCX_DSQ_GLOBAL);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(fifo_init)
{
	return 0;
}

void BPF_STRUCT_OPS(fifo_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(fifo_ops,
	       .select_cpu	= (void *)fifo_select_cpu,
	       .enqueue		= (void *)fifo_enqueue,
	       .dispatch	= (void *)fifo_dispatch,
	       .init		= (void *)fifo_init,
	       .exit		= (void *)fifo_exit,
	       .flags		= SCX_OPS_SWITCH_PARTIAL,
	       .name		= "fifo");
