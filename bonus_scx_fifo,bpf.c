/* scx_fifo.bpf.c */
#include <scx/common.bpf.h>
#include "scx_fifo.h" 
char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct task_stats);
} proc_stats SEC(".maps");

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

	u32 pid = p->pid;
	struct task_stats *s;
	u64 now = bpf_ktime_get_ns();

	s = bpf_map_lookup_elem(&proc_stats, &pid);
	if (!s) {
		struct task_stats new_stat = {};
		new_stat.enqueue_time = now;
		bpf_map_update_elem(&proc_stats, &pid, &new_stat, BPF_ANY);
	}
	/* -------------------------------------- */

	scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_INF, enq_flags);
}

void BPF_STRUCT_OPS(fifo_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_consume(SCX_DSQ_GLOBAL);
}

void BPF_STRUCT_OPS(fifo_running, struct task_struct *p)
{
	u32 pid = p->pid;
	struct task_stats *s;
	u64 now = bpf_ktime_get_ns();

	s = bpf_map_lookup_elem(&proc_stats, &pid);
	if (s) {
		if (s->first_run_time == 0)
			s->first_run_time = now;

		s->nr_switches++;

		s->last_run_ts = now;
	}
}

void BPF_STRUCT_OPS(fifo_stopping, struct task_struct *p, bool runnable)
{
	u32 pid = p->pid;
	struct task_stats *s;
	u64 now = bpf_ktime_get_ns();

	s = bpf_map_lookup_elem(&proc_stats, &pid);
	if (s && s->last_run_ts > 0) {
		s->total_runtime += (now - s->last_run_ts);
		s->last_run_ts = 0; 
	}
}

void BPF_STRUCT_OPS(fifo_exit, struct task_struct *p)
{
	struct scx_exit_info ei; 
}

void BPF_STRUCT_OPS(fifo_scheduler_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(fifo_init)
{
	return 0;
}

SCX_OPS_DEFINE(fifo_ops,
	       .select_cpu	= (void *)fifo_select_cpu,
	       .enqueue		= (void *)fifo_enqueue,
	       .dispatch	= (void *)fifo_dispatch,
           // اضافه کردن هوک‌های جدید
           .running     = (void *)fifo_running,
           .stopping    = (void *)fifo_stopping,
	       .init		= (void *)fifo_init,
	       .exit		= (void *)fifo_scheduler_exit, 
	       .flags		= SCX_OPS_SWITCH_PARTIAL,
	       .name		= "fifo");
