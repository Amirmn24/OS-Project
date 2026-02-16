/* Fix header clash: vmlinux.h and uapi/linux/bpf.h can both define some enums */
#ifndef __LINUX_BPF_H__
#define __LINUX_BPF_H__
#endif

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/* DSQs */
#define DSQ_HI 0
#define DSQ_LO 1

#define NS_PER_MS 1000000ULL
#define HI_SLICE_NS (50ULL * NS_PER_MS)   /* 50ms */

/* Only emit events for CPU0 (matches your CPU0 testing) */
#define TRACE_CPU 0

/* Per-task level: 0 => HI, 1 => LO */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(u32));    /* pid */
	__uint(value_size, sizeof(u8));   /* level */
	__uint(max_entries, 65536);
} task_level SEC(".maps");

/* Minimal stats */
enum {
	STAT_ENQ_HI = 0,
	STAT_ENQ_LO = 1,
	STAT_CONS_HI = 2,
	STAT_CONS_LO = 3,
	STAT_DEMOTE = 4,
	STAT_NR,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, STAT_NR);
} stats SEC(".maps");

static __always_inline void stat_inc(u32 idx)
{
	u64 *cnt = bpf_map_lookup_elem(&stats, &idx);
	if (cnt)
		(*cnt)++;
}

static __always_inline u32 task_pid(struct task_struct *p)
{
	return (u32)BPF_CORE_READ(p, pid);
}

static __always_inline u8 get_level(struct task_struct *p)
{
	u32 pid = task_pid(p);
	u8 *lvl = bpf_map_lookup_elem(&task_level, &pid);
	return lvl ? *lvl : 0; /* default HI */
}

static __always_inline void set_level(struct task_struct *p, u8 lvl)
{
	u32 pid = task_pid(p);
	bpf_map_update_elem(&task_level, &pid, &lvl, BPF_ANY);
}

static __always_inline void del_level(struct task_struct *p)
{
	u32 pid = task_pid(p);
	bpf_map_delete_elem(&task_level, &pid);
}

/* ---- log events via ringbuf (NO timeline, NO comm) ---- */
enum ev_type {
	EV_DEMOTE  = 1,
	EV_DONE_LO = 2,
};

struct ev {
	u64 ts_ns;
	u32 cpu;
	u32 pid;
	u8  type;
	u8  _pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1MB */
} events SEC(".maps");

static __always_inline void emit_event(struct task_struct *p, u8 type)
{
	struct ev *e;
	u32 cpu = bpf_get_smp_processor_id();

	if (cpu != TRACE_CPU)
		return;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;

	e->ts_ns = bpf_ktime_get_ns();
	e->cpu   = cpu;
	e->pid   = task_pid(p);
	e->type  = type;

	bpf_ringbuf_submit(e, 0);
}

/* Keep CPU selection default; no queue-bypass fastpaths. */
s32 BPF_STRUCT_OPS(mlfq_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
}

void BPF_STRUCT_OPS(mlfq_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (get_level(p) == 0) {
		stat_inc(STAT_ENQ_HI);
		scx_bpf_dispatch(p, DSQ_HI, HI_SLICE_NS, enq_flags);
	} else {
		stat_inc(STAT_ENQ_LO);
		scx_bpf_dispatch(p, DSQ_LO, SCX_SLICE_INF, enq_flags);
	}
}

void BPF_STRUCT_OPS(mlfq_dispatch, s32 cpu, struct task_struct *prev)
{
	stat_inc(STAT_CONS_HI);
	if (scx_bpf_consume(DSQ_HI))
		return;

	stat_inc(STAT_CONS_LO);
	scx_bpf_consume(DSQ_LO);
}

/*
 * DEMOTE logic: unchanged from your file’s behavior:
 * - only if runnable
 * - only if currently HI
 * - only if slice consumed (p->scx.slice == 0)
 */
void BPF_STRUCT_OPS(mlfq_stopping, struct task_struct *p, bool runnable)
{
	/* One-round RR then FIFO demotion */
	if (!runnable)
		return;

	if (get_level(p) != 0)
		return;

	if (p->scx.slice == 0) {
		set_level(p, 1);
		stat_inc(STAT_DEMOTE);

		/* demote signal (same mechanism as before) */
		emit_event(p, EV_DEMOTE);
	}
}

void BPF_STRUCT_OPS(mlfq_enable, struct task_struct *p)
{
	set_level(p, 0);
}

void BPF_STRUCT_OPS(mlfq_disable, struct task_struct *p)
{
	/* DONE in LO: task is leaving sched_ext while it is in LO */
	if (get_level(p) == 1)
		emit_event(p, EV_DONE_LO);

	del_level(p);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mlfq_init)
{
	int ret;

	ret = scx_bpf_create_dsq(DSQ_HI, -1);
	if (ret)
		return ret;

	ret = scx_bpf_create_dsq(DSQ_LO, -1);
	if (ret)
		return ret;

	return 0;
}

void BPF_STRUCT_OPS(mlfq_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(mlfq_ops,
	       .select_cpu	= (void *)mlfq_select_cpu,
	       .enqueue		= (void *)mlfq_enqueue,
	       .dispatch	= (void *)mlfq_dispatch,
	       .stopping	= (void *)mlfq_stopping,
	       .enable		= (void *)mlfq_enable,
	       .disable		= (void *)mlfq_disable,
	       .init		= (void *)mlfq_init,
	       .exit		= (void *)mlfq_exit,
	       .flags		= SCX_OPS_SWITCH_PARTIAL,
	       .name		= "mlfq2_raw");
