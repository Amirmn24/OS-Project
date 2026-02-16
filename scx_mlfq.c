#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <scx/common.h>
#include "scx_mlfq.bpf.skel.h"

#define PRINT_INTERVAL_MS 50

static bool verbose;
static volatile sig_atomic_t exit_req;

/* time-zero for pretty event timestamps */
static uint64_t t0_ns;

/* Must match BPF event struct + enums */
enum ev_type {
	EV_DEMOTE  = 1,
	EV_DONE_LO = 2,
};

struct ev {
	uint64_t ts_ns;
	uint32_t cpu;
	uint32_t pid;
	uint8_t  type;
	uint8_t  _pad[3];
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int sig)
{
	(void)sig;
	exit_req = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	(void)ctx;
	if (data_sz < sizeof(struct ev))
		return 0;

	const struct ev *e = (const struct ev *)data;

	/* BPF filters to cpu0 already, but keep this harmless check */
	if (e->cpu != 0)
		return 0;

	if (!t0_ns)
		t0_ns = e->ts_ns;

	double t_ms = (double)(e->ts_ns - t0_ns) / 1e6;

	if (e->type == EV_DEMOTE) {
		printf("[%.3fms] DEMOTE pid=%u -> LO\n", t_ms, e->pid);
		fflush(stdout);
	} else if (e->type == EV_DONE_LO) {
		printf("[%.3fms] DONE_LO pid=%u\n", t_ms, e->pid);
		fflush(stdout);
	}

	return 0;
}


static void read_needed_stats(struct scx_mlfq *skel, __u64 *enq_hi, __u64 *enq_lo, __u64 *demote)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 cnts[nr_cpus];
	__u32 idx;
	int ret, cpu;

	*enq_hi = *enq_lo = *demote = 0;

	idx = 0;
	ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &idx, cnts);
	if (ret == 0)
		for (cpu = 0; cpu < nr_cpus; cpu++) *enq_hi += cnts[cpu];

	idx = 1;
	ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &idx, cnts);
	if (ret == 0)
		for (cpu = 0; cpu < nr_cpus; cpu++) *enq_lo += cnts[cpu];

	idx = 4;
	ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &idx, cnts);
	if (ret == 0)
		for (cpu = 0; cpu < nr_cpus; cpu++) *demote += cnts[cpu];
}

int main(int argc, char **argv)
{
	struct scx_mlfq *skel;
	struct bpf_link *link;
	struct ring_buffer *rb = NULL;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:
	skel = SCX_OPS_OPEN(mlfq_ops, scx_mlfq);

	while ((opt = getopt(argc, argv, "vh")) != (unsigned)-1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, "Usage: %s [-v]\n", basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, mlfq_ops, scx_mlfq, uei);
	link = SCX_OPS_ATTACH(skel, mlfq_ops, scx_mlfq);

	/* ringbuf setup */
	{
		int efd = bpf_map__fd(skel->maps.events);
		rb = ring_buffer__new(efd, handle_event, NULL, NULL);
		if (!rb) {
			fprintf(stderr, "ring_buffer__new failed\n");
			exit_req = 1;
		}
	}

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 enq_hi, enq_lo, demote;

		/* Drain events so DEMOTE/DONE_LO print quickly */
		if (rb)
			ring_buffer__poll(rb, 0);

		read_needed_stats(skel, &enq_hi, &enq_lo, &demote);
		printf("enq_hi=%llu enq_lo=%llu demote=%llu\n",
		       (unsigned long long)enq_hi,
		       (unsigned long long)enq_lo,
		       (unsigned long long)demote);
		fflush(stdout);

		usleep((useconds_t)PRINT_INTERVAL_MS * 1000);
	}

	/* final drain */
	if (rb)
		ring_buffer__poll(rb, 0);

	if (rb)
		ring_buffer__free(rb);

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_mlfq__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;

	return 0;
}
