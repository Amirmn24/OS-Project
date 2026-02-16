/* scx_fifo.c */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <libgen.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <scx/common.h>
#include "scx_fifo.h"         
#include "scx_fifo.bpf.skel.h"

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level,
			   const char *format, va_list args)
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

static void read_stats(struct scx_fifo *skel, __u64 stats_out[2])
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 cnts[2][nr_cpus];
	__u32 idx;

	stats_out[0] = stats_out[1] = 0;

	for (idx = 0; idx < 2; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &idx, cnts[idx]);
		if (ret < 0)
			continue;

		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats_out[idx] += cnts[idx][cpu];
	}
}

static void print_process_details(struct scx_fifo *skel)
{
    int map_fd = bpf_map__fd(skel->maps.proc_stats);
    __u32 key, next_key;
    struct task_stats val;
    
    printf("\n");
    printf("%-8s %-12s %-15s %-12s\n", "PID", "Wait(ms)", "Ctx Switches", "Runtime(ms)");
    printf("%-8s %-12s %-15s %-12s\n", "---", "--------", "------------", "-----------");

    /* iterate on keys */
    key = 0;

    __u32 *cur_key = NULL; 

    while (bpf_map_get_next_key(map_fd, cur_key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
            double wait_ms = 0.0;
            double run_ms = (double)val.total_runtime / 1000000.0;
            
            if (val.first_run_time > val.enqueue_time) {
                wait_ms = (double)(val.first_run_time - val.enqueue_time) / 1000000.0;
            }

            if (val.enqueue_time > 0) {
                 // (wait)
                if (val.first_run_time == 0) {
                     printf("%-8u %-12s %-15llu %-12.2f\n", 
                        next_key, "(Waiting)", val.nr_switches, run_ms);
                } else {
                    printf("%-8u %-12.2f %-15llu %-12.2f\n", 
                        next_key, wait_ms, val.nr_switches, run_ms);
                }
            }
        }
        cur_key = &next_key;
    }
    printf("----------------------------------------------------\n");
}

int main(int argc, char **argv)
{
	struct scx_fifo *skel;
	struct bpf_link *link;
	int ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:
	skel = SCX_OPS_OPEN(fifo_ops, scx_fifo);

	SCX_OPS_LOAD(skel, fifo_ops, scx_fifo, uei);
	link = SCX_OPS_ATTACH(skel, fifo_ops, scx_fifo);
    
    printf("Scheduler Loaded. Showing Stats... (Ctrl+C to stop)\n");

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 st[2];

		read_stats(skel, st);
        
        printf("\033[H\033[J"); 

		printf("Global Stats: local_fastpath=%llu global_enq=%llu\n",
		       (unsigned long long)st[0],
		       (unsigned long long)st[1]);

        print_process_details(skel);

		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_fifo__destroy(skel);

	if (ecode == SCX_ECODE_ACT_RESTART)
		goto restart;

	return 0;
}
