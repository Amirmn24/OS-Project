/*
 * main.c - Loader for scx_fifo with Statistics Reporting (Fixed)
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_fifo.bpf.skel.h"

// structure similar to ebpf
struct task_stats {
    __u64 total_run_ns;
    __u64 total_wait_ns;
    __u64 nr_switches;
    __u64 last_enq_ts;
    __u64 last_run_ts;
    char comm[16];
};

static volatile int exiting = 0;

static void sig_int(int signo)
{
    exiting = 1;
}

// printing
static void print_statistics(int map_fd)
{
    __u32 key, next_key;
    struct task_stats value;
    
    printf("\n\n================= SCHEDULER STATISTICS (BONUS) =================\n");
    printf("%-7s | %-16s | %-12s | %-12s | %-8s\n", 
           "PID", "Command", "Run Time(ms)", "Wait Time(ms)", "Switches");
    printf("----------------------------------------------------------------\n");

    key = 0; 
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            if (value.total_run_ns > 0) {
                printf("%-7d | %-16s | %-12llu | %-12llu | %-8llu\n", 
                    next_key, 
                    value.comm, 
                    value.total_run_ns / 1000000, 
                    value.total_wait_ns / 1000000, 
                    value.nr_switches);
            }
        }
        key = next_key;
    }
    printf("================================================================\n");
}

int main(int argc, char **argv)
{
    struct scx_fifo_bpf *skel;
    int err;

    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);

    skel = scx_fifo_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return -1;
    }

    err = scx_fifo_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    err = scx_fifo_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("SCX FIFO Scheduler Loaded with Stats Collection.\n");
    printf("Run your workload now using load_generator.py...\n");
    printf("Press Ctrl+C to stop scheduler and view statistics.\n");

    // *** FIX: Removed checking skel->links.fifo_ops which caused the error ***
    while (!exiting) {
        sleep(1);
    }

    // get file descriptor
    if (skel->maps.stats_map) {
        int map_fd = bpf_map__fd(skel->maps.stats_map);
        if (map_fd >= 0) {
            print_statistics(map_fd);
        }
    } else {
        fprintf(stderr, "Could not find stats map to print results.\n");
    }

cleanup:
    scx_fifo_bpf__destroy(skel);
    printf("Scheduler Unloaded.\n");
    return 0;
}
