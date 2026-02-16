/*
 * main.c - Loader for scx_fifo
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <scx/common.h>
#include "scx_fifo.bpf.skel.h" 

// exit by ctrl+c
static volatile int exiting = 0;

static void sig_int(int signo)
{
    exiting = 1;
}

int main(int argc, char **argv)
{
    struct scx_fifo_bpf *skel;
    struct scx_init_args init_args = {}; // initial setup
    int err;

    // signal handler
    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);

    // open bpf
    skel = scx_fifo_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return -1;
    }

    // load in kernel
    err = scx_fifo_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    // attach scheduler to system
    err = scx_fifo_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("SCX FIFO Scheduler Loaded. Press Ctrl+C to unload.\n");

    while (!exiting && !skel->links.fifo_ops) {
        sleep(1);
    }

cleanup:
    // back to linux scheduler
    scx_fifo_bpf__destroy(skel);
    printf("Scheduler Unloaded.\n");
    return 0;
}
