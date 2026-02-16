#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/file.h>
#include <signal.h>

#define NS_PER_MS 1000000LL

/* ---- Fixed defaults ---- */
#define MIN_PROCESSES     5
#define MAX_PROCESSES     20

#define MAX_ARRIVAL_MS    1000
#define MIN_RUNTIME_MS    30
#define MAX_RUNTIME_MS    150

#define LOG_FILE          "load_log.csv"

/* ---- sched-ext ---- */
#ifndef SCHED_EXT
#define SCHED_EXT 7
#endif

typedef struct {
    int   id;
    long  arrival_ms;
    long  runtime_ms;
    pid_t pid;
} process_spec;

/* ---- Time helpers ---- */
static inline long long now_mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static inline long long now_cpu_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* ---- CPU workload ---- */
static void cpu_spin_cpu_time(long runtime_ms)
{
    long long start = now_cpu_ns();
    long long dur   = runtime_ms * NS_PER_MS;

    while ((now_cpu_ns() - start) < dur)
        asm volatile("" ::: "memory");
}

/* ---- pin current process to CPU 0 ---- */
static void pin_to_cpu0_or_die(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);

    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        fprintf(stderr, "sched_setaffinity(CPU0) failed: %s\n",
                strerror(errno));
        exit(1);
    }
}

/* ---- SCHED_EXT switch ---- */
static void set_sched_ext_or_die(void)
{
    struct sched_param sp = { .sched_priority = 0 };

    if (sched_setscheduler(0, SCHED_EXT, &sp) != 0) {
        fprintf(stderr,
            "sched_setscheduler(SCHED_EXT) failed: %s\n",
            strerror(errno));
        _exit(1);
    }
}

/* ---- Sort by arrival ---- */
static int cmp_arrival(const void *a, const void *b)
{
    const process_spec *p1 = a;
    const process_spec *p2 = b;

    return (p1->arrival_ms > p2->arrival_ms) -
           (p1->arrival_ms < p2->arrival_ms);
}

/* ---- CSV append with lock ---- */
static void append_csv_line(const char *path,
                            int id, pid_t pid, long arrival_ms,
                            double start_ms, double end_ms, long runtime_ms)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0)
        return;

    flock(fd, LOCK_EX);

    char buf[256];
    int len = snprintf(buf, sizeof(buf),
        "%d,%d,%ld,%.3f,%.3f,%ld\n",
        id, (int)pid, arrival_ms,
        start_ms, end_ms, runtime_ms);

    write(fd, buf, len);

    flock(fd, LOCK_UN);
    close(fd);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <seed>\n", argv[0]);
        return 1;
    }

    pin_to_cpu0_or_die();
    srand(atoi(argv[1]));

    int nproc = MIN_PROCESSES +
        rand() % (MAX_PROCESSES - MIN_PROCESSES + 1);

    process_spec *procs = calloc(nproc, sizeof(*procs));
    if (!procs)
        return 1;

    for (int i = 0; i < nproc; i++) {
        procs[i].id = i;
        procs[i].arrival_ms = rand() % (MAX_ARRIVAL_MS + 1);
        procs[i].runtime_ms =
            MIN_RUNTIME_MS +
            rand() % (MAX_RUNTIME_MS - MIN_RUNTIME_MS + 1);
    }

    qsort(procs, nproc, sizeof(*procs), cmp_arrival);

    /* CSV header */
    {
        int fd = open(LOG_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        const char *hdr =
            "ID,PID,Arrival(ms),Start(ms),End(ms),Runtime(ms)\n";
        write(fd, hdr, strlen(hdr));
        close(fd);
    }

    long long global_start = now_mono_ns();

    /* ---- Fork all children in arrival order ---- */
    for (int i = 0; i < nproc; i++) {

        long long release =
            global_start + procs[i].arrival_ms * NS_PER_MS;

        while (now_mono_ns() < release)
            ;

        pid_t pid = fork();
        if (pid < 0)
            exit(1);

        if (pid == 0) {
            pin_to_cpu0_or_die();
            set_sched_ext_or_die();

            /* Hard barrier: do not run */
            raise(SIGSTOP);

            long long start_wall = now_mono_ns();
            cpu_spin_cpu_time(procs[i].runtime_ms);
            long long end_wall   = now_mono_ns();

            append_csv_line(LOG_FILE,
                procs[i].id, getpid(), procs[i].arrival_ms,
                (start_wall - global_start) / 1e6,
                (end_wall   - global_start) / 1e6,
                procs[i].runtime_ms);

            _exit(0);
        }

        procs[i].pid = pid;
    }

    /* ---- Ensure all children are stopped ---- */
    for (int i = 0; i < nproc; i++) {
        int status;
        waitpid(procs[i].pid, &status, WUNTRACED);
    }

    /* ---- Release children strictly FIFO ---- */
    for (int i = 0; i < nproc; i++)
        kill(procs[i].pid, SIGCONT);

    /* ---- Reap ---- */
    while (wait(NULL) > 0)
        ;

    free(procs);
    return 0;
}