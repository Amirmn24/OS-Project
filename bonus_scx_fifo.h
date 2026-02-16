/* scx_fifo.h */
#ifndef __SCX_FIFO_H
#define __SCX_FIFO_H

struct task_stats {
    unsigned long long enqueue_time;   
    unsigned long long first_run_time;    
    unsigned long long total_runtime;     
    unsigned long long nr_switches;    
    unsigned long long last_run_ts;     
};

#endif /* __SCX_FIFO_H */
