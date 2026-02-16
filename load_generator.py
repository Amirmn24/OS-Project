import time
import random
import multiprocessing
import argparse
import sys
import os

#output
LOG_FILE = "scheduler_log.csv"

def cpu_burner(proc_id, duration_ms, results_queue):

    start_time = time.time()
    
    duration_sec = duration_ms / 1000.0
    
    # busy wait
    while (time.time() - start_time) < duration_sec:
        pass 
    
    end_time = time.time()
    
    # format: ID, StartTime, EndTime, DurationRequested
    results_queue.put((proc_id, start_time, end_time, duration_ms))

def run_workload(seed, num_procs, max_duration, max_delay):

    random.seed(seed)
    
    # process features (id, arrival_delay_ms, duration_ms)
    tasks = []
    for i in range(num_procs):
        arrival_delay = random.randint(0, max_delay)  
        duration = random.randint(100, max_duration) 
        tasks.append({'id': i, 'delay': arrival_delay, 'duration': duration})
    
    # sort
    tasks.sort(key=lambda x: x['delay'])
    
    print(f"Generating {num_procs} processes with Seed={seed}...")
    print(f"Tasks plan: {tasks}")
    
    results_queue = multiprocessing.Queue()

    with open(LOG_FILE, "w") as f:
        f.write("ProcessID,ArrivalTimestamp,StartTimestamp,EndTimestamp,DurationMS\n")
    
    # main loop
    base_time = time.time()
    active_procs = []
    
    for task in tasks:
        # current time
        current_offset_ms = (time.time() - base_time) * 1000
        wait_ms = task['delay'] - current_offset_ms
 
        if wait_ms > 0:
            time.sleep(wait_ms / 1000.0)
            
        # precise arrival time
        actual_arrival_time = time.time()
        
        # create and run the process
        p = multiprocessing.Process(
            target=cpu_burner, 
            args=(task['id'], task['duration'], results_queue)
        )
        p.start()
        active_procs.append(p)
        print(f"Process {task['id']} spawned at {actual_arrival_time:.4f} (Planned delay: {task['delay']}ms)")
        
    # wait for all processes
    for p in active_procs:
        p.join()
  
    print("\nAll processes finished. Saving logs...")
    
    results = []
    while not results_queue.empty():
        results.append(results_queue.get())
    
    # rewrite file with new information
    with open(LOG_FILE, "a") as f:
        for r in results:
            p_id, start, end, dur = r

            f.write(f"{p_id},0,{start:.6f},{end:.6f},{dur}\n")

    print(f"Logs saved to {LOG_FILE}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Load Generator for OS Project")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--procs", type=int, default=5, help="Number of processes")
    parser.add_argument("--duration", type=int, default=2000, help="Max duration (ms)")
    parser.add_argument("--delay", type=int, default=3000, help="Max arrival delay (ms)")
    
    args = parser.parse_args()
    
    run_workload(args.seed, args.procs, args.duration, args.delay)
