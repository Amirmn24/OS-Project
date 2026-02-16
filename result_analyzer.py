import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

plt.style.use('bmh')

def analyze_fifo(log_file):

    df = pd.read_csv(log_file)

    # sort by StartTimestamp
    df = df.sort_values(by='StartTimestamp')
    
    min_time = df['StartTimestamp'].min()
    df['RelStart'] = df['StartTimestamp'] - min_time
    df['RelEnd'] = df['EndTimestamp'] - min_time
    
    print("\n--- Process Execution Table ---")
    print(df[['ProcessID', 'RelStart', 'RelEnd', 'DurationMS']])

    # check FIFO condition
    print("\n--- FIFO Validation ---")
    violation = False
    sorted_tasks = df.to_dict('records')
    
    for i in range(1, len(sorted_tasks)):
        prev_task = sorted_tasks[i-1]
        curr_task = sorted_tasks[i]
        
        # check for overlap
        if curr_task['RelStart'] < prev_task['RelEnd']:
            print(f"[!] Violation: Process {curr_task['ProcessID']} started before {prev_task['ProcessID']} finished!")
            violation = True
        else:
             print(f"[OK] Process {curr_task['ProcessID']} started after {prev_task['ProcessID']} finished.")
             
    if not violation:
        print("\nSUCCESS: Strict FIFO behavior confirmed (No preemption detected).")

    fig, ax = plt.subplots(figsize=(10, 6))
    
    colors = plt.cm.tab10.colors 
    
    for i, task in df.iterrows():
        pid = task['ProcessID']
        start = task['RelStart']
        duration = task['RelEnd'] - task['RelStart']
        
        ax.broken_barh([(start, duration)], (pid * 10, 9), 
                      facecolors=colors[int(pid) % len(colors)])
        
        ax.text(start + duration/2, pid * 10 + 4.5, f"P{int(pid)}", 
                ha='center', va='center', color='white', fontweight='bold')

    ax.set_ylim(-5, len(df) * 10 + 5)
    ax.set_xlim(0, df['RelEnd'].max() + 0.5)
    ax.set_xlabel('Time (seconds)')
    ax.set_ylabel('Process ID')
    ax.set_yticks([i * 10 + 4.5 for i in df['ProcessID']])
    ax.set_yticklabels([f"P{i}" for i in df['ProcessID']])
    ax.set_title('Gantt Chart: FIFO Scheduler Execution')
    ax.grid(True)
    
    plt.tight_layout()
    plt.savefig("fifo_gantt_chart.png")
    print("\nGantt chart saved to 'fifo_gantt_chart.png'")
    plt.show()

if __name__ == "__main__":
    analyze_fifo("scheduler_log.csv")