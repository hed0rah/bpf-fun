#!/usr/bin/env python3
"""Trace all new process executions (execve syscall) on arm64."""

from bcc import BPF
from time import strftime

prog = r"""
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx) {
    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event="__arm64_sys_execve", fn_name="trace_execve")

print("%-9s %-7s %-7s %s" % ("TIME", "PID", "PPID", "COMM"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-9s %-7d %-7d %s" % (
        strftime("%H:%M:%S"),
        event.pid,
        event.ppid,
        event.comm.decode('utf-8', errors='replace')
    ))

b["events"].open_perf_buffer(print_event)
print("Tracing execve()... Ctrl+C to stop\n")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDone.")
        exit()
