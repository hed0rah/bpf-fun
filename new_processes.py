#!/usr/bin/env python3
"""Watch every new process that spawns -- with full command line.

Catches short-lived processes that ps/top would miss. Great for seeing
what cron jobs fire, what subprocesses your app spawns, or catching
suspicious exec activity.

Usage:
    sudo python3 new_processes.py
    sudo python3 new_processes.py --failed     # also show failed execs
"""

import sys
import argparse
import time
from bcc import BPF

parser = argparse.ArgumentParser()
parser.add_argument("--failed", action="store_true", help="include failed execs")
args = parser.parse_args()

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    int retval;
    char comm[16];
    char arg0[80];
    char arg1[40];
    char arg2[40];
};

BPF_PERF_OUTPUT(events);

// Per-CPU scratch space so we don't blow the 512-byte stack limit
BPF_PERCPU_ARRAY(event_buf, struct event_t, 1);

// Stash args on entry (before the binary image replaces them)
struct data_t {
    char arg0[80];
    char arg1[40];
    char arg2[40];
};
BPF_HASH(execs, u32, struct data_t);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t d = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_probe_read_user_str(d.arg0, sizeof(d.arg0), args->filename);

    const char *const *argv = (const char *const *)args->argv;
    const char *argp;

    bpf_probe_read_user(&argp, sizeof(argp), &argv[1]);
    if (argp)
        bpf_probe_read_user_str(d.arg1, sizeof(d.arg1), argp);

    bpf_probe_read_user(&argp, sizeof(argp), &argv[2]);
    if (argp)
        bpf_probe_read_user_str(d.arg2, sizeof(d.arg2), argp);

    execs.update(&pid, &d);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct data_t *dp = execs.lookup(&pid);
    if (dp == 0) return 0;

    int ret = args->ret;
    FILTER_FAILED

    // Use per-cpu array instead of stack allocation
    int zero = 0;
    struct event_t *evt = event_buf.lookup(&zero);
    if (evt == 0) return 0;

    evt->pid = pid;
    evt->retval = ret;
    evt->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt->ppid = task->real_parent->tgid;

    __builtin_memcpy(evt->arg0, dp->arg0, sizeof(evt->arg0));
    __builtin_memcpy(evt->arg1, dp->arg1, sizeof(evt->arg1));
    __builtin_memcpy(evt->arg2, dp->arg2, sizeof(evt->arg2));

    events.perf_submit(args, evt, sizeof(*evt));
    execs.delete(&pid);
    return 0;
}
"""

if args.failed:
    bpf_text = bpf_text.replace("FILTER_FAILED", "")
else:
    bpf_text = bpf_text.replace("FILTER_FAILED", "if (ret != 0) { execs.delete(&pid); return 0; }")

b = BPF(text=bpf_text)

print(f"Watching new processes" +
      (" (including failed)" if args.failed else "") +
      "... Ctrl-C to stop\n")
print(f"{'TIME':<10} {'PID':<8} {'PPID':<8} {'UID':<6} {'RET':<5} {'COMMAND':<50}")
print("-" * 90)

def handle_event(cpu, data, size):
    evt = b["events"].event(data)
    ts = time.strftime("%H:%M:%S")

    arg0 = evt.arg0.decode("utf-8", errors="replace")
    arg1 = evt.arg1.decode("utf-8", errors="replace")
    arg2 = evt.arg2.decode("utf-8", errors="replace")

    cmdline = arg0
    if arg1:
        cmdline += f" {arg1}"
    if arg2:
        cmdline += f" {arg2}"
        cmdline += " ..."

    ret = evt.retval
    ret_str = "OK" if ret == 0 else f"E{abs(ret)}"

    # Highlight failed execs or root
    marker = ""
    if ret != 0:
        marker = " FAILED"
    elif evt.uid == 0:
        marker = " [root]"

    print(f"{ts:<10} {evt.pid:<8} {evt.ppid:<8} {evt.uid:<6} {ret_str:<5} {cmdline:<50}{marker}")

b["events"].open_perf_buffer(handle_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nDone.")
