#!/usr/bin/env python3
"""BPF program that watches file opens, reads, and writes with byte counts.

Usage:
    sudo python3 file_watcher.py              # watch all processes
    sudo python3 file_watcher.py <pid>         # watch a specific pid
    sudo python3 file_watcher.py <comm>        # watch by process name (e.g. python3)

"""

import os
import sys
from bcc import BPF

# always exclude our own pid so the watcher doesn't trace itself
my_pid = os.getpid()

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 fd;
    u64 bytes;
    char comm[16];
    char fname[128];
    u32 op;        // 0=open, 1=read, 2=write
};

BPF_PERF_OUTPUT(events);

// --- openat ---
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    FILTER_SELF
    FILTER_PID
    FILTER_COMM

    struct event_t evt = {};
    evt.pid = pid;
    evt.op = 0;
    evt.bytes = 0;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.fname, sizeof(evt.fname), args->filename);

    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

// --- read ---
TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    FILTER_SELF
    FILTER_PID
    FILTER_COMM

    long ret = args->ret;
    if (ret <= 0) return 0;

    struct event_t evt = {};
    evt.pid = pid;
    evt.op = 1;
    evt.bytes = (u64)ret;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

// --- write ---
TRACEPOINT_PROBE(syscalls, sys_exit_write) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    FILTER_SELF
    FILTER_PID
    FILTER_COMM

    long ret = args->ret;
    if (ret <= 0) return 0;

    struct event_t evt = {};
    evt.pid = pid;
    evt.op = 2;
    evt.bytes = (u64)ret;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""

# always filter out our own pid
bpf_text = bpf_text.replace("FILTER_SELF", f"if (pid == {my_pid}) return 0;")

# apply user filters
filter_pid = ""
filter_comm = ""

if len(sys.argv) > 1:
    arg = sys.argv[1]
    if arg.isdigit():
        filter_pid = f"if (pid != {arg}) return 0;"
    else:
        bpf_text = f'#define COMM_FILTER "{arg}"\n' + bpf_text
        filter_comm = (
            "{ char c[16]; bpf_get_current_comm(&c, sizeof(c)); "
            "if (__builtin_memcmp(c, COMM_FILTER, sizeof(COMM_FILTER) - 1) != 0) return 0; }"
        )

bpf_text = bpf_text.replace("FILTER_PID", filter_pid)
bpf_text = bpf_text.replace("FILTER_COMM", filter_comm)

b = BPF(text=bpf_text)

op_names = {0: "OPEN ", 1: "READ ", 2: "WRITE"}

def print_event(cpu, data, size):
    evt = b["events"].event(data)
    op = op_names.get(evt.op, "?    ")
    fname = evt.fname.decode("utf-8", errors="replace") if evt.op == 0 else ""
    bytes_str = f"{evt.bytes} bytes" if evt.op != 0 else ""
    comm = evt.comm.decode("utf-8", errors="replace")
    print(f"  {op}  pid={evt.pid:<7} comm={comm:<16} {bytes_str:>12}  {fname}")

target_desc = sys.argv[1] if len(sys.argv) > 1 else "all processes"
print(f"Watching file I/O for: {target_desc}  (excluding self pid={my_pid})")
print(f"{'─' * 78}")
print(f"  {'OP':<7} {'PID':<12} {'COMM':<20} {'BYTES':>12}  FILENAME")
print(f"{'─' * 78}")

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nDone.")
