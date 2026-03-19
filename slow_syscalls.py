#!/usr/bin/env python3
"""Catch slow syscalls — find what's blocking your app.

Shows any syscall that takes longer than a threshold (default 10ms).
Perfect for finding slow disk I/O, blocking network calls, lock contention.

Usage:
    sudo python3 slow_syscalls.py                     # all procs, >10ms
    sudo python3 slow_syscalls.py java                # only 'java'
    sudo python3 slow_syscalls.py python3 --ms 50     # python3, >50ms
    sudo python3 slow_syscalls.py --ms 1              # everything >1ms
"""

import sys
import argparse
import time
from bcc import BPF

parser = argparse.ArgumentParser()
parser.add_argument("comm", nargs="?", default=None, help="filter by process name")
parser.add_argument("--ms", type=int, default=10, help="min latency in ms (default 10)")
args = parser.parse_args()

threshold_ns = args.ms * 1_000_000

bpf_text = """
#include <uapi/linux/ptrace.h>

struct start_t {
    u64 ts;
    long id;
};

struct event_t {
    u32 pid;
    u64 latency_ns;
    long syscall_id;
    char comm[16];
};

BPF_HASH(start, u64, struct start_t);
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct start_t s = {};
    s.ts = bpf_ktime_get_ns();
    s.id = args->id;
    start.update(&pid_tgid, &s);
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct start_t *sp = start.lookup(&pid_tgid);
    if (sp == 0) return 0;

    u64 delta = bpf_ktime_get_ns() - sp->ts;
    if (delta < THRESHOLD_NS) {
        start.delete(&pid_tgid);
        return 0;
    }

    struct event_t evt = {};
    evt.pid = pid_tgid >> 32;
    evt.latency_ns = delta;
    evt.syscall_id = sp->id;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    events.perf_submit(args, &evt, sizeof(evt));
    start.delete(&pid_tgid);
    return 0;
}
"""

bpf_text = bpf_text.replace("THRESHOLD_NS", str(threshold_ns))
b = BPF(text=bpf_text)

# Build syscall name table (NR -> name)
import os
syscall_names = {}
try:
    # Read from the audit subsystem or just use the constants
    with open("/usr/include/asm-generic/unistd.h") as f:
        for line in f:
            if line.startswith("#define __NR_") and "NR3264" not in line:
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[1].replace("__NR_", "")
                    try:
                        syscall_names[int(parts[2])] = name
                    except ValueError:
                        pass
except FileNotFoundError:
    pass

# Fallback: try ausyscall if available
if not syscall_names:
    try:
        import subprocess
        result = subprocess.run(["ausyscall", "--dump"], capture_output=True, text=True)
        for line in result.stdout.strip().split("\n")[1:]:
            parts = line.split()
            if len(parts) == 2:
                syscall_names[int(parts[0])] = parts[1]
    except FileNotFoundError:
        pass

def syscall_name(nr):
    return syscall_names.get(nr, f"syscall_{nr}")

def fmt_latency(ns):
    if ns >= 1_000_000_000:
        return f"{ns/1e9:.2f}s"
    elif ns >= 1_000_000:
        return f"{ns/1e6:.1f}ms"
    elif ns >= 1_000:
        return f"{ns/1e3:.0f}μs"
    return f"{ns}ns"

print(f"Tracing syscalls slower than {args.ms}ms" +
      (f" for '{args.comm}'" if args.comm else "") +
      "... Ctrl-C to stop\n")
print(f"{'TIME':<10} {'PID':<8} {'COMM':<16} {'LATENCY':>10}  {'SYSCALL':<20}")
print("─" * 68)

def handle_event(cpu, data, size):
    evt = b["events"].event(data)
    comm = evt.comm.decode("utf-8", errors="replace")

    if args.comm and comm != args.comm:
        return

    ts = time.strftime("%H:%M:%S")
    lat = fmt_latency(evt.latency_ns)
    sc = syscall_name(evt.syscall_id)

    # Flag by severity
    if evt.latency_ns >= 1_000_000_000:
        marker = " *** CRITICAL"
    elif evt.latency_ns >= 100_000_000:
        marker = " ** SLOW"
    elif evt.latency_ns >= 10_000_000:
        marker = " *"
    else:
        marker = ""

    print(f"{ts:<10} {evt.pid:<8} {comm:<16} {lat:>10}  {sc:<20}{marker}")

b["events"].open_perf_buffer(handle_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nDone.")
