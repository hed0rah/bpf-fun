#!/usr/bin/env python3
"""Count syscalls per process over a 5-second window."""

from bcc import BPF
from time import sleep

prog = r"""
#include <linux/sched.h>

struct key_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(counts, struct key_t, u64);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct key_t key = {};
    key.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    counts.increment(key);
    return 0;
}
"""

b = BPF(text=prog)
print("Counting syscalls for 5 seconds...")
sleep(5)

print("\n%-7s %-16s %s" % ("PID", "COMM", "SYSCALLS"))
print("-" * 40)
for k, v in sorted(b["counts"].items(), key=lambda x: x[1].value, reverse=True)[:20]:
    print("%-7d %-16s %d" % (k.pid, k.comm.decode('utf-8', errors='replace'), v.value))
