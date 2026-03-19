#!/usr/bin/env python3
"""Trace all outbound TCP connections — shows what your processes are connecting to.

Usage:
    sudo python3 tcp_connect.py              # all processes
    sudo python3 tcp_connect.py curl         # only 'curl'
    sudo python3 tcp_connect.py python3      # only 'python3'
"""

import sys
import os
import struct
import socket
from bcc import BPF

filter_comm = sys.argv[1] if len(sys.argv) > 1 else None

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct event_t {
    u32 pid;
    u32 uid;
    u16 dport;
    u32 daddr;
    u32 saddr;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

// Stash the sock pointer so we can grab it on return
BPF_HASH(currsock, u32, struct sock *);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    currsock.update(&pid, &sk);
    return 0;
}

int trace_connect_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct sock **skpp = currsock.lookup(&pid);
    if (skpp == 0) return 0;

    if (ret != 0) {
        currsock.delete(&pid);
        return 0;
    }

    struct sock *skp = *skpp;
    u16 dport = skp->__sk_common.skc_dport;

    // Only trace IPv4 for simplicity
    u16 family = skp->__sk_common.skc_family;
    if (family != AF_INET) {
        currsock.delete(&pid);
        return 0;
    }

    struct event_t evt = {};
    evt.pid = pid;
    evt.uid = bpf_get_current_uid_gid();
    evt.dport = ntohs(dport);
    evt.daddr = skp->__sk_common.skc_daddr;
    evt.saddr = skp->__sk_common.skc_rcv_saddr;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    events.perf_submit(ctx, &evt, sizeof(evt));
    currsock.delete(&pid);
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")

def inet_ntoa(addr):
    return socket.inet_ntoa(struct.pack("I", addr))

print(f"Tracing outbound TCP connections" +
      (f" for: {filter_comm}" if filter_comm else "") +
      "... Ctrl-C to stop\n")
print(f"{'PID':<8} {'COMM':<16} {'UID':<6} {'SOURCE':<22} {'DESTINATION':<22}")
print("─" * 76)

def handle_event(cpu, data, size):
    evt = b["events"].event(data)
    comm = evt.comm.decode("utf-8", errors="replace")

    if filter_comm and comm != filter_comm:
        return

    src = f"{inet_ntoa(evt.saddr)}"
    dst = f"{inet_ntoa(evt.daddr)}:{evt.dport}"
    print(f"{evt.pid:<8} {comm:<16} {evt.uid:<6} {src:<22} {dst:<22}")

b["events"].open_perf_buffer(handle_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nDone.")
