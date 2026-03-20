#!/usr/bin/env python3
"""Detect possible port scans by watching for TCP SYN packets to many ports.

Tracks incoming TCP connection attempts per source IP and alerts when
a single IP hits more than THRESHOLD unique ports within WINDOW seconds.

Usage:
    sudo python3 port_scan_detect.py
    sudo python3 port_scan_detect.py --threshold 10 --window 30
"""

import sys
import struct
import socket
import time
import argparse
from collections import defaultdict
from bcc import BPF

parser = argparse.ArgumentParser()
parser.add_argument("--threshold", type=int, default=5,
                    help="unique ports to trigger alert (default 5)")
parser.add_argument("--window", type=int, default=60,
                    help="time window in seconds (default 60)")
args = parser.parse_args()

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>

struct event_t {
    u32 pid;
    u32 saddr;    // source (remote) IP
    u32 daddr;    // dest (local) IP
    u16 lport;    // local port being hit
    char comm[16];
};

BPF_PERF_OUTPUT(events);

int trace_tcp_recv(struct pt_regs *ctx, struct sock *sk) {
    // Only care about TCP sockets in LISTEN state (SYN received)
    u8 state = sk->__sk_common.skc_state;
    // TCP_NEW_SYN_RECV = 12, TCP_SYN_RECV = 3
    // But inet_csk_reqsk_queue_hash_add is better — let's just
    // trace tcp_v4_syn_recv_sock which fires on SYN for listen sockets

    u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET)
        return 0;

    struct event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.saddr = sk->__sk_common.skc_daddr;     // remote addr
    evt.daddr = sk->__sk_common.skc_rcv_saddr; // local addr
    struct inet_sock *inet = inet_sk(sk);
    evt.lport = sk->__sk_common.skc_num;        // local port (host order)
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

b = BPF(text=bpf_text)
# tcp_v4_conn_request fires on incoming SYN to a LISTEN socket
b.attach_kprobe(event="tcp_v4_conn_request", fn_name="trace_tcp_recv")

def inet_ntoa(addr):
    return socket.inet_ntoa(struct.pack("I", addr))

# Track: source_ip -> {(port, timestamp), ...}
connections = defaultdict(list)
alerted = set()

print(f"Watching for port scans (>{args.threshold} ports in {args.window}s)...")
print(f"Ctrl-C to stop\n")
print(f"{'TIME':<10} {'SOURCE IP':<18} {'LOCAL PORT':<12} {'STATUS':<30}")
print("─" * 72)

def handle_event(cpu, data, size):
    evt = b["events"].event(data)
    src_ip = inet_ntoa(evt.saddr)
    now = time.time()
    port = evt.lport

    # Record this connection attempt
    connections[src_ip].append((port, now))

    # Prune old entries outside the window
    connections[src_ip] = [(p, t) for p, t in connections[src_ip]
                           if now - t < args.window]

    unique_ports = len(set(p for p, t in connections[src_ip]))
    ts = time.strftime("%H:%M:%S")

    if unique_ports >= args.threshold:
        if src_ip not in alerted:
            ports_hit = sorted(set(p for p, t in connections[src_ip]))
            print(f"{ts:<10} {src_ip:<18} {'—':<12} "
                  f"⚠️  SCAN DETECTED! {unique_ports} ports: {ports_hit}")
            alerted.add(src_ip)
    else:
        print(f"{ts:<10} {src_ip:<18} {port:<12} "
              f"({unique_ports}/{args.threshold} unique ports)")

b["events"].open_perf_buffer(handle_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n\nSummary — source IPs that triggered alerts:")
    if alerted:
        for ip in sorted(alerted):
            ports = sorted(set(p for p, t in connections[ip]))
            print(f"  {ip}: {len(ports)} unique ports — {ports}")
    else:
        print("  None detected.")
    print("Done.")
