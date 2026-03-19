#!/usr/bin/env python3
"""Measure TCP connection latency (SYN -> ESTABLISHED).

Shows how long each outbound TCP connection takes to complete the handshake.
Great for spotting slow DB connections, API timeouts, network issues.

Usage:
    sudo python3 tcp_latency.py                  # all connections
    sudo python3 tcp_latency.py --ms 5           # only show >5ms
    sudo python3 tcp_latency.py java             # only 'java' process
    sudo python3 tcp_latency.py --port 5432      # only PostgreSQL
    sudo python3 tcp_latency.py --port 3306      # only MySQL
"""

import sys
import struct
import socket
import time
import argparse
from bcc import BPF

parser = argparse.ArgumentParser()
parser.add_argument("comm", nargs="?", default=None, help="filter by process name")
parser.add_argument("--ms", type=float, default=0, help="min latency to show (ms)")
parser.add_argument("--port", type=int, default=0, help="filter by dest port")
args = parser.parse_args()

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/tcp_states.h>

struct start_t {
    u64 ts;
    u32 pid;
    char comm[16];
};

struct event_t {
    u32 pid;
    u64 latency_ns;
    u32 saddr;
    u32 daddr;
    u16 dport;
    char comm[16];
};

BPF_HASH(start, struct sock *, struct start_t);
BPF_PERF_OUTPUT(events);

int trace_connect(struct pt_regs *ctx, struct sock *sk) {
    struct start_t s = {};
    s.ts = bpf_ktime_get_ns();
    s.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&s.comm, sizeof(s.comm));
    start.update(&sk, &s);
    return 0;
}

// tcp_finish_connect fires exactly when outbound SYN_SENT -> ESTABLISHED
int trace_tcp_finish_connect(struct pt_regs *ctx, struct sock *sk) {
    struct start_t *sp = start.lookup(&sk);
    if (sp == 0) return 0;

    u64 delta = bpf_ktime_get_ns() - sp->ts;

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) {
        start.delete(&sk);
        return 0;
    }

    struct event_t evt = {};
    evt.pid = sp->pid;
    evt.latency_ns = delta;
    bpf_probe_read_kernel(&evt.daddr, sizeof(evt.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&evt.saddr, sizeof(evt.saddr), &sk->__sk_common.skc_rcv_saddr);

    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    evt.dport = ntohs(dport);

    __builtin_memcpy(&evt.comm, sp->comm, 16);

    events.perf_submit(ctx, &evt, sizeof(evt));
    start.delete(&sk);
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect")
b.attach_kprobe(event="tcp_finish_connect", fn_name="trace_tcp_finish_connect")

WELL_KNOWN = {
    22: "ssh", 25: "smtp", 53: "dns", 80: "http", 443: "https",
    3306: "mysql", 5432: "postgres", 6379: "redis", 27017: "mongo",
    8080: "http-alt", 8443: "https-alt", 9200: "elastic", 9300: "elastic",
    2181: "zookeeper", 9092: "kafka", 5672: "rabbitmq", 11211: "memcached",
    6443: "k8s-api", 2379: "etcd", 8500: "consul",
}

def inet_ntoa(addr):
    return socket.inet_ntoa(struct.pack("I", addr))

def fmt_latency(ns):
    if ns >= 1_000_000_000:
        return f"{ns/1e9:.2f}s"
    elif ns >= 1_000_000:
        return f"{ns/1e6:.1f}ms"
    elif ns >= 1_000:
        return f"{ns/1e3:.0f}μs"
    return f"{ns}ns"

print(f"Tracing TCP connection latency" +
      (f" for '{args.comm}'" if args.comm else "") +
      (f" port {args.port}" if args.port else "") +
      (f" >{args.ms}ms" if args.ms else "") +
      "... Ctrl-C to stop\n")
print(f"{'TIME':<10} {'PID':<8} {'COMM':<16} {'LATENCY':>10}  "
      f"{'DESTINATION':<24} {'SERVICE':<12}")
print("─" * 84)

def handle_event(cpu, data, size):
    evt = b["events"].event(data)
    comm = evt.comm.decode("utf-8", errors="replace")

    if args.comm and comm != args.comm:
        return
    if args.port and evt.dport != args.port:
        return
    if args.ms and evt.latency_ns < args.ms * 1_000_000:
        return

    ts = time.strftime("%H:%M:%S")
    lat = fmt_latency(evt.latency_ns)
    dst = f"{inet_ntoa(evt.daddr)}:{evt.dport}"
    svc = WELL_KNOWN.get(evt.dport, "")

    # Flag slow connections
    if evt.latency_ns >= 1_000_000_000:
        marker = " *** SLOW!"
    elif evt.latency_ns >= 200_000_000:
        marker = " **"
    elif evt.latency_ns >= 50_000_000:
        marker = " *"
    else:
        marker = ""

    print(f"{ts:<10} {evt.pid:<8} {comm:<16} {lat:>10}  {dst:<24} {svc:<12}{marker}")

b["events"].open_perf_buffer(handle_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nDone.")
