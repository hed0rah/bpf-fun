#!/usr/bin/env python3
"""Live connection map — shows all TCP connections grouped by destination.

Periodically snapshots active connections and shows a summary:
which processes are talking to which IPs/ports, with byte counts.

Think of it as a live "who's talking to what" dashboard.

Usage:
    sudo python3 conn_map.py                  # refresh every 5s
    sudo python3 conn_map.py --interval 10    # refresh every 10s
    sudo python3 conn_map.py java             # only 'java' process
"""

import sys
import struct
import socket
import time
import argparse
from collections import defaultdict
from bcc import BPF

parser = argparse.ArgumentParser()
parser.add_argument("comm", nargs="?", default=None, help="filter by process name")
parser.add_argument("--interval", type=int, default=5, help="refresh interval (s)")
args = parser.parse_args()

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/tcp_states.h>

struct key_t {
    u32 pid;
    u32 daddr;
    u16 dport;
    char comm[16];
};

struct val_t {
    u64 send_bytes;
    u64 recv_bytes;
    u64 count;
};

BPF_HASH(conn_map, struct key_t, struct val_t, 10240);

// Helper to fill a key from a sock — all reads go through bpf_probe_read
static inline int fill_key(struct sock *sk, struct key_t *key) {
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) return -1;

    key->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_kernel(&key->daddr, sizeof(key->daddr), &sk->__sk_common.skc_daddr);

    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    key->dport = ntohs(dport);

    bpf_get_current_comm(&key->comm, sizeof(key->comm));
    return 0;
}

// Track bytes sent
int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg,
                      size_t size) {
    struct key_t key = {};
    if (fill_key(sk, &key) != 0) return 0;

    struct val_t zero = {};
    struct val_t *val = conn_map.lookup_or_try_init(&key, &zero);
    if (val) {
        val->send_bytes += size;
        val->count += 1;
    }
    return 0;
}

// Track bytes received
int trace_tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied) {
    if (copied <= 0) return 0;

    struct key_t key = {};
    if (fill_key(sk, &key) != 0) return 0;

    struct val_t zero = {};
    struct val_t *val = conn_map.lookup_or_try_init(&key, &zero);
    if (val) {
        val->recv_bytes += copied;
    }
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
b.attach_kprobe(event="tcp_cleanup_rbuf", fn_name="trace_tcp_cleanup_rbuf")

WELL_KNOWN = {
    22: "ssh", 80: "http", 443: "https",
    3306: "mysql", 5432: "postgres", 6379: "redis", 27017: "mongo",
    8080: "http-alt", 9200: "elastic", 9092: "kafka", 5672: "rabbitmq",
    6443: "k8s-api", 2379: "etcd", 11211: "memcache", 8500: "consul",
}

def inet_ntoa(addr):
    return socket.inet_ntoa(struct.pack("I", addr))

def fmt_bytes(n):
    if n >= 1_073_741_824:
        return f"{n/1073741824:.1f}G"
    elif n >= 1_048_576:
        return f"{n/1048576:.1f}M"
    elif n >= 1024:
        return f"{n/1024:.1f}K"
    return f"{n}B"

print(f"Connection map — refreshing every {args.interval}s" +
      (f" (filtering: {args.comm})" if args.comm else "") +
      "... Ctrl-C to stop\n")

try:
    while True:
        time.sleep(args.interval)

        conn_table = b.get_table("conn_map")
        rows = []
        for k, v in conn_table.items():
            comm = k.comm.decode("utf-8", errors="replace")
            if args.comm and comm != args.comm:
                continue
            rows.append((comm, k.pid, k.daddr, k.dport,
                          v.send_bytes, v.recv_bytes, v.count))

        if not rows:
            continue

        # Sort by total bytes descending
        rows.sort(key=lambda r: r[4] + r[5], reverse=True)

        ts = time.strftime("%H:%M:%S")
        print(f"\n{'═'*90}")
        print(f"  CONNECTION MAP — {ts}")
        print(f"{'═'*90}")
        print(f"  {'COMM':<16} {'PID':<8} {'DESTINATION':<26} {'SERVICE':<10} "
              f"{'TX':>8} {'RX':>8} {'CALLS':>7}")
        print(f"  {'─'*16} {'─'*8} {'─'*26} {'─'*10} {'─'*8} {'─'*8} {'─'*7}")

        for comm, pid, daddr, dport, tx, rx, count in rows:
            dst = f"{inet_ntoa(daddr)}:{dport}"
            svc = WELL_KNOWN.get(dport, "")
            print(f"  {comm:<16} {pid:<8} {dst:<26} {svc:<10} "
                  f"{fmt_bytes(tx):>8} {fmt_bytes(rx):>8} {count:>7}")

        total_tx = sum(r[4] for r in rows)
        total_rx = sum(r[5] for r in rows)
        print(f"  {'─'*86}")
        print(f"  {'TOTAL':<16} {'':8} {'':26} {'':10} "
              f"{fmt_bytes(total_tx):>8} {fmt_bytes(total_rx):>8} "
              f"{sum(r[6] for r in rows):>7}")

        # Clear for next interval
        conn_table.clear()

except KeyboardInterrupt:
    print("\nDone.")
