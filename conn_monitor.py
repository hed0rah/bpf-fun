#!/usr/bin/env python3
"""Combined TCP connection monitor -- merges conn_map and tcp_latency into
one production-grade dashboard.

Tracks outbound TCP connections with byte counts (TX/RX), connection counts,
and handshake latency (p95 and avg), refreshing on a configurable interval.

Usage:
    sudo python3 conn_monitor.py                          # show everything
    sudo python3 conn_monitor.py --comm java              # filter by process
    sudo python3 conn_monitor.py --port 5432              # filter by dest port
    sudo python3 conn_monitor.py --subnet 10.0.0.0/8      # filter by subnet
    sudo python3 conn_monitor.py --sort lat --top 10      # top 10 by latency
    sudo python3 conn_monitor.py --cumulative             # running totals
    sudo python3 conn_monitor.py --ignore 'sshd|bash'    # hide noisy processes

Examples:

    # Production app server -- what's java talking to?
    sudo python3 conn_monitor.py --comm java --sort lat

    # DB connections only, running totals over time:
    sudo python3 conn_monitor.py --port 5432 --cumulative

    # Internal traffic only, ignore infra noise:
    sudo python3 conn_monitor.py --subnet 10.0.0.0/8 --ignore 'sshd|node_exporter|consul'

    # Quick triage -- top 5 connections by latency, fast refresh:
    sudo python3 conn_monitor.py --sort lat --top 5 --interval 2

    # Everything except the monitoring stack:
    sudo python3 conn_monitor.py --ignore 'prometheus|grafana|telegraf|collectd'
"""

import sys
import struct
import socket
import time
import argparse
import ipaddress
import threading
from collections import defaultdict
from bcc import BPF

# ---------------------------------------------------------------------------
# CLI arguments
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    description="Combined TCP connection monitor with latency tracking")
parser.add_argument("--comm", default=None,
                    help="Filter by process name (exact match)")
parser.add_argument("--port", type=int, default=0,
                    help="Filter by destination port")
parser.add_argument("--subnet", default=None,
                    help="Filter by destination subnet (e.g. 10.0.0.0/8)")
parser.add_argument("--interval", type=int, default=5,
                    help="Refresh interval in seconds (default: 5)")
parser.add_argument("--sort", choices=["tx", "rx", "lat", "conns"],
                    default=None,
                    help="Sort column (default: total bytes tx+rx)")
parser.add_argument("--cumulative", action="store_true",
                    help="Running totals mode -- don't clear between intervals")
parser.add_argument("--top", type=int, default=0,
                    help="Only show top N rows")
parser.add_argument("--ignore", default=None,
                    help="Pipe-separated list of comm names to ignore "
                         "(e.g. 'sshd|bash|node_exporter')")
args = parser.parse_args()

# Parse ignore list once
ignore_comms = set()
if args.ignore:
    ignore_comms = set(args.ignore.split("|"))

# Parse subnet filter once
subnet_filter = None
if args.subnet:
    try:
        subnet_filter = ipaddress.ip_network(args.subnet, strict=False)
    except ValueError as e:
        print(f"Invalid subnet: {e}", file=sys.stderr)
        sys.exit(1)

# ---------------------------------------------------------------------------
# Well-known port names
# ---------------------------------------------------------------------------

WELL_KNOWN = {
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    443: "https",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    27017: "mongo",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elastic",
    9092: "kafka",
    5672: "rabbitmq",
    11211: "memcached",
    6443: "k8s-api",
    2379: "etcd",
    8500: "consul",
}

# ---------------------------------------------------------------------------
# BPF program
# ---------------------------------------------------------------------------

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/tcp_states.h>

// --- Latency tracking (tcp_v4_connect -> tcp_finish_connect) ---

struct start_t {
    u64 ts;
    u32 pid;
    char comm[16];
};

// Latency event emitted via perf buffer
struct lat_event_t {
    u32 pid;
    u64 latency_ns;
    u32 daddr;
    u16 dport;
    char comm[16];
};

// Connect/close event for connection counting
struct conn_event_t {
    u32 pid;
    u32 daddr;
    u16 dport;
    u8  type;   // 1 = connect, 2 = close
    char comm[16];
};

BPF_HASH(start, struct sock *, struct start_t);
BPF_PERF_OUTPUT(lat_events);
BPF_PERF_OUTPUT(conn_events);

// --- Byte tracking (sendmsg / cleanup_rbuf) ---

struct key_t {
    u32 pid;
    u32 daddr;
    u16 dport;
    char comm[16];
};

struct val_t {
    u64 send_bytes;
    u64 recv_bytes;
};

BPF_HASH(byte_map, struct key_t, struct val_t, 10240);

// Helper: fill key from sock. Returns 0 on success, -1 if not IPv4.
static inline int fill_key(struct sock *sk, struct key_t *key) {
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) return -1;

    key->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_kernel(&key->daddr, sizeof(key->daddr),
                          &sk->__sk_common.skc_daddr);

    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    key->dport = ntohs(dport);

    bpf_get_current_comm(&key->comm, sizeof(key->comm));
    return 0;
}

// --- Probes ---

// 1. tcp_v4_connect entry: record start timestamp
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    struct start_t s = {};
    s.ts = bpf_ktime_get_ns();
    s.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&s.comm, sizeof(s.comm));
    start.update(&sk, &s);
    return 0;
}

// 2. tcp_finish_connect: compute handshake latency, emit event
int trace_finish_connect(struct pt_regs *ctx, struct sock *sk) {
    struct start_t *sp = start.lookup(&sk);
    if (sp == 0) return 0;

    u64 delta = bpf_ktime_get_ns() - sp->ts;

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) {
        start.delete(&sk);
        return 0;
    }

    struct lat_event_t evt = {};
    evt.pid = sp->pid;
    evt.latency_ns = delta;
    bpf_probe_read_kernel(&evt.daddr, sizeof(evt.daddr),
                          &sk->__sk_common.skc_daddr);

    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    evt.dport = ntohs(dport);

    __builtin_memcpy(&evt.comm, sp->comm, 16);
    lat_events.perf_submit(ctx, &evt, sizeof(evt));

    // Also emit a connect event for connection counting
    struct conn_event_t ce = {};
    ce.pid = sp->pid;
    ce.daddr = evt.daddr;
    ce.dport = evt.dport;
    ce.type = 1;  // connect
    __builtin_memcpy(&ce.comm, sp->comm, 16);
    conn_events.perf_submit(ctx, &ce, sizeof(ce));

    start.delete(&sk);
    return 0;
}

// 3. tcp_sendmsg: track bytes sent
int trace_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg,
                  size_t size) {
    struct key_t key = {};
    if (fill_key(sk, &key) != 0) return 0;

    struct val_t zero = {};
    struct val_t *val = byte_map.lookup_or_try_init(&key, &zero);
    if (val) {
        val->send_bytes += size;
    }
    return 0;
}

// 4. tcp_cleanup_rbuf: track bytes received
int trace_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied) {
    if (copied <= 0) return 0;

    struct key_t key = {};
    if (fill_key(sk, &key) != 0) return 0;

    struct val_t zero = {};
    struct val_t *val = byte_map.lookup_or_try_init(&key, &zero);
    if (val) {
        val->recv_bytes += copied;
    }
    return 0;
}

// 5. tcp_close: emit close event
int trace_close(struct pt_regs *ctx, struct sock *sk) {
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) return 0;

    struct conn_event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_kernel(&evt.daddr, sizeof(evt.daddr),
                          &sk->__sk_common.skc_daddr);

    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    evt.dport = ntohs(dport);

    evt.type = 2;  // close
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    conn_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

# ---------------------------------------------------------------------------
# Load BPF and attach probes
# ---------------------------------------------------------------------------

b = BPF(text=bpf_text)

# 1. tcp_v4_connect entry -- start timestamp for latency
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")

# 2. tcp_finish_connect -- latency calculation
b.attach_kprobe(event="tcp_finish_connect", fn_name="trace_finish_connect")

# 3. tcp_sendmsg -- bytes sent
b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_sendmsg")

# 4. tcp_cleanup_rbuf -- bytes received
b.attach_kprobe(event="tcp_cleanup_rbuf", fn_name="trace_cleanup_rbuf")

# 5. tcp_close -- connection close tracking
b.attach_kprobe(event="tcp_close", fn_name="trace_close")

# ---------------------------------------------------------------------------
# Reverse DNS cache (background lookups)
# ---------------------------------------------------------------------------

dns_cache = {}       # ip_str -> hostname or ip_str
dns_lock = threading.Lock()
dns_pending = set()  # IPs currently being resolved


def resolve_ip(ip_str):
    """Resolve an IP to a hostname in the background. Non-blocking."""
    with dns_lock:
        if ip_str in dns_cache or ip_str in dns_pending:
            return
        dns_pending.add(ip_str)

    def _do_resolve():
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_str)
        except (socket.herror, socket.gaierror, OSError):
            hostname = ip_str
        with dns_lock:
            dns_cache[ip_str] = hostname
            dns_pending.discard(ip_str)

    t = threading.Thread(target=_do_resolve, daemon=True)
    t.start()


def get_hostname(ip_str):
    """Return cached hostname or the raw IP if not yet resolved."""
    with dns_lock:
        return dns_cache.get(ip_str, ip_str)

# ---------------------------------------------------------------------------
# Python-side data structures
# ---------------------------------------------------------------------------

# Key: (comm, pid, daddr_int, dport)
# Latency samples collected between intervals
latency_samples = defaultdict(list)       # key -> [latency_ns, ...]
latency_samples_lock = threading.Lock()

# Connection opens/closes per destination (comm, pid, daddr_int, dport)
conn_opens = defaultdict(int)
conn_closes = defaultdict(int)
conn_lock = threading.Lock()

# Track destinations seen in previous interval for NEW highlighting
prev_destinations = set()   # set of (daddr_int, dport)

# Cumulative data (only used when --cumulative)
cumul_tx = defaultdict(int)
cumul_rx = defaultdict(int)
cumul_latency = defaultdict(list)
cumul_opens = defaultdict(int)
cumul_closes = defaultdict(int)

# ---------------------------------------------------------------------------
# Perf buffer callbacks
# ---------------------------------------------------------------------------


def handle_lat_event(cpu, data, size):
    """Called for each latency event from BPF."""
    evt = b["lat_events"].event(data)
    comm = evt.comm.decode("utf-8", errors="replace")
    if ignore_comms and comm in ignore_comms:
        return
    key = (comm, evt.pid, evt.daddr, evt.dport)
    with latency_samples_lock:
        latency_samples[key].append(evt.latency_ns)


def handle_conn_event(cpu, data, size):
    """Called for each connect/close event from BPF."""
    evt = b["conn_events"].event(data)
    comm = evt.comm.decode("utf-8", errors="replace")
    if ignore_comms and comm in ignore_comms:
        return
    key = (comm, evt.pid, evt.daddr, evt.dport)
    with conn_lock:
        if evt.type == 1:
            conn_opens[key] += 1
        elif evt.type == 2:
            conn_closes[key] += 1


b["lat_events"].open_perf_buffer(handle_lat_event, page_cnt=64)
b["conn_events"].open_perf_buffer(handle_conn_event, page_cnt=64)

# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def inet_ntoa(addr):
    """Convert a 32-bit network-order int to dotted-quad string."""
    return socket.inet_ntoa(struct.pack("I", addr))


def fmt_bytes(n):
    """Human-readable byte count."""
    if n >= 1_073_741_824:
        return f"{n / 1_073_741_824:.1f}G"
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f}M"
    if n >= 1024:
        return f"{n / 1024:.1f}K"
    return f"{n}B"


def fmt_latency(ns):
    """Human-readable latency."""
    if ns >= 1_000_000_000:
        return f"{ns / 1e9:.2f}s"
    if ns >= 1_000_000:
        return f"{ns / 1e6:.1f}ms"
    if ns >= 1_000:
        return f"{ns / 1e3:.0f}us"
    return f"{ns}ns"


def percentile(sorted_list, pct):
    """Compute the given percentile from an already-sorted list."""
    if not sorted_list:
        return 0
    idx = int(len(sorted_list) * pct / 100.0)
    idx = min(idx, len(sorted_list) - 1)
    return sorted_list[idx]


def matches_filters(comm, daddr_int, dport):
    """Return True if the row passes all user-specified filters."""
    if ignore_comms and comm in ignore_comms:
        return False
    if args.comm and comm != args.comm:
        return False
    if args.port and dport != args.port:
        return False
    if subnet_filter:
        ip = ipaddress.ip_address(inet_ntoa(daddr_int))
        if ip not in subnet_filter:
            return False
    return True

# ---------------------------------------------------------------------------
# Dashboard rendering
# ---------------------------------------------------------------------------

HEADER_WIDTH = 120


def render_dashboard(interval_num):
    """Collect data, build rows, print the dashboard."""
    global prev_destinations

    # -- Gather byte data from BPF hash map --
    byte_table = b.get_table("byte_map")
    byte_data = {}  # key -> (tx, rx)
    for k, v in byte_table.items():
        comm = k.comm.decode("utf-8", errors="replace")
        key = (comm, k.pid, k.daddr, k.dport)
        byte_data[key] = (v.send_bytes, v.recv_bytes)

    # -- Snapshot and clear latency samples --
    with latency_samples_lock:
        lat_snap = dict(latency_samples)
        if not args.cumulative:
            latency_samples.clear()

    # -- Snapshot and clear conn counts --
    with conn_lock:
        opens_snap = dict(conn_opens)
        closes_snap = dict(conn_closes)
        if not args.cumulative:
            conn_opens.clear()
            conn_closes.clear()

    # -- Merge all keys --
    all_keys = set(byte_data.keys()) | set(lat_snap.keys()) | \
               set(opens_snap.keys()) | set(closes_snap.keys())

    # -- Build rows --
    current_destinations = set()
    rows = []

    for key in all_keys:
        comm, pid, daddr_int, dport = key

        if not matches_filters(comm, daddr_int, dport):
            continue

        tx, rx = byte_data.get(key, (0, 0))
        samples = lat_snap.get(key, [])
        opens = opens_snap.get(key, 0)
        closes = closes_snap.get(key, 0)

        # In cumulative mode, accumulate
        if args.cumulative:
            cumul_tx[key] += tx
            cumul_rx[key] += rx
            cumul_latency[key].extend(samples)
            cumul_opens[key] += opens
            cumul_closes[key] += closes
            tx = cumul_tx[key]
            rx = cumul_rx[key]
            samples = cumul_latency[key]
            opens = cumul_opens[key]
            closes = cumul_closes[key]

        # Active connections = opens - closes (floor at 0)
        active = max(0, opens - closes)

        # Latency stats
        if samples:
            sorted_samples = sorted(samples)
            p95 = percentile(sorted_samples, 95)
            avg = sum(sorted_samples) // len(sorted_samples)
        else:
            p95 = 0
            avg = 0

        dest_key = (daddr_int, dport)
        current_destinations.add(dest_key)

        # Kick off background DNS resolution
        ip_str = inet_ntoa(daddr_int)
        resolve_ip(ip_str)

        is_new = dest_key not in prev_destinations and interval_num > 1

        rows.append({
            "comm": comm,
            "pid": pid,
            "daddr": daddr_int,
            "dport": dport,
            "tx": tx,
            "rx": rx,
            "active": active,
            "p95": p95,
            "avg": avg,
            "is_new": is_new,
        })

    # -- Sort --
    if args.sort == "tx":
        rows.sort(key=lambda r: r["tx"], reverse=True)
    elif args.sort == "rx":
        rows.sort(key=lambda r: r["rx"], reverse=True)
    elif args.sort == "lat":
        rows.sort(key=lambda r: r["p95"], reverse=True)
    elif args.sort == "conns":
        rows.sort(key=lambda r: r["active"], reverse=True)
    else:
        # Default: total bytes (tx + rx)
        rows.sort(key=lambda r: r["tx"] + r["rx"], reverse=True)

    # -- Top N --
    if args.top > 0:
        rows = rows[:args.top]

    # Always clear BPF byte map -- in cumulative mode we've already
    # accumulated into cumul_tx/cumul_rx so the BPF map must reset to
    # avoid double-counting on the next interval.
    byte_table.clear()

    # -- Print dashboard --
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    mode = "CUMULATIVE" if args.cumulative else f"INTERVAL {args.interval}s"

    print(f"\033[2J\033[H", end="")  # clear screen, cursor to top
    print(f"{'=' * HEADER_WIDTH}")
    print(f"  TCP CONNECTION MONITOR  |  {ts}  |  {mode}  |  "
          f"#{interval_num}")
    if args.comm or args.port or args.subnet:
        filters = []
        if args.comm:
            filters.append(f"comm={args.comm}")
        if args.port:
            filters.append(f"port={args.port}")
        if args.subnet:
            filters.append(f"subnet={args.subnet}")
        print(f"  Filters: {', '.join(filters)}")
    print(f"{'=' * HEADER_WIDTH}")

    # Column headers
    hdr = (f"  {'':3} {'COMM':<16} {'PID':<8} {'DESTINATION':<28} "
           f"{'SERVICE':<12} {'TX':>8} {'RX':>8} {'CONNS':>6} "
           f"{'P95 LAT':>10} {'AVG LAT':>10}")
    print(hdr)
    print(f"  {'':3} {'---':<16} {'---':<8} {'---':<28} "
           f"{'---':<12} {'---':>8} {'---':>8} {'---':>6} "
           f"{'---':>10} {'---':>10}")

    if not rows:
        print(f"\n  (no connections observed this interval)\n")
    else:
        for r in rows:
            ip_str = inet_ntoa(r["daddr"])
            hostname = get_hostname(ip_str)
            # If hostname differs from IP, show hostname; otherwise show IP
            if hostname != ip_str:
                display_host = hostname
                # Truncate long hostnames
                if len(display_host) > 20:
                    display_host = display_host[:18] + ".."
            else:
                display_host = ip_str
            dst = f"{display_host}:{r['dport']}"
            svc = WELL_KNOWN.get(r["dport"], "")
            marker = " + " if r["is_new"] else "   "

            p95_str = fmt_latency(r["p95"]) if r["p95"] > 0 else "-"
            avg_str = fmt_latency(r["avg"]) if r["avg"] > 0 else "-"

            print(f"  {marker}{r['comm']:<16} {r['pid']:<8} {dst:<28} "
                  f"{svc:<12} {fmt_bytes(r['tx']):>8} "
                  f"{fmt_bytes(r['rx']):>8} {r['active']:>6} "
                  f"{p95_str:>10} {avg_str:>10}")

    # -- Totals --
    total_tx = sum(r["tx"] for r in rows)
    total_rx = sum(r["rx"] for r in rows)
    total_conns = sum(r["active"] for r in rows)
    all_p95 = [r["p95"] for r in rows if r["p95"] > 0]
    all_avg = [r["avg"] for r in rows if r["avg"] > 0]
    overall_p95 = fmt_latency(max(all_p95)) if all_p95 else "-"
    overall_avg = fmt_latency(
        sum(all_avg) // len(all_avg)) if all_avg else "-"

    print(f"  {'-' * (HEADER_WIDTH - 4)}")
    print(f"  {'':3} {'TOTAL':<16} {'':8} {len(rows):>3} destinations"
          f"{'':13} {fmt_bytes(total_tx):>8} "
          f"{fmt_bytes(total_rx):>8} {total_conns:>6} "
          f"{overall_p95:>10} {overall_avg:>10}")
    print(f"{'=' * HEADER_WIDTH}")
    print(f"  Press Ctrl-C to stop")

    # Update previous destinations for next interval's NEW detection
    prev_destinations = current_destinations

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

print(f"Starting TCP connection monitor (interval={args.interval}s)...")
print(f"Attaching BPF probes... waiting for data.\n")

interval_num = 0

try:
    while True:
        # Poll perf buffers (non-blocking, with timeout)
        # We poll in small increments across the interval to keep latency
        # and connection events flowing promptly.
        deadline = time.monotonic() + args.interval
        while time.monotonic() < deadline:
            remaining_ms = int((deadline - time.monotonic()) * 1000)
            if remaining_ms <= 0:
                break
            poll_ms = min(remaining_ms, 100)
            b.perf_buffer_poll(timeout=poll_ms)

        interval_num += 1
        render_dashboard(interval_num)

except KeyboardInterrupt:
    print(f"\n\nStopped after {interval_num} intervals.")
    sys.exit(0)
