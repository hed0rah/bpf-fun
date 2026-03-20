#!/usr/bin/env python3
"""ioscope — BPF-powered file I/O visibility.

Live event stream plus a periodic summary dashboard showing top processes
and top files by I/O volume and operation count.

Usage:
    sudo python3 ioscope.py                              # watch all processes
    sudo python3 ioscope.py python3                      # filter by comm name
    sudo python3 ioscope.py --pid 1234                   # filter by pid
    sudo python3 ioscope.py --path /var/log              # only files under path
    sudo python3 ioscope.py --summary 10                 # summary every 10s
    sudo python3 ioscope.py --top 20                     # top 20 in summary
    sudo python3 ioscope.py --quiet                      # summary only, no live events
    sudo python3 ioscope.py --sort ops                   # sort by operation count

Examples:

    # What's thrashing the disk on a busy server? Summary-only, sorted by bytes:
    sudo python3 ioscope.py --quiet --summary 10

    # Find which process keeps writing to /var/log and how much:
    sudo python3 ioscope.py --path /var/log --quiet --sort bytes

    # App is doing a ton of small reads -- find the inode-heavy offender:
    sudo python3 ioscope.py java --sort ops --summary 5

    # Watch what files nginx touches in real time:
    sudo python3 ioscope.py nginx

    # Quick check -- what's a specific PID doing right now?
    sudo python3 ioscope.py --pid 1234

    # Production: top 30 files hit in the last 30s, no live noise:
    sudo python3 ioscope.py --quiet --summary 30 --top 30

    # Investigate a DB -- is postgres reading from disk or cache?
    sudo python3 ioscope.py postgres --path /var/lib/postgresql --summary 5

    # Catch config file reads across all processes:
    sudo python3 ioscope.py --path /etc --sort ops --quiet

    # Ignore noisy background processes:
    sudo python3 ioscope.py --ignore 'bash|sshd|grep|cat|systemd'

    # Combine -- watch /var/log but ignore known log rotators:
    sudo python3 ioscope.py --path /var/log --ignore 'logrotate|gzip' --quiet
"""

import os
import sys
import time
import argparse
import threading
from collections import defaultdict
from bcc import BPF

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(
    prog="ioscope",
    description="ioscope — BPF-powered file I/O visibility")
parser.add_argument("comm", nargs="?", default=None,
                    help="Filter by process name (e.g. python3, java, nginx)")
parser.add_argument("--pid", type=int, default=0,
                    help="Filter by PID")
parser.add_argument("--path", default=None,
                    help="Only show files under this path prefix")
parser.add_argument("--summary", type=int, default=15,
                    help="Summary interval in seconds (default 15, 0=disable)")
parser.add_argument("--top", type=int, default=15,
                    help="Top N entries in summary (default 15)")
parser.add_argument("--quiet", action="store_true",
                    help="Suppress live event stream, only show summaries")
parser.add_argument("--sort", choices=["bytes", "ops"], default="bytes",
                    help="Sort summary by total bytes or op count (default: bytes)")
parser.add_argument("--ignore", default=None,
                    help="Pipe-separated list of comm names to ignore "
                         "(e.g. 'bash|ssh|sshd|grep')")
args = parser.parse_args()

# Parse ignore list once
ignore_comms = set()
if args.ignore:
    ignore_comms = set(args.ignore.split("|"))

my_pid = os.getpid()

# ---------------------------------------------------------------------------
# BPF program
# ---------------------------------------------------------------------------

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u64 bytes;
    char comm[16];
    char fname[128];
    u32 op;        // 0=open, 1=read, 2=write
};

BPF_PERF_OUTPUT(events);

// Stash the filename from openat so we can tie fd reads/writes back to paths
// Key: pid_tgid, Value: fd -> filename (we track in userspace instead)

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

# Always filter our own pid
bpf_text = bpf_text.replace("FILTER_SELF", f"if (pid == {my_pid}) return 0;")

# Apply user filters
filter_pid = ""
filter_comm = ""

if args.pid:
    filter_pid = f"if (pid != {args.pid}) return 0;"

if args.comm:
    bpf_text = f'#define COMM_FILTER "{args.comm}"\n' + bpf_text
    filter_comm = (
        "{ char c[16]; bpf_get_current_comm(&c, sizeof(c)); "
        "if (__builtin_memcmp(c, COMM_FILTER, sizeof(COMM_FILTER) - 1) != 0) return 0; }"
    )

bpf_text = bpf_text.replace("FILTER_PID", filter_pid)
bpf_text = bpf_text.replace("FILTER_COMM", filter_comm)

b = BPF(text=bpf_text)

# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

op_names = {0: "OPEN ", 1: "READ ", 2: "WRITE"}


def fmt_bytes(n):
    if n >= 1_073_741_824:
        return f"{n / 1_073_741_824:.1f}G"
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f}M"
    if n >= 1024:
        return f"{n / 1024:.1f}K"
    return f"{n}B"


# ---------------------------------------------------------------------------
# Summary data structures (protected by lock)
# ---------------------------------------------------------------------------

stats_lock = threading.Lock()

# Per-process stats: comm -> {reads, writes, opens, read_bytes, write_bytes}
proc_stats = defaultdict(lambda: {
    "reads": 0, "writes": 0, "opens": 0,
    "read_bytes": 0, "write_bytes": 0, "pids": set()
})

# Per-file stats: fname -> {reads, writes, opens, read_bytes, write_bytes}
file_stats = defaultdict(lambda: {
    "reads": 0, "writes": 0, "opens": 0,
    "read_bytes": 0, "write_bytes": 0, "comms": set()
})

# Track last opened file per pid for correlating reads/writes
last_open = {}  # pid -> filename

interval_count = 0


def reset_stats():
    """Clear stats for next interval."""
    proc_stats.clear()
    file_stats.clear()
    # Don't clear last_open -- we want to keep correlating


# ---------------------------------------------------------------------------
# Event handler
# ---------------------------------------------------------------------------

def handle_event(cpu, data, size):
    evt = b["events"].event(data)
    op = evt.op
    comm = evt.comm.decode("utf-8", errors="replace")
    fname = evt.fname.decode("utf-8", errors="replace") if op == 0 else ""
    pid = evt.pid
    nbytes = evt.bytes

    # Ignore list filter
    if ignore_comms and comm in ignore_comms:
        return

    # Path filter
    if args.path and op == 0 and not fname.startswith(args.path):
        return

    # Track last opened file per pid
    if op == 0 and fname:
        last_open[pid] = fname

    # Get associated filename for reads/writes
    assoc_file = ""
    if op == 0:
        assoc_file = fname
    else:
        assoc_file = last_open.get(pid, "")
        # Apply path filter to reads/writes too
        if args.path and not assoc_file.startswith(args.path):
            return

    # Print live event (unless --quiet)
    if not args.quiet:
        op_str = op_names.get(op, "?    ")
        if op == 0:
            bytes_str = ""
        else:
            bytes_str = f"{fmt_bytes(nbytes):>10}"
        file_display = fname if op == 0 else (assoc_file if assoc_file else "")
        print(f"  {op_str}  pid={pid:<7} {comm:<16} {bytes_str:>10}  {file_display}")

    # Accumulate stats
    if args.summary > 0:
        with stats_lock:
            ps = proc_stats[comm]
            ps["pids"].add(pid)
            if op == 0:
                ps["opens"] += 1
            elif op == 1:
                ps["reads"] += 1
                ps["read_bytes"] += nbytes
            elif op == 2:
                ps["writes"] += 1
                ps["write_bytes"] += nbytes

            if assoc_file:
                fs = file_stats[assoc_file]
                fs["comms"].add(comm)
                if op == 0:
                    fs["opens"] += 1
                elif op == 1:
                    fs["reads"] += 1
                    fs["read_bytes"] += nbytes
                elif op == 2:
                    fs["writes"] += 1
                    fs["write_bytes"] += nbytes


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------

def print_summary():
    global interval_count
    interval_count += 1

    with stats_lock:
        if not proc_stats and not file_stats:
            return

        ts = time.strftime("%H:%M:%S")
        w = 100

        print(f"\n{'=' * w}")
        print(f"  ioscope SUMMARY  |  {ts}  |  "
              f"interval {args.summary}s  |  #{interval_count}")
        print(f"{'=' * w}")

        # --- Top processes by I/O ---
        print(f"\n  TOP PROCESSES BY {'OPS' if args.sort == 'ops' else 'BYTES'}:")
        print(f"  {'COMM':<16} {'PIDs':>5} {'OPENS':>8} {'READS':>8} "
              f"{'WRITES':>8} {'READ':>10} {'WRITTEN':>10} {'TOTAL':>10}")
        print(f"  {'-' * 16} {'-' * 5} {'-' * 8} {'-' * 8} "
              f"{'-' * 8} {'-' * 10} {'-' * 10} {'-' * 10}")

        proc_rows = []
        for comm, s in proc_stats.items():
            total_bytes = s["read_bytes"] + s["write_bytes"]
            total_ops = s["opens"] + s["reads"] + s["writes"]
            proc_rows.append((comm, s, total_bytes, total_ops))

        if args.sort == "ops":
            proc_rows.sort(key=lambda r: r[3], reverse=True)
        else:
            proc_rows.sort(key=lambda r: r[2], reverse=True)

        for comm, s, total_bytes, total_ops in proc_rows[:args.top]:
            print(f"  {comm:<16} {len(s['pids']):>5} {s['opens']:>8} "
                  f"{s['reads']:>8} {s['writes']:>8} "
                  f"{fmt_bytes(s['read_bytes']):>10} "
                  f"{fmt_bytes(s['write_bytes']):>10} "
                  f"{fmt_bytes(total_bytes):>10}")

        # --- Top files by I/O ---
        print(f"\n  TOP FILES BY {'OPS' if args.sort == 'ops' else 'BYTES'}:")
        print(f"  {'FILE':<50} {'OPENS':>6} {'READS':>6} "
              f"{'WRITES':>6} {'READ':>10} {'WRITTEN':>10}")
        print(f"  {'-' * 50} {'-' * 6} {'-' * 6} "
              f"{'-' * 6} {'-' * 10} {'-' * 10}")

        file_rows = []
        for fname, s in file_stats.items():
            total_bytes = s["read_bytes"] + s["write_bytes"]
            total_ops = s["opens"] + s["reads"] + s["writes"]
            file_rows.append((fname, s, total_bytes, total_ops))

        if args.sort == "ops":
            file_rows.sort(key=lambda r: r[3], reverse=True)
        else:
            file_rows.sort(key=lambda r: r[2], reverse=True)

        for fname, s, total_bytes, total_ops in file_rows[:args.top]:
            # Truncate long paths, keep the tail
            if len(fname) > 48:
                display = ".." + fname[-(46):]
            else:
                display = fname
            comms = ",".join(sorted(s["comms"]))
            print(f"  {display:<50} {s['opens']:>6} {s['reads']:>6} "
                  f"{s['writes']:>6} {fmt_bytes(s['read_bytes']):>10} "
                  f"{fmt_bytes(s['write_bytes']):>10}  [{comms}]")

        # --- Totals ---
        total_opens = sum(s["opens"] for _, s in proc_stats.items())
        total_reads = sum(s["reads"] for _, s in proc_stats.items())
        total_writes = sum(s["writes"] for _, s in proc_stats.items())
        total_read_bytes = sum(s["read_bytes"] for _, s in proc_stats.items())
        total_write_bytes = sum(s["write_bytes"] for _, s in proc_stats.items())
        unique_files = len(file_stats)

        print(f"\n  TOTALS: {total_opens} opens, {total_reads} reads, "
              f"{total_writes} writes  |  "
              f"read {fmt_bytes(total_read_bytes)}, "
              f"wrote {fmt_bytes(total_write_bytes)}  |  "
              f"{unique_files} unique files")
        print(f"{'=' * w}")

        reset_stats()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

filters = []
if args.comm:
    filters.append(f"comm={args.comm}")
if args.pid:
    filters.append(f"pid={args.pid}")
if args.path:
    filters.append(f"path={args.path}")
filter_desc = ", ".join(filters) if filters else "all processes"

print(f"ioscope: {filter_desc}  (self pid={my_pid} excluded)")
if args.summary > 0:
    print(f"Summary every {args.summary}s, top {args.top}, "
          f"sorted by {args.sort}")
if args.quiet:
    print(f"Quiet mode -- live events suppressed")
print(f"{'─' * 78}")

if not args.quiet:
    print(f"  {'OP':<7} {'PID':<12} {'COMM':<16} {'BYTES':>10}  FILENAME")
    print(f"{'─' * 78}")

b["events"].open_perf_buffer(handle_event, page_cnt=64)

try:
    last_summary = time.monotonic()
    while True:
        b.perf_buffer_poll(timeout=100)

        if args.summary > 0:
            now = time.monotonic()
            if now - last_summary >= args.summary:
                print_summary()
                last_summary = now

except KeyboardInterrupt:
    # Print final summary if we have data
    if args.summary > 0:
        print_summary()
    print("\nDone.")
