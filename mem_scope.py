#!/usr/bin/env python3
"""mem_scope — Real-time memory allocation visibility with eBPF.

Traces mmap, munmap, brk, and page fault syscalls at the kernel level.
Shows which processes are requesting memory, how much, and how fast they grow.
Great for catching memory leaks, runaway allocations, and OOM candidates.

Usage:
    sudo python3 mem_scope.py                           # watch everything
    sudo python3 mem_scope.py --comm java               # filter by process
    sudo python3 mem_scope.py --pid 1234                # filter by PID
    sudo python3 mem_scope.py --interval 10             # refresh every 10s
    sudo python3 mem_scope.py --top 20                  # top 20 in dashboard
    sudo python3 mem_scope.py --sort allocs             # sort by alloc count
    sudo python3 mem_scope.py --sort growth             # sort by net growth
    sudo python3 mem_scope.py --alert 100M              # alert on >100M allocs
    sudo python3 mem_scope.py --cumulative              # running totals
    sudo python3 mem_scope.py --ignore 'bash|sshd'      # hide noisy procs
    sudo python3 mem_scope.py --live                    # show live events too

Examples:

    # Which process is eating all the RAM?
    sudo python3 mem_scope.py --sort growth --top 10

    # Watch a specific app for memory leaks over time:
    sudo python3 mem_scope.py --comm myapp --cumulative --interval 10

    # Alert when any single allocation exceeds 50MB:
    sudo python3 mem_scope.py --alert 50M --live

    # What's java doing with memory? Show mmap/brk activity:
    sudo python3 mem_scope.py --comm java --live

    # Quick check -- is anything doing huge mmaps?
    sudo python3 mem_scope.py --sort size --top 5 --interval 3

    # Track page faults to see real memory pressure:
    sudo python3 mem_scope.py --sort faults

    # Ignore infra, focus on app servers:
    sudo python3 mem_scope.py --ignore 'sshd|systemd|journald|rsyslogd'

    # Find processes that allocate and never free (leak detection):
    sudo python3 mem_scope.py --cumulative --sort growth --interval 30
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
    description="mem_scope -- real-time memory allocation visibility with eBPF")
parser.add_argument("--comm", default=None,
                    help="Filter by process name (exact match)")
parser.add_argument("--pid", type=int, default=0,
                    help="Filter by PID")
parser.add_argument("--interval", type=int, default=5,
                    help="Dashboard refresh interval in seconds (default: 5)")
parser.add_argument("--top", type=int, default=15,
                    help="Top N entries in dashboard (default: 15)")
parser.add_argument("--sort", choices=["size", "allocs", "growth", "faults"],
                    default="size",
                    help="Sort by: size (total mapped), allocs (count), "
                         "growth (mapped - unmapped), faults (page faults)")
parser.add_argument("--alert", default=None,
                    help="Alert when a single mmap exceeds this size "
                         "(e.g. 10M, 100M, 1G)")
parser.add_argument("--cumulative", action="store_true",
                    help="Running totals -- don't clear between intervals")
parser.add_argument("--ignore", default=None,
                    help="Pipe-separated list of comm names to ignore")
parser.add_argument("--live", action="store_true",
                    help="Show live mmap/munmap events as they happen")
args = parser.parse_args()

# Parse ignore list
ignore_comms = set()
if args.ignore:
    ignore_comms = set(args.ignore.split("|"))

# Parse alert threshold
alert_bytes = 0
if args.alert:
    s = args.alert.upper().strip()
    multipliers = {"K": 1024, "M": 1024**2, "G": 1024**3}
    if s[-1] in multipliers:
        alert_bytes = int(float(s[:-1]) * multipliers[s[-1]])
    else:
        alert_bytes = int(s)

my_pid = os.getpid()

# ---------------------------------------------------------------------------
# BPF program
# ---------------------------------------------------------------------------

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm.h>

// Event types
#define EVT_MMAP    1
#define EVT_MUNMAP  2
#define EVT_BRK     3
#define EVT_FAULT   4

struct event_t {
    u32 pid;
    u32 type;       // EVT_MMAP, EVT_MUNMAP, EVT_BRK, EVT_FAULT
    u64 size;       // bytes for mmap/munmap, new brk addr for brk
    u64 addr;       // return address for mmap, addr for munmap
    char comm[16];
};

BPF_PERF_OUTPUT(events);

// Track mmap sizes by pid_tgid for pairing enter/exit
BPF_HASH(mmap_sizes, u64, u64);    // pid_tgid -> requested size
BPF_HASH(brk_addrs, u64, u64);     // pid_tgid -> old brk

// --- mmap entry: stash the requested size ---
TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    FILTER_SELF
    FILTER_PID
    FILTER_COMM

    u64 len = args->len;
    mmap_sizes.update(&pid_tgid, &len);
    return 0;
}

// --- mmap exit: emit event with return address ---
TRACEPOINT_PROBE(syscalls, sys_exit_mmap) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 *lenp = mmap_sizes.lookup(&pid_tgid);
    if (lenp == 0) return 0;

    u64 len = *lenp;
    mmap_sizes.delete(&pid_tgid);

    // Only emit if mmap succeeded (ret != MAP_FAILED)
    long ret = args->ret;
    if (ret < 0 || ret == -1) return 0;

    struct event_t evt = {};
    evt.pid = pid;
    evt.type = EVT_MMAP;
    evt.size = len;
    evt.addr = (u64)ret;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

// --- munmap ---
TRACEPOINT_PROBE(syscalls, sys_enter_munmap) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    FILTER_SELF
    FILTER_PID
    FILTER_COMM

    struct event_t evt = {};
    evt.pid = pid;
    evt.type = EVT_MUNMAP;
    evt.addr = args->addr;
    evt.size = args->len;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

// --- brk entry: stash current brk ---
TRACEPOINT_PROBE(syscalls, sys_enter_brk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    FILTER_SELF
    FILTER_PID
    FILTER_COMM

    u64 brk = args->brk;
    brk_addrs.update(&pid_tgid, &brk);
    return 0;
}

// --- brk exit: compute delta ---
TRACEPOINT_PROBE(syscalls, sys_exit_brk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    u64 *old_brk_p = brk_addrs.lookup(&pid_tgid);
    if (old_brk_p == 0) return 0;

    u64 old_brk = *old_brk_p;
    u64 new_brk = (u64)args->ret;
    brk_addrs.delete(&pid_tgid);

    // Only emit if brk actually changed
    if (new_brk <= old_brk) return 0;

    struct event_t evt = {};
    evt.pid = pid;
    evt.type = EVT_BRK;
    evt.size = new_brk - old_brk;
    evt.addr = new_brk;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

// --- page faults (major + minor) ---
// We use the handle_mm_fault kprobe for fault counting
struct fault_key_t {
    u32 pid;
    char comm[16];
};

BPF_HASH(fault_map, struct fault_key_t, u64, 10240);

int trace_page_fault(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    FILTER_SELF_KPROBE

    struct fault_key_t key = {};
    key.pid = pid;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    u64 zero = 0;
    u64 *val = fault_map.lookup_or_try_init(&key, &zero);
    if (val) {
        (*val)++;
    }
    return 0;
}
"""

# Apply filters
bpf_text = bpf_text.replace("FILTER_SELF",
                             f"if (pid == {my_pid}) return 0;")
bpf_text = bpf_text.replace("FILTER_SELF_KPROBE",
                             f"if (pid == {my_pid}) return 0;")

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

# ---------------------------------------------------------------------------
# Load BPF
# ---------------------------------------------------------------------------

b = BPF(text=bpf_text)

# Attach page fault kprobe
b.attach_kprobe(event="handle_mm_fault", fn_name="trace_page_fault")

# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

EVT_NAMES = {1: "MMAP", 2: "MUNMAP", 3: "BRK", 4: "FAULT"}


def fmt_bytes(n):
    if n >= 1_073_741_824:
        return f"{n / 1_073_741_824:.1f}G"
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f}M"
    if n >= 1024:
        return f"{n / 1024:.1f}K"
    return f"{n}B"


def fmt_bytes_signed(n):
    """Format bytes with +/- sign for growth."""
    if n >= 0:
        return f"+{fmt_bytes(n)}"
    else:
        return f"-{fmt_bytes(abs(n))}"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

stats_lock = threading.Lock()

# Per-process stats
proc_stats = defaultdict(lambda: {
    "mmap_count": 0,
    "mmap_bytes": 0,
    "munmap_count": 0,
    "munmap_bytes": 0,
    "brk_count": 0,
    "brk_bytes": 0,
    "pids": set(),
    "largest_mmap": 0,
})

# Page fault counts are tracked in BPF map, read at dashboard time

# Cumulative data
cumul_stats = defaultdict(lambda: {
    "mmap_count": 0,
    "mmap_bytes": 0,
    "munmap_count": 0,
    "munmap_bytes": 0,
    "brk_count": 0,
    "brk_bytes": 0,
    "pids": set(),
    "largest_mmap": 0,
})

interval_count = 0


def reset_stats():
    proc_stats.clear()


# ---------------------------------------------------------------------------
# Event handler
# ---------------------------------------------------------------------------

def handle_event(cpu, data, size):
    evt = b["events"].event(data)
    comm = evt.comm.decode("utf-8", errors="replace")
    pid = evt.pid
    etype = evt.type
    ebytes = evt.size

    # Ignore filter
    if ignore_comms and comm in ignore_comms:
        return

    # Live event printing
    if args.live:
        ename = EVT_NAMES.get(etype, "?")
        print(f"  {ename:<8} pid={pid:<7} {comm:<16} {fmt_bytes(ebytes):>10}"
              f"  addr=0x{evt.addr:x}")

    # Alert on large allocations
    if alert_bytes > 0 and etype == 1 and ebytes >= alert_bytes:
        print(f"\n  *** ALERT: {comm} (pid={pid}) mmap'd {fmt_bytes(ebytes)}"
              f" at 0x{evt.addr:x} ***\n")

    # Accumulate stats
    with stats_lock:
        ps = proc_stats[comm]
        ps["pids"].add(pid)

        if etype == 1:  # MMAP
            ps["mmap_count"] += 1
            ps["mmap_bytes"] += ebytes
            if ebytes > ps["largest_mmap"]:
                ps["largest_mmap"] = ebytes
        elif etype == 2:  # MUNMAP
            ps["munmap_count"] += 1
            ps["munmap_bytes"] += ebytes
        elif etype == 3:  # BRK
            ps["brk_count"] += 1
            ps["brk_bytes"] += ebytes


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

def render_dashboard():
    global interval_count
    interval_count += 1

    # -- Read page fault counts from BPF --
    fault_table = b.get_table("fault_map")
    fault_data = {}  # comm -> total faults
    for k, v in fault_table.items():
        comm = k.comm.decode("utf-8", errors="replace")
        if ignore_comms and comm in ignore_comms:
            continue
        fault_data[comm] = fault_data.get(comm, 0) + v.value

    with stats_lock:
        # Build rows
        all_comms = set(proc_stats.keys()) | set(fault_data.keys())
        rows = []

        for comm in all_comms:
            if ignore_comms and comm in ignore_comms:
                continue
            if args.comm and comm != args.comm:
                continue

            s = proc_stats.get(comm, {
                "mmap_count": 0, "mmap_bytes": 0,
                "munmap_count": 0, "munmap_bytes": 0,
                "brk_count": 0, "brk_bytes": 0,
                "pids": set(), "largest_mmap": 0,
            })

            # In cumulative mode, accumulate
            if args.cumulative:
                cs = cumul_stats[comm]
                cs["mmap_count"] += s["mmap_count"]
                cs["mmap_bytes"] += s["mmap_bytes"]
                cs["munmap_count"] += s["munmap_count"]
                cs["munmap_bytes"] += s["munmap_bytes"]
                cs["brk_count"] += s["brk_count"]
                cs["brk_bytes"] += s["brk_bytes"]
                cs["pids"].update(s.get("pids", set()))
                cs["largest_mmap"] = max(cs["largest_mmap"],
                                         s.get("largest_mmap", 0))
                s = cs

            total_mapped = s["mmap_bytes"] + s["brk_bytes"]
            total_unmapped = s["munmap_bytes"]
            net_growth = total_mapped - total_unmapped
            total_allocs = s["mmap_count"] + s["brk_count"]
            faults = fault_data.get(comm, 0)

            rows.append({
                "comm": comm,
                "pids": s.get("pids", set()),
                "mmap_count": s["mmap_count"],
                "mmap_bytes": s["mmap_bytes"],
                "munmap_count": s["munmap_count"],
                "munmap_bytes": s["munmap_bytes"],
                "brk_count": s["brk_count"],
                "brk_bytes": s["brk_bytes"],
                "total_mapped": total_mapped,
                "net_growth": net_growth,
                "total_allocs": total_allocs,
                "faults": faults,
                "largest": s.get("largest_mmap", 0),
            })

        # Sort
        if args.sort == "allocs":
            rows.sort(key=lambda r: r["total_allocs"], reverse=True)
        elif args.sort == "growth":
            rows.sort(key=lambda r: r["net_growth"], reverse=True)
        elif args.sort == "faults":
            rows.sort(key=lambda r: r["faults"], reverse=True)
        else:  # size
            rows.sort(key=lambda r: r["total_mapped"], reverse=True)

        # Top N
        rows = rows[:args.top]

        # Print dashboard
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        mode = "CUMULATIVE" if args.cumulative else f"INTERVAL {args.interval}s"
        w = 120

        print(f"\033[2J\033[H", end="")  # clear screen
        print(f"{'=' * w}")
        print(f"  mem_scope  |  {ts}  |  {mode}  |  #{interval_count}")
        if args.comm or args.pid or args.ignore:
            filters = []
            if args.comm:
                filters.append(f"comm={args.comm}")
            if args.pid:
                filters.append(f"pid={args.pid}")
            if args.ignore:
                filters.append(f"ignore={args.ignore}")
            print(f"  Filters: {', '.join(filters)}")
        if alert_bytes:
            print(f"  Alert threshold: {fmt_bytes(alert_bytes)}")
        print(f"{'=' * w}")

        # Headers
        print(f"\n  {'COMM':<16} {'PIDs':>5} {'MMAPS':>7} {'MAPPED':>10} "
              f"{'UNMAPS':>7} {'FREED':>10} {'BRKs':>6} {'BRK+':>8} "
              f"{'NET':>10} {'FAULTS':>8} {'LARGEST':>10}")
        print(f"  {'-' * 16} {'-' * 5} {'-' * 7} {'-' * 10} "
              f"{'-' * 7} {'-' * 10} {'-' * 6} {'-' * 8} "
              f"{'-' * 10} {'-' * 8} {'-' * 10}")

        if not rows:
            print(f"\n  (no memory events observed this interval)\n")
        else:
            for r in rows:
                net_str = fmt_bytes_signed(r["net_growth"])
                # Highlight big net growth
                if r["net_growth"] > 100 * 1024 * 1024:  # >100MB
                    net_str = f"{net_str} !!"
                elif r["net_growth"] > 10 * 1024 * 1024:  # >10MB
                    net_str = f"{net_str} !"

                largest_str = fmt_bytes(r["largest"]) if r["largest"] > 0 else "-"

                print(f"  {r['comm']:<16} {len(r['pids']):>5} "
                      f"{r['mmap_count']:>7} {fmt_bytes(r['mmap_bytes']):>10} "
                      f"{r['munmap_count']:>7} {fmt_bytes(r['munmap_bytes']):>10} "
                      f"{r['brk_count']:>6} {fmt_bytes(r['brk_bytes']):>8} "
                      f"{net_str:>12} {r['faults']:>8} {largest_str:>10}")

        # Totals
        total_mapped = sum(r["total_mapped"] for r in rows)
        total_freed = sum(r["munmap_bytes"] for r in rows)
        total_net = sum(r["net_growth"] for r in rows)
        total_faults = sum(r["faults"] for r in rows)
        total_allocs = sum(r["total_allocs"] for r in rows)

        print(f"\n  {'-' * (w - 4)}")
        print(f"  TOTALS: {total_allocs} allocs, "
              f"mapped {fmt_bytes(total_mapped)}, "
              f"freed {fmt_bytes(total_freed)}, "
              f"net {fmt_bytes_signed(total_net)}  |  "
              f"{total_faults} page faults")
        print(f"{'=' * w}")
        print(f"  Press Ctrl-C to stop")

        # Reset for next interval (unless cumulative)
        if not args.cumulative:
            reset_stats()
            fault_table.clear()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

print(f"""
  ┌──────────────────────────────────────────────┐
  │  mem_scope  --  memory allocation visibility  │
  │  eBPF-powered mmap/brk/fault tracing          │
  └──────────────────────────────────────────────┘
""")
print(f"  Attaching BPF probes... interval={args.interval}s")
print(f"  Waiting for data.\n")

b["events"].open_perf_buffer(handle_event, page_cnt=64)

try:
    while True:
        deadline = time.monotonic() + args.interval
        while time.monotonic() < deadline:
            remaining_ms = int((deadline - time.monotonic()) * 1000)
            if remaining_ms <= 0:
                break
            poll_ms = min(remaining_ms, 100)
            b.perf_buffer_poll(timeout=poll_ms)

        render_dashboard()

except KeyboardInterrupt:
    render_dashboard()
    print(f"\n\nStopped after {interval_count} intervals.")
    sys.exit(0)
