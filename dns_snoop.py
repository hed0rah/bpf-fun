#!/usr/bin/env python3
"""Snoop DNS queries by tracing UDP sends to port 53.

Shows which processes are doing DNS lookups and what they're resolving.

Usage:
    sudo python3 dns_snoop.py              # all processes
    sudo python3 dns_snoop.py curl         # only 'curl'
"""

import sys
import struct
import socket
from bcc import BPF

filter_comm = sys.argv[1] if len(sys.argv) > 1 else None

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/udp.h>

struct event_t {
    u32 pid;
    u16 dport;
    u32 daddr;
    char comm[16];
    // First 64 bytes of the UDP payload (enough to parse DNS query name)
    unsigned char payload[64];
    u32 payload_len;
};

BPF_PERF_OUTPUT(events);

int trace_udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg) {
    u16 dport = sk->__sk_common.skc_dport;
    // port 53 in network byte order = 0x3500
    if (dport != __constant_htons(53))
        return 0;

    u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET)
        return 0;

    struct event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.dport = ntohs(dport);
    evt.daddr = sk->__sk_common.skc_daddr;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // Try to read the DNS payload from the iovec
    struct iov_iter *iter = &msg->msg_iter;

    // Read from the first iovec
    if (iter->__iov != NULL) {
        struct iovec iov;
        bpf_probe_read_kernel(&iov, sizeof(iov), iter->__iov);
        if (iov.iov_base != NULL) {
            u32 len = iov.iov_len;
            if (len > 64) len = 64;
            evt.payload_len = len;
            bpf_probe_read_user(evt.payload, len, iov.iov_base);
        }
    }

    events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")

def inet_ntoa(addr):
    return socket.inet_ntoa(struct.pack("I", addr))

def parse_dns_name(payload, offset=12):
    """Parse a DNS query name from raw payload starting after the 12-byte header."""
    labels = []
    i = offset
    while i < len(payload):
        length = payload[i]
        if length == 0:
            break
        i += 1
        if i + length > len(payload):
            break
        labels.append(payload[i:i+length].decode("ascii", errors="replace"))
        i += length
    return ".".join(labels) if labels else "?"

print(f"Snooping DNS queries" +
      (f" for: {filter_comm}" if filter_comm else "") +
      "... Ctrl-C to stop\n")
print(f"{'PID':<8} {'COMM':<16} {'DNS SERVER':<18} {'QUERY':<40}")
print("─" * 84)

def handle_event(cpu, data, size):
    evt = b["events"].event(data)
    comm = evt.comm.decode("utf-8", errors="replace")

    if filter_comm and comm != filter_comm:
        return

    dns_server = inet_ntoa(evt.daddr)
    payload = bytes(evt.payload[:evt.payload_len])
    query_name = parse_dns_name(payload) if len(payload) > 12 else "?"

    print(f"{evt.pid:<8} {comm:<16} {dns_server:<18} {query_name:<40}")

b["events"].open_perf_buffer(handle_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nDone.")
