 cat http_monitor.py
#!/usr/bin/python3
from bcc import BPF
from time import sleep, strftime
import ctypes as ct
import socket
import struct  # Added struct import

# Define BPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/tcp.h>
#include <linux/ip.h>

// Structure to store HTTP request information
struct http_request_t {
    u64 timestamp;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char method[16];
};

BPF_PERF_OUTPUT(events);

int trace_tcp_probe(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    if (sk == NULL || skb == NULL)
        return 0;

    // Get basic socket info
    u16 family = sk->__sk_common.skc_family;

    // Only handle IPv4
    if (family != AF_INET)
        return 0;

    // Check if it's port 80 (HTTP) or 443 (HTTPS)
    u16 dport = sk->__sk_common.skc_dport;
    if (ntohs(dport) != 80 && ntohs(dport) != 443)
        return 0;

    struct http_request_t req = {};

    // Fill basic information
    req.timestamp = bpf_ktime_get_ns();
    req.pid = bpf_get_current_pid_tgid() >> 32;
    req.saddr = sk->__sk_common.skc_rcv_saddr;
    req.daddr = sk->__sk_common.skc_daddr;
    req.sport = sk->__sk_common.skc_num;
    req.dport = dport;

    // Submit event
    events.perf_submit(ctx, &req, sizeof(req));

    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_program)

# Attach kprobe
b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_probe")

# Format IP address
def ip2str(addr):
    return socket.inet_ntoa(struct.pack("<I", addr))

# Print header
print("Monitoring HTTP requests... Press Ctrl+C to exit")
print("%-9s %-6s %-15s %-15s %-6s %-6s %-6s" %
    ("TIME", "PID", "SOURCE IP", "DEST IP", "SPORT", "DPORT", "TYPE"))

# Process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    time_str = strftime("%H:%M:%S")
    dport = socket.ntohs(event.dport)
    conn_type = "HTTPS" if dport == 443 else "HTTP"

    try:
        print("%-9s %-6d %-15s %-15s %-6d %-6d %-6s" % (
            time_str,
            event.pid,
            ip2str(event.saddr),
            ip2str(event.daddr),
            event.sport,
            dport,
            conn_type
        ))
    except Exception as e:
        print(f"Error processing event: {e}")

# Loop with callback
b["events"].open_perf_buffer(print_event)

try:
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error polling: {e}")
            continue

except KeyboardInterrupt:
    print("\nDetaching...")

print("Monitoring stopped")
