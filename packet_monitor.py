 cat packet_monitor.py
#!/usr/bin/python3
from bcc import BPF
from time import sleep, strftime
import ctypes as ct  # Added ctypes import

# Define BPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// Define data structure for network stats
struct net_stats_t {
    u64 packets;
    u64 bytes;
};

BPF_HASH(stats, u32, struct net_stats_t);

TRACEPOINT_PROBE(net, net_dev_xmit) {
    struct net_stats_t *val, zero = {0};
    u32 key = 0;

    // Get existing or initialize new stats
    val = stats.lookup_or_init(&key, &zero);

    // Update counters
    val->packets++;
    val->bytes += args->len;

    return 0;
}

TRACEPOINT_PROBE(net, netif_receive_skb) {
    struct net_stats_t *val, zero = {0};
    u32 key = 1;

    // Get existing or initialize new stats
    val = stats.lookup_or_init(&key, &zero);

    // Update counters
    val->packets++;
    val->bytes += args->len;

    return 0;
}
"""

# Initialize BPF
try:
    b = BPF(text=bpf_program)
except Exception as e:
    print(f"Failed to compile BPF program: {e}")
    exit(1)

print("Monitoring network traffic... Press Ctrl+C to exit")
print("%-12s %-10s %-10s %-10s %-10s" %
    ("TIME", "RX-PKTS", "RX-BYTES", "TX-PKTS", "TX-BYTES"))

# Previous values for calculating rates
prev_rx_pkts = 0
prev_rx_bytes = 0
prev_tx_pkts = 0
prev_tx_bytes = 0

try:
    while True:
        try:
            sleep(1)
            time_str = strftime("%H:%M:%S")

            # Get statistics
            stats = b.get_table("stats")

            # Get RX stats (key = 1)
            rx_key = ct.c_uint(1)
            rx_stats = stats[rx_key] if rx_key in stats else type('Stats', (), {'packets': 0, 'bytes': 0})

            # Get TX stats (key = 0)
            tx_key = ct.c_uint(0)
            tx_stats = stats[tx_key] if tx_key in stats else type('Stats', (), {'packets': 0, 'bytes': 0})

            # Calculate rates
            rx_pkts = rx_stats.packets
            rx_bytes = rx_stats.bytes
            tx_pkts = tx_stats.packets
            tx_bytes = tx_stats.bytes

            # Print rates (delta from previous values)
            print("%-12s %-10d %-10d %-10d %-10d" % (
                time_str,
                rx_pkts - prev_rx_pkts,
                rx_bytes - prev_rx_bytes,
                tx_pkts - prev_tx_pkts,
                tx_bytes - prev_tx_bytes
            ))

            # Update previous values
            prev_rx_pkts = rx_pkts
            prev_rx_bytes = rx_bytes
            prev_tx_pkts = tx_pkts
            prev_tx_bytes = tx_bytes

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error reading stats: {e}")
            continue

except KeyboardInterrupt:
    print("\nDetaching...")

print("Monitoring stopped")
