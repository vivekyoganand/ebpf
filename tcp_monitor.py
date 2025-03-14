cat tcp_monitor.py
#!/usr/bin/python3
from bcc import BPF
from time import sleep
from datetime import datetime

# Define BPF program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Define a simple hash to store connection counts
BPF_HASH(conn_count, u32, u32);

int trace_tcp_connect(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 count = 0;
    u32 zero = 0;
    u32 *val;

    // Lookup or initialize the counter
    val = conn_count.lookup_or_init(&pid, &zero);
    if (val) {
        count = *val + 1;
        conn_count.update(&pid, &count);
    }

    // Get process name
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Output connection information
    bpf_trace_printk("TCP connect: pid=%d comm=%s count=%d\\n", pid, comm, count);
    return 0;
}
"""

# Initialize BPF
try:
    b = BPF(text=bpf_program)
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_connect")
except Exception as e:
    print(f"Error loading BPF program: {e}")
    print("\nTrying to fix permissions...")
    print("Please run these commands and try again:")
    print("sudo sysctl -w kernel.perf_event_paranoid=1")
    print("sudo sysctl -w kernel.kptr_restrict=0")
    print("sudo sysctl -w net.core.bpf_jit_enable=1")
    exit(1)

print("Monitoring TCP connections... Press Ctrl+C to exit")
print("%-9s %-6s %-16s %-6s" % ("TIME", "PID", "COMM", "COUNT"))

# Process events
try:
    while True:
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()

            # Parse the message
            try:
                time_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
                msg_str = msg.decode()

                # Extract information from the message
                # Format: "TCP connect: pid=XX comm=YY count=ZZ"
                parts = msg_str.split()
                pid = int(parts[2].split('=')[1])
                comm = parts[3].split('=')[1]
                count = int(parts[4].split('=')[1])

                print("%-9s %-6d %-16s %-6d" % (time_str, pid, comm, count))

            except Exception as e:
                print(f"Error parsing message: {msg_str} - {e}")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error reading trace: {e}")

        sleep(0.1)

except KeyboardInterrupt:
    print("\nDetaching...")

finally:
    # Clean up
    print("Cleaning up...")
    if 'b' in locals():
        b.cleanup()

print("Monitoring stopped")
