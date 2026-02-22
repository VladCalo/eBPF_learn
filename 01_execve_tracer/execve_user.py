from bcc import BPF

def callback_func(cpu, data, size):
    event = bpf["events"].event(data)
    pid      = event.pid
    comm     = event.comm.decode("utf-8", errors="replace")
    filename = event.filename.decode("utf-8", errors="replace")
    print(f"PID: {pid} COMM: {comm} FILE: {filename}")

bpf = BPF(src_file="execve_kern.c")

# bpf.attach_tracepoint(
#         tp="syscalls:sys_enter_execve",
#         fn_name="trace_execve")


# TRACEPOINT_PROBE auto-attaches — no manual attach needed

bpf["events"].open_perf_buffer(callback_func)

print("Tracing execve... Ctrl+C to stop")
try:
    while True:
        bpf.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nStopping.")