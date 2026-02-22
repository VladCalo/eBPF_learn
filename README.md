# eBPF_learn

### Program 1 — Trace execve
Attach to tracepoint:
- sys_enter_execve
- print PID + command

### Program 2 — Trace open()
Use kprobe on:
- do_sys_open

### Program 3 — Trace user-space function (uprobes)
Attach to:
- malloc in libc