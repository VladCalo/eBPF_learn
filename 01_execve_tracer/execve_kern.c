/*
 * struct tracepoint__syscalls__sys_enter_execve {
 *     unsigned short common_type;           offset:0,  size:2
 *     unsigned char  common_flags;          offset:2,  size:1
 *     unsigned char  common_preempt_count;  offset:3,  size:1
 *     int            common_pid;            offset:4,  size:4
 *     int            __syscall_nr;          offset:8,  size:4
 *     unsigned int   __pad;                 offset:12, size:4
 *     const char    *filename;              offset:16, size:8
 *     const char   *const *argv;            offset:24, size:8
 *     const char   *const *envp;            offset:32, size:8
 * };
 */

typedef struct data {
    u32  pid;
    char comm[16];
    char filename[256];
} data_t;

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(data.filename, sizeof(data.filename), args->filename);

    events.perf_submit(args, &data, sizeof(data));

    return 0;
}
