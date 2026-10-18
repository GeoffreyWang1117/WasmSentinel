// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// WasmSentinel eBPF event collector: six kernel hooks feeding one ring buffer.
//
//   sched/sched_process_exec      -> EVENT_PROCESS_EXEC   (filename + full argv)
//   sched/sched_process_exit      -> EVENT_PROCESS_EXIT   (thread-group leader only)
//   syscalls/sys_enter_openat     -> EVENT_FILE_OPEN      (path + flags)
//   kprobe/tcp_connect            -> EVENT_NETWORK_CONNECT
//   kretprobe/inet_csk_accept     -> EVENT_NETWORK_ACCEPT
//   raw_tracepoint/sys_enter      -> EVENT_SYSCALL        (allow-listed high-risk syscalls)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_FILENAME_LEN 256
#define MAX_COMM_LEN 16
#define MAX_ARGS_LEN 256

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6

#define EVENT_PROCESS_EXEC    1
#define EVENT_PROCESS_EXIT    2
#define EVENT_FILE_OPEN       3
#define EVENT_NETWORK_CONNECT 4
#define EVENT_NETWORK_ACCEPT  5
#define EVENT_SYSCALL         6

// 1 MiB ring buffer: ~1,700 records of headroom for openat bursts.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

// Event record shared with the Go side (bpf2go -type event). Members are ordered
// so every field is naturally aligned: the C and Go layouts are then identical
// without any packing attribute. Total size: 592 bytes.
struct event {
    u64 timestamp_ns;          // 0   bpf_ktime_get_ns (CLOCK_MONOTONIC)
    s64 retval;                // 8   exit status for EXIT, else 0
    u32 pid;                   // 16  thread group id
    u32 ppid;                  // 20
    u32 uid;                   // 24
    u32 gid;                   // 28
    u32 event_type;            // 32
    u32 syscall_nr;            // 36  SYSCALL only
    u32 flags;                 // 40  open(2) flags for FILE_OPEN
    u32 saddr;                 // 44  IPv4, network byte order (0 for IPv6)
    u32 daddr;                 // 48
    u16 sport;                 // 52  host byte order
    u16 dport;                 // 54
    u16 family;                // 56  AF_INET / AF_INET6
    u16 protocol;              // 58
    u32 args_len;              // 60  bytes used in args
    char comm[MAX_COMM_LEN];   // 64
    char filename[MAX_FILENAME_LEN]; // 80  exec path / opened path
    char args[MAX_ARGS_LEN];   // 336 EXEC: NUL-separated argv (first 256 bytes)
};                             // 592

// Keeps struct event in BTF even if the compiler would otherwise drop it.
const struct event *unused_event_for_btf __attribute__((unused));

static __always_inline void fill_task(struct event *e)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = pid_tgid >> 32;
    e->uid = (u32)uid_gid;
    e->gid = uid_gid >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline struct event *reserve_event(u32 type)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return NULL;
    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = type;
    fill_task(e);
    return e;
}

static __always_inline void fill_sock4(struct event *e, struct sock *sk)
{
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    e->family = family;
    e->protocol = IPPROTO_TCP;
    if (family != AF_INET)
        return; // IPv6 addresses are not carried yet; family tells the host
    e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

// Fires after a successful execve: the new image is in place, so mm->arg_start
// holds the new argv and the tracepoint carries the resolved filename.
SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct event *e = reserve_event(EVENT_PROCESS_EXEC);
    if (!e)
        return 0;

    unsigned int fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    unsigned long arg_start = BPF_CORE_READ(task, mm, arg_start);
    unsigned long arg_end = BPF_CORE_READ(task, mm, arg_end);
    if (arg_end > arg_start) {
        unsigned long len = arg_end - arg_start;
        if (len > MAX_ARGS_LEN)
            len = MAX_ARGS_LEN;
        if (bpf_probe_read_user(&e->args, len, (void *)arg_start) == 0)
            e->args_len = len;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Thread-group leader exits only; thread exits would multiply the volume.
SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if ((u32)pid_tgid != (u32)(pid_tgid >> 32))
        return 0;

    struct event *e = reserve_event(EVENT_PROCESS_EXIT);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int exit_code = BPF_CORE_READ(task, exit_code);
    e->retval = (exit_code >> 8) & 0xff;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = reserve_event(EVENT_FILE_OPEN);
    if (!e)
        return 0;

    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
    e->flags = (u32)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(kprobe_tcp_connect, struct sock *sk)
{
    struct event *e = reserve_event(EVENT_NETWORK_CONNECT);
    if (!e)
        return 0;
    fill_sock4(e, sk);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe_inet_csk_accept, struct sock *sk)
{
    if (!sk)
        return 0;
    struct event *e = reserve_event(EVENT_NETWORK_ACCEPT);
    if (!e)
        return 0;
    fill_sock4(e, sk);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Allow-listed syscalls that matter for privilege escalation, container escape
// and persistence. Numbers are x86_64; the Go side names them.
static __always_inline bool is_watched_syscall(unsigned long nr)
{
    switch (nr) {
    case 56:  // clone
    case 57:  // fork
    case 59:  // execve
    case 62:  // kill
    case 101: // ptrace
    case 105: // setuid
    case 106: // setgid
    case 155: // pivot_root
    case 157: // prctl
    case 161: // chroot
    case 165: // mount
    case 166: // umount2
    case 175: // init_module
    case 272: // unshare
    case 308: // setns
    case 313: // finit_module
    case 319: // memfd_create
    case 321: // bpf
    case 322: // execveat
    case 435: // clone3
        return true;
    default:
        return false;
    }
}

SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long syscall_nr = ctx->args[1];
    if (!is_watched_syscall(syscall_nr))
        return 0;

    struct event *e = reserve_event(EVENT_SYSCALL);
    if (!e)
        return 0;
    e->syscall_nr = syscall_nr;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
