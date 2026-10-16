// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// WasmSentinel eBPF Event Collector
// High-performance kernel-level event tracing for threat detection

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_FILENAME_LEN 256
#define MAX_COMM_LEN 16
#define MAX_ARGS_LEN 256
#define TASK_COMM_LEN 16

// Network constants (from socket.h)
#define AF_INET 2
#define IPPROTO_TCP 6

// Event types
#define EVENT_PROCESS_EXEC    1
#define EVENT_PROCESS_EXIT    2
#define EVENT_FILE_OPEN       3
#define EVENT_NETWORK_CONNECT 4
#define EVENT_NETWORK_ACCEPT  5
#define EVENT_SYSCALL         6

// Ring buffer for high-performance event delivery
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} events SEC(".maps");

// Process info cache for correlation
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);   // pid
    __type(value, u64); // start_time
} process_cache SEC(".maps");

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64); // flags
} sentinel_config SEC(".maps");

// Event structure - optimized for Wasm consumption
struct event {
    u64 timestamp_ns;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 event_type;
    s64 retval;
    char comm[MAX_COMM_LEN];
    char filename[MAX_FILENAME_LEN];

    // Network specific fields
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 family;
    u16 protocol;

    // Syscall specific
    u32 syscall_nr;
    u32 flags;

    // For args (first 256 bytes)
    char args[MAX_ARGS_LEN];
    u32 args_len;
} __attribute__((packed));

// Helper to get current task info
static __always_inline void get_task_info(struct event *e) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->gid = bpf_get_current_uid_gid() >> 32;

    // Get parent PID
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
        bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid), &parent->tgid);
    }

    // Get comm
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// Tracepoint: Process execution (execve)
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = EVENT_PROCESS_EXEC;
    get_task_info(e);

    // Read filename from args[0]
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    // Read argv[1] for first argument (if exists)
    const char **argv = (const char **)ctx->args[1];
    if (argv) {
        const char *arg1;
        bpf_probe_read_user(&arg1, sizeof(arg1), &argv[1]);
        if (arg1) {
            bpf_probe_read_user_str(&e->args, sizeof(e->args), arg1);
            e->args_len = sizeof(e->args);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Tracepoint: Process exit
SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = EVENT_PROCESS_EXIT;
    get_task_info(e);

    // Remove from process cache
    u32 pid = e->pid;
    bpf_map_delete_elem(&process_cache, &pid);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Tracepoint: File open
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = EVENT_FILE_OPEN;
    get_task_info(e);

    // Read filename
    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    // Read flags
    e->flags = (u32)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Kprobe: TCP connect
SEC("kprobe/tcp_connect")
int BPF_KPROBE(kprobe_tcp_connect, struct sock *sk) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = EVENT_NETWORK_CONNECT;
    get_task_info(e);

    // Read socket info
    u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    e->family = family;

    if (family == AF_INET) {
        bpf_probe_read_kernel(&e->saddr, sizeof(e->saddr),
                              &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&e->daddr, sizeof(e->daddr),
                              &sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&e->dport, sizeof(e->dport),
                              &sk->__sk_common.skc_dport);
        e->dport = __builtin_bswap16(e->dport);
        bpf_probe_read_kernel(&e->sport, sizeof(e->sport),
                              &sk->__sk_common.skc_num);
    }

    e->protocol = IPPROTO_TCP;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Kprobe: inet_csk_accept (for incoming connections)
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe_inet_csk_accept, struct sock *sk) {
    if (!sk) {
        return 0;
    }

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = EVENT_NETWORK_ACCEPT;
    get_task_info(e);

    // Read socket info
    u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    e->family = family;

    if (family == AF_INET) {
        bpf_probe_read_kernel(&e->saddr, sizeof(e->saddr),
                              &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&e->daddr, sizeof(e->daddr),
                              &sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&e->sport, sizeof(e->sport),
                              &sk->__sk_common.skc_num);
        bpf_probe_read_kernel(&e->dport, sizeof(e->dport),
                              &sk->__sk_common.skc_dport);
        e->dport = __builtin_bswap16(e->dport);
    }

    e->protocol = IPPROTO_TCP;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Raw tracepoint for syscall enter (general purpose)
SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    unsigned long syscall_nr = ctx->args[1];

    // Only trace specific high-risk syscalls
    // 59: execve, 322: execveat, 56: clone, 57: fork
    // 62: kill, 157: prctl, 101: ptrace
    switch (syscall_nr) {
        case 59:  // execve - already handled
        case 322: // execveat
        case 56:  // clone
        case 57:  // fork
        case 62:  // kill
        case 157: // prctl
        case 101: // ptrace
            break;
        default:
            return 0;
    }

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = EVENT_SYSCALL;
    e->syscall_nr = syscall_nr;
    get_task_info(e);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
