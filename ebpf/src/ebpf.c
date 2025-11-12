// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Ring buffer used to send events to user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/**
 * Function: trace_openat
 * Summary:
 *   eBPF tracepoint handler for sys_enter_openat. Captures process
 *   information and the filename being opened, then submits the event
 *   to a ring buffer for user-space processing.
 *
 * Parameters:
 *   - ctx: pointer to the tracepoint context (syscall arguments and metadata).
 *
 * Return:
 *   - 0: always returns 0 to indicate successful probe execution.
 */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];
    struct file_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = id & 0xffffffff;
    e->uid = bpf_get_current_uid_gid();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->ts_ns = bpf_ktime_get_ns();
    e->fd = -1;
    e->count = 0;
    e->type = SYSCALL_OPEN;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/**
 * Function: trace_read
 * Summary:
 *   eBPF tracepoint handler for sys_enter_read. Captures process and
 *   read syscall information (PID, UID, fd, count, timestamp, etc.)
 *   and submits the event to the ring buffer for user-space processing.
 *
 * Parameters:
 *   - ctx: pointer to the tracepoint context containing syscall arguments.
 *
 * Return:
 *   - 0: always returns 0 to indicate successful probe execution.
 */
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = id & 0xffffffff;
    e->uid = bpf_get_current_uid_gid();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->ts_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->fd = (int)ctx->args[0];
    e->count = (int)ctx->args[2];
    e->filename[0] = '\0'; 
    e->type = SYSCALL_READ;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/**
 * Function: trace_write
 * Summary:
 *   eBPF tracepoint handler for sys_enter_write. Captures information
 *   about write system calls, including process IDs, UID, file descriptor,
 *   write size, and timestamp, then submits the event to the ring buffer.
 *
 * Parameters:
 *   - ctx: pointer to the tracepoint context containing syscall arguments.
 *
 * Return:
 *   - 0: always returns 0 to indicate successful probe execution.
 */
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx)
{
    struct file_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = id & 0xffffffff;
    e->uid = bpf_get_current_uid_gid();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->ts_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->fd = (int)ctx->args[0];
    e->count = (int)ctx->args[2];
    e->filename[0] = '\0'; 
    e->type = SYSCALL_WRITE;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
