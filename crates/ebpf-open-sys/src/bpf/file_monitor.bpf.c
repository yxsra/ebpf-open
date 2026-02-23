// SPDX-License-Identifier: GPL-2.0

#include "common/helpers.h"

volatile const __u8 verbose_level = 1;
volatile const __u8 modify_enabled = 1;

SEC("raw_tracepoint.w/sys_enter")
int raw_syscall_enter(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    unsigned long id = ctx->args[1];

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    bool is32 = BPF_CORE_READ(task, thread_info.flags) & _TIF_32BIT;

    __u32 nr = (__u32)id;
    struct syscall_arg_info *info;
    if (is32)
        info = bpf_map_lookup_elem(&syscall_args_32, &nr);
    else
        info = bpf_map_lookup_elem(&syscall_args_64, &nr);

    if (!info)
        return 0;

    __u32 str_reg_idx = info->str_reg_idx;
    __u32 flags = info->flags;

    __u32 zero = 0;
    struct heap_buf *hb = bpf_map_lookup_elem(&heap, &zero);
    if (!hb)
        return 0;

    hb->ctx.pid_tgid = bpf_get_current_pid_tgid();
    hb->ctx.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&hb->ctx.comm, sizeof(hb->ctx.comm));

    if (is_whitelisted(&hb->ctx))
        return 0;

    u64 fname_ptr = 0;
    switch (str_reg_idx) {
    case 0: bpf_probe_read_kernel(&fname_ptr, sizeof(fname_ptr), &regs->regs[0]); break;
    case 1: bpf_probe_read_kernel(&fname_ptr, sizeof(fname_ptr), &regs->regs[1]); break;
    case 2: bpf_probe_read_kernel(&fname_ptr, sizeof(fname_ptr), &regs->regs[2]); break;
    case 3: bpf_probe_read_kernel(&fname_ptr, sizeof(fname_ptr), &regs->regs[3]); break;
    case 4: bpf_probe_read_kernel(&fname_ptr, sizeof(fname_ptr), &regs->regs[4]); break;
    case 5: bpf_probe_read_kernel(&fname_ptr, sizeof(fname_ptr), &regs->regs[5]); break;
    default: return 0;
    }

    if (fname_ptr == 0)
        return 0;

    handle_syscall(hb, fname_ptr, nr, flags);
    return 0;
}

SEC("raw_tracepoint.w/sys_exit")
int raw_syscall_exit(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // 恢复路径
    struct pending_restore *pr = bpf_map_lookup_elem(&pending_restores, &pid_tgid);
    if (pr) {
        long ret = (long)ctx->args[1];
        __u32 nr = pr->syscall_nr;
        // execve/execveat 成功后旧地址空间已销毁
        if (!((nr == 221 || nr == 281) && ret == 0)) {
            __u32 len = pr->original_len;
            if (len >= 1 && len <= MAX_PATH_LEN) {
                len = ((len - 1) & 0xFF) + 1;
                bpf_probe_write_user((void *)pr->fname_ptr, pr->original, len);
            }
        }
        bpf_map_delete_elem(&pending_restores, &pid_tgid);
    }

    // print 事件
    struct pending_print *pp = bpf_map_lookup_elem(&pending_prints, &pid_tgid);
    if (pp) {
        struct print_event *pe = bpf_ringbuf_reserve(&events, sizeof(*pe), 0);
        if (pe) {
            pe->pid = pid_tgid >> 32;
            pe->tid = (__u32)pid_tgid;
            pe->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            pe->syscall_nr = pp->syscall_nr;
            pe->ret = (long)ctx->args[1];
            bpf_get_current_comm(&pe->comm, sizeof(pe->comm));
            __builtin_memcpy(pe->fname, pp->fname, MAX_PATH_LEN);
            bpf_ringbuf_submit(pe, 0);
        }
        bpf_map_delete_elem(&pending_prints, &pid_tgid);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
