// SPDX-License-Identifier: GPL-2.0
#ifndef __FILE_MONITOR_HELPERS_H__
#define __FILE_MONITOR_HELPERS_H__

#include "common/maps.h"

extern volatile const __u8 verbose_level;
extern volatile const __u8 modify_enabled;

// 白名单检查
static __always_inline bool is_whitelisted(struct proc_ctx *ctx)
{
    __u32 pid = ctx->pid_tgid >> 32;
    if (bpf_map_lookup_elem(&pid_whitelist, &pid))
        return true;
    if (bpf_map_lookup_elem(&uid_whitelist, &ctx->uid))
        return true;
    return false;
}

static __always_inline __u32 uid_to_group_mask(__u32 uid)
{
    __u32 mask = 0;
    if (uid >= 10000 && uid <= 19999)
        mask |= UID_GROUP_APP;
    if (uid >= 90000 && uid <= 99999)
        mask |= UID_GROUP_ISO;
    return mask;
}

// 过滤检查：通过返回 true，不通过返回 false
static __always_inline bool check_filter(struct modify_rule_entry *rule, struct proc_ctx *ctx)
{
    struct rule_filter_key fk;
    fk.rule_index = rule->rule_index;

    switch (rule->filter_type) {
    case FILTER_PIDS:
        fk.value = ctx->pid_tgid >> 32;
        return bpf_map_lookup_elem(&rule_filter, &fk) != NULL;
    case FILTER_UIDS:
        fk.value = ctx->uid;
        return bpf_map_lookup_elem(&rule_filter, &fk) != NULL;
    case FILTER_UID_GROUPS:
        if (!(uid_to_group_mask(ctx->uid) & rule->allowed_uid_mask))
            return false;
        if (rule->has_exclude_uids) {
            fk.value = ctx->uid;
            if (bpf_map_lookup_elem(&rule_filter, &fk))
                return false;
        }
        return true;
    default:
        return true;
    }
}

// 尝试修改：查 modify_rules，过滤，重定向，保存恢复，上报事件
static __always_inline bool try_modify(u64 fname_ptr, struct heap_buf *hb,
                                       int path_len, __u32 syscall_nr)
{
    struct modify_rule_entry *rule = bpf_map_lookup_elem(&modify_rules, hb->path);
    if (!rule)
        return false;

    __builtin_memcpy(&hb->rule_copy, rule, sizeof(hb->rule_copy));

    if (!check_filter(&hb->rule_copy, &hb->ctx))
        return false;

    // 保存恢复信息
    if (!hb->rule_copy.no_restore) {
        __builtin_memset(&hb->pr, 0, sizeof(hb->pr));
        hb->pr.fname_ptr = fname_ptr;
        hb->pr.original_len = path_len > 0 ? (__u32)path_len : 0;
        hb->pr.syscall_nr = syscall_nr;
        __builtin_memcpy(hb->pr.original, hb->path, MAX_PATH_LEN);
        bpf_map_update_elem(&pending_restores, &hb->ctx.pid_tgid, &hb->pr, BPF_ANY);
    }

    // 执行重定向
    __s32 write_ret = 0;
    __u32 tlen = hb->rule_copy.to_len;
    if (tlen >= 1 && tlen <= MAX_PATH_LEN) {
        tlen = ((tlen - 1) & 0xFF) + 1;
        write_ret = (__s32)bpf_probe_write_user((void *)fname_ptr,
                                                 hb->rule_copy.to, tlen);
    }

    // 上报拦截事件
    struct intercept_event *ie = bpf_ringbuf_reserve(&intercept_events, sizeof(*ie), 0);
    if (ie) {
        ie->pid = hb->ctx.pid_tgid >> 32;
        ie->tid = (__u32)hb->ctx.pid_tgid;
        ie->uid = hb->ctx.uid;
        __builtin_memcpy(ie->comm, hb->ctx.comm, sizeof(ie->comm));
        __builtin_memcpy(ie->from, hb->path, MAX_PATH_LEN);
        __builtin_memcpy(ie->to, hb->rule_copy.to, MAX_PATH_LEN);
        ie->write_ret = write_ret;
        bpf_ringbuf_submit(ie, 0);
    }

    return true;
}

// 公共处理：修改 + print 暂存
static __noinline int handle_syscall(struct heap_buf *hb, u64 fname_ptr,
                                     __u32 syscall_nr, __u32 flags)
{
    __builtin_memset(hb->path, 0, MAX_PATH_LEN);
    int path_len = bpf_probe_read_user_str(hb->path, sizeof(hb->path), (const char *)fname_ptr);

    if ((flags & SYSCALL_FLAG_MODIFY) && modify_enabled && path_len > 0)
        try_modify(fname_ptr, hb, path_len, syscall_nr);

    if (flags & SYSCALL_FLAG_PRINT) {
        struct pending_print pp = {};
        pp.syscall_nr = syscall_nr;
        if (path_len > 0)
            __builtin_memcpy(pp.fname, hb->path, MAX_PATH_LEN);
        bpf_map_update_elem(&pending_prints, &hb->ctx.pid_tgid, &pp, BPF_ANY);
    }

    return 0;
}

#endif
