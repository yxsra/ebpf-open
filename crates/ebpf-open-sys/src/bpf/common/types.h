#ifndef __FILE_MONITOR_TYPES_H__
#define __FILE_MONITOR_TYPES_H__

#include "aarch64/vmlinux_5.15.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common/misc.h"

#define TASK_COMM_LEN    16
#define MAX_PATH_LEN     256

// syscall_arg_info.flags
#define SYSCALL_FLAG_MODIFY (1 << 0)
#define SYSCALL_FLAG_PRINT  (1 << 1)

// modify_rule_entry.filter_type
#define FILTER_NONE       0
#define FILTER_PIDS       1
#define FILTER_UIDS       2
#define FILTER_UID_GROUPS 3

// uid group bitmask
#define UID_GROUP_APP    (1 << 0)
#define UID_GROUP_ISO    (1 << 1)

struct syscall_arg_info {
    __u32 str_reg_idx;
    __u32 flags;
};

struct modify_rule_entry {
    char  to[MAX_PATH_LEN];
    __u32 to_len;
    __u32 filter_type;
    __u32 rule_index;
    __u32 allowed_uid_mask;
    __u32 has_exclude_uids;
    __u32 no_restore;
};

struct rule_filter_key {
    __u32 rule_index;
    __u32 value;
};

struct pending_restore {
    __u64 fname_ptr;
    char  original[MAX_PATH_LEN];
    __u32 original_len;
    __u32 syscall_nr;
};

struct pending_print {
    __u32 syscall_nr;
    __u8  fname[MAX_PATH_LEN];
};

struct intercept_event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u8  comm[TASK_COMM_LEN];
    char  from[MAX_PATH_LEN];
    char  to[MAX_PATH_LEN];
    __s32 write_ret;
};

struct print_event {
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 syscall_nr;
    __s64 ret;
    __u8  comm[TASK_COMM_LEN];
    __u8  fname[MAX_PATH_LEN];
};

struct proc_ctx {
    __u64 pid_tgid;
    __u32 uid;
    __u8  comm[TASK_COMM_LEN];
};

struct heap_buf {
    struct proc_ctx ctx;
    char path[MAX_PATH_LEN];
    struct pending_restore pr;
    struct modify_rule_entry rule_copy;
};

#endif
