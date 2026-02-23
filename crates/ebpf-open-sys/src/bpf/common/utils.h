// #include "aarch64/vmlinux_5.15.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>



#define READ_KERN(ptr)                                                                         \
    ({                                                                                         \
        typeof(ptr) _val;                                                                      \
        __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
        bpf_probe_read((void *) &_val, sizeof(_val), &ptr);                                    \
        _val;                                                                                  \
    })

static __always_inline u32 get_task_pid(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;
    pid = READ_KERN(task->thread_pid);
    level = READ_KERN(pid->level);
    return READ_KERN(pid->numbers[level].nr);
}