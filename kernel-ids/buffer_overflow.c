#include "ids.h"

/* Hooked function to check stack canary */
static asmlinkage long jhooked_syscall(const struct pt_regs *regs) {
    if (unlikely(current->stack_canary != current->stack_end)) {
        printk(KERN_ALERT "IDS: Stack canary mismatch detected for process %s (pid %d)\n",
               current->comm, current->pid);
    }
    jprobe_return();
    return 0;  // Continue normal syscall execution
}

/* Function to setup the buffer overflow detection */
void detect_stack_canary(void) {
    jp.kp.addr = (kprobe_opcode_t *)kallsyms_lookup_name("sys_open");
    if (!jp.kp.addr) {
        printk(KERN_ERR "IDS: Couldn't find sys_open to hook\n");
    } else {
        jp.entry = (kprobe_opcode_t *)jhooked_syscall;
        register_jprobe(&jp);
        printk(KERN_INFO "IDS: Stack Canary Detection Initialized.\n");
    }
}

