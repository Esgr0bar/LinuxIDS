
#include "ids.h"

/* Function to check syscall table integrity */
void check_syscall_table(void) {
    syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    if (!syscall_table) {
        printk(KERN_ERR "IDS: Unable to locate syscall table\n");
    } else {
        unsigned long original_syscall = syscall_table[__NR_open];
        if (syscall_table[__NR_open] != (unsigned long)sys_open) {
            printk(KERN_ALERT "IDS: Syscall table modification detected! Possible rootkit!\n");
        } else {
            printk(KERN_INFO "IDS: Syscall table integrity verified.\n");
        }
    }
}
