#include "ids.h"

unsigned long *syscall_table;
struct nf_hook_ops netfilter_ops;
struct jprobe jp;

/* Initialization function */
static int __init ids_init(void) {
    printk(KERN_INFO "Initializing IDS Modules...\n");

    /* Buffer Overflow Detection */
    detect_stack_canary();

    /* Rootkit Detection */
    check_syscall_table();

    /* Unauthorized Kernel Interaction Detection */
    check_hidden_processes();

    /* Setup Network Monitoring */
    monitor_network_traffic();

    printk(KERN_INFO "IDS Module Loaded Successfully.\n");
    return 0;
}

/* Cleanup function */
static void __exit ids_exit(void) {
    unregister_jprobe(&jp);
    nf_unregister_net_hook(&init_net, &netfilter_ops);
    printk(KERN_INFO "IDS Module Unloaded Successfully.\n");
}

module_init(ids_init);
module_exit(ids_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kernel-level IDS with Buffer Overflow, Rootkit, and Unauthorized Access Detection");

