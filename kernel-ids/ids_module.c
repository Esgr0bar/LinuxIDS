#include "ids.h"

/* Initialization function */
static int __init ids_init(void) {
    printk(KERN_INFO "Initializing IDS Modules...\n");
    
    /* Setup Netlink socket for communication with user space */
    setup_netlink_socket();
    
    /* Setup PF_RING for high-speed packet capture */
    pf_ring_setup();

    /* Setup eBPF programs for in-kernel packet filtering */
    setup_ebpf_programs();

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
    netlink_kernel_release(nl_sk);

    /* Remove eBPF program */
    bpf_set_link_xdp_fd(if_nametoindex("eth0"), -1, XDP_FLAGS_UPDATE_IF_NOEXIST);

    printk(KERN_INFO "IDS Module Unloaded Successfully.\n");
}

module_init(ids_init);
module_exit(ids_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kernel-level IDS with eBPF, PF_RING, and advanced detection modules");
