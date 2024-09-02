#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* Kprobe structure for hooking into sys_open syscall */
static struct jprobe jp;

/* NF hook structure for monitoring network packets */
static struct nf_hook_ops netfilter_ops;

/* Check the stack canary value to detect potential stack overflow */
static asmlinkage long jhooked_syscall(const struct pt_regs *regs) {
    if (unlikely(current->stack_canary != current->stack_end)) {
        printk(KERN_ALERT "IDS: Stack canary mismatch detected for process %s (pid %d)\n",
               current->comm, current->pid);
    }
    jprobe_return();
    return 0;  // Continue normal syscall execution
}

/* Function to hook into open syscall */
static asmlinkage long jhooked_open(const char __user *filename, int flags, mode_t mode) {
    printk(KERN_INFO "IDS: File access detected: %s\n", filename);
    jprobe_return();
    return 0; /* Allow normal operation */
}

/* Function to monitor network packets */
unsigned int netfilter_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)((__u32 *)ip_header + ip_header->ihl);
        printk(KERN_INFO "IDS: TCP packet detected - Source: %pI4, Dest: %pI4\n",
               &ip_header->saddr, &ip_header->daddr);
    } else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)((__u32 *)ip_header + ip_header->ihl);
        printk(KERN_INFO "IDS: UDP packet detected - Source: %pI4, Dest: %pI4\n",
               &ip_header->saddr, &ip_header->daddr);
    }
    return NF_ACCEPT; /* Allow packet to pass through */
}

static int __init ids_init(void) {
    /* Setup jprobe for sys_open */
    jp.kp.addr = (kprobe_opcode_t *)kallsyms_lookup_name("sys_open");
    if (!jp.kp.addr) {
        printk(KERN_ERR "IDS: Couldn't find sys_open to hook\n");
        return -1;
    }
    jp.entry = (kprobe_opcode_t *)jhooked_open;
    register_jprobe(&jp);

    /* Setup netfilter hook */
    netfilter_ops.hook = netfilter_hook;
    netfilter_ops.pf = PF_INET;
    netfilter_ops.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &netfilter_ops);

    printk(KERN_INFO "IDS Module Loaded.\n");
    return 0;
}

static void __exit ids_exit(void) {
    unregister_jprobe(&jp);
    nf_unregister_net_hook(&init_net, &netfilter_ops);
    printk(KERN_INFO "IDS Module Unloaded.\n");
}

module_init(ids_init);
module_exit(ids_exit);

MODULE_DESCRIPTION("Kernel-level IDS Module");
