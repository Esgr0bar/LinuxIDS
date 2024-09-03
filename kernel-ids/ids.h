#ifndef IDS_H
#define IDS_H

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
#include <linux/sched.h>
#include <linux/ebpf.h>  // eBPF support
#include <pf_ring.h>     // PF_RING support
#include <asm/stackprotector.h>  // Stack canary

extern unsigned long *syscall_table;
extern struct nf_hook_ops netfilter_ops;
extern struct jprobe jp;

/* Function prototypes */
void monitor_network_traffic(void);
void detect_stack_canary(void);
void check_syscall_table(void);
void check_hidden_processes(void);
void setup_ebpf_programs(void);
void pf_ring_setup(void);

#endif // IDS_H
