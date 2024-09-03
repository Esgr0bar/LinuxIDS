#include "ids.h"

/* eBPF program to filter and drop malicious packets */
static int ebpf_packet_filter(struct __sk_buff *skb) {
    struct iphdr *ip = (struct iphdr *)(skb->data + sizeof(struct ethhdr));
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if (tcp->dest == htons(80) && tcp->syn) {
            return XDP_DROP;  // Drop TCP SYN packets to port 80 (example)
        }
    }
    return XDP_PASS;  // Pass all other packets
}

/* Function to load eBPF programs into the kernel */
void setup_ebpf_programs(void) {
    int prog_fd = bpf_load_program(BPF_PROG_TYPE_XDP, ebpf_packet_filter, sizeof(ebpf_packet_filter));
    if (prog_fd < 0) {
        printk(KERN_ERR "IDS: Failed to load eBPF program\n");
        return;
    }

    if (bpf_set_link_xdp_fd(if_nametoindex("eth0"), prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST) < 0) {
        printk(KERN_ERR "IDS: Failed to attach eBPF program to eth0\n");
        close(prog_fd);
        return;
    }

    printk(KERN_INFO "IDS: eBPF program attached to eth0\n");
}
