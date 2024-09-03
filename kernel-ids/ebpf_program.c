#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp_filter")
int xdp_filter_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    /* Ensure the Ethernet header is within packet bounds */
    if (eth + 1 > data_end)
        return XDP_DROP;

    /* Check if the packet is an IP packet */
    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);

        if (ip + 1 > data_end)
            return XDP_DROP;

        /* Drop UDP packets from a specific IP as an example */
        if (ip->protocol == IPPROTO_UDP && ip->saddr == htonl(0xC0A80001)) {
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
