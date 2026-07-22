#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"
#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17

struct rewrite_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct rewrite_value {
    __u16 new_dst_port;
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct rewrite_key);
    __type(value, struct rewrite_value);
} udp_rewrite_rules SEC(".maps");

static __always_inline int parse_udp(void *data, void *data_end,
                                     struct iphdr **iph_out,
                                     struct udphdr **udph_out)
{
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct udphdr *udph;

    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    if (iph->ihl < 5)
        return -1;

    if ((void *)iph + iph->ihl * 4 > data_end)
        return -1;

    if (iph->protocol != IPPROTO_UDP)
        return -1;

    udph = (void *)iph + iph->ihl * 4;
    if ((void *)(udph + 1) > data_end)
        return -1;

    *iph_out = iph;
    *udph_out = udph;
    return 0;
}

SEC("xdp")
int rewrite_and_pass(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct iphdr *iph;
    struct udphdr *udph;
    struct rewrite_key key = {};
    struct rewrite_value *rule;
    __u16 old_dest;
    __u16 new_dest;

    if (parse_udp(data, data_end, &iph, &udph) < 0)
        return XDP_PASS;

    key.src_ip = iph->saddr;
    key.dst_ip = iph->daddr;
    key.src_port = bpf_ntohs(udph->source);
    key.dst_port = bpf_ntohs(udph->dest);

    rule = bpf_map_lookup_elem(&udp_rewrite_rules, &key);
    if (!rule)
        return XDP_PASS;

    old_dest = udph->dest;
    new_dest = bpf_htons(rule->new_dst_port);

    if (old_dest == new_dest)
        return XDP_PASS;

    /* bpf_l4_csum_replace is skb-only; do incremental update for XDP. */
    if (udph->check) {
        __u32 sum = (~(__u32)udph->check & 0xffff) +
                    (~(__u32)old_dest & 0xffff) +
                    (__u32)new_dest;
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        udph->check = (__sum16)~sum;
        if (!udph->check)
            udph->check = 0xffff;
    }
    udph->dest = new_dest;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
