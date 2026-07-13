#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"
#define ETH_ALEN 6

struct mac_rule {
    __u8 dst[ETH_ALEN];
    __u8 src[ETH_ALEN];
    __u32 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct mac_rule);
} mac_redirect_rules SEC(".maps");

static __always_inline void copy_mac(__u8 *dst, const __u8 *src)
{
    int i;

#pragma unroll
    for (i = 0; i < ETH_ALEN; i++)
        dst[i] = src[i];
}

SEC("xdp")
int rewrite_and_redirect(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 ingress_ifindex = ctx->ingress_ifindex;
    struct mac_rule *rule;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    rule = bpf_map_lookup_elem(&mac_redirect_rules, &ingress_ifindex);
    if (!rule)
        return XDP_PASS;

    copy_mac(eth->h_dest, rule->dst);
    copy_mac(eth->h_source, rule->src);

    return bpf_redirect(rule->ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
