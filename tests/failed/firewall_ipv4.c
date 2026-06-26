#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct fw_key {
    __u32 src_ip;
    __u16 dst_port;
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct fw_key);
    __type(value, __u8);
} firewall_rules SEC(".maps");

static __always_inline int parse_ipv4_tcp_udp(void *data, void *data_end,
                                              struct iphdr **iph_out,
                                              __u16 *dst_port_out)
{
    struct ethhdr *eth = data;
    struct iphdr *iph;
    void *l4hdr;
    __u16 h_proto;

    if ((void *)(eth + 1) > data_end)
        return -1;

    h_proto = eth->h_proto;
    if (h_proto != bpf_htons(ETH_P_IP))
        return -1;

    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    if (iph->ihl < 5)
        return -1;

    if ((void *)iph + iph->ihl * 4 > data_end)
        return -1;

    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return -1;

    l4hdr = (void *)iph + iph->ihl * 4;
    if (l4hdr + sizeof(__u32) > data_end)
        return -1;

    *iph_out = iph;
    *dst_port_out = *(__be16 *)(l4hdr + sizeof(__u16));
    return 0;
}

SEC("xdp")
int firewall_ipv4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct iphdr *iph;
    struct fw_key key = {};
    __u16 dst_port;
    __u8 *action;

    if (parse_ipv4_tcp_udp(data, data_end, &iph, &dst_port) < 0)
        return XDP_PASS;

    key.src_ip = iph->saddr;
    key.dst_port = bpf_ntohs(dst_port);

    action = bpf_map_lookup_elem(&firewall_rules, &key);
    if (action && *action)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
