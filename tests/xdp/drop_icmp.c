#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define IPPROTO_ICMP 1

SEC("xdp")
int drop_icmp(struct xdp_md *ctx) {
    // 获取数据包的起始和结束指针
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 仅处理 IPv4 数据包
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 解析 IPv4 头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 检查是否为 ICMP 协议 (Ping)
    if (ip->protocol == IPPROTO_ICMP) {
        return XDP_DROP; // 丢弃数据包
    }

    return XDP_PASS; // 其他包放行
}

char _license[] SEC("license") = "GPL";