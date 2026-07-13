#include <bpf/bpf_helpers.h>
#include <bpf/string.h>
#include "vmlinux.h"

#define ETH_P_IP 0x0800
#define __constant_ntohs(x) __builtin_bswap16(x)
#define __constant_htons(x) __builtin_bswap16(x)

SEC("xdp")
int print_udp(struct xdp_md *ctx) {
    // 必须在任何函数调用前提取 ctx 的值
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    bpf_printk("[1] Start XDP\n");
    
    // 1. 以太网头部检查
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk("[2] ETH OOB\n");
        return XDP_PASS;
    }

    bpf_printk("[3] ETH OK\n");

    // 检查以太网协议类型
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        bpf_printk("[4] Not IP: 0x%x\n", __constant_ntohs(eth->h_proto));
        return XDP_PASS;
    }

    bpf_printk("[5] IP proto OK\n");

    // 2. IP 头部检查
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) {
        bpf_printk("[6] IP header OOB\n");
        return XDP_PASS;
    }

    bpf_printk("[7] IP header OK\n");

    if (iph->protocol != IPPROTO_UDP) {
        bpf_printk("[8] Not UDP: %d\n", iph->protocol);
        return XDP_PASS;
    }

    bpf_printk("[9] UDP proto OK\n");

    // 3. UDP 头部检查
    struct udphdr *udp = (void *)iph + sizeof(struct iphdr);
    if ((void *)(udp + 1) > data_end) {
        bpf_printk("[10] UDP header OOB\n");
        return XDP_PASS;
    }

    bpf_printk("[11] UDP header OK\n");

    // 4. 计算载荷大小
    unsigned int udp_len = __constant_ntohs(udp->len);
    if (udp_len < sizeof(struct udphdr)) {
        bpf_printk("[12] UDP len too small: %d\n", udp_len);
        return XDP_PASS;
    }

    bpf_printk("[13] UDP len OK: %d\n", udp_len);

    unsigned int payload_len = udp_len - sizeof(struct udphdr);
    
    bpf_printk("[14] Payload len: %d\n", payload_len);
    
    // 打印 IP 地址
    bpf_printk("[15] UDP: %pI4 -> %pI4\n", &iph->saddr, &iph->daddr);

    // 5. 如果载荷 <= 127 字节，复制到栈并打印
    if (payload_len > 0 && payload_len <= 128) {
        bpf_printk("[16] Copying payload\n");
        
        char buf[128];
        void *payload = (void *)udp + sizeof(struct udphdr);

        // 再次检查边界
        if (payload + payload_len > data_end) {
            bpf_printk("[17] Payload OOB\n");
            return XDP_PASS;
        }
        
        bpf_printk("[18] Payload boundary OK\n");
        
        memset(buf, 0, sizeof(buf));
        memcpy(buf, payload, payload_len & 0x7F);
        
        bpf_printk("[19] Payload(%d): %s\n", payload_len, buf);
    } else {
        bpf_printk("[20] Payload len out of range: %d\n", payload_len);
    }

    bpf_printk("[21] Done\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
