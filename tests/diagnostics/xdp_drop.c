// XDP drop. Same checks as the three aya-type objects.
// Short header returns XDP_ABORTED. A map hit returns XDP_DROP.
// The barrier keeps the ethernet type check and the IPv4 bound check apart.

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#define ETH_P_IP 0x0800

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u32);
} blocklist SEC(".maps");

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip;

	if ((void *)(eth + 1) > data_end)
		return XDP_ABORTED;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	asm volatile("" ::: "memory");

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_ABORTED;

	if (bpf_map_lookup_elem(&blocklist, &ip->saddr))
		return XDP_DROP;
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
