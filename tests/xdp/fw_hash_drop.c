/* Hash-based firewall: match src_ip -> XDP_DROP; miss -> XDP_PASS. */
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#define ETH_P_IP   0x0800
#define IPPROTO_UDP 17
#define FW_CTRL_PORT 8081

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u8);
} fw_rules SEC(".maps");

SEC("xdp")
int fw_hash_drop(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct udphdr *udph;
	__u32 key;
	__u8 *hit;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	/* Control plane bypass */
	if (iph->protocol == IPPROTO_UDP) {
		udph = (void *)iph + sizeof(*iph);
		if ((void *)(udph + 1) <= data_end &&
		    udph->dest == bpf_htons(FW_CTRL_PORT))
			return XDP_PASS;
	}

	key = iph->saddr;
	hit = bpf_map_lookup_elem(&fw_rules, &key);
	if (hit)
		return XDP_DROP;

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
