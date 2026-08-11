/* Hash-based firewall: match src_ip -> swap L2/L3/L4, XDP_TX; miss -> XDP_PASS. */
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#define ETH_P_IP   0x0800
#define ETH_ALEN   6
#define IPPROTO_UDP 17
#define FW_CTRL_PORT 8081

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u8);
} fw_rules SEC(".maps");

SEC("xdp")
int fw_hash_bounce(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct udphdr *udph;
	__u32 key;
	__u8 *hit;
	__u8 tmp;
	__u32 tmp32;
	__u16 tmp16;
	int i;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	/* Control plane bypass: UDP :8081 always passes to userspace. */
	if (iph->protocol == IPPROTO_UDP) {
		udph = (void *)iph + sizeof(*iph);
		if ((void *)(udph + 1) <= data_end &&
		    udph->dest == bpf_htons(FW_CTRL_PORT))
			return XDP_PASS;
	}

	key = iph->saddr;
	hit = bpf_map_lookup_elem(&fw_rules, &key);
	if (!hit)
		return XDP_PASS;

	/* Swap L2 */
#pragma unroll
	for (i = 0; i < ETH_ALEN; i++) {
		tmp = eth->h_dest[i];
		eth->h_dest[i] = eth->h_source[i];
		eth->h_source[i] = tmp;
	}

	/* Swap L3 */
	tmp32 = iph->saddr;
	iph->saddr = iph->daddr;
	iph->daddr = tmp32;

	/* Swap L4 (UDP ports) */
	if (iph->protocol == IPPROTO_UDP) {
		udph = (void *)iph + sizeof(*iph);
		if ((void *)(udph + 1) <= data_end) {
			tmp16 = udph->source;
			udph->source = udph->dest;
			udph->dest = tmp16;
		}
	}

	return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
