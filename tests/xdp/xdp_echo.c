/* Always XDP_TX bounce (L2/L3/L4 swap). UDP :8081 always PASS (control). */
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#define ETH_P_IP 0x0800
#define ETH_ALEN 6
#define IPPROTO_UDP 17
#define FW_CTRL_PORT 8081

SEC("xdp")
int xdp_echo(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct udphdr *udph;
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

	if (iph->protocol == IPPROTO_UDP) {
		udph = (void *)iph + sizeof(*iph);
		if ((void *)(udph + 1) <= data_end &&
		    udph->dest == bpf_htons(FW_CTRL_PORT))
			return XDP_PASS;
	}

#pragma unroll
	for (i = 0; i < ETH_ALEN; i++) {
		tmp = eth->h_dest[i];
		eth->h_dest[i] = eth->h_source[i];
		eth->h_source[i] = tmp;
	}

	tmp32 = iph->saddr;
	iph->saddr = iph->daddr;
	iph->daddr = tmp32;

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
