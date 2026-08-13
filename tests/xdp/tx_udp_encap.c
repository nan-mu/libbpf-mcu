#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17

/* Observable TX-hijack marker: rewrite UDP sport, clear checksum, XDP_TX. */
#define MARK_SPORT 0x4254 /* 'BT' */

SEC("xdp")
int tx_udp_encap(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct udphdr *udph;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	if (iph->ihl < 5)
		return XDP_PASS;

	if ((void *)iph + iph->ihl * 4 > data_end)
		return XDP_PASS;

	if (iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	udph = (void *)iph + iph->ihl * 4;
	if ((void *)(udph + 1) > data_end)
		return XDP_PASS;

	udph->source = bpf_htons(MARK_SPORT);
	udph->check = 0;

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
