/* merge_try — ethertype diamond with shared bounds-check suffix.
 *
 * Build:
 *   pixi run build --firmware <firmware.elf> -c merge_try
 */
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

SEC("xdp")
int merge_try(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u16 proto;
	__u32 off;

	if (data + sizeof(*eth) > data_end)
		return XDP_DROP;

	proto = eth->h_proto;
	off = sizeof(*eth);

	/* Two real arms (IPv4 vs IPv6); both fall into the same suffix. */
	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + off;

		if ((void *)(iph + 1) > data_end)
			return XDP_DROP;
		/* fall through */
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		void *ip6 = data + off;

		if (ip6 + 40 > data_end)
			return XDP_DROP;
		/* fall through */
	} else {
		return XDP_DROP;
	}

	/* Shared suffix after either L3 header check. */
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
