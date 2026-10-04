/* ARRAY firewall: idx0 DROP, idx1 L2/L3/L4 swap + tail shrink + XDP_TX, else PASS. */
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#define ETH_P_IP 0x0800
#define ETH_ALEN 6
#define IPPROTO_UDP 17
#define FW_CTRL_PORT 8081
/* Must match router-probe test0 `TX_SHRINK`. Probe asserts bounce L2 = 1492-N. */
#define TX_SHRINK 64

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u32);
} firewall_array SEC(".maps");

static __always_inline __u16 ipv4_header_checksum(struct iphdr *iph)
{
	__u8 *b = (__u8 *)iph;
	__u32 sum = 0;
	int i;

#pragma unroll
	for (i = 0; i < 20; i += 2)
		sum += ((__u32)b[i] << 8) | b[i + 1];
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return bpf_htons((__u16)~sum);
}

SEC("xdp")
int firewall_array_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct udphdr *udph;
	__u32 idx;
	__u32 *slot;
	__u8 tmp;
	__u32 tmp32;
	__u16 tmp16;
	__u16 tot;
	__u16 ulen;
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

	idx = 0;
	slot = bpf_map_lookup_elem(&firewall_array, &idx);
	if (slot && *slot != 0 && iph->saddr == *slot)
		return XDP_DROP;

	idx = 1;
	slot = bpf_map_lookup_elem(&firewall_array, &idx);
	if (!slot || *slot == 0 || iph->saddr != *slot)
		return XDP_PASS;

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

	if (bpf_xdp_adjust_tail(ctx, -TX_SHRINK) < 0)
		return XDP_TX;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_TX;
	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_TX;

	tot = bpf_ntohs(iph->tot_len);
	if (tot < TX_SHRINK)
		return XDP_TX;
	iph->tot_len = bpf_htons(tot - TX_SHRINK);
	iph->check = 0;
	iph->check = ipv4_header_checksum(iph);

	if (iph->protocol == IPPROTO_UDP) {
		udph = (void *)iph + sizeof(*iph);
		if ((void *)(udph + 1) <= data_end) {
			ulen = bpf_ntohs(udph->len);
			if (ulen >= TX_SHRINK)
				udph->len = bpf_htons(ulen - TX_SHRINK);
			udph->check = 0;
		}
	}

	return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
