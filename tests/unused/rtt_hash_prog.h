/* HASH src IPv4 → u8: 0 DROP, nonzero TX (L2/L3/L4 swap), miss PASS. Ctrl :8081 PASS. */
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#ifndef TRIM_TO_ECHO
#define TRIM_TO_ECHO 0
#endif

#define ETH_P_IP 0x0800
#define ETH_ALEN 6
#define IPPROTO_UDP 17
#define FW_CTRL_PORT 8081
/* Userspace echo UDP payload 34 → L2 14+20+8+34. */
#define ECHO_L2_LEN 76

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u8);
} rtt_hash SEC(".maps");

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
int rtt_hash_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct udphdr *udph;
	__u32 key;
	__u8 *val;
	__u8 tmp;
	__u32 tmp32;
	__u16 tmp16;
	int i;
#if TRIM_TO_ECHO
	int pkt_len;
	int shrink;
	__u16 tot;
	__u16 ulen;
#endif

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

	key = iph->saddr;
	val = bpf_map_lookup_elem(&rtt_hash, &key);
	if (!val)
		return XDP_PASS;
	if (*val == 0)
		return XDP_DROP;

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

#if TRIM_TO_ECHO
	pkt_len = (int)((long)data_end - (long)data);
	if (pkt_len > ECHO_L2_LEN) {
		shrink = pkt_len - ECHO_L2_LEN;
		if (bpf_xdp_adjust_tail(ctx, ECHO_L2_LEN - pkt_len) < 0)
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
		if (tot >= (__u16)shrink) {
			iph->tot_len = bpf_htons(tot - (__u16)shrink);
			iph->check = 0;
			iph->check = ipv4_header_checksum(iph);
		}
		if (iph->protocol == IPPROTO_UDP) {
			udph = (void *)iph + sizeof(*iph);
			if ((void *)(udph + 1) <= data_end) {
				ulen = bpf_ntohs(udph->len);
				if (ulen >= (__u16)shrink)
					udph->len = bpf_htons(ulen - (__u16)shrink);
				udph->check = 0;
			}
		}
	}
#endif

	return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
