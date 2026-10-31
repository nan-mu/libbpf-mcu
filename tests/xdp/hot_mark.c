/* UDP bounce that rewrites the IPv4 destination.
 *
 * The destination is set to 203.0.113.77 (TEST-NET-3). The IPv4 header
 * checksum is recomputed over the fixed 20-byte header, and the UDP checksum
 * is cleared because IPv4 allows a zero UDP checksum. Ethernet MACs are
 * swapped so the rewritten frame returns to the sender.
 */
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#define ETH_P_IP 0x0800

/* 203.0.113.77 */
#define MARK_DST 0xcb00714d

struct bpf_map_def SEC("maps") rxcnt = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(long),
	.max_entries = 256,
};

static void swap_mac(void *data)
{
	unsigned short *p = data;
	unsigned short dst0 = p[0];
	unsigned short dst1 = p[1];
	unsigned short dst2 = p[2];

	p[0] = p[3];
	p[1] = p[4];
	p[2] = p[5];
	p[3] = dst0;
	p[4] = dst1;
	p[5] = dst2;
}

/* Ones' complement over the 20-byte header. check is zeroed first. */
static void ipv4_csum(struct iphdr *ip)
{
	__u8 *b = (void *)ip;
	__u32 sum = 0;

	ip->check = 0;
	sum += ((__u32)b[0] << 8) | b[1];
	sum += ((__u32)b[2] << 8) | b[3];
	sum += ((__u32)b[4] << 8) | b[5];
	sum += ((__u32)b[6] << 8) | b[7];
	sum += ((__u32)b[8] << 8) | b[9];
	sum += ((__u32)b[10] << 8) | b[11];
	sum += ((__u32)b[12] << 8) | b[13];
	sum += ((__u32)b[14] << 8) | b[15];
	sum += ((__u32)b[16] << 8) | b[17];
	sum += ((__u32)b[18] << 8) | b[19];
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	ip->check = bpf_htons((__u16)~sum);
}

SEC("xdp1")
int xdp_prog1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct udphdr *udp;
	long *value;
	__u32 proto;

	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_DROP;

	asm volatile("" ::: "memory");

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_DROP;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_DROP;

	udp = (void *)(ip + 1);
	if ((void *)(udp + 1) > data_end)
		return XDP_DROP;

	proto = IPPROTO_UDP;
	value = bpf_map_lookup_elem(&rxcnt, &proto);
	if (value)
		*value += 1;

	swap_mac(data);
	ip->daddr = bpf_htonl(MARK_DST);
	ipv4_csum(ip);
	udp->check = 0;
	return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
