/* UDP bounce that swaps the IPv4 addresses.
 *
 * A standard 20-byte IPv4 header plus a UDP header is required. The Ethernet
 * MACs are swapped so the frame returns to the sender. Swapping both IPv4
 * addresses and both UDP ports leaves the IPv4 and UDP checksums unchanged.
 * tcpdump then shows the original destination as the source.
 */
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#define ETH_P_IP 0x0800

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
	__be32 addr;
	__be16 port;

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
	addr = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = addr;
	port = udp->source;
	udp->source = udp->dest;
	udp->dest = port;
	return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
