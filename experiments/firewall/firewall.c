// Firewall XDP — hash-map blacklist (hit DROP + count).
//
// Classifier dual expand: no `ip->ihl * 4`, no UDP ctrl path, and a compiler
// barrier between the ethertype check and the IPv4 header bound check so RV32
// does not OR-merge those predicates (eBPF keeps them separate).

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#define ETH_P_IP 0x0800

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u32);
} blacklist SEC(".maps");

SEC("xdp")
int firewall(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	__u16 h_proto;
	__u32 *cnt;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	h_proto = eth->h_proto;
	if (h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	asm volatile("" ::: "memory");

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	cnt = bpf_map_lookup_elem(&blacklist, &ip->saddr);
	if (cnt) {
		*cnt = *cnt + 1;
		return XDP_DROP;
	}
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
