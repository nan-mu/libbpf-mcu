#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#define ETH_P_IP 0x0800
#define ETH_ALEN 6
#define IPPROTO_UDP 17
#define FW_LISTEN_PORT 8080
#define FW_CTRL_PORT 8081

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} vip_ip SEC(".maps");

SEC("xdp")
int vip_l2_redirect(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct udphdr *udph;
	__u32 key = 0;
	__u32 *vip;
	__u32 saddr_h;
	__u32 daddr_h;
	__u8 tmp;
	int i;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	saddr_h = bpf_ntohl(iph->saddr);
	daddr_h = bpf_ntohl(iph->daddr);

	/* Control plane: always PASS UDP :8081 to userspace (never VIP TX). */
	if (iph->protocol == IPPROTO_UDP) {
		udph = (void *)iph + sizeof(*iph);
		if ((void *)(udph + 1) <= data_end &&
		    udph->dest == bpf_htons(FW_CTRL_PORT)) {
			bpf_printk("ctrl %pI4->%pI4\n", saddr_h, daddr_h);
			return XDP_PASS;
		}
	}

	vip = bpf_map_lookup_elem(&vip_ip, &key);
	if (!vip || *vip == 0 || iph->daddr != *vip) {
		if (iph->protocol == IPPROTO_UDP) {
			udph = (void *)iph + sizeof(*iph);
			if ((void *)(udph + 1) <= data_end &&
			    udph->dest == bpf_htons(FW_LISTEN_PORT)) {
				bpf_printk("pass %pI4->%pI4\n", saddr_h, daddr_h);
			}
		}
		return XDP_PASS;
	}

	bpf_printk("vip TX %pI4->%pI4\n", saddr_h, daddr_h);

#pragma unroll
	for (i = 0; i < ETH_ALEN; i++) {
		tmp = eth->h_dest[i];
		eth->h_dest[i] = eth->h_source[i];
		eth->h_source[i] = tmp;
	}

	return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
