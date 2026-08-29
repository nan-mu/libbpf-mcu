/* Drop bench: count UDP drops, milestones in XDP, events via dut_evt ringbuf. */
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#define IPPROTO_UDP 17
#define CTRL_PORT 8081
#define WARMUP_PKTS 10000ULL
#define CAP_PKTS 100000ULL
#define KEY_T_FIRST 0u
#define KEY_T_LAST 1u

#define XPOST_EVT_FEED 1u
#define XPOST_EVT_BENCH_DONE 2u

struct xpost_evt_feed {
	__u32 kind;
	__u32 us;
};

struct xpost_evt_bench {
	__u32 kind;
	__u32 _pad;
	__u64 count;
	__u64 t_first_us;
	__u64 t_last_us;
};

struct bpf_map_def SEC("maps") rxcnt = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") bench_ts = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(__u64),
	.max_entries = 2,
};

struct bpf_map_def SEC("maps") dut_evt = {
	.type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = 4096,
};

static int parse_ipv4(void *data, u64 nh_off, void *data_end)
{
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end)
		return 0;
	return iph->protocol;
}

static int parse_ipv6(void *data, u64 nh_off, void *data_end)
{
	__u8 *ip6h = data + nh_off;

	if (ip6h + 40 > data_end)
		return 0;
	return ip6h[6];
}

static int parse_ipv4_udp_dport(void *data, u64 nh_off, void *data_end)
{
	struct iphdr *iph = data + nh_off;
	struct udphdr *udp;
	__u32 ihl;

	if (iph + 1 > data_end)
		return -1;
	if (iph->protocol != IPPROTO_UDP)
		return -1;
	ihl = iph->ihl * 4;
	if (ihl < sizeof(*iph))
		return -1;
	udp = data + nh_off + ihl;
	if (udp + 1 > data_end)
		return -1;
	return bpf_ntohs(udp->dest);
}

static void stamp_ts(__u32 key, __u64 now_us)
{
	__u64 *slot = bpf_map_lookup_elem(&bench_ts, &key);

	if (slot)
		*slot = now_us;
}

static __u64 read_ts(__u32 key)
{
	__u64 *slot = bpf_map_lookup_elem(&bench_ts, &key);

	if (!slot)
		return 0;
	return *slot;
}

static void emit_feed(__u32 now_us)
{
	struct xpost_evt_feed rec = {
		.kind = XPOST_EVT_FEED,
		.us = now_us,
	};

	bpf_ringbuf_output(&dut_evt, &rec, sizeof(rec), 0);
}

static void emit_bench_done(__u64 count, __u64 t_first, __u64 t_last)
{
	struct xpost_evt_bench rec = {
		.kind = XPOST_EVT_BENCH_DONE,
		._pad = 0,
		.count = count,
		.t_first_us = t_first,
		.t_last_us = t_last,
	};

	bpf_ringbuf_output(&dut_evt, &rec, sizeof(rec), 0);
	bpf_xpost_evt_wake();
}

SEC("xdp1")
int xdp_prog1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	long *value;
	u16 h_proto;
	u64 nh_off;
	u32 ipproto;
	int udp_dport = -1;
	__u64 prev;
	__u64 now_us;
	__u64 count;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	h_proto = eth->h_proto;

	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return XDP_DROP;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if (h_proto == htons(ETH_P_IP)) {
		ipproto = parse_ipv4(data, nh_off, data_end);
		if (ipproto == IPPROTO_UDP)
			udp_dport = parse_ipv4_udp_dport(data, nh_off, data_end);
	} else if (h_proto == htons(ETH_P_IPV6)) {
		ipproto = parse_ipv6(data, nh_off, data_end);
	} else {
		ipproto = 0;
	}

	if (udp_dport == CTRL_PORT)
		return XDP_PASS;

	value = bpf_map_lookup_elem(&rxcnt, &ipproto);
	if (!value)
		return XDP_DROP;

	prev = *value;
	if ((__u64)prev >= CAP_PKTS)
		return XDP_DROP;

	*value = prev + 1;
	count = prev + 1;

	now_us = bpf_ktime_get_ns();
	if ((__u64)prev == WARMUP_PKTS - 1)
		stamp_ts(KEY_T_FIRST, now_us);
	if (count > WARMUP_PKTS)
		stamp_ts(KEY_T_LAST, now_us);

	emit_feed((__u32)now_us);

	if (count == CAP_PKTS)
		emit_bench_done(count, read_ts(KEY_T_FIRST), read_ts(KEY_T_LAST));

	return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
