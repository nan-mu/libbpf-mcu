/* Rate-based blacklist: per-src pps over window → ban → XDP_DROP.
 * ctrl_wl hit → always PASS (control / benign probe host).
 * UDP :8081 → always PASS (ctrl-plane port bypass).
 *
 * MCU perf: banned path skips ktime/thresh/update; count mutates in-place
 * via lookup ptr (map_update only on first insert). Keep .text small enough
 * for one-shot SWAP under WiFi L2 MTU 1492 (UDP payload ≤1450).
 */
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define FW_CTRL_PORT 8081

#define DEFAULT_THRESH 200u
#define WINDOW_NS 1000000000ull

#define STAT_RX_OK 0
#define STAT_RX_DROP 1
#define STAT_BAN_EVENTS 2

struct rate_ent {
	__u32 count;
	__u32 pad;
	__u64 window_start_ns;
	__u8 banned;
	__u8 _r[7];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, struct rate_ent);
} rate_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u8);
} ctrl_wl SEC(".maps");

/* idx0 = thresh (0 → DEFAULT_THRESH) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} params SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} stats SEC(".maps");

static __always_inline void bump_stat(__u32 idx)
{
	__u32 *p = bpf_map_lookup_elem(&stats, &idx);

	if (p)
		(*p)++;
}

static __always_inline __u32 load_thresh(void)
{
	__u32 zero = 0;
	__u32 *p = bpf_map_lookup_elem(&params, &zero);

	if (p && *p != 0)
		return *p;
	return DEFAULT_THRESH;
}

SEC("xdp")
int ddos_rate_bl_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct udphdr *udph;
	__u32 key;
	__u8 *wl;
	struct rate_ent *st;
	struct rate_ent init;
	__u64 now;
	__u32 thresh;

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
		    udph->dest == bpf_htons(FW_CTRL_PORT)) {
			bump_stat(STAT_RX_OK);
			return XDP_PASS;
		}
	}

	key = iph->saddr;
	wl = bpf_map_lookup_elem(&ctrl_wl, &key);
	if (wl) {
		bump_stat(STAT_RX_OK);
		return XDP_PASS;
	}

	/* Fast DROP before ktime / thresh / update. */
	st = bpf_map_lookup_elem(&rate_state, &key);
	if (st && st->banned) {
		bump_stat(STAT_RX_DROP);
		return XDP_DROP;
	}

	now = bpf_ktime_get_ns();
	thresh = load_thresh();

	if (!st) {
		init.count = 1;
		init.pad = 0;
		init.window_start_ns = now;
		init.banned = 0;
		init._r[0] = 0;
		init._r[1] = 0;
		init._r[2] = 0;
		init._r[3] = 0;
		init._r[4] = 0;
		init._r[5] = 0;
		init._r[6] = 0;
		bpf_map_update_elem(&rate_state, &key, &init, BPF_ANY);
		bump_stat(STAT_RX_OK);
		return XDP_PASS;
	}

	if (now - st->window_start_ns >= WINDOW_NS) {
		st->window_start_ns = now;
		st->count = 1;
		bump_stat(STAT_RX_OK);
		return XDP_PASS;
	}

	st->count++;
	if (st->count > thresh) {
		st->banned = 1;
		bump_stat(STAT_BAN_EVENTS);
		bump_stat(STAT_RX_DROP);
		return XDP_DROP;
	}

	bump_stat(STAT_RX_OK);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
