/* Negative: helper key from uninitialized stack — PREVAIL must FAIL (S2/S4). */
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

struct bpf_map_def SEC("maps") cnt = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 4,
};

SEC("xdp")
int xdp_uninit_key(struct xdp_md *ctx)
{
	__u32 key;
	__u64 *value;

	(void)ctx;
	/* `key` never written. */
	value = bpf_map_lookup_elem(&cnt, &key);
	if (value)
		*value += 1;
	return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
