/* Negative: dereference map lookup without NULL check — PREVAIL must FAIL (S3/S4). */
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

struct bpf_map_def SEC("maps") cnt = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1,
};

SEC("xdp")
int xdp_null_map_deref(struct xdp_md *ctx)
{
	__u32 key = 0;
	__u64 *value;

	(void)ctx;
	value = bpf_map_lookup_elem(&cnt, &key);
	/* Deliberately no `if (value)` before store. */
	*value += 1;
	return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
