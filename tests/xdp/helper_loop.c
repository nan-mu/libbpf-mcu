// Helper-in-loop XDP: bounded map lookups inside an arithmetic loop.
// Classifier suite uses this for LimitExceeded under a tight budget while
// still observing helper predicates on the frontier (unlike fib, where the
// helper call sits after the loop body).

#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u32);
} counters SEC(".maps");

SEC("xdp")
int helper_loop(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 *hdr = data;
	__u32 n, i, key;

	if ((void *)(hdr + 1) > data_end)
		return XDP_ABORTED;
	n = *hdr;
	if (n > 8)
		n = 8;
	for (i = 0; i < n; i++) {
		__u32 *cnt;

		key = i;
		cnt = bpf_map_lookup_elem(&counters, &key);
		if (cnt)
			*cnt = *cnt + 1;
	}
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
