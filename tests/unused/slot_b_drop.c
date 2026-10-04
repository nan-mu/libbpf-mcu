/* Slot B policy: drop everything (hot-replace target). */
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

SEC("xdp")
int xdp_slot_b_drop(struct xdp_md *ctx)
{
	return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
