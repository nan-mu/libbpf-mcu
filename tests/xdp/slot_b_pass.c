/* Slot B policy: pass everything (alternate hot-replace target). */
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

SEC("xdp")
int xdp_slot_b_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
