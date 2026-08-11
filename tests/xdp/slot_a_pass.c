/* Slot A policy: pass everything (HOT_A hot-replace payload for fwtest). */
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

SEC("xdp")
int xdp_slot_a_pass(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
