/* Slot A policy: drop everything (HOT_A hot-replace payload for fwtest). */
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

SEC("xdp")
int xdp_slot_a_drop(struct xdp_md *ctx)
{
	return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
