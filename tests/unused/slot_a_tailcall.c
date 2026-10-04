/* Slot A entry: try tail_call(0) into HOT_B; fall back to XDP_PASS. */
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} jmp_table SEC(".maps");

SEC("xdp")
int xdp_slot_a_tailcall(struct xdp_md *ctx)
{
	bpf_tail_call(ctx, &jmp_table, 0);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
