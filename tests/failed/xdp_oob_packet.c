/* Negative: packet access without bounds check — PREVAIL must FAIL (S1). */
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

SEC("xdp")
int xdp_oob_packet(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	/* Deliberately no data_end check before ethertype load. */
	__u16 *proto = data + 12;
	return *proto == 0 ? XDP_DROP : XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
