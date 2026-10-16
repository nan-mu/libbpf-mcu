#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

/* App copies map key 0 into ctx and copies ctx to key 1. Compute on ctx. */
struct exec_val {
	__u32 w0;
	__u32 w1;
	__u32 w2;
	__u32 w3;
	__u32 w4;
	__u32 w5;
	__u32 w6;
	__u32 w7;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__type(key, __u8);
	__type(value, struct exec_val);
} workload SEC(".maps");

static __always_inline __u32 load_u32(const __u8 *p)
{
	return (__u32)p[0] | ((__u32)p[1] << 8) | ((__u32)p[2] << 16) |
	       ((__u32)p[3] << 24);
}

static __always_inline int ctx_view(struct xdp_md *ctx, __u8 **payload,
				    __u32 *avail, __u32 *param)
{
	__u8 *data = (__u8 *)(long)ctx->data;
	__u8 *end = (__u8 *)(long)ctx->data_end;

	if (data + 8 > end)
		return -1;
	*param = load_u32(data + 4);
	*payload = data + 8;
	*avail = (__u32)(end - *payload);
	return 0;
}

SEC("xdp")
int memcpy_xdp(struct xdp_md *ctx)
{
	__u8 *payload;
	__u8 *end = (__u8 *)(long)ctx->data_end;
	__u32 avail, param;
	int i;

	if (ctx_view(ctx, &payload, &avail, &param))
		return XDP_ABORTED;
	/* Exec value is 32 bytes, so the payload is 24. param <= 12 matches
	 * the old param <= avail/2 bound on that value. Unroll keeps every
	 * packet offset constant for PREVAIL. */
	if (payload + 24 > end || avail < 24 || param == 0 || param > 12)
		return XDP_ABORTED;
#pragma unroll
	for (i = 0; i < 12; i++) {
		if ((__u32)i >= param)
			continue;
		payload[param + i] = payload[i];
	}
	bpf_printk("OK finish");
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
