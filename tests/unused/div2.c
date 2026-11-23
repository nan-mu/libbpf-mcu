#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

static __always_inline __u32 load_u32(const __u8 *p)
{
	return (__u32)p[0] | ((__u32)p[1] << 8) | ((__u32)p[2] << 16) |
	       ((__u32)p[3] << 24);
}

SEC("xdp")
int div2(struct xdp_md *ctx)
{
	__u8 *data = (__u8 *)(long)ctx->data;
	__u8 *end = (__u8 *)(long)ctx->data_end;
	__u32 a, b;

	if (data + 8 > end)
		return 0;
	a = load_u32(data);
	b = load_u32(data + 4);
	if (b == 0)
		return 0;
	return a / b;
}

char LICENSE[] SEC("license") = "GPL";
