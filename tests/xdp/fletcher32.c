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

static __always_inline void store_u32(__u8 *p, __u32 v)
{
	p[0] = (__u8)v;
	p[1] = (__u8)(v >> 8);
	p[2] = (__u8)(v >> 16);
	p[3] = (__u8)(v >> 24);
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

/* Wikipedia / RFC 3720 §12.1 Fletcher-32.
 * Exec payload is 24 bytes, so param + 4 <= 24 (param <= 20) is a single
 * 360-word chunk. Offsets are unrolled so PREVAIL sees constants. */
static __always_inline __u32 f32(const __u8 *data, __u32 len)
{
	__u32 sum1 = 0xffffu, sum2 = 0xffffu;
	int w, k;

#pragma unroll
	for (w = 0; w < 10; w++) {
		__u16 word;

		if ((__u32)(w * 2 + 1) >= len)
			continue;
		word = (__u16)data[w * 2] | ((__u16)data[w * 2 + 1] << 8);
		sum1 += word;
		sum2 += sum1;
	}
	sum1 = (sum1 & 0xffffu) + (sum1 >> 16);
	sum2 = (sum2 & 0xffffu) + (sum2 >> 16);
	if (len & 1) {
#pragma unroll
		for (k = 0; k < 20; k += 2) {
			/* Stop both compilers turning this unroll into different decision trees. */
			asm volatile("" ::: "memory");
			if ((__u32)k + 1 != len)
				continue;
			sum1 += data[k];
			sum2 += sum1;
			sum1 = (sum1 & 0xffffu) + (sum1 >> 16);
			sum2 = (sum2 & 0xffffu) + (sum2 >> 16);
		}
	}
	sum1 = (sum1 & 0xffffu) + (sum1 >> 16);
	sum2 = (sum2 & 0xffffu) + (sum2 >> 16);
	return (sum2 << 16) | sum1;
}

SEC("xdp")
int fletcher32(struct xdp_md *ctx)
{
	__u8 *payload;
	__u8 *end = (__u8 *)(long)ctx->data_end;
	__u32 avail, param, sum;
	int k;

	if (ctx_view(ctx, &payload, &avail, &param))
		return XDP_ABORTED;
	if (payload + 24 > end || avail < 24 || param == 0 || param > 20)
		return XDP_ABORTED;
	sum = f32(payload, param);
#pragma unroll
	for (k = 1; k <= 20; k++) {
		asm volatile("" ::: "memory");
		if (param == (__u32)k)
			store_u32(payload + k, sum);
	}
	bpf_printk("OK finish");
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
