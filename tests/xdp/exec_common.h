/* Shared header for the exec workloads.
 *
 * Every workload file used to repeat the same value layout, the same map, and
 * the same four helpers. Copies diverge: one file gains a bounds check the
 * others lack, and the comparison stops being about the workload. The shared
 * parts live here so a change reaches all eight.
 *
 * # Value layout
 *
 * The map value is 32 bytes, which is what the carrier and the HAL twin both
 * move around. Header first, then payload:
 *
 *   offset  size  field
 *   0       4     opcode   LE u32
 *   4       4     param    LE u32
 *   8       24    payload
 *
 * # Batch protocol
 *
 * One call per sample puts a fixed cost next to a computation that is often a
 * few microseconds. The batch removes it from the measurement instead of
 * estimating it: the program loops `batch` times on the same payload, and the
 * engine time divided by the batch is the per-iteration cost. The cost that
 * remains is the loop itself plus one engine entry, and the loop body is the
 * workload.
 *
 * A batch result goes to the payload, so the host reads the same 32 bytes. Two
 * things make one input reusable `batch` times:
 *
 *   - `param` is re-read from the value each iteration, so an iteration that
 *     would modify it cannot change the work of the next.
 *   - the loop re-seeds the payload from the header each iteration, when the
 *     workload is destructive. `EXEC_BATCH_RESEED` does that.
 *
 * PREVAIL decides whether the loop is acceptable. Nothing here caps the batch
 * count; the verifier's own limits are the only limits.
 */
#ifndef EXEC_COMMON_H
#define EXEC_COMMON_H

#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

/* The carrier's 32-byte value: header plus a 24-byte payload. */
#define EXEC_VALUE_LEN 32
#define EXEC_HEADER_LEN 8
#define EXEC_PAYLOAD_LEN (EXEC_VALUE_LEN - EXEC_HEADER_LEN)

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

/* Key 0 is the input, key 1 the output. The carrier also copies the value out of
 * its own buffer, so the map is not the only path, but the exam reads it. */
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

/* Read the header and locate the payload.
 *
 * `-1` means the frame is too short to hold the header. The caller turns that
 * into XDP_ABORTED, so a short frame is a refusal and not a silent pass. */
static __always_inline int ctx_view(struct xdp_md *ctx, __u8 **payload,
				    __u32 *avail, __u32 *param)
{
	__u8 *data = (__u8 *)(long)ctx->data;
	__u8 *end = (__u8 *)(long)ctx->data_end;

	if (data + EXEC_HEADER_LEN > end)
		return -1;
	*param = load_u32(data + 4);
	*payload = data + EXEC_HEADER_LEN;
	*avail = (__u32)(end - *payload);
	return 0;
}

/* Copy the 24-byte payload from `src` to `dst`.
 *
 * Unrolled so every offset is a constant, which is what PREVAIL needs to bound
 * each access. A loop over offsets would leave the verifier unable to prove the
 * last one. */
static __always_inline void copy_payload(__u8 *dst, const __u8 *src)
{
#pragma unroll
	for (int i = 0; i < EXEC_PAYLOAD_LEN; i++)
		dst[i] = src[i];
}

#endif /* EXEC_COMMON_H */
