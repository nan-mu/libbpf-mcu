#include "exec_common.h"

/* Reverse the bits of the payload word `batch` times.
 *
 * This is the fixed-work program, which makes it the clearest place to check the
 * batch protocol: the per-iteration cost does not depend on the payload, so time
 * must grow linearly with `param`. A flat line means the loop was removed or
 * never ran.
 *
 * Each iteration reads what the previous one wrote. That dependency chain is
 * what keeps the loop: the first version wrote the same constant every
 * iteration, and the AOT compiler removed the entire loop, leaving one reverse
 * and a flat measurement.
 *
 * The payload after the call depends on how many iterations ran, by design. The
 * exam's expected bytes describe one iteration, so a batched run is measured and
 * not compared; the comparison runs at batch one.
 */
SEC("xdp")
int bitswap(struct xdp_md *ctx)
{
	__u8 *payload;
	__u32 avail, param, x, i;

	if (ctx_view(ctx, &payload, &avail, &param))
		return XDP_ABORTED;
	/* RV32 OR-merges this with the check inside ctx_view. eBPF does not. */
	asm volatile("" ::: "memory");
	if (avail < EXEC_PAYLOAD_LEN)
		return XDP_ABORTED;
	/* Zero would mean the host asked for no work, which is a caller mistake and
	 * not a legitimate measurement, so refuse it instead of timing nothing. */
	if (param == 0)
		return XDP_ABORTED;

#pragma clang loop unroll(disable)
	for (i = 0; i < param; i++) {
		x = load_u32(payload);
		store_u32(payload, __builtin_bitreverse32(x));
	}
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
