#pragma once
#include "../vmlinux.h"

extern uint32_t helper_dispatcher(uint32_t idx, const void *arg1, const void *arg2,
                                  const void *arg3, const void *arg4, const void *arg5);

/* safe helper_dispatcher call */
static inline __attribute__((always_inline))
uint32_t safe_helper_call(uint32_t idx, uint32_t arg1, uint32_t arg2,
                          uint32_t arg3, uint32_t arg4, uint32_t arg5)
{
	register uint32_t __a0 asm("a0") = idx;
	register uint32_t __a1 asm("a1") = arg1;
	register uint32_t __a2 asm("a2") = arg2;
	register uint32_t __a3 asm("a3") = arg3;
	register uint32_t __a4 asm("a4") = arg4;
	register uint32_t __a5 asm("a5") = arg5;

	asm volatile (
		"call helper_dispatcher"
		: "+r"(__a0), "+r"(__a1), "+r"(__a2), "+r"(__a3), "+r"(__a4), "+r"(__a5)
		:
		: "ra", "a6", "a7",
		  "t0", "t1", "t2", "t3", "t4", "t5", "t6", "memory"
	);

	return __a0;
}

/*
 * Linux helper IDs (a0); args in a1..a5.
 * On RV32/ilp32, __u64 helper fields use the low 32 bits only.
 */
#define BPF_FUNC_map_lookup_elem           1
#define BPF_FUNC_map_update_elem           2
#define BPF_FUNC_map_delete_elem           3
#define BPF_FUNC_ktime_get_ns              5
#define BPF_FUNC_trace_printk              6
#define BPF_FUNC_tail_call                 12
#define BPF_FUNC_redirect                  23
#define BPF_FUNC_csum_diff                 28
#define BPF_FUNC_xdp_adjust_head           44
#define BPF_FUNC_redirect_map              51
#define BPF_FUNC_xdp_adjust_tail           65
#define BPF_FUNC_ringbuf_output            130
#define BPF_FUNC_ringbuf_reserve           131
#define BPF_FUNC_ringbuf_submit            132
#define BPF_FUNC_ringbuf_discard           133
#define BPF_FUNC_ringbuf_query             134
#define BPF_FUNC_for_each_map_elem         164
#define BPF_FUNC_xdp_load_bytes            189
#define BPF_FUNC_xdp_store_bytes           190
#define BPF_FUNC_dynptr_from_mem           197
#define BPF_FUNC_ringbuf_reserve_dynptr    198
#define BPF_FUNC_ringbuf_submit_dynptr     199
#define BPF_FUNC_ringbuf_discard_dynptr    200
#define BPF_FUNC_dynptr_read               201
#define BPF_FUNC_dynptr_write              202
#define BPF_FUNC_dynptr_data               203

#define ___bpf_map_lookup_elem_call(map, key) \
	safe_helper_call(BPF_FUNC_map_lookup_elem, (uint32_t)(map), (uint32_t)(key), \
	                 0, 0, 0)

#define ___bpf_map_update_elem_call(map, key, value, flags) \
	safe_helper_call(BPF_FUNC_map_update_elem, (uint32_t)(map), (uint32_t)(key), \
	                 (uint32_t)(value), (uint32_t)(flags), 0)

#define ___bpf_map_delete_elem_call(map, key) \
	safe_helper_call(BPF_FUNC_map_delete_elem, (uint32_t)(map), (uint32_t)(key), \
	                 0, 0, 0)

#define ___bpf_ktime_get_ns_call() \
	safe_helper_call(BPF_FUNC_ktime_get_ns, 0, 0, 0, 0, 0)

#define ___bpf_tail_call_call(ctx, map, index) \
	safe_helper_call(BPF_FUNC_tail_call, (uint32_t)(ctx), (uint32_t)(map), \
	                 (uint32_t)(index), 0, 0)

#define ___bpf_redirect_call(ifindex, flags) \
	safe_helper_call(BPF_FUNC_redirect, (uint32_t)(ifindex), (uint32_t)(flags), \
	                 0, 0, 0)

#define ___bpf_csum_diff_call(from, from_size, to, to_size, seed) \
	safe_helper_call(BPF_FUNC_csum_diff, (uint32_t)(from), (uint32_t)(from_size), \
	                 (uint32_t)(to), (uint32_t)(to_size), (uint32_t)(seed))

#define ___bpf_xdp_adjust_head_call(xdp_md, delta) \
	safe_helper_call(BPF_FUNC_xdp_adjust_head, (uint32_t)(xdp_md), \
	                 (uint32_t)(delta), 0, 0, 0)

#define ___bpf_redirect_map_call(map, key, flags) \
	safe_helper_call(BPF_FUNC_redirect_map, (uint32_t)(map), (uint32_t)(key), \
	                 (uint32_t)(flags), 0, 0)

#define ___bpf_xdp_adjust_tail_call(xdp_md, delta) \
	safe_helper_call(BPF_FUNC_xdp_adjust_tail, (uint32_t)(xdp_md), \
	                 (uint32_t)(delta), 0, 0, 0)

#define ___bpf_ringbuf_output_call(ringbuf, data, size, flags) \
	safe_helper_call(BPF_FUNC_ringbuf_output, (uint32_t)(ringbuf), \
	                 (uint32_t)(data), (uint32_t)(size), (uint32_t)(flags), 0)

#define ___bpf_ringbuf_reserve_call(ringbuf, size, flags) \
	safe_helper_call(BPF_FUNC_ringbuf_reserve, (uint32_t)(ringbuf), \
	                 (uint32_t)(size), (uint32_t)(flags), 0, 0)

#define ___bpf_ringbuf_submit_call(data, flags) \
	safe_helper_call(BPF_FUNC_ringbuf_submit, (uint32_t)(data), \
	                 (uint32_t)(flags), 0, 0, 0)

#define ___bpf_ringbuf_discard_call(data, flags) \
	safe_helper_call(BPF_FUNC_ringbuf_discard, (uint32_t)(data), \
	                 (uint32_t)(flags), 0, 0, 0)

#define ___bpf_ringbuf_query_call(ringbuf, flags) \
	safe_helper_call(BPF_FUNC_ringbuf_query, (uint32_t)(ringbuf), \
	                 (uint32_t)(flags), 0, 0, 0)

#define ___bpf_for_each_map_elem_call(map, callback_fn, callback_ctx, flags) \
	safe_helper_call(BPF_FUNC_for_each_map_elem, (uint32_t)(map), \
	                 (uint32_t)(callback_fn), (uint32_t)(callback_ctx), \
	                 (uint32_t)(flags), 0)

#define ___bpf_xdp_load_bytes_call(xdp_md, offset, buf, len) \
	safe_helper_call(BPF_FUNC_xdp_load_bytes, (uint32_t)(xdp_md), \
	                 (uint32_t)(offset), (uint32_t)(buf), (uint32_t)(len), 0)

#define ___bpf_xdp_store_bytes_call(xdp_md, offset, buf, len) \
	safe_helper_call(BPF_FUNC_xdp_store_bytes, (uint32_t)(xdp_md), \
	                 (uint32_t)(offset), (uint32_t)(buf), (uint32_t)(len), 0)

#define ___bpf_dynptr_from_mem_call(data, size, flags, ptr) \
	safe_helper_call(BPF_FUNC_dynptr_from_mem, (uint32_t)(data), \
	                 (uint32_t)(size), (uint32_t)(flags), (uint32_t)(ptr), 0)

#define ___bpf_ringbuf_reserve_dynptr_call(ringbuf, size, flags, ptr) \
	safe_helper_call(BPF_FUNC_ringbuf_reserve_dynptr, (uint32_t)(ringbuf), \
	                 (uint32_t)(size), (uint32_t)(flags), (uint32_t)(ptr), 0)

#define ___bpf_ringbuf_submit_dynptr_call(ptr, flags) \
	safe_helper_call(BPF_FUNC_ringbuf_submit_dynptr, (uint32_t)(ptr), \
	                 (uint32_t)(flags), 0, 0, 0)

#define ___bpf_ringbuf_discard_dynptr_call(ptr, flags) \
	safe_helper_call(BPF_FUNC_ringbuf_discard_dynptr, (uint32_t)(ptr), \
	                 (uint32_t)(flags), 0, 0, 0)

#define ___bpf_dynptr_read_call(dst, len, src, offset, flags) \
	safe_helper_call(BPF_FUNC_dynptr_read, (uint32_t)(dst), (uint32_t)(len), \
	                 (uint32_t)(src), (uint32_t)(offset), (uint32_t)(flags))

#define ___bpf_dynptr_write_call(dst, offset, src, len, flags) \
	safe_helper_call(BPF_FUNC_dynptr_write, (uint32_t)(dst), (uint32_t)(offset), \
	                 (uint32_t)(src), (uint32_t)(len), (uint32_t)(flags))

#define ___bpf_dynptr_data_call(ptr, offset, len) \
	safe_helper_call(BPF_FUNC_dynptr_data, (uint32_t)(ptr), (uint32_t)(offset), \
	                 (uint32_t)(len), 0, 0)

/* bpf_trace_printk: a2 = (nargs<<24)|(fmt_size&0xffffff); firmware must reject %s */
#define BPF_PRINTK_NARGS_SHIFT 24
#define BPF_PRINTK_SIZE_MASK   0x00ffffffu
#define BPF_PRINTK_PACK(size, n) \
	((((uint32_t)(n)) << BPF_PRINTK_NARGS_SHIFT) | \
	 (((uint32_t)(size)) & BPF_PRINTK_SIZE_MASK))

#define ___bpf_trace_printk_call(nargs, fmt, fmt_size, arg1, arg2, arg3) \
	safe_helper_call(BPF_FUNC_trace_printk, (uint32_t)(fmt), \
	                 BPF_PRINTK_PACK(fmt_size, nargs), \
	                 (uint32_t)(arg1), (uint32_t)(arg2), (uint32_t)(arg3))
