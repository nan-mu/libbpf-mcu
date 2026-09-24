/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__

/*
 * MCU freestanding program-facing helpers (map DSL, SEC, bpf_printk).
 * Helper call packaging lives in bpf_helper_defs.h.
 * BPF-target / CO-RE / BTF macros belong in include-bpf/, not here.
 */
#include "bpf_helper_defs.h"

#ifndef ___bpf_concat
#define ___bpf_concat(a, b) a ## b
#endif
#ifndef ___bpf_apply
#define ___bpf_apply(fn, n) ___bpf_concat(fn, n)
#endif
#ifndef ___bpf_nth
#define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
#endif
#ifndef ___bpf_narg
#define ___bpf_narg(...) \
	___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#endif

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]
#define __ulong(name, val) enum { ___bpf_concat(__unique_value, __COUNTER__) = val } name

#define SEC(name) __attribute__((section(name), used))

#undef __always_inline
#define __always_inline inline __attribute__((always_inline))

#ifndef NULL
#define NULL ((void *)0)
#endif

/* MCU vmlinux.h comments out some types/enums used by helpers; provide fallbacks. */
#ifndef __s32
typedef int __s32;
#endif
#ifndef __s64
#pragma push_macro("long")
#undef long
typedef long long int __s64;
#pragma pop_macro("long")
#endif

/* Helper results are the low 32 bits. Sign-extend into BPF `long`. */
#define __bpf_long(v) ((long)(__s32)(v))

#ifndef BPF_ANY
#define BPF_ANY 0
#endif
#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#endif
#ifndef BPF_EXIST
#define BPF_EXIST 2
#endif

#ifndef BPF_RB_AVAIL_DATA
#define BPF_RB_AVAIL_DATA 0
#endif
#ifndef BPF_RB_RING_SIZE
#define BPF_RB_RING_SIZE 1
#endif
#ifndef BPF_RB_CONS_POS
#define BPF_RB_CONS_POS 2
#endif
#ifndef BPF_RB_PROD_POS
#define BPF_RB_PROD_POS 3
#endif

struct bpf_map;

#ifndef __BPF_DYNPTR_DEFINED
#define __BPF_DYNPTR_DEFINED
struct bpf_dynptr {
	__u64 __opaque[2];
};
#endif

#define bpf_map_lookup_elem(map, key) \
	((void *)___bpf_map_lookup_elem_call(map, key))

#define bpf_map_update_elem(map, key, value, flags) \
	__bpf_long(___bpf_map_update_elem_call(map, key, value, flags))

#define bpf_map_delete_elem(map, key) \
	__bpf_long(___bpf_map_delete_elem_call(map, key))

#define bpf_ktime_get_ns() \
	((__u64)___bpf_ktime_get_ns_call())

#define bpf_xpost_wdt_feed(handle) \
	((void)___bpf_xpost_wdt_feed_call(handle))

#define bpf_xpost_evt_wake() \
	((void)___bpf_xpost_evt_wake_call())

#define bpf_tail_call(ctx, map, index) \
	__bpf_long(___bpf_tail_call_call(ctx, map, index))

#define bpf_redirect(ifindex, flags) \
	__bpf_long(___bpf_redirect_call(ifindex, flags))

#define bpf_csum_diff(from, from_size, to, to_size, seed) \
	((__s64)___bpf_csum_diff_call(from, from_size, to, to_size, seed))

#define bpf_xdp_adjust_head(xdp_md, delta) \
	__bpf_long(___bpf_xdp_adjust_head_call(xdp_md, delta))

#define bpf_redirect_map(map, key, flags) \
	__bpf_long(___bpf_redirect_map_call(map, key, flags))

#define bpf_xdp_adjust_tail(xdp_md, delta) \
	__bpf_long(___bpf_xdp_adjust_tail_call(xdp_md, delta))

#define bpf_ringbuf_output(ringbuf, data, size, flags) \
	__bpf_long(___bpf_ringbuf_output_call(ringbuf, data, size, flags))

#define bpf_ringbuf_reserve(ringbuf, size, flags) \
	((void *)___bpf_ringbuf_reserve_call(ringbuf, size, flags))

#define bpf_ringbuf_submit(data, flags) \
	((void)___bpf_ringbuf_submit_call(data, flags))

#define bpf_ringbuf_discard(data, flags) \
	((void)___bpf_ringbuf_discard_call(data, flags))

#define bpf_ringbuf_query(ringbuf, flags) \
	((__u64)___bpf_ringbuf_query_call(ringbuf, flags))

#define bpf_for_each_map_elem(map, callback_fn, callback_ctx, flags) \
	__bpf_long(___bpf_for_each_map_elem_call(map, callback_fn, callback_ctx, flags))

#define bpf_xdp_load_bytes(xdp_md, offset, buf, len) \
	__bpf_long(___bpf_xdp_load_bytes_call(xdp_md, offset, buf, len))

#define bpf_xdp_store_bytes(xdp_md, offset, buf, len) \
	__bpf_long(___bpf_xdp_store_bytes_call(xdp_md, offset, buf, len))

#define bpf_dynptr_from_mem(data, size, flags, ptr) \
	__bpf_long(___bpf_dynptr_from_mem_call(data, size, flags, ptr))

#define bpf_ringbuf_reserve_dynptr(ringbuf, size, flags, ptr) \
	__bpf_long(___bpf_ringbuf_reserve_dynptr_call(ringbuf, size, flags, ptr))

#define bpf_ringbuf_submit_dynptr(ptr, flags) \
	((void)___bpf_ringbuf_submit_dynptr_call(ptr, flags))

#define bpf_ringbuf_discard_dynptr(ptr, flags) \
	((void)___bpf_ringbuf_discard_dynptr_call(ptr, flags))

#define bpf_dynptr_read(dst, len, src, offset, flags) \
	__bpf_long(___bpf_dynptr_read_call(dst, len, src, offset, flags))

#define bpf_dynptr_write(dst, offset, src, len, flags) \
	__bpf_long(___bpf_dynptr_write_call(dst, offset, src, len, flags))

#define bpf_dynptr_data(ptr, offset, len) \
	((void *)___bpf_dynptr_data_call(ptr, offset, len))

#define ___bpf_trace_printk0(fmt, fmt_size) \
	___bpf_trace_printk_call(0, fmt, fmt_size, 0, 0, 0)
#define ___bpf_trace_printk1(fmt, fmt_size, arg1) \
	___bpf_trace_printk_call(1, fmt, fmt_size, arg1, 0, 0)
#define ___bpf_trace_printk2(fmt, fmt_size, arg1, arg2) \
	___bpf_trace_printk_call(2, fmt, fmt_size, arg1, arg2, 0)
#define ___bpf_trace_printk3(fmt, fmt_size, arg1, arg2, arg3) \
	___bpf_trace_printk_call(3, fmt, fmt_size, arg1, arg2, arg3)

#define bpf_trace_printk(fmt, fmt_size, ...) \
	___bpf_apply(___bpf_trace_printk, ___bpf_narg(__VA_ARGS__))(fmt, fmt_size, ##__VA_ARGS__)

#ifdef BPF_NO_GLOBAL_DATA
#define BPF_PRINTK_FMT_MOD
#else
#define BPF_PRINTK_FMT_MOD static const
#endif

/* ≤3 fmt args; matches ___bpf_trace_printk0..3 */
#define bpf_printk(fmt, ...)				\
({							\
	BPF_PRINTK_FMT_MOD char ____fmt[] = fmt;	\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

#endif /* __BPF_HELPERS__ */
