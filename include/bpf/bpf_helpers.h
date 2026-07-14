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

#ifdef BPF_NO_GLOBAL_DATA
#define BPF_PRINTK_FMT_MOD
#else
#define BPF_PRINTK_FMT_MOD static const
#endif

/* ≤3 fmt args; matches bpf_trace_printk0..3 in bpf_helper_defs.h */
#define bpf_printk(fmt, ...)				\
({							\
	BPF_PRINTK_FMT_MOD char ____fmt[] = fmt;	\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

#endif /* __BPF_HELPERS__ */

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
