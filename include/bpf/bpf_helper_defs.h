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

/* Linux helper IDs (a0); args in a1..a5. u64 fields use low 32 bits on RV32. */
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_trace_printk    6
#define BPF_FUNC_redirect        23
#define BPF_FUNC_redirect_map    51

#define ___bpf_map_lookup_elem_call(map, key) \
	safe_helper_call(BPF_FUNC_map_lookup_elem, (uint32_t)(map), (uint32_t)(key), \
	                 0, 0, 0)

#define ___bpf_redirect_call(ifindex, flags) \
	safe_helper_call(BPF_FUNC_redirect, (uint32_t)(ifindex), (uint32_t)(flags), \
	                 0, 0, 0)

#define ___bpf_redirect_map_call(map, key, flags) \
	safe_helper_call(BPF_FUNC_redirect_map, (uint32_t)(map), (uint32_t)(key), \
	                 (uint32_t)(flags), 0, 0)

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
