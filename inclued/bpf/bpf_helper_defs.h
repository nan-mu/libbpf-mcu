#include "unimplemented.h"
#include "../vmlinux.h"

extern uint32_t helper_dispatcher(uint32_t idx, const void* arg1, const void* arg2, const void* arg3, const void* arg4, const void* arg5);

// 安全的 helper_dispatcher 调用包装
// 明确告诉编译器所有调用者保存的寄存器都会被破坏
static inline __attribute__((always_inline)) 
uint32_t safe_helper_call(uint32_t idx, uint32_t arg1, uint32_t arg2, 
                          uint32_t arg3, uint32_t arg4, uint32_t arg5) {
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
		// 明确列出所有会被破坏的调用者保存寄存器
		: "ra", "a6", "a7",
		  "t0", "t1", "t2", "t3", "t4", "t5", "t6", "memory"
	);
	
	return __a0;
}

#define ___bpf_trace_printk_call(idx, fmt, fmt_size, arg1, arg2, arg3) \
	safe_helper_call(idx, (uint32_t)(fmt), (uint32_t)(fmt_size), \
	                 (uint32_t)(arg1), (uint32_t)(arg2), (uint32_t)(arg3))

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

