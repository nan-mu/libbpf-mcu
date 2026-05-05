#pragma once
#include "../core.h"

extern uint32_t syscall_dispatcher(uint32_t idx, const void* ptr, uint32_t len);

#define bpf_helper_log(str) do { \
    register uint32_t a0_idx asm("a0") = 1;               /* Syscall ID */ \
    register const void* a1_ptr asm("a1") = (str);        /* 参数 1: 地址 */ \
    register uint32_t a2_len asm("a2") = sizeof(str) - 1; /* 参数 2: 长度 */ \
    \
    /* 使用内联汇编触发调用，告知编译器 a0, a1, a2 已被占用 */ \
    __asm__ volatile ( \
        "call syscall_dispatcher" \
        : "+r"(a0_idx) \
        : "r"(a1_ptr), "r"(a2_len) \
        : "ra", "memory" \
    ); \
} while(0)