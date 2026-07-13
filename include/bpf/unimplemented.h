#pragma once
// The interfaces declared in this file are to allow compilation when libbpf's bpf_helpers.h interfaces are not used; if they are actually used, compilation must fail.
// void foo(void);

// #ifdef REQUIRE_IMPLEMENTATION
// #error "foo() requires implementation"
// #endif

// #include "../vmlinux.h"