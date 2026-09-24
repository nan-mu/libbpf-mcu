/* MCU ilp32 only. BPF `--target=bpf` already has 64-bit `long`; do not include
 * this header from include-bpf/.
 *
 * Included at the end of include/vmlinux.h, after
 * `typedef long long unsigned int __u64`, so that typedef is not rewritten.
 * Replacement tokens are not re-scanned, so `long` becomes `long long`. */
#ifndef __BPF_LONG_H__
#define __BPF_LONG_H__

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wkeyword-macro"
#define long long long
#pragma clang diagnostic pop

#endif /* __BPF_LONG_H__ */
