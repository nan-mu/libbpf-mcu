#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Minimal DROP policy. The runner owns observation and counts. */
SEC("xdp")
int just_drop(struct xdp_md *ctx)
{
    (void)ctx;
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
