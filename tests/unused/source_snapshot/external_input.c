#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "action.h"

SEC("xdp")
int external_input(struct xdp_md *ctx)
{
    (void)ctx;
    return SNAPSHOT_ACTION;
}

char LICENSE[] SEC("license") = "GPL";
