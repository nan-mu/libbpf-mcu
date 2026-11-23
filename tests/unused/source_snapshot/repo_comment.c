#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "action.h" /* program-local header */

SEC("xdp")
int repo_comment(struct xdp_md *ctx)
{
    (void)ctx;
    return SNAPSHOT_ACTION;
}

char LICENSE[] SEC("license") = "GPL";
