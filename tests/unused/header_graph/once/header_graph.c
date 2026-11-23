#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#if 0
#include "left.h"
#endif
#include "left.h" /* program-local header */
#include "right.h"

SEC("xdp")
int header_graph(struct xdp_md *ctx)
{
    (void)ctx;
    return LEFT_PART + RIGHT_PART;
}

char LICENSE[] SEC("license") = "GPL";
