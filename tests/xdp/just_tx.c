#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "just_tx_core.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} rxcnt SEC(".maps");

SEC("xdp")
int just_tx(struct xdp_md *ctx)
{
    jtx_u8 *data = (void *)(long)ctx->data;
    jtx_u8 *end = (void *)(long)ctx->data_end;
    if (!jtx_matches(data, end))
        return XDP_PASS;
    __u32 key = 17;
    __u32 *count = bpf_map_lookup_elem(&rxcnt, &key);
    if (!count)
        return XDP_ABORTED;
    *count += 1;
    jtx_swap_mac(data);
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
