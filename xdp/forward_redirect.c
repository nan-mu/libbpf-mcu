#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} tx_port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} redirect_config SEC(".maps");

SEC("xdp")
int forward_redirect(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 cfg_key = 0;
    __u32 *tx_port_index;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    tx_port_index = bpf_map_lookup_elem(&redirect_config, &cfg_key);
    if (!tx_port_index)
        return XDP_PASS;

    return bpf_redirect_map(&tx_port_map, *tx_port_index, XDP_PASS);
}

char LICENSE[] SEC("license") = "GPL";
