#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") count_by_case = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 5,
};

struct bpf_map_def SEC("maps") seq_log = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 7,
};

SEC("xdp")
int check_bindings(struct xdp_md *ctx)
{
    (void)ctx;
    __u32 key = 0;
    __u32 *count = bpf_map_lookup_elem(&count_by_case, &key);
    __u64 *entry = bpf_map_lookup_elem(&seq_log, &key);
    return count && entry ? XDP_PASS : XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
