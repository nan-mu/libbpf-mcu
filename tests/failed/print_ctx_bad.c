#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

SEC("xdp")
int print_ctx(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* BPF 典型错误：不检查 data+1 是否超过 data_end，直接读首字节 */
    if (data + 1 > data_end) {
        bpf_printk("data+1 out of bounds\n");
        return XDP_PASS;
    }
    __u8 b = *(__u8 *)data;

    bpf_printk("first byte: %d\n", b);
    return XDP_PASS;
}
