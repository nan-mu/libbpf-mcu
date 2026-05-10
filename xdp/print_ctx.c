#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

SEC("xdp")
int print_ctx(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
    __u64 bytes = data_end - data;
    bpf_printk("XDP context len: %d\n", bytes);
    return XDP_PASS;
}
