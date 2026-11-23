#ifndef CASE_PROGRAM_H
#define CASE_PROGRAM_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "just_tx_core.h"

SEC("xdp")
int case_reply(struct xdp_md *ctx)
{
    jtx_u8 *data = (void *)(long)ctx->data;
    jtx_u8 *end = (void *)(long)ctx->data_end;
    /* JTX1 plus the version and marker occupy exactly 40 UDP payload bytes. */
    if (data + 82 > end || !jtx_matches(data, end) || jtx_be16(data + 38) != 48)
        return XDP_PASS;
    if (data[74] || data[75] || data[76] || data[77])
        return XDP_PASS;

    data[74] = 0;
    data[75] = 0;
    data[76] = 0;
    data[77] = CASE_VERSION;
    data[78] = 'C';
    data[79] = 'A';
    data[80] = 'S';
    data[81] = '2';
    data[40] = 0;
    data[41] = 0;
    jtx_swap_mac(data);
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
#endif
