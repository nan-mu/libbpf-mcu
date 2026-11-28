#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
typedef unsigned char jtx_u8;
typedef unsigned int jtx_u32;
#define JTX_PORT 8080u
#define JTX_HEADER_SIZE 32u

static __inline__ __attribute__((always_inline)) unsigned jtx_be16(const jtx_u8 *p)
{
    return ((unsigned)p[0] << 8) | p[1];
}

/* Controlled workload: Ethernet II, IPv4 IHL=5, unfragmented UDP, JTX1. */
static __inline__ __attribute__((always_inline)) int
jtx_matches(jtx_u8 *data, jtx_u8 *end)
{
    if (data + 74 > end)
        return 0;
    if (data[12] != 0x08 || data[13] != 0x00 || data[14] != 0x45)
        return 0;
    if (data[23] != 17 || (jtx_be16(data + 20) & 0x3fffu) != 0)
        return 0;
    unsigned ip_len = jtx_be16(data + 16);
    unsigned udp_len = jtx_be16(data + 38);
    if (ip_len < 60 || ip_len > 1500 || data + 14 + ip_len > end)
        return 0;
    if (udp_len != ip_len - 20 || udp_len < 40 || jtx_be16(data + 36) != JTX_PORT)
        return 0;
    const jtx_u8 *p = data + 42;
    return p[0] == 'J' && p[1] == 'T' && p[2] == 'X' && p[3] == '1'
        && p[4] == 1 && p[5] == 0 && p[6] == 0 && p[7] == JTX_HEADER_SIZE;
}

static __inline__ __attribute__((always_inline)) void jtx_swap_mac(jtx_u8 *p)
{
    jtx_u8 t;
#define JTX_SWAP(i) do { t = p[i]; p[i] = p[(i) + 6]; p[(i) + 6] = t; } while (0)
    JTX_SWAP(0); JTX_SWAP(1); JTX_SWAP(2);
    JTX_SWAP(3); JTX_SWAP(4); JTX_SWAP(5);
#undef JTX_SWAP
}

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
    data[77] = 2;
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
