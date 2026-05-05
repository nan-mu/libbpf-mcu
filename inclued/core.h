#pragma once

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#if defined(__APPLE__)
#define SEC(name) __attribute__((used))
#else
#define SEC(name) __attribute__((section(name), used))
#endif

#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

/* 1. 以太网相关 (Ethernet) */
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800     /* Internet Protocol packet  */
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD   /* IPv6 over bluebook        */
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806    /* Address Resolution packet */
#endif

/* 2. IP 协议号 (IP Protocols) */
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

/* 3. 常见的 TCP 标志位 (TCP Flags) */
#ifndef TCP_FLAG_FIN
#define TCP_FLAG_FIN 0x01
#endif

#ifndef TCP_FLAG_SYN
#define TCP_FLAG_SYN 0x02
#endif

#ifndef TCP_FLAG_RST
#define TCP_FLAG_RST 0x04
#endif

#ifndef TCP_FLAG_ACK
#define TCP_FLAG_ACK 0x10
#endif

/* 4. ICMP 类型 */
#ifndef ICMP_ECHO
#define ICMP_ECHO 8         /* Echo Request */
#endif

#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0    /* Echo Reply   */
#endif

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef __u16 __be16;
typedef __u32 __be32;

enum {
    XDP_ABORTED = 0,
    XDP_DROP = 1,
    XDP_PASS = 2,
    XDP_TX = 3,
    XDP_REDIRECT = 4,
};

enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_DEVMAP = 14,
};

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

#define ETH_ALEN 6
#define ETH_P_IP 0x0800

struct ethhdr {
    __u8 h_dest[ETH_ALEN];
    __u8 h_source[ETH_ALEN];
    __be16 h_proto;
};

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 ihl : 4;
    __u8 version : 4;
#else
    __u8 version : 4;
    __u8 ihl : 4;
#endif
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __be32 saddr;
    __be32 daddr;
};

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
};

static __always_inline __u16 __bpf_bswap16(__u16 value)
{
    return __builtin_bswap16(value);
}

static __always_inline __u32 __bpf_bswap32(__u32 value)
{
    return __builtin_bswap32(value);
}

static __always_inline __u16 bpf_htons(__u16 value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __bpf_bswap16(value);
#else
    return value;
#endif
}

static __always_inline __u16 bpf_ntohs(__u16 value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __bpf_bswap16(value);
#else
    return value;
#endif
}

static __always_inline __u32 bpf_htonl(__u32 value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __bpf_bswap32(value);
#else
    return value;
#endif
}

static __always_inline __u32 bpf_ntohl(__u32 value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __bpf_bswap32(value);
#else
    return value;
#endif
}

// extern void *bpf_map_lookup_elem(const void *map, const void *key);
// extern int bpf_redirect_map(const void *map, __u32 key, __u64 flags);
// extern int bpf_redirect(__u32 ifindex, __u64 flags);
// extern int bpf_l4_csum_replace(struct xdp_md *ctx, __u64 offset,
//                                __u64 from, __u64 to, __u64 flags);

                               /* 手动定义符合 RV32 架构的类型 */
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

typedef signed char        int8_t;
typedef signed short       int16_t;
typedef signed int         int32_t;

/* 既然你要做 syscall 转发，定义 void* 也很常用 */
typedef void*              c_void;
