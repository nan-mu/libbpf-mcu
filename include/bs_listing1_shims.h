/* Shims for classic XDP Listing 1 samples (htons / ETH_P_* / bpf_map_def / …).
 * Included at the end of vmlinux.h so paper sources need no local macros. */
#ifndef BS_LISTING1_SHIMS_H
#define BS_LISTING1_SHIMS_H

#ifndef u64
typedef __u64 u64;
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#ifndef htons
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) __builtin_bswap16((__u16)(x))
#else
#define htons(x) ((__u16)(x))
#endif
#endif

/* MCU vmlinux comments out vlan_hdr; provide a minimal definition. */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

#endif /* BS_LISTING1_SHIMS_H */
