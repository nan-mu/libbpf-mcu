;     void *data_end = (void *)(long)ctx->data_end;
       0:       w2 = *(u32 *)(r1 + 0x4)
;     void *data = (void *)(long)ctx->data;
       1:       w3 = *(u32 *)(r1 + 0x0)
       2:       r1 = 0x0
;     struct fw_key key = {};
       3:       *(u64 *)(r10 - 0x8) = r1
       4:       w0 = 0x2
;     if ((void *)(eth + 1) > data_end)
       5:       r1 = r3
       6:       r1 += 0xe
       7:       if r1 > r2 goto +0x29 <firewall_ipv4+0x188>
;     h_proto = eth->h_proto;
       8:       w4 = *(u16 *)(r3 + 0xc)
;     if (h_proto != bpf_htons(ETH_P_IP))
       9:       if w4 != 0x8 goto +0x27 <firewall_ipv4+0x188>
      10:       r3 += 0x22
;     if (h_proto != bpf_htons(ETH_P_IP))
      11:       if r3 > r2 goto +0x25 <firewall_ipv4+0x188>
;     if (iph->ihl < 5)
      12:       w3 = *(u8 *)(r1 + 0x0)
      13:       w3 &= 0xf
      14:       if w3 < 0x5 goto +0x22 <firewall_ipv4+0x188>
;     if ((void *)iph + iph->ihl * 4 > data_end)
      15:       w3 = *(u8 *)(r1 + 0x0)
      16:       r3 <<= 0x2
      17:       r3 &= 0x3c
      18:       r4 = r1
      19:       r4 += r3
      20:       if r4 > r2 goto +0x1c <firewall_ipv4+0x188>
;     if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
      21:       w3 = *(u8 *)(r1 + 0x9)
      22:       if w3 == 0x6 goto +0x2 <firewall_ipv4+0xc8>
      23:       w3 = *(u8 *)(r1 + 0x9)
      24:       if w3 != 0x11 goto +0x18 <firewall_ipv4+0x188>
;     l4hdr = (void *)iph + iph->ihl * 4;
      25:       w4 = *(u8 *)(r1 + 0x0)
      26:       r4 <<= 0x2
      27:       r4 &= 0x3c
      28:       r3 = r1
      29:       r3 += r4
;     if (l4hdr + sizeof(__u32) > data_end)
      30:       r4 = r3
      31:       r4 += 0x4
      32:       if r4 > r2 goto +0x10 <firewall_ipv4+0x188>
;     key.src_ip = iph->saddr;
      33:       w1 = *(u32 *)(r1 + 0xc)
;     key.dst_port = bpf_ntohs(dst_port);
      34:       w2 = *(u16 *)(r3 + 0x2)
;     key.src_ip = iph->saddr;
      35:       *(u32 *)(r10 - 0x8) = w1
;     key.dst_port = bpf_ntohs(dst_port);
      36:       r2 = be16 r2
      37:       *(u16 *)(r10 - 0x4) = w2
      38:       r2 = r10
      39:       r2 += -0x8
;     action = bpf_map_lookup_elem(&firewall_rules, &key);
      40:       r1 = 0x0 ll
      42:       call 0x1
      43:       r1 = r0
;     if (action && *action)
      44:       if r1 == 0x0 goto +0x3 <firewall_ipv4+0x180>
      45:       w0 = 0x1
;     if (action && *action)
      46:       w1 = *(u8 *)(r1 + 0x0)
      47:       if w1 != 0x0 goto +0x1 <firewall_ipv4+0x188>
      48:       w0 = 0x2
; }
      49:       exit