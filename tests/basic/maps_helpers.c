#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

/*
 * basic/maps_helpers: smoke-test ARRAY / HASH / RINGBUF map R/W plus the MCU
 * helper surface (no DEVMAP). redirect_map / tail_call are gated by array
 * flag 0xdead so default traffic still returns XDP_PASS.
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} arr_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u32);
} hash_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} rb_map SEC(".maps");

struct rb_event {
	__u32 seq;
	__u32 value;
};

static long
iter_hash(struct bpf_map *map, __u32 *key, __u32 *val, void *ctx)
{
	__u32 *sum = ctx;

	(void)map;
	if (!key || !val || !sum)
		return 1;
	*sum += *val;
	bpf_printk("foreach key=%u val=%u\n", *key, *val);
	return 0;
}

SEC("xdp")
int maps_helpers(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__u32 zero = 0;
	__u32 one = 1;
	__u32 key = 7;
	__u32 val = 42;
	__u32 *p;
	__u32 sum = 0;
	__u32 gate;
	__u64 tns;
	__u64 avail;
	__s64 csum;
	long ret;
	void *sample;
	__u8 eth_buf[14];
	__be32 from_ip, to_ip;
	struct bpf_dynptr dptr;
	struct bpf_dynptr rb_dptr;
	__u8 dyn_scratch[8];
	void *dyn_data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	tns = bpf_ktime_get_ns();
	bpf_printk("ktime lo=%u\n", (__u32)tns);

	/* ---- ARRAY: update + lookup ---- */
	ret = bpf_map_update_elem(&arr_map, &zero, &val, BPF_ANY);
	bpf_printk("arr update ret=%d\n", ret);
	p = bpf_map_lookup_elem(&arr_map, &zero);
	if (p)
		bpf_printk("arr lookup val=%u\n", *p);
	else
		bpf_printk("arr lookup miss\n");

	/* ---- HASH: update + lookup + delete ---- */
	ret = bpf_map_update_elem(&hash_map, &key, &val, BPF_ANY);
	bpf_printk("hash update ret=%d\n", ret);
	p = bpf_map_lookup_elem(&hash_map, &key);
	if (p)
		bpf_printk("hash lookup val=%u\n", *p);
	else
		bpf_printk("hash lookup miss\n");

	ret = bpf_for_each_map_elem(&hash_map, iter_hash, &sum, 0);
	bpf_printk("foreach ret=%d sum=%u\n", ret, sum);

	ret = bpf_map_delete_elem(&hash_map, &key);
	bpf_printk("hash delete ret=%d\n", ret);

	/* ---- RINGBUF: output / reserve-submit / reserve-discard / query ---- */
	{
		struct rb_event ev = { .seq = 1, .value = val };

		ret = bpf_ringbuf_output(&rb_map, &ev, sizeof(ev), 0);
		bpf_printk("rb output ret=%d\n", ret);
	}

	sample = bpf_ringbuf_reserve(&rb_map, sizeof(struct rb_event), 0);
	if (sample) {
		struct rb_event *ev = sample;

		ev->seq = 2;
		ev->value = val + 1;
		bpf_ringbuf_submit(sample, 0);
		bpf_printk("rb submit ok\n");
	} else {
		bpf_printk("rb reserve fail\n");
	}

	sample = bpf_ringbuf_reserve(&rb_map, sizeof(struct rb_event), 0);
	if (sample) {
		bpf_ringbuf_discard(sample, 0);
		bpf_printk("rb discard ok\n");
	}

	avail = bpf_ringbuf_query(&rb_map, BPF_RB_AVAIL_DATA);
	bpf_printk("rb avail=%u\n", (__u32)avail);

	/* ---- dynptr from map value + ringbuf dynptr ---- */
	p = bpf_map_lookup_elem(&arr_map, &zero);
	if (p) {
		ret = bpf_dynptr_from_mem(p, sizeof(*p), 0, &dptr);
		bpf_printk("dynptr_from_mem ret=%d\n", ret);
		ret = bpf_dynptr_read(dyn_scratch, sizeof(__u32), &dptr, 0, 0);
		bpf_printk("dynptr_read ret=%d\n", ret);
		dyn_data = bpf_dynptr_data(&dptr, 0, sizeof(__u32));
		bpf_printk("dynptr_data ok=%u\n", dyn_data ? 1 : 0);
	}

	ret = bpf_ringbuf_reserve_dynptr(&rb_map, sizeof(struct rb_event), 0,
					&rb_dptr);
	bpf_printk("rb_reserve_dynptr ret=%d\n", ret);
	if (ret == 0) {
		struct rb_event ev = { .seq = 3, .value = 99 };

		ret = bpf_dynptr_write(&rb_dptr, 0, &ev, sizeof(ev), 0);
		bpf_printk("dynptr_write ret=%d\n", ret);
		bpf_ringbuf_submit_dynptr(&rb_dptr, 0);
	} else {
		bpf_ringbuf_discard_dynptr(&rb_dptr, 0);
	}

	ret = bpf_ringbuf_reserve_dynptr(&rb_map, sizeof(struct rb_event), 0,
					&rb_dptr);
	bpf_ringbuf_discard_dynptr(&rb_dptr, 0);
	bpf_printk("rb_discard_dynptr done\n");

	/* ---- packet helpers ---- */
	ret = bpf_xdp_load_bytes(ctx, 0, eth_buf, sizeof(eth_buf));
	bpf_printk("load_bytes ret=%d\n", ret);
	if (ret == 0) {
		ret = bpf_xdp_store_bytes(ctx, 0, eth_buf, sizeof(eth_buf));
		bpf_printk("store_bytes ret=%d\n", ret);
	}

	from_ip = 0x0100007f; /* 127.0.0.1 */
	to_ip = 0x0200007f;
	csum = bpf_csum_diff(&from_ip, sizeof(from_ip), &to_ip, sizeof(to_ip), 0);
	bpf_printk("csum_diff=%d\n", (__s32)csum);

	/* delta 0 keeps packet layout; still emits the helper calls */
	ret = bpf_xdp_adjust_head(ctx, 0);
	bpf_printk("adjust_head ret=%d\n", ret);
	ret = bpf_xdp_adjust_tail(ctx, 0);
	bpf_printk("adjust_tail ret=%d\n", ret);

	/*
	 * redirect / redirect_map / tail_call: emit calls only when array[1]
	 * is 0xdead (default unset → PASS). Maps remain ARRAY/HASH/RINGBUF.
	 */
	p = bpf_map_lookup_elem(&arr_map, &one);
	gate = p ? *p : 0;
	if (gate == 0xdead) {
		ret = bpf_redirect(1, 0);
		bpf_printk("redirect ret=%d\n", ret);
		ret = bpf_redirect_map(&hash_map, key, XDP_PASS);
		bpf_printk("redirect_map ret=%d\n", ret);
		bpf_tail_call(ctx, &arr_map, 0);
		bpf_printk("tail_call returned\n");
	}

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
