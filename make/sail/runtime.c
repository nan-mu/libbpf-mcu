/* Temporary freestanding host for sail-riscv (RV32IMC).
 * Provides _start, HTIF tohost, and a minimal helper_dispatcher.
 * Not part of the MCU/firmware ABI.
 */

#include <stdint.h>

extern int xdp_prog1(void *ctx);
extern char _stack_top[];

volatile uint64_t tohost __attribute__((section(".tohost"), used));

/* Paper sample: ARRAY max_entries=256, value=long. */
static long sail_rxcnt_values[256];

enum {
	BPF_FUNC_map_lookup_elem = 1,
};

uint32_t helper_dispatcher(uint32_t idx, const void *arg1, const void *arg2,
			   const void *arg3, const void *arg4, const void *arg5)
{
	(void)arg1;
	(void)arg3;
	(void)arg4;
	(void)arg5;

	if (idx == BPF_FUNC_map_lookup_elem) {
		const uint32_t *key = (const uint32_t *)arg2;

		if (key == 0 || *key >= 256)
			return 0;
		return (uint32_t)(uintptr_t)&sail_rxcnt_values[*key];
	}
	return 0;
}

struct sail_xdp_md {
	uint32_t data;
	uint32_t data_end;
	uint32_t data_meta;
	uint32_t ingress_ifindex;
	uint32_t rx_queue_index;
	uint32_t egress_ifindex;
};

static uint8_t pkt[64];

static void fill_udp_ipv4(void)
{
	unsigned i;

	for (i = 0; i < sizeof(pkt); i++)
		pkt[i] = 0;

	/* dst / src MAC */
	pkt[0] = 0x11;
	pkt[1] = 0x22;
	pkt[2] = 0x33;
	pkt[3] = 0x44;
	pkt[4] = 0x55;
	pkt[5] = 0x66;
	pkt[6] = 0xaa;
	pkt[7] = 0xbb;
	pkt[8] = 0xcc;
	pkt[9] = 0xdd;
	pkt[10] = 0xee;
	pkt[11] = 0xff;
	/* ETH_P_IP */
	pkt[12] = 0x08;
	pkt[13] = 0x00;
	/* IPv4: version/ihl + protocol=UDP at offset 9 of IP hdr */
	pkt[14] = 0x45;
	pkt[23] = 17;
}

void sail_main(void)
{
	struct sail_xdp_md ctx;
	int rc;

	fill_udp_ipv4();
	ctx.data = (uint32_t)(uintptr_t)pkt;
	ctx.data_end = (uint32_t)(uintptr_t)(pkt + sizeof(pkt));
	ctx.data_meta = 0;
	ctx.ingress_ifindex = 0;
	ctx.rx_queue_index = 0;
	ctx.egress_ifindex = 0;

	rc = xdp_prog1(&ctx);
	/* HTIF exit: ((code << 1) | 1). XDP_TX == 3 → tohost == 7. */
	tohost = ((uint64_t)(uint32_t)rc << 1) | 1u;
	for (;;)
		;
}

__attribute__((naked, noreturn)) void _start(void)
{
	__asm__ volatile(
		"la sp, _stack_top\n"
		"call sail_main\n"
		"1: j 1b\n");
}
