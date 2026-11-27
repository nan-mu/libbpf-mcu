/* EXB2 task 2. The mutable request buffer is described in docs/benchmarks.md. */
#include "vmlinux.h"

#define EB_TASK_ID 2

/* EXB2, fixed-capacity little-endian protocol, independent of n and rounds. */
typedef unsigned char eb_u8;
typedef unsigned short eb_u16;
typedef unsigned int eb_u32;
typedef __u64 eb_u64;
_Static_assert(sizeof(eb_u8) == 1 && sizeof(eb_u16) == 2 &&
               sizeof(eb_u32) == 4 && sizeof(eb_u64) == 8, "integer widths");

#define EB_MAGIC 0x32425845u /* bytes: E X B 2 */
#define EB_VERSION 2u
#define EB_HEADER_BYTES 64u
#define EB_NOT_RUN 0xffffffffu
#define EB_CONTEXT_BYTES 8258u
_Static_assert(EB_CONTEXT_BYTES >= EB_HEADER_BYTES &&
               EB_CONTEXT_BYTES <= 0xffffffffu, "context capacity");

enum eb_task {
    EB_NOOP = 0, EB_PRIME = 1, EB_LOG2 = 2, EB_COPY = 3,
    EB_FLETCHER32 = 4, EB_BSORT = 5, EB_STRCMP = 6
};
enum eb_status {
    EB_OK = 0, EB_BAD_MAGIC = 1, EB_BAD_VERSION = 2,
    EB_BAD_TASK = 3, EB_BAD_RANGE = 4, EB_BAD_LAYOUT = 5,
    EB_BAD_VARIANT = 6, EB_SHORT_BUFFER = 7
};
enum eb_offset {
    EB_O_MAGIC = 0, EB_O_VERSION = 4, EB_O_HEADER = 6,
    EB_O_TASK = 8, EB_O_N = 12, EB_O_ROUNDS = 16,
    EB_O_VARIANT = 20, EB_O_SEED = 24, EB_O_INPUT_BYTES = 28,
    EB_O_SCRATCH_BYTES = 32, EB_O_STATUS = 36, EB_O_COMPLETED = 40,
    EB_O_RESULT_LO = 44, EB_O_RESULT_HI = 48, EB_O_DIGEST = 52,
    EB_O_RESERVED0 = 56, EB_O_RESERVED1 = 60
};

#define EB_MAX_ROUNDS 65536u
#define EB_MAX_BYTES 4096u
#define EB_MAX_WORDS 1024u
#define EB_MAX_SORT 128u
#define EB_MAX_PRIME 8192u

#define EB_INLINE static __inline__ __attribute__((always_inline))
#define EB_LOOP _Pragma("clang loop unroll(disable)")

/* Clang can turn bounded scalar indexes into loop-carried packet pointers.
 * Keep the scalar bound and the pointer comparison visible to PREVAIL.
 * No validated offset in this protocol reaches the mask boundary. */
_Static_assert(EB_CONTEXT_BYTES <= 0x4000u, "packet offsets fit the scalar mask");
EB_INLINE eb_u32 eb_offset(eb_u32 offset)
{
    __asm__ __volatile__("" : "+r"(offset));
    return offset & 0x3fffu;
}
#define EB_CHECK(ptr, width) do { \
    __asm__ __volatile__("" : "+r"(ptr)); \
    if ((ptr) + (width) > end) return EB_SHORT_BUFFER; \
} while (0)

EB_INLINE eb_u16 eb_load16(const eb_u8 *p)
{
    return (eb_u16)((eb_u16)p[0] | ((eb_u16)p[1] << 8));
}
EB_INLINE eb_u32 eb_load32(const eb_u8 *p)
{
    return (eb_u32)p[0] | ((eb_u32)p[1] << 8) |
           ((eb_u32)p[2] << 16) | ((eb_u32)p[3] << 24);
}
EB_INLINE eb_u32 eb_load32_volatile(const volatile eb_u8 *p)
{
    return (eb_u32)p[0] | ((eb_u32)p[1] << 8) |
           ((eb_u32)p[2] << 16) | ((eb_u32)p[3] << 24);
}
EB_INLINE void eb_store32(eb_u8 *p, eb_u32 x)
{
    p[0] = (eb_u8)x; p[1] = (eb_u8)(x >> 8);
    p[2] = (eb_u8)(x >> 16); p[3] = (eb_u8)(x >> 24);
}

/* Both results describe the LAST complete round. digest covers ALL rounds. */
struct eb_result { eb_u32 lo, hi; };

#if EB_MAX_PRIME > 0xfffffffeu || EB_MAX_WORDS > 0x1fffffffu || \
    EB_MAX_SORT > 0x3fffffffu || EB_MAX_BYTES > 0x7ffffffeu
#error "Configured limits exceed protocol arithmetic bounds"
#endif

/* Integer floor(log2), with log2(0)=0 by protocol definition. */
EB_INLINE eb_u32 eb_log2_32(eb_u32 v)
{
    eb_u32 r = 0;
    if (v >= 0x10000u) { v >>= 16; r += 16; }
    if (v >= 0x100u) { v >>= 8; r += 8; }
    if (v >= 0x10u) { v >>= 4; r += 4; }
    if (v >= 4u) { v >>= 2; r += 2; }
    if (v >= 2u) ++r;
    return r;
}
EB_INLINE eb_u32 eb_kernel(const eb_u8 *in, eb_u8 *scratch, eb_u32 n,
                         eb_u32 variant, eb_u32 stride, struct eb_result *out,
                         const eb_u8 *end)
{
    eb_u32 sum = 0, hash = 0;
    (void)scratch; (void)stride;
    EB_LOOP
    for (eb_u32 i = 0; i < EB_MAX_WORDS && i < n; ++i) {
        const eb_u8 *word = in + eb_offset(i * (variant ? 8u : 4u));
        EB_CHECK(word, 4);
        eb_u32 lo = eb_load32(word);
        eb_u32 r;
        if (variant) {
            const eb_u8 *high = word + 4;
            EB_CHECK(high, 4);
            eb_u32 hi = eb_load32(high);
            r = hi ? 32u + eb_log2_32(hi) : eb_log2_32(lo);
        } else {
            r = eb_log2_32(lo);
        }
        sum += r;
        hash = (hash << 5) | (hash >> 27);
        hash ^= r + i;
    }
    out->lo = sum; out->hi = hash;
    return EB_OK;
}

EB_INLINE eb_u32 eb_finish(eb_u8 *mem, eb_u32 status, eb_u32 completed,
                           struct eb_result result, eb_u32 digest)
{
    eb_store32(mem + EB_O_COMPLETED, completed);
    eb_store32(mem + EB_O_RESULT_LO, result.lo);
    eb_store32(mem + EB_O_RESULT_HI, result.hi);
    eb_store32(mem + EB_O_DIGEST, digest);
    eb_store32(mem + EB_O_STATUS, status);
    return status;
}

EB_INLINE eb_u32 eb_execute(eb_u8 *mem, eb_u32 byte_length, const eb_u8 *end)
{
    struct eb_result result = {0, 0};
    eb_u32 n, rounds, variant, input_bytes, scratch_bytes;
    eb_u32 required_input = 0, required_scratch = 0, stride = 0;
    if (byte_length != EB_CONTEXT_BYTES) return EB_SHORT_BUFFER;
    /* Header-sized invalid requests get a defined, empty response. */
    eb_finish(mem, EB_NOT_RUN, 0, result, 0);
    if (eb_load32(mem + EB_O_MAGIC) != EB_MAGIC)
        return eb_finish(mem, EB_BAD_MAGIC, 0, result, 0);
    if (eb_load16(mem + EB_O_VERSION) != EB_VERSION ||
        eb_load16(mem + EB_O_HEADER) != EB_HEADER_BYTES)
        return eb_finish(mem, EB_BAD_VERSION, 0, result, 0);
    if (eb_load32(mem + EB_O_TASK) != EB_TASK_ID)
        return eb_finish(mem, EB_BAD_TASK, 0, result, 0);
    if (eb_load32(mem + EB_O_RESERVED0) || eb_load32(mem + EB_O_RESERVED1))
        return eb_finish(mem, EB_BAD_LAYOUT, 0, result, 0);
    n = eb_load32(mem + EB_O_N);
    rounds = eb_load32(mem + EB_O_ROUNDS);
    variant = eb_load32(mem + EB_O_VARIANT);
    input_bytes = eb_load32(mem + EB_O_INPUT_BYTES);
    scratch_bytes = eb_load32(mem + EB_O_SCRATCH_BYTES);
    if (!rounds || rounds > EB_MAX_ROUNDS)
        return eb_finish(mem, EB_BAD_RANGE, 0, result, 0);

    if (n > EB_MAX_WORDS) return eb_finish(mem, EB_BAD_RANGE, 0, result, 0);
    if (variant > 1) return eb_finish(mem, EB_BAD_VARIANT, 0, result, 0);
    required_input = n * (variant ? 8u : 4u);
    if (input_bytes != required_input || scratch_bytes != required_scratch)
        return eb_finish(mem, EB_BAD_LAYOUT, 0, result, 0);
    eb_u32 remaining = byte_length - EB_HEADER_BYTES;
    if (required_input > remaining)
        return eb_finish(mem, EB_SHORT_BUFFER, 0, result, 0);
    if (required_scratch > remaining - required_input)
        return eb_finish(mem, EB_SHORT_BUFFER, 0, result, 0);
    /* Only form pointers after proving their offsets fit the supplied object. */
    eb_u8 *in = mem + EB_HEADER_BYTES;
    eb_u8 *scratch = in + eb_offset(required_input);
    eb_u32 digest = eb_load32(mem + EB_O_SEED) ^ 0x811c9dc5u;
    EB_LOOP
    for (eb_u32 r = 0; r < rounds; ++r) {
        /* A volatile runtime scale prevents hoisting a pure kernel out of this
         * loop. The caller MUST NOT mutate the request during execution.
         * Bounding by the validated scale also bounds every kernel's storage.
         */
        __asm__ __volatile__("" ::: "memory");
        eb_u32 round_n = eb_load32_volatile(mem + EB_O_N);
        if (round_n > n)
            return eb_finish(mem, EB_BAD_RANGE, r, result, digest);
        eb_u32 status = eb_kernel(in, scratch, round_n, variant, stride, &result, end);
        if (status != EB_OK)
            return eb_finish(mem, status, r, result, digest);
        digest = (digest << 5) | (digest >> 27);
        digest ^= result.lo;
        digest += result.hi ^ r ^ 0x9e3779b9u;
        /* Make each round's stores visible at the compiler boundary. This is
         * not a CPU fence, cache flush, or per-byte volatile instrumentation.
         */
        __asm__ __volatile__("" : "+r"(digest) : : "memory");
    }
    return eb_finish(mem, EB_OK, rounds, result, digest);
}

/* First two fields match the Linux xdp_md ABI. Existing firmware integrations
 * may define EB_EXTERNAL_XDP_CTX and pre-include their own vmlinux.h.
 */
__attribute__((section("xdp"), used))
int exec_entry(struct xdp_md *ctx)
{
    eb_u8 *data = (eb_u8 *)(unsigned long)ctx->data;
    eb_u8 *end = (eb_u8 *)(unsigned long)ctx->data_end;
    /* Explicit packet-pointer range check, followed by the fixed-size rule. */
    if (data + EB_CONTEXT_BYTES > end) return 0;
    if ((eb_u64)(end - data) != EB_CONTEXT_BYTES) return 0;
    return eb_execute(data, EB_CONTEXT_BYTES, end) == EB_OK ? 2 /* PASS */ : 0 /* ABORTED */;
}
char eb_license[] __attribute__((section("license"), used)) = "GPL";
