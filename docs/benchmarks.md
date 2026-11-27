# Benchmark programs

The default build produces raw BPF and portable images for these twelve programs. XPOST binds deployment images to the firmware slot.

| Programs | Behavior and source |
| --- | --- |
| `noop`, `prime`, `log2`, `copy`, `fletcher32`, `bsort`, `strcmp` | Fixed-buffer EXB2 from `exec/` in the November 12 delivery `xpost-bench.zip` (SHA-256 `48439942b21e340b974c778a40027cfb9a0cfd222a740a930cf06d7d79215785`). `log2` uses the original `log2_int` kernel. |
| `just_tx` | The supplied Just TX specialist candidate. Match IPv4 UDP port 8080 and the JTX1 header, increment ARRAY `rxcnt[17]` modulo 2³², swap MAC addresses and return `XDP_TX`. An unbound counter aborts a matching packet. Other packets pass. |
| `just_drop` | The supplied minimal DROP design. Return `XDP_DROP` without packet parsing or map access. |
| `case_mark`, `case_swap` | The supplied CAS2 design. Match JTX1 with a 40-byte UDP payload and a zero version. Write a big-endian version of 1 or 2 at payload offset 32 and `CAS2` at offset 36. Preserve the IPv4 header and the request ID, clear the UDP checksum, swap MAC addresses and return `XDP_TX`. |
| `firewall` | The original-upload classifier further specified by the firewall design. Look up the IPv4 source address in the `blacklist` HASH map. A hit increments the 32-bit value and drops, and a miss passes. The map holds up to 256 entries with 32-bit keys and values. |

The November 12 networking samples used XBT1 and a different measurement setup. The later specialist JTX1, minimal DROP and CAS2 designs govern the corresponding programs here. The firewall keeps the original HASH classifier. The earlier `just_tx`, `just_drop`, `case_mark`, `case_swap`, `bsort` and `fletcher32` sources are available at `80cb5b16`. [Earlier program sources](https://github.com/nan-mu/libbpf-mcu/tree/80cb5b16b4dc7a70209b18fa08a913b0bc94f994/tests/xdp)

`helper_loop` measures repeated `counters` lookups, `merge_try` exercises branch merging, and `xdp_drop` exercises a separate `blocklist`-based drop. Their prior sources are retained in `tests/diagnostics/` for explicit builds. `bitswap`, `buf`, `div2`, `fib`, `incr`, `square` and `memcpy` are historical fixtures in `tests/unused/`. That directory retains the bounded 1–12 byte `memcpy` for legacy regression checks. It uses the old 32-byte request shape. The new `copy` has its own EXB2 ABI and copies up to 4096 bytes.

## EXB2 compute ABI

Allocate one mutable 8258-byte buffer with a 64-byte little-endian header. Initialize the input after the header, followed by writable scratch for `copy` or `bsort`, then pad to capacity. Hold the request stable for a single call. The XDP entry receives an `xdp_md` whose `data` and `data_end` delimit exactly that buffer. The independent XPOST HAL reference accepts the same raw buffer and byte length. Each program runs all `rounds` inside the call. The XDP entry returns `XDP_PASS` on success and `XDP_ABORTED` on error. Read the result in place after return. No map is involved.

| Offsets | Fields |
| --- | --- |
| 0, 4, 6 | `EXB2`, u16 version 2, u16 header size 64 |
| 8, 12, 16 | u32 task, scale `n`, rounds 1–65536 |
| 20, 24, 28, 32 | u32 variant, seed, input bytes, scratch bytes |
| 36, 40, 44, 48, 52 | u32 status (request sets `0xffffffff`), completed rounds, last result low and high words, digest over all rounds |
| 56, 60 | Reserved u32 fields, both zero |

| Task | Scale and input |
| --- | --- |
| 0 `noop` | `n=0`, no input |
| 1 `prime` | `n≤8192`, no input, count primes through `n` and report the last one |
| 2 `log2` | Up to 1024 little-endian words, either u32 (variant 0) or u64 (variant 1) |
| 3 `copy` | Up to 4096 input bytes and equally large scratch |
| 4 `fletcher32` | Up to 4096 input bytes, interpreted as little-endian u16 words with an odd tail padded by zero |
| 5 `bsort` | Up to 128 little-endian u32 words and equally large scratch for the sorted output |
| 6 `strcmp` | Two strings of `n≤4096` bytes, each followed by a NUL |

All other variants are zero. A known request is `copy`, `n=4`, `rounds=3`, `variant=0`, `seed=1`, input and scratch lengths of 4, input `44 20 82 3c`, scratch initially `a5 a5 a5 a5`, and remaining padding set to `cc`. After `XDP_PASS`, offsets 36–55 contain `status=0`, `completed=3`, `result_lo=4`, `result_hi=0`, `digest=0x91efe859`. Scratch at offsets 68–71 contains `44 20 82 3c`. The input and padding stay unchanged.

XPOST’s previous runner exchanges 32-byte values at `workload[0]` and `workload[1]`. A separate design uses 88-byte `workload_v2` values. Both need a new caller for this ABI. At cold start, build or select a container for each engine from the pinned producer artifacts and matching linked firmware, install that image in its assigned slot, and verify the known request before recording measurements. The default 7z archives supply the original eBPF objects. Device installation, runtime checks and measurement remain with XPOST. [XPOST integration PR](https://github.com/nan-mu/xpost/pull/23)
