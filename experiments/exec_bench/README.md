# EXB2 compute

Each XDP entry consumes a fixed 8258-byte mutable EXB2 request, validates the header and task-specific input, runs the requested rounds, and writes the status, last result and digest in place. Success returns `XDP_PASS`. Invalid requests return `XDP_ABORTED`. The programs use no maps or helpers.

| Program | Workload |
| --- | --- |
| `noop` | Dispatch and result publication with no input |
| `prime` | Count primes and report the last one |
| `log2` | Integer floor logarithms on u32 or u64 words |
| `copy` | Copy input to scratch |
| `fletcher32` | Compute a checksum on little-endian u16 words |
| `bsort` | Bubble sort u32 words in scratch |
| `strcmp` | Compare two bounded NUL-terminated strings |

Build a selected program with `cargo run --locked -p mcu -- build -c copy`. [Buffer layout and known request](../../docs/benchmarks.md#exb2-compute-abi)
