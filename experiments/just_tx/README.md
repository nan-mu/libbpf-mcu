# Just TX

The workload matches unfragmented IPv4 UDP to port 8080 with the JTX1 request header. A hit increments `rxcnt[17]` in the ARRAY map, swaps the Ethernet addresses and returns `XDP_TX`. A failed lookup aborts. Unmatched packets pass.

Build the portable modes with `cargo run --locked -p mcu -- build -c just_tx`. [Protocol reference](../../docs/benchmarks.md)
