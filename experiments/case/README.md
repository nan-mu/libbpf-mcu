# CAS2

Both programs accept a JTX1 request with a 40-byte UDP payload and zero version. They write a big-endian version at payload offset 32 and `CAS2` at offset 36. They clear the UDP checksum, swap MAC addresses and return `XDP_TX`. `case_mark` writes version 1 and `case_swap` writes version 2. Other packets pass. Neither program uses maps or helpers.

Build both with `./mcu build -c case_mark -c case_swap`. [Protocol reference](../../docs/benchmarks.md)
