# libbpf-mcu tests

Test and validation source code for libbpf-mcu.

## Categories

- **basic/**: Minimal eBPF programs that must compile without BPF helper functions (Except for `bpf_printk`). Used to verify the toolchain constraint and compiler environment demand.
- **xdp/**: eBPF programs using BPF helper functions, maps and the context struct (`struct xdp_md`) about XDP. These must compile cleanly and serve as reference implementations for firmware integration.
- **failed/**: Programs expected to fail compilation. They may work on other platforms but violate project constraints (excess headers, forbidden features, etc.).

## Usage

TODO: Write brief for each file in each folder.
