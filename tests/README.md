# libbpf-mcu tests

Test and validation source for libbpf-mcu.

## Categories

- **basic/**: Minimal XDP programs (mostly `bpf_printk` + bounds checks). Used to smoke-test the bpf toolchain.
- **xdp/**: Reference XDP programs with maps/helpers (`XDP_DROP` / `PASS` / `TX` / `redirect`). Default build inputs.
- **failed/**: Negative cases excluded from default builds. Currently: verifier-style / intentional bad patterns.

## Layout

```
tests/
├── basic/
│   ├── print_ctx.c
│   ├── print_udp.c
│   └── maps_helpers.c
├── xdp/
│   ├── drop_icmp.c
│   ├── mac_swap.c
│   ├── firewall_ipv4.c
│   ├── forward_redirect.c
│   ├── rewrite_and_pass.c
│   ├── rewrite_and_redirect.c
│   └── vip_l2_redirect.c
└── failed/
    └── print_ctx_bad.c
```

## Naming

- File stem matches the primary `SEC("xdp")` entry symbol when practical (`drop_icmp.c` → `drop_icmp`).
- No redundant `xdp_` filename prefix under `tests/xdp/` (directory already scopes XDP).
- Prefer `<action>_<object>` / `<verb>_<noun>` (`firewall_ipv4`, `rewrite_and_pass`).

## Usage

Default `build` skips anything under `failed/` (`make/build.py`).
