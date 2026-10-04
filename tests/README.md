# libbpf-mcu tests

Test and validation source for libbpf-mcu.

## Categories

- **xdp/**: Programs used by `xpost/examples` (vendored AOT / HAL counterparts).
  Default build inputs.
- **unused/**: Archived or negative cases; excluded from default builds.

## Layout

```
tests/
├── xdp/
│   ├── just_drop.c
│   ├── just_tx.c
│   └── firewall.c
└── unused/
    └── …
```

## Naming

- File stem matches the primary `SEC("xdp")` entry symbol when practical.
- No redundant `xdp_` filename prefix under `tests/xdp/` (directory already scopes XDP).

## Usage

Default `build` skips anything under `unused/` (`make/build.py`).
