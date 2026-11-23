# libbpf-mcu tests

Test and validation source for libbpf-mcu.

## Categories

- **xdp/**: Default compute and networking programs. Shared headers live beside the programs that include them.
- **diagnostics/**: Opt-in `helper_loop`, `merge_try` and `xdp_drop` probes.
- **unused/**: Archived or negative cases; excluded from default builds.

## Layout

```
tests/
├── xdp/
│   ├── exb2/
│   ├── just_drop.c
│   ├── just_tx.c
│   └── firewall.c
├── diagnostics/
│   └── …
└── unused/
    └── …
```

## Naming

- File stem matches the primary `SEC("xdp")` entry symbol when practical.
- No redundant `xdp_` filename prefix under `tests/xdp/` (directory already scopes XDP).

## Usage

Use `pixi run build -c helper_loop` for an opt-in diagnostic. Select archived sources explicitly with `--inputs`. The [benchmark contracts](../docs/benchmarks.md) list the active workloads and the archived fixtures.
