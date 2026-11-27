# Toolchain architecture

The tool boundaries follow [ADR 0001](https://gitea.nas.nan-mu.cc/mcp/libbpf-mcu/src/commit/6c82e8b01366848bd22bcd476d738bcd61a3cebd/docs/adr/0001-rust-toolchain-boundaries.md).

```text
./mcu
  Cargo reports executable locations
  mcu Generate resolves the graph and zero-address linker scripts
  mcu Execute launches Ninja from the checkout root
    Clang -> original BPF ELF -> mcu-object PREVAIL gate
                                     |
                          accepted BPF object and source
                            /         |               \
   Clang RV32IMC -> LLD -> AOT       mcu-jit           rBPF
                           |         |                 ^
                           +---------|-----------------+
                           canonical AOT map layout
                           \         |                /
                             llvm-objdump and report
                                       |
                                   v3 index

tools release -> finished program directories -> verified 7z archives
mcu-object bind -> selected indexed image pair + target layout -> Compact ELF V0
tools reference -> archived objects + target layout -> independent direct link
```

`mcu-bpf` parses original eBPF and BTF, invokes PREVAIL and rewrites rBPF map references. `mcu-image` owns portable layouts, ELF extraction, fixups and address binding. `mcu-index` validates indexed artifact paths and contents. `mcu-report` verifies the disassembly bytes against ELF sections and renders Markdown. `mcu-project` shares program discovery, build locking and resolved tool paths. `mcu-deps` restricts Clang depfiles to source and target SDK paths. The host JIT compiler remains a library in `jit/`.

Inspect `build/build.ninja` for the actual inputs and outputs. Ninja owns scheduling and incremental execution. Raw objects, depfiles, linked ELFs, report inputs and linker scripts persist under `build/intermediates/`. The binder validates the indexed image pair and modifies the archived native bytes for the requested layout. The independent reference asks LLD or the JIT link API to link the original objects at those addresses.
