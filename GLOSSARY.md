# libbpf-mcu

libbpf-mcu builds and packages XDP programs for XPOST on ESP32-C3.

## Language

**Program archive**:
The release attachment for one program, containing its original standalone C source (before the Rust migration, a generated source snapshot), original BPF object, build report and indexed deployment artifacts.

**Deployment mode**:
One supported execution path for a program: LLVM AOT (`llvm-aot`), host JIT (`jit`) or rBPF (`ebpf`).

**Program index**:
The v3 manifest of the files published for a program, identified by role, canonical relative path, size and digest.

**Target slot**:
The address range reserved in linked XPOST firmware for a deployment image.

**Build system**:
The repository's normal user entry point. Resolves build inputs and tools, generates the Ninja graph and invokes Ninja.

**Object tool**:
Host executable for ELF and BPF analysis, portable images and Compact ELF, and build reports. It does not implement JIT compilation or orchestrate the full build.

**Portable image**:
Firmware-independent payload and layout; native AOT/JIT code starts at a zero base and has explicit fixups. The rBPF image contains map-indexed bytecode.
