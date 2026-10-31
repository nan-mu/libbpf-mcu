# libbpf-mcu

libbpf-mcu 把 libbpf 风格的 XDP C 编译成两份结果。一份是主机上的 eBPF 对象。另一份是 ESP32-C3 上的 RV32IMC XDP ELF。MCU 侧是独立的 freestanding 编译，不是把 eBPF 字节码翻译成 RV32，也不是在 MCU 上运行 Linux XDP。

已经实现的目标是 RV32IMC，ABI 为 `ilp32`，没有 FPU。eBPF 检查器接受 `bpf.o`，并不由此推出 MCU 二进制已经满足相应安全性质。链接布局和调用约定要单独说明。

论文 coming soon。

本仓库自己的代码使用 [MIT](LICENSE)。`include/bpf/` 与 `include-bpf/bpf/` 里带 SPDX 的头文件保持其上游许可证，当前是 LGPL-2.1 或 BSD-2-Clause。`prevail/` 是 [vbpf/prevail](https://github.com/vbpf/prevail) 子模块，许可证以该目录中的文件为准。

libbpf-mcu compiles libbpf-style XDP C into two results. One result is a host eBPF object. The other is an RV32IMC XDP ELF for the ESP32-C3. The MCU build is a separate freestanding compilation. It does not translate eBPF bytecode into RV32, and it is not a Linux XDP runtime on the MCU.

The implemented target is RV32IMC, the ABI is `ilp32`, and there is no FPU. Acceptance of `bpf.o` by an eBPF checker does not by itself establish the safety of the MCU binary. The linker layout and the calling convention need their own account.

Paper: coming soon.

Code in this repository uses the [MIT](LICENSE) license. Headers under `include/bpf/` and `include-bpf/bpf/` that carry an SPDX line keep their upstream license. Those lines currently say LGPL-2.1 or BSD-2-Clause. `prevail/` is the [vbpf/prevail](https://github.com/vbpf/prevail) submodule. Use the license files in that directory.

## 现状

代码还在改。这次按现状发布。下文的 `pixi` 命令是当前的构建方式。换一台机器时，缺的依赖和路径需要自己看代码，没有另写一份部署说明。实验室配置的清理以后再做。

## Status

The code is still changing. This publication keeps the tree as it is. The `pixi` commands below are the current build. On another machine, missing dependencies and paths have to be read out of the code. There is no separate deployment guide. Lab-specific cleanup comes later.

## 构建

在本仓库根目录运行。`--firmware` 是已经链接好的固件 ELF，里面要有 `.xpost.mem`，格式为 XPM1。地址按文件中的值用于槽位链接和 XDP ELF 元数据。本仓库不决定烧录哪一份镜像。

```bash
pixi run build --firmware <firmware.elf>
pixi run build --firmware <firmware.elf> -c just_drop
pixi run clean
```

不写 `-c` 时，先构建 `bpf`，再构建 `esp32c3`。输入是 `tests/**/*.c`，不含 `tests/unused/`。`-c <stem>` 只构建 `tests/**/<stem>.c`，同样跳过 `unused/`。

产物写到 `../build/<stem>/`。

| 文件 File | 作用 Role |
| --- | --- |
| `bpf.o` | 主机 eBPF 对象。Host eBPF object. |
| `bpf.toml` | BPF 报告和 map 元数据。MCU 链接后写入 `aot_addr`。BPF report and map metadata. `aot_addr` is added after the MCU link. |
| `<stem>.elf` | XDP ELF V0，也称为 `xdp.elf`。与固件分开烧录。XDP ELF V0, also called `xdp.elf`. Flash it separately from the firmware. |
| `esp32c3.toml` | MCU 报告，含 `elf_size_kb`。MCU report, including `elf_size_kb`. |

中间文件有 `esp32c3.o`、`esp32c3.elf` 和 `esp32c3.bin`。不要把 `.bin` 嵌进固件。`esp32c3.elf` 是 AOT 调试 ELF，不是 XDP ELF。`layout.toml` 不是编译输入。

Run the commands from this repository root. `--firmware` is a linked firmware ELF that contains `.xpost.mem` in the XPM1 format. Addresses are taken from that file and used for slot linking and XDP ELF metadata. This repository does not choose which image to flash.

Without `-c`, the build produces `bpf` and then `esp32c3` for every `tests/**/*.c` file outside `tests/unused/`. `-c <stem>` builds only `tests/**/<stem>.c`, and it also skips `unused/`.

Outputs go to `../build/<stem>/`.

Intermediate files are `esp32c3.o`, `esp32c3.elf`, and `esp32c3.bin`. Do not embed the `.bin` into the firmware. `esp32c3.elf` is the AOT debug ELF, not the XDP ELF. `layout.toml` is not a compile input.

## 流水线

`make/cli.py` 和 `make/build.py` 只排路径。它们解析输入，准备主机工具，读取 XPM1，并写出一张 ninja 图。Ninja 执行这些步骤。

1. `cargo build` 生成 `tools/target/<host>/release/xpost-mcu-elf`。`tools/` 或 `xpost-elf` 的输入变化时重新构建。
2. clang 编译 `bpf.o`。构建包含 ESP32-C3 时，ninja 先对这份 `bpf.o` 运行 PREVAIL，写出 `prevail.ok`，再进入 ESP32-C3 的编译边。
3. clang 完成链接、bin 和报告。
4. 直接调用 `xpost-mcu-elf pack`，并写入 `elf_size_kb`。不要用 `cargo run` 代替这次调用。

`prevail/bin/prevail` 是检查器二进制。只构建 `bpf` 时不运行 PREVAIL。XDP ELF 的编解码只用 `xpost-elf`。不能写入 XDP ELF V0 的 map 不进入元数据。

`make/cli.py` and `make/build.py` only plan the route. They resolve inputs, prepare the host tool, read XPM1, and write one ninja graph. Ninja runs the steps.

1. `cargo build` produces `tools/target/<host>/release/xpost-mcu-elf`. It rebuilds when `tools/` or `xpost-elf` inputs change.
2. clang compiles `bpf.o`. When the build includes ESP32-C3, ninja runs PREVAIL on that `bpf.o`, writes `prevail.ok`, and then compiles for ESP32-C3.
3. clang links, writes the bin, and writes the report.
4. The build calls `xpost-mcu-elf pack` directly and records `elf_size_kb`. Do not replace that call with `cargo run`.

The checker binary is `prevail/bin/prevail`. A `bpf` only build does not run PREVAIL. XDP ELF encode and decode use `xpost-elf`. Maps that cannot be stored in XDP ELF V0 stay out of the metadata.

## 头文件

`include/` 给 MCU freestanding 目标使用，对应 `esp32c3` 的 ninja 边。`include-bpf/` 给主机 BPF 目标使用，对应 `bpf` 的 ninja 边。两边不要混用。

`include/` is for the MCU freestanding target and the `esp32c3` ninja edge. `include-bpf/` is for the host BPF target and the `bpf` ninja edge. Do not mix the two trees.

## 范围

编译标志包括 `riscv32-unknown-none-elf`、`-march=rv32imc`、`-mabi=ilp32`、`-nostdlib`、`-ffreestanding` 和 `-fno-builtin`。源码不使用 libc、操作系统接口、动态分配或 Linux 运行时。第二个非 RISC-V 目标还没有实现。在那之前，跨架构是设计方向。

The compile flags include `riscv32-unknown-none-elf`, `-march=rv32imc`, `-mabi=ilp32`, `-nostdlib`, `-ffreestanding`, and `-fno-builtin`. The sources do not use libc, an operating-system interface, dynamic allocation, or a Linux runtime. A second non-RISC-V target is not implemented yet. Until that target exists, cross-architecture support is a design direction.
