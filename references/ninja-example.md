# firewall 全后端 Ninja 示例说明

阅读 [firewall.build.ninja](firewall.build.ninja) 查看一份 C 输入到最终 index 的完整图。规范与验收见 [design.md](design.md) G1/G2/G4；本文件只说明示例的路径、如何阅读和实际检查方法。

假定仓库根为 cwd，生成阶段准备必要目录及 [零地址链接脚本](firewall.zero.ld)（示例路径 build/intermediates/firewall/zero.ld；0x1000000 是现有生产者解析上限而非 MCU slot 容量）。内部和外部工具路径以真实环境解析结果替换。用户实际使用 mcu build；从仓库根审阅生成的文件时可运行：

```sh
ninja -f build/build.ninja -t commands firewall
ninja -f build/build.ninja -t graph firewall
```

示例文件结构（工作目录下）：

```text
build/
├── build.ninja
├── .ninja_log
├── intermediates/firewall/
│   ├── firewall_bpf.o           # 未经验证的 Clang 输出
│   ├── firewall_rv32.elf        # 零地址链接后的 ELF
│   ├── zero.ld
│   ├── bpf.d
│   ├── rv32.d
│   └── report/
│       ├── jit.elf
│       ├── ebpf.elf
│       ├── bpf.txt
│       ├── aot.txt
│       ├── jit.txt
│       ├── ebpf.txt
│       └── recipes.txt
└── firewall/                   # 正式程序目录：成员见 G4 的 PR7 规范
```

原始 BPF/linked AOT ELF 已能供 objdump 直接读取；只有 JIT/rBPF 需要生成适配 ELF。recipes.txt 是 Report 的实际配方输入，不是运行日志。图中的 17 个执行节点是示例，不冻结节点数。具体 API 暂定；真实 Rust 接口、编译和归档待实现。实测结果见 [Ninja 示例检查](../tests/ninja-example-static.md)。
