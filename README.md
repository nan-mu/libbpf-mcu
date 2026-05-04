# xdp4

`xdp4` 的目标是提供一个 C 语言兼容层/库，使 LLVM 可以把一部分常见的 XDP C 程序编译成适合热加载到 RV32 单片机固件中的 patch 对象。

这些 patch 对象的重点不是直接在 Linux/BPF 语义下运行，而是要尽量保留 `ctx`、map、helper 调用点和重定位信息，供后续 Rust patcher 把它们重写成单片机固件中的真实地址布局。

后续会在本仓库中加入一个 Rust 程序，用于把编译产物中的 `ctx` 指针、helper 符号和函数地址重写为单片机可用的地址。

## 当前阶段

当前仓库已经完成第一轮初始化，并加入了一批用于后续兼容验证的 XDP 示例：

- 项目说明文档
- 目录骨架
- `cargo-make` 任务定义 
- `examples/xdp/` 下的基础 XDP 示例集合
- `c-lib/compat/` 下的 Linux/BPF 同名兼容头

## 设计目标

- 为常见 XDP 程序提供最小可编译的 C 侧接口
- 将 Linux/XDP 语义中与目标 MCU 无关的部分抽象出来
- 把示例编译成适合热加载的 RV32 patch 对象，而不是把 helper 逻辑提前内联折叠掉
- 保留 helper 调用点、map 符号和必要 relocation，供后续 patcher 重写到固件函数/数据地址
- 尽量兼容现有 XDP 代码习惯，使现有 XDP 程序可以保持原有 include、helper 名称和 map/section 宏写法
- 为 LLVM 到 RV32 的编译流程预留稳定的头文件和源文件组织方式
- 为后续 Rust 地址重定位工具预留独立目录

## 目录规划

- `c-lib/`
  - `include/xdp_rv32/`：内部基础 ABI 头，供兼容层复用
  - `compat/`：Linux/BPF 同名兼容头，目标是让现有 XDP 源码尽量不改即可编译
  - `src/`：后续 C 侧支持代码
- `tools/relocator/`：后续 Rust 地址重写工具
- `examples/xdp/`：用于验证编译兼容性的 XDP 示例
- `tests/fixtures/`：测试输入、预期输出和二进制夹具
- `scripts/`：辅助脚本

## 当前示例

`examples/xdp/` 里现在包含几类基础样例，用来覆盖常见 XDP 写法：

- `firewall_ipv4.c`：基于 `HASH map` 的简单防火墙，按 `src_ip + dst_port` 决定 `XDP_DROP` 或 `XDP_PASS`
- `forward_redirect.c`：基于 `DEVMAP` 的简单转发，使用 `bpf_redirect_map`
- `rewrite_and_pass.c`：根据规则表重写 UDP 目标端口后 `XDP_PASS`
- `rewrite_and_redirect.c`：改写二层 MAC 地址后 `redirect`
- `common.h`：这些样例共用的最小解析辅助函数

这些样例目前主要用于定义“兼容目标输入”，也就是：后续你的 `c-lib` 需要逐步支持把这类 XDP 程序从常见 Linux/XDP 写法迁移到面向 RV32 MCU 的可编译形式。

## 示例覆盖能力

当前样例已经覆盖了后续兼容层最需要面对的一批基础能力：

- 包解析：以太网头、IPv4 头、UDP 头的边界检查与访问
- `map` 访问：`BPF_MAP_TYPE_HASH`、`BPF_MAP_TYPE_ARRAY`、`BPF_MAP_TYPE_DEVMAP`
- helper 调用：`bpf_map_lookup_elem`、`bpf_redirect_map`、`bpf_ntohs`、`bpf_csum_diff`
- 常见动作：`XDP_PASS`、`XDP_DROP`、`XDP_ABORTED`、redirect
- 数据改写：UDP 目标端口重写、二层 MAC 地址改写
- 简单统计：通过数组 map 做计数

## 当前限制

这些样例现在仍然采用典型的 Linux/BPF 头文件写法，例如：

- `<linux/bpf.h>`
- `<linux/ip.h>`
- `<bpf/bpf_helpers.h>`
- `<bpf/bpf_endian.h>`

这是一种有意的过渡状态。这样做的目的是先把“目标支持的 XDP 写法”收集出来，再由 `c-lib/include/xdp_rv32/` 逐步提供自己的兼容头和 helper 声明，把这些示例从 Linux 依赖迁到适合 RV32 MCU 的接口上。

换句话说，当前这些示例更像是测试向量和需求样本，而不是最终面向 MCU 的头文件形态。

## 使用 `cargo-make`

初始化目录：

```bash
cargo make init-layout
```

查看预期结构：

```bash
cargo make show-layout
```

把 `examples/xdp/` 下全部 `.c` 示例编译成 RV32 目标产物：

```bash
cargo make tests
```

默认输出目录是 `target/xdp-rv32/`，每个示例会生成一个对应的 `.o` 文件。

## 编译说明

为了让现有 XDP 源码尽量保持不变，仓库中现在分成两层头文件：

- `c-lib/include/xdp_rv32/xdp_rv32.h`：内部基础 ABI 定义
- `c-lib/compat/`：对外暴露的 Linux/BPF 同名兼容头

兼容头当前覆盖了这些常见路径：

- `linux/bpf.h`
- `linux/if_ether.h`
- `linux/in.h`
- `linux/ip.h`
- `linux/udp.h`
- `bpf/bpf_helpers.h`
- `bpf/bpf_endian.h`

这意味着现有 XDP 程序只要使用这些常见 include、helper 名称和 map/section 宏写法，就可以在不改源码或尽量少改源码的前提下，借助 `-I c-lib/compat` 编译到我们的 patch 目标模型。

内部基础 ABI 当前提供了这些最小集合：

- 基础整数类型：`__u8`、`__u16`、`__u32`、`__u64`
- `xdp_md`
- XDP 返回码
- `BPF_MAP_TYPE_*` 的最小枚举
- `SEC`、`__uint`、`__type` 等 map 声明宏
- `ethhdr`、`iphdr`、`udphdr`
- `bpf_ntohs`、`bpf_htons` 等纯头文件内联工具
- `bpf_map_lookup_elem`、`bpf_redirect_map`、`bpf_csum_diff` 等 helper 的外部符号声明

这里最重要的设计点是：

- 现有 XDP 程序应尽量保持原始 include 形式
- helper 不是头文件里的常量桩实现
- helper 会作为未解析外部符号保留在目标文件里
- 后续 patcher 可以扫描这些符号和 relocation，把它们替换成 MCU 固件中的真实函数地址

注意：

- `cargo make tests` 的目标是验证“这些 XDP 示例能否作为 RV32 patch 输入被编译成目标文件”，不是验证 Linux 内核可加载语义。
- 对于热加载 patch 场景，保留 helper 调用点和 relocation 比“把 helper 逻辑内联成普通 C 函数”更重要。
- 任务会先使用宿主机 `clang` 对所有示例做一轮 `-fsyntax-only` 检查，以确认兼容头和示例代码本身是自洽的。
- 之后才会进入真正的 RV32 目标编译阶段。
- 当前任务依赖一个支持 `riscv32-unknown-elf` 的 `clang`。
- 在本机默认环境下，`/usr/bin/clang` 是 Apple clang，不包含 RISC-V 后端，因此任务会在“宿主机语法检查通过后”给出明确报错。
- 后续应安装 LLVM clang，并通过环境变量指定，例如：

```bash
CLANG=/path/to/llvm/bin/clang cargo make tests
```

## 后续建议

1. 在 `c-lib/include/xdp_rv32/` 中先定义最小的 `xdp_md`、返回码、map 定义宏和常用 helper 声明。
2. 把 `examples/xdp/` 中的示例逐步改造成同时支持“Linux 风格输入”和“xdp_rv32 兼容头输入”的验证样本。
3. 在 `tools/relocator/` 下创建 Rust crate，负责对编译后的符号、`ctx` 和函数地址进行重写。
4. 增加更多覆盖面更广的样例，比如 LPM trie、防火墙规则链、事件上报、tail call 等。
5. 逐步建立面向“可编译通过”的兼容矩阵，而不是一开始追求完整 Linux XDP 语义。
