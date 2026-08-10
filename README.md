# libbpf-mcu

`libbpf-mcu` 是一个面向 MCU 编译目标的 freestanding C 兼容层/中间层。它的目标不是把用户态 `libbpf` 或 Linux XDP runtime 移植到 MCU，而是让使用 libbpf 风格头文件、helper 名称、map/section 宏和 XDP return code 的 BPF/XDP C 程序，可以被 LLVM 编译为适合 MCU 固件 AOT/热加载执行的 native patch 对象。

第一阶段 concrete target 是 ESP32-C3/RV32IMC；该目录应被理解为 architecture-agnostic 双目标编译路线中的 C 侧兼容层，而不是 ESP32-C3-only 或 RISC-V-only 组件。

这些 patch 对象的重点不是直接在完整 Linux/BPF 语义下运行。当前加载/链接方向是通过 linker script 将 helper call、map region、HOT_REGION 等绑定到固件 memory map 中的绝对地址，并生成 stripped/minimal binary 或 memory image，避免在固件端保留完整符号表、relocation sections 或实现复杂 ELF parser。

## 目标平台

- **硬件**: ESP32-C3 (RISC-V 32位单核芯片)
- **架构**: RV32IMC (带整数乘除法和压缩指令扩展)
- **ABI**: ilp32
- **内存**: 400KB SRAM
- **特点**: 无 FPU，支持中断和异常处理

## 设计目标

- 为 libbpf 风格 BPF/XDP C 程序提供最小可编译的 C 侧接口
- 将 Linux/XDP 语义中与目标 MCU 无关的部分抽象出来
- 把示例编译成适合热加载的 RV32 patch 对象，而不是把 helper 逻辑提前内联折叠掉
- 通过 linker script 把 helper、map region 和 hot-load region 绑定到固件定义的绝对地址，减少 MCU 侧元数据和解析逻辑
- 尽量兼容现有 XDP 代码习惯，使现有 XDP 程序可以保持原有 include、helper 名称和 map/section 宏写法
- 为 LLVM 到 MCU native target 的编译流程预留稳定的头文件和源文件组织方式

## 目录结构

```
libbpf-mcu/
├── inclued/              # 兼容层头文件
│   ├── linux/           # Linux 内核头文件兼容
│   │   ├── bpf.h
│   │   ├── if_ether.h
│   │   ├── in.h
│   │   ├── ip.h
│   │   └── udp.h
│   ├── bpf/             # BPF helper 兼容
│   │   ├── bpf_helpers.h
│   │   └── bpf_endian.h
│   └── core.h           # 核心定义和 ABI
├── tests/               # 测试与参考用例（见 tests/README.md）
│   ├── basic/           # 最小 XDP（printk / 解析）
│   ├── xdp/             # maps / redirect / 改写等参考实现
│   └── failed/          # 负例（默认构建跳过）
└── make/                # Python CLI + ninja 模板
```

## XDP / 测试用例

源码在 `tests/`（不再使用顶层 `xdp/`）。分类约定见 `tests/README.md`。

### basic/
- **`print_ctx.c`**: 打印 XDP 上下文长度后 `XDP_PASS`
- **`print_udp.c`**: 解析 UDP 并 `bpf_printk`

### xdp/
- **`drop_icmp.c`**: 丢弃 ICMP
- **`mac_swap.c`**: 交换以太网源/目的 MAC 后 `XDP_TX`
- **`firewall_ipv4.c`**: `HASH` 按 `src_ip + dst_port` 决定 `DROP`/`PASS`
- **`forward_redirect.c`**: `DEVMAP` + `bpf_redirect_map`
- **`rewrite_and_pass.c`**: 按规则重写 UDP 目的端口后 `PASS`
- **`rewrite_and_redirect.c`**: 改写二层 MAC 后 `bpf_redirect`
- **`vip_l2_redirect.c`**: dst VIP 命中则 MAC swap + `XDP_TX`，否则 `PASS`

### failed/
- **`print_ctx_bad.c`**: 负例（默认构建排除）

### 覆盖能力

这些示例覆盖了兼容层需要支持的基础能力：

- **包解析**: 以太网头、IPv4 头、UDP 头、TCP 头、ICMP 头的边界检查与访问
- **map 访问**: `BPF_MAP_TYPE_HASH`、`BPF_MAP_TYPE_ARRAY`、`BPF_MAP_TYPE_DEVMAP`
- **helper 调用**: `bpf_map_lookup_elem`、`bpf_redirect_map`、`bpf_ntohs`、增量 checksum
- **常见动作**: `XDP_PASS`、`XDP_DROP`、`XDP_TX`、redirect
- **数据改写**: UDP 目标端口重写、二层 MAC 地址改写
- **简单统计**: 通过数组 map 做计数

## 使用 cargo-make

### 安装依赖

需要安装支持 RISC-V 后端的 LLVM clang：

```bash
# macOS (Homebrew)
brew install llvm

# Ubuntu/Debian
sudo apt install clang llvm

# Arch Linux
sudo pacman -S clang llvm
```

默认使用 Homebrew LLVM (`/opt/homebrew/opt/llvm/bin/clang`)，可通过环境变量覆盖：

```bash
export CLANG=/path/to/llvm/bin/clang
```

### 可用任务

```bash
# 查看帮助
cargo make help

# 快速编译所有示例
cargo make build

# 完整测试（语法检查 + 编译）
cargo make tests

# 清理编译产物
cargo make clean
```

### 编译流程

**`cargo make build`** - 快速编译
- 直接编译所有 XDP 示例到 RV32IMC 目标
- 每个 `.c` 文件生成独立目录和 `.o` 文件

**`cargo make tests`** - 完整测试
- 阶段 1: 使用宿主机 clang 进行语法检查
- 阶段 2: 编译到 RV32IMC (ESP32-C3) 目标

### 输出结构

每个示例编译后会在 `target/` 下创建独立目录：

```
target/
├── firewall_ipv4/
│   └── firewall_ipv4.o
├── xdp_hello/
│   └── xdp_hello.o
└── ...
```

这种结构便于后续存放：
- 符号分析结果
- 重定位信息
- 地址映射表
- 调试信息

## 编译配置

### 目标参数

```bash
-target riscv32-unknown-none-elf  # RISC-V 32位裸机目标
-march=rv32imc                     # RV32I + M扩展(乘除) + C扩展(压缩指令)
-mabi=ilp32                        # 32位整数、长整型、指针 ABI
```

### 编译选项

```bash
-nostdlib                          # 不链接标准库
-ffreestanding                     # 独立环境（无操作系统）
-O2                                # 优化级别 2
-fno-builtin                       # 禁止内联 builtin 函数（保留 helper 调用）
-ffunction-sections                # 每个函数独立段（便于重定位）
-fdata-sections                    # 每个数据独立段（便于重定位）
-fno-exceptions                    # 禁用 C++ 异常
-fno-unwind-tables                 # 禁用栈展开表（减少体积）
-fno-asynchronous-unwind-tables    # 禁用异步栈展开表
```

### 头文件包含

```bash
-I inclued                         # 兼容层头文件
-I inclued/bpf                     # BPF helper 头文件
-include inclued/core.h            # 自动包含核心定义
```

## 兼容层设计

### 头文件组织

兼容层提供 Linux/BPF 同名头文件，使现有 XDP 程序可以不改或少改源码直接编译：

- `linux/bpf.h` - BPF 常量、枚举、结构体定义
- `linux/if_ether.h` - 以太网协议定义
- `linux/in.h` - Internet 协议族定义
- `linux/ip.h` - IPv4 头结构
- `linux/udp.h` - UDP 头结构
- `bpf/bpf_helpers.h` - BPF helper 函数声明
- `bpf/bpf_endian.h` - 字节序转换宏

### 核心 ABI (core.h)

`inclued/core.h` 提供最小 ABI 集合：

- **基础类型**: `__u8`, `__u16`, `__u32`, `__u64`, `__s8`, `__s16`, `__s32`, `__s64`
- **XDP 结构**: `xdp_md` (XDP 元数据上下文)
- **返回码**: `XDP_PASS`, `XDP_DROP`, `XDP_ABORTED`, `XDP_TX`, `XDP_REDIRECT`
- **Map 类型**: `BPF_MAP_TYPE_HASH`, `BPF_MAP_TYPE_ARRAY`, `BPF_MAP_TYPE_DEVMAP` 等
- **Map 宏**: `SEC()`, `__uint()`, `__type()` 等 map 声明宏
- **协议头**: `ethhdr`, `iphdr`, `udphdr`, `tcphdr`, `icmphdr`
- **Helper 声明**: `bpf_map_lookup_elem`, `bpf_redirect_map`, `bpf_csum_diff` 等

### 关键设计点

1. **保留外部符号**: helper 函数作为未解析外部符号保留，不内联
2. **保留重定位信息**: 编译产物包含完整 relocation 信息
3. **兼容现有代码**: XDP 程序保持原有 include 和写法
4. **适配 ESP32-C3**: 针对 400KB SRAM 和无 FPU 环境优化

## 检查编译产物

使用 `readelf` 或 `llvm-readelf` 检查符号和重定位信息：

```bash
# 查看文件头
llvm-readelf -h target/xdp_hello/xdp_hello.o

# 查看节信息
llvm-readelf -S target/xdp_hello/xdp_hello.o

# 查看符号表（确认 helper 函数为外部符号）
llvm-readelf -s target/xdp_hello/xdp_hello.o

# 查看重定位信息
llvm-readelf -r target/xdp_hello/xdp_hello.o

# 反汇编查看指令
llvm-objdump -d target/xdp_hello/xdp_hello.o
```

## 后续工作

1. **Rust Patcher 工具**
   - 解析 ELF 目标文件
   - 识别 helper 函数调用点
   - 重写符号地址为 ESP32-C3 固件中的实际地址
   - 处理 map 访问的地址重定位
   - 生成可热加载的 patch 二进制

2. **ESP32-C3 固件集成**
   - 实现 helper 函数的 MCU 版本
   - 实现 map 数据结构（hash、array 等）
   - 提供动态加载和卸载机制
   - 实现 XDP 程序的调用接口

3. **扩展示例**
   - LPM trie (最长前缀匹配)
   - 防火墙规则链
   - 事件上报机制
   - Tail call 支持
   - 更复杂的包改写场景

4. **测试和验证**
   - 单元测试框架
   - 集成测试
   - 性能基准测试
   - 内存占用分析

## 注意事项

- `cargo make tests` 验证的是"XDP 示例能否编译成 RV32IMC patch 对象"，不是验证 Linux 内核可加载语义
- 对于热加载 patch 场景，保留 helper 调用点和 relocation 比内联更重要
- ESP32-C3 只有 400KB SRAM，需要控制编译产物大小
- 使用 RV32IMC 的 C 扩展（压缩指令）可减少代码体积约 25-30%
- helper 函数必须作为外部符号保留，供后续 patcher 重写地址

## 环境变量

- `CLANG` - 指定 clang 编译器路径（默认: `/opt/homebrew/opt/llvm/bin/clang`）
- `TARGET` - 编译目标（默认: `riscv32-unknown-none-elf`）
- `ARCH` - 目标架构（默认: `rv32imc`）
- `ABI` - 目标 ABI（默认: `ilp32`）

## 许可证

待定
