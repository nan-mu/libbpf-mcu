# libbpf-mcu 用户决定

本文件记录经用户确认、跨 PR 适用的架构边界。历史任务书保留原状。

## native-image-address-binding · 2026-11-27

AOT 和 JIT 的发布产物必须包含以零地址为基准的已生成原生机器码及足够的重定位信息。目标 Firmware ELF 的真实 slot、helper 等地址由 xpost-agent 在部署准备阶段读取，并用于加工原有机器码；不能以部署时重新编译 C/eBPF、直接使用预链接到固定真实地址的镜像或仅修改 ELF 元数据代替。libbpf-mcu 负责发布与目标固件布局解耦的产物；XPOST 负责实际地址绑定和设备装载。相同布局的直接链接参考用于验证定位结果。HAL 与 rBPF 不需要原生机器码重定位。已有 v0.1.1 实验数据保留，先验证新旧产物与布局的一致性，再继续正式实验。

来源：[PR6 初始任务书](https://gitea.nas.nan-mu.cc/mcp/libbpf-mcu/src/commit/67df9629dad9227580ee2b1de220bedd1043e145/taskbook.md) 的原生定址要求；2026-11-27 用户确认应先修复 AOT/JIT 零地址镜像实际加工路径再继续实验。此前 PR6 的固件绑定发布方式是历史实现，不是本架构约束的替代。

## release-version · 2026-11-23

正式发布系列 v0.1 的 patch 按整数递增，不向前两段进位；同次正式发布重试复用已分配版本。来源：[PR6 任务书](https://gitea.nas.nan-mu.cc/mcp/libbpf-mcu/src/commit/8dce1abd0d47bc47dddc66d829d4103181c16feb/taskbook.md)。

## rust-toolchain-boundaries · 2026-11-28

采用 [ADR 0001](docs/adr/0001-rust-toolchain-boundaries.md)：一个 Cargo Workspace、四个可执行文件；专用编译系统即时生成并执行 Ninja 图，独立 JIT、Object 处理器及开发工具 `tools release`。共享功能抽成独立库供多个程序复用，不复制生产算法。不要求手工安装自研工具，不设置 configure 阶段。依据：本轮 OpenSpec 讨论中用户逐项确认及最后一条共享库要求。具体工具名称和库数量暂定。

## standalone-program-source · 2026-11-28

程序逻辑直接保存在独立 C 文件中，BPF 与 RV32 使用同一份程序源代码，由 `include-bpf/` 与 `include/` 分别提供目标 SDK。禁止通过宏选择不同目标下的业务逻辑或借共享头文件选择不同实验程序实现；允许与目标无关的常量宏、正常 SDK 头文件。归档直接复制实际编译源码，不再实现自定义头文件展开、源码快照生成器。迁移现有程序时保留原协议、算法与 Map/Helper 行为；不盲删其他真实消费者仍需要的头文件。依据：本轮 OpenSpec 讨论中用户明确要求删除宽泛源码快照机制并恢复明确的头文件依赖。
