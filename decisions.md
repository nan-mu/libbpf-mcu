# libbpf-mcu 用户决定

本文件记录经用户确认、跨 PR 适用的架构边界。历史任务书保留原状。

## native-image-address-binding · 2026-11-27

AOT 和 JIT 的发布产物必须包含以零地址为基准的已生成原生机器码及足够的重定位信息。目标 Firmware ELF 的真实 slot、helper 等地址由 xpost-agent 在部署准备阶段读取，并用于加工原有机器码；不能以部署时重新编译 C/eBPF、直接使用预链接到固定真实地址的镜像或仅修改 ELF 元数据代替。libbpf-mcu 负责发布与目标固件布局解耦的产物；XPOST 负责实际地址绑定和设备装载。相同布局的直接链接参考用于验证定位结果。HAL 与 rBPF 不需要原生机器码重定位。已有 v0.1.1 实验数据保留，先验证新旧产物与布局的一致性，再继续正式实验。

来源：[PR6 初始任务书](https://gitea.nas.nan-mu.cc/mcp/libbpf-mcu/src/commit/67df9629dad9227580ee2b1de220bedd1043e145/taskbook.md) 的原生定址要求；2026-11-27 用户确认应先修复 AOT/JIT 零地址镜像实际加工路径再继续实验。此前 PR6 的固件绑定发布方式是历史实现，不是本架构约束的替代。

## release-version · 2026-11-23

正式发布系列 v0.1 的 patch 按整数递增，不向前两段进位；同次正式发布重试复用已分配版本。来源：[PR6 任务书](https://gitea.nas.nan-mu.cc/mcp/libbpf-mcu/src/commit/8dce1abd0d47bc47dddc66d829d4103181c16feb/taskbook.md)。

## rust-toolchain-boundaries · 2026-11-28

采用 [ADR 0001](docs/adr/0001-rust-toolchain-boundaries.md)：一个 Cargo Workspace、四个可执行文件；专用编译系统即时生成并执行 Ninja 图，独立 JIT、Object 处理器及开发工具 `tools release`。共享功能抽成独立库供多个程序复用，不复制生产算法。不要求手工安装自研工具，不设置 configure 阶段。2026-11-28 PR8 审核修订：编译系统只提供 build、clean、doctor；通过 Cargo 直接调用 Rust 程序，不保留根目录 mcu 启动脚本或其他等价包装器。测试使用 Cargo 原生测试机制，不提供 mcu test 或独立测试调度器；单元测试随对应 src 源码，真实二进制/工具链集成测试放对应 crate 的 tests 目录。依据：本轮 OpenSpec 讨论中用户逐项确认及最后一条共享库要求。具体工具名称和库数量暂定。

## standalone-program-source · 2026-11-28

程序逻辑直接保存在独立 C 文件中，BPF 与 RV32 使用同一份程序源代码，由 `include-bpf/` 与 `include/` 分别提供目标 SDK。禁止通过宏选择不同目标下的业务逻辑或借共享头文件选择不同实验程序实现；允许与目标无关的常量宏、正常 SDK 头文件。归档直接复制实际编译源码，不再实现自定义头文件展开、源码快照生成器。迁移现有程序时保留原协议、算法与 Map/Helper 行为；不盲删其他真实消费者仍需要的头文件。依据：本轮 OpenSpec 讨论中用户明确要求删除宽泛源码快照机制并恢复明确的头文件依赖。

## build-generation-and-execution · 2026-11-28

编译系统内部明确分为生成 Ninja 构建图和执行该图两个阶段，各自可独立测试；用户只调用 `mcu build`，同一次调用按顺序完成两个阶段，生成失败不执行旧图。不新增 configure 命令。依据：用户本轮修订要求。

## experiment-source-layout · 2026-11-28

按实验而非通用 XDP 测试目录组织正式程序的 C 源码，每个实验目录维护自己的 README，解释实验与程序。保持程序标识和发布契约；实验源码与工具链自身的测试 fixtures/diagnostics 区分。具体目录名不冻结。依据：用户本轮要求调整代码路径，使其与对应实验相关并各有 README。

## readable-work-directory-graph · 2026-11-28

Ninja 使用明确的工作目录作为路径基准，生成图时解析外部工具的真实绝对路径；项目内工具与外部工具明确区分，不绑定某个 Cargo target/profile 路径。生成的图应有面向人类阅读的注释、简洁的功能节点，减少无必要的中间文件、重复参数和 Object 工具的泛化职责。（该条中临时目录的约定由 persistent-build-intermediates 取代。）依据：用户对 PR8 Ninja 示例的反馈。具体局部路径、记录方式及节点合并是可调整的设计选择，不得削弱现有验证和产物契约。

## repository-root-work-directory · 2026-11-28

取代上一轮 readable-work-directory-graph 中容易误解的工作目录解释。work directory 明确为 libbpf-mcu checkout 根目录，build directory 为其下的构建输出目录（默认 build/）。Ninja 在仓库根执行；项目源码、SDK、Cargo 生成的自研工具均以该根定位，外部工具在生成图时解析为真实绝对路径。直接使用 Cargo 实际产生的可执行文件，不复制、不链接到构建目录，不创建 .work。Ninja 图是实际编译流程，不另设审计/状态管理流水线、重复 staging 产物树、通用 commands 账本或无必要的验证 JSON。保留必要的编译中间文件、原有产物格式和真实验证；持久化的生命周期以 persistent-build-intermediates 为准。依据：用户本轮明确纠正 work directory 含义、内部工具定位及中间产物设计。

## separate-bpf-compilation-and-verification · 2026-11-28

BPF 编译与 PREVAIL 验证是两个独立 Ninja 节点。Ninja rule 只表达清楚的工具调用、文件依赖和必要的重定向/临时文件管理；程序入口选择、验证器输出分析、ELF/BTF/Map 信息提取及其他领域字符串处理由 Rust 工具或共享库实现，不用 sed/awk 等 Shell 逻辑代替。跨节点的真实中间文件必须声明为输出和输入并保留用于增量；单节点内部的文件生命周期见 persistent-build-intermediates。依据：用户明确指出合并 compile_bpf 与 verifier 以及 Shell 解析是错误设计，并要求确认临时文件对 Ninja 的影响。验证适配器的具体接口仍为示例，不冻结。PR7 的公开 bin/json 和 index 格式不在本决定中改变。

## persistent-build-intermediates · 2026-11-28

采用 [ADR 0001 的构建文件生命周期](docs/adr/0001-rust-toolchain-boundaries.md#build-file-lifetime)。本条取代此前关于编译和 Report 临时目录的决定；保留编译与验证分离及仓库根 work directory 的其他要求。依据：用户明确要求编译、Report 的中间结果跨多次开发构建保留，只有 Release 压缩归档过程允许系统临时目录，完成后删除；同一信息只在一个权威文件描述，其他材料引用。
