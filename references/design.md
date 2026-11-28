# Rust/Ninja 工具链：行为规格与验收

本文保留原 G1–G5 的行为契约，并在末尾给出 PR8 审查修订 R1–R5。本轮以 R1–R5 为增量实施和验收范围；与原条款不一致之处以本版修订为准。使用原项目术语，具体二进制/库名、内部文件名和等价实现可调整；每个 G 结束时按其验收条件核对。代码引用固定于 GitHub main c235b94ffa065ab132ae5ceb54a36db2e3e6d10a。

## G1. 一个 workspace 与一个正常编译入口

一个 Cargo workspace、一个 lockfile、多个独立共享库、四个可执行文件：

| 程序（暂名） | 职责 |
| --- | --- |
| mcu | 专用编译系统：build、clean、doctor；解析输入、生成构建图、执行 Ninja、必要检查与失败清理 |
| mcu-jit | eBPF → RV32IM 编译与 fixups，CLI 复用 image 库直接输出正式 JIT pair |
| mcu-object | ELF/BPF/BTF、Image（含 Compact ELF）、Report（含反汇编准备）、既有 Index 的纯文件转换 |
| tools | 独立开发工具；release 子命令见 G4 |

同一领域类型、格式规则和算法由独立 Rust 库提供唯一实现，四个程序按需引用；禁止重复生产算法、依赖其他二进制的入口实现、循环依赖或万能 common 库。JIT 编译核心独立于容器、报告和发布流程。优先使用 object 与 xpost-elf 等已有库。普通构建不调用 tools。

直接通过 Cargo 调用 Rust 可执行程序（如 cargo run --locked -p mcu -- build），不提供根目录 mcu 脚本或等价启动包装器，不要求安装自研二进制。Rust 编译系统自动构建/刷新所需工具并解析 Cargo 实际产物位置。mcu build 自动依次调用两个独立可测试的内部阶段：Generate 接收解析后的输入与工具路径，生成/更新 Ninja 图及链接脚本，返回本次图、目标和执行上下文；Execute 只执行该图、取得结果。生成失败不能运行旧图；没有 test、configure、独立 bootstrap 或 mcu tool 转发命令。doctor 检查外部工具能力和自研工具状态，正常 build 不要求先执行 doctor。保留程序选择、BPF-only、指定 portable 后端、默认全矩阵、--build-dir 与强制重建能力；旧 Pixi CLI 不保留别名。

work directory 是 libbpf-mcu checkout 根，Ninja 始终以它为 cwd。build directory 默认 build/，自定义 --build-dir 仅改变构建输出位置。外部工具由配置/环境及明确搜索规则解析真实绝对路径；内建工具直接引用 Cargo 实际输出（不假定 target/release、profile、host 或 target-dir），不复制/链接工具到 build，不创建 .work。Cargo 缓存与构建产物分离；clean 清理所选构建目录而不删除 Cargo 缓存。正确处理路径中的空格和 Ninja/shell 转义。

**验收 G1：** 检查 workspace 和真实调用链。从干净 checkout 执行正常入口；分别测试 Generate（无程序编译）与 Execute（真实 Ninja），用已有旧图加本次生成失败验证阻断。重复无变化构建不重新编译；更换实际 Cargo 输出位置或工具版本、从其他 cwd 调用、checkout/build-dir/工具路径包含空格均工作。doctor 缺失工具或目标能力时明确报错，Cargo 或 Ninja 失败正确返回。普通构建不依赖 tools。

现状：[make/build.py](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/make/build.py)、[make/cli.py](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/make/cli.py)、[pixi.toml](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/pixi.toml)、[tools/Cargo.toml](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/tools/Cargo.toml) 与 [jit/Cargo.toml](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/jit/Cargo.toml)。

## G2. 构建图和领域工具

### 文件生命周期

编译、验证、报告、地址绑定及直接链接参考的所有需要落盘的中间数据使用构建目录内稳定的路径（例如 build/intermediates/<program>/），跨多次开发编译保留，直到被正常更新或执行 clean。普通流程不创建系统临时目录、每次调用的 scratch 目录或用完即删的目录，不使用 mktemp/trap 清理报告文件。内存中的计算数据不必额外落盘。所有跨节点文件都声明实际输入和输出，交给 Ninja 管理；不因命名为中间产物而每次删除。报告的反汇编输入 ELF、原始反汇编文本和构建配方同样持久化。不要把它们混入正式程序归档目录，也不要创建第二套 staging 产物树。

正式程序目录 build/<program>/ 就是最终产物目录。index 是现有格式的最终文件转换节点。除 Ninja 自身日志与 depfile、必要中间文件、已有正式契约，不创建额外状态或审计系统（verified.json、commands 账本、每步 receipt、通用 evidence API 等）；不把这些职责藏在 mcu/object。必要的原子文件替换可在其正式父目录完成，不需要临时目录。Release 是唯一允许使用系统临时目录的生产流程，见 G4。

### 节点接口

完整参考：[firewall.build.ninja](firewall.build.ninja) 与 [示例说明](ninja-example.md)。图以真实功能、明确输入输出和注释组织；Clang、LLD、llvm-objdump 直接由 Ninja 调用。PREVAIL 的动态入口选择和输出解析由职责明确的 Rust verifier 适配器处理，是有限的外部工具调用例外。所有字符串/ELF/BTF/Map/验证结果解析必须在 Rust；不使用 sed、awk、shell 正则、文本切割等代替。shell 仅用于明确的工具调用和必要重定向等文件操作，不隐藏编排。

| 功能节点 | 输入 | 输出 / 责任 |
| --- | --- | --- |
| BPF compile | 独立 C、include-bpf SDK、Clang | 原始 BPF ELF、depfile |
| BPF verify | 原始 ELF、PREVAIL | 独立规则：列出唯一 xdp/xdp1 entry，512-byte stack、300 秒超时，检查退出码及明确 PASS；通过后原样复制 ELF 至正式路径，不移动/删除原始对象，不修改 section；失败撤销旧有效 BPF |
| Source copy | 同一实际 C、验证成功 | 原始 C 字节 |
| RV32 compile | 同一 C、include SDK、Clang | RV32IMC ILP32 freestanding .o、depfile |
| AOT link | RV32 object、零地址脚本 | 零地址 linked ELF，禁止 relaxation、保留 relocations |
| Image AOT | linked ELF、RV32 reference object、BPF ELF | llvm-aot.bin/json，真实区域、map 和 fixups |
| JIT | BPF ELF | JIT 直接输出 jit.bin/json；不先写重复中间 pair 再调用 Object |
| Image rBPF | BPF ELF、canonical AOT map layout | ebpf.bin/json，map-indexed bytecode，无 native fixup；不改变 map order/offset |
| Report prepare | JIT/rBPF 的 image/layout | 供 objdump 读取的 ELF（复用现有 BPF/linked AOT ELF，无需重复包装） |
| Disassemble | 对应 ELF、ISA 选项 | 原始 objdump 输出；保持 BPF、RV32IMC AOT、RV32IM JIT 的解释差异 |
| Report generate | 源码、真实对象与镜像、反汇编、构建配方 | 单个 report.md；源码一次，正确 ISA、地址、机器码与汇编逐字节对应。配方可取自实际 Ninja 图；不能宣称为本轮逐命令执行历史 |
| Index | 所选程序的实际完整文件集合 | v3 index.toml；相对路径、大小、摘要、mode、fixup 等按 G4 契约校验 |

BPF metadata 通过共享 Rust 库从原始 ELF 直接读取，既有 BTF 类型、Map/Relocation 不必另写 metadata.json。可独立测试 ELF section/symbol/relocation/XPM1，BPF BTF/map/entry/rewrite、Image/fixup/container、JIT、Report、Index。各操作选择固定真实 ELF、已知指令与格式规格、LLVM 或独立参考为期望；不使用被测 pack/unpack 自证。保留 JIT 算术（含除零）、控制流、ABI、Helper/Map、有效 Oracle 等既有独立语义覆盖。报告可用人工核对的 fixture 与原始 disassembly 做独立测试。

Ninja 管理 depfile、工具文件、命令变更、增量和并行。mcu 只做必要的现有 index、SDK depfile 和输入一致性检查及失败清理；损坏/失效输出交给 Ninja 重建，生成失败不允许将旧成功结果冒充当前结果。任一构建/最终校验失败返回非零，撤销不再有效的 index 及相关产物，不误删仍有效的其他程序/模式。输入在构建期间变化应拒绝不一致结果。通过 PREVAIL 前不得暴露本轮正式程序产物。不能仅凭文件存在信任缓存，也不得新建并行增量调度或持久状态账本。

**验收 G2：**

- 从 G1 正常入口实际生成并执行单程序 firewall 全后端图，审查 ninja -t commands/-t graph、真实输出以及上述数据依赖、领域职责；不接受把整个后端或 Shell 文本解析藏在 rule 或包装器中。以完整示例的语义而非行数、节点数裁决。
- 分别测试真实 Ninja 无变化、C/SDK 变更、工具/参数变更、缺失或损坏的输出。修改 verifier 触发验证而不重新编译原始 BPF；移除原始 ELF 触发必要重建；删除一份反汇编文本只重建受影响的报告链。实际比较构建前后持久文件、修改时间及执行节点，确认正常编译/报告未创建或清理临时目录（含工具内部间接调用），未复制工具或额外账本。独立库和 CLI 测试不要求启动整个编译系统。
- 使用 PREVAIL 非零、超时、无 PASS、多个 XDP entry、非法 BPF 的反例核对失败传播和旧产物撤销；不能把未验证 ELF 发布。模拟输入变化/产物篡改/失败中断，检查现有 index 门槛；验证 Report 的真实机器码和汇编及缺失/非法输入。编译、PREVAIL、字节完整性及独立语义各自记录，不能互相替代。
- 参考图的已做检查见 [测试记录](../tests/ninja-example-static.md)，实际工具链必须按 G1–G4 验收。

现状：[make/build.py](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/make/build.py) 和 [make/portable_build.py](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/make/portable_build.py) 隐藏多步编译；[make/build_state.py](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/make/build_state.py) 有旧状态系统；[make/prevail_gate.py](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/make/prevail_gate.py) 是 verifier 现有行为依据；[make/obj_report.py](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/make/obj_report.py)、[tools/src/portable.rs](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/tools/src/portable.rs)、[make/btf.py](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/make/btf.py) 是解析/反汇编迁移线索。

## G3. 实验源码

正式程序按实验组织，每个实验目录有 README。建议布局如下（目录名可等价调整）：

| 实验目录 | C 程序 |
| --- | --- |
| experiments/firewall/ | firewall |
| experiments/just_drop/ | just_drop |
| experiments/just_tx/ | just_tx |
| experiments/exec_bench/ | noop、prime、log2、copy、fletcher32、bsort、strcmp |
| experiments/case/ | case_mark、case_swap |

README 记录实验目的、程序行为、输入输出/协议、关键 Map/Helper 及编译方式；协议依据 [docs/benchmarks.md](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/docs/benchmarks.md)。tests/ 仅为工具链测试、诊断及 fixtures。程序 stem、归档名、发布目录及协议不变。使用唯一程序发现/清单规则支持默认 12 程序与明确选择；拒绝重名，诊断和 fixture 不默认发布。

每个程序是一份完整 C，程序逻辑直接写在自身文件中。BPF 和 RV32 编译同一源文件，目标差异只由 include-bpf/ 和 include/ 提供；禁止通过宏选择不同目标业务逻辑或从共享头文件选择不同实验程序实现。普通常量宏、include guard、SDK 内部实现允许。EXB2 按各任务具体算法、协议与入口内联；Case/just_tx 同样按实际逻辑整理，接受必要代码重复。保留实际程序 ID、协议、Map/Helper、返回值和语义，不修补超时或更换算法。归档直接保留实际编译 C 的字节，删除 source_snapshot 和自定义头文件展开。禁止未声明外部业务头文件，检查 CPATH/C_INCLUDE_PATH 等隐式输入；仅允许对应 SDK 与明确必要编译器资源。迁移或确认其他消费者之前不删除仍被 host/HAL/reference fixtures 使用的共享代码。

**验收 G3：** 实际构建发现完整 12 程序且 README 与代码对应，显式选择仍使用原 stem/输出名；旧 tests/xdp 不再是生产入口。逐个从隔离的固定测试目录仅带单份 C 和对应 SDK 编译两个目标，确认归档 C 与实际输入字节一致；非法外部依赖被拒绝。对照固定基线协议、可执行 section、Map/Relocation 及独立行为测试，报告差异；不要求无关调试字节完全相同，不接受仅能编译而程序语义退化。以新的独立源码与行为测试替换已废弃的快照测试，保留有效 fixtures。

现状：[source_snapshot](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/make/build_steps.py#L135)、[EXB2 shared header](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/tests/xdp/exb2/exec_program.h)、[copy.c](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/tests/xdp/copy.c)、[case_mark.c](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/tests/xdp/case_mark.c)、[just_tx.c](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/tests/xdp/just_tx.c)。

## G4. Release 与部署契约

保持 [PR7 的公开产物规格](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/docs/artifacts.md)：portable image v1、v3 index、Compact ELF V0，RV32IMC/ILP32 ESP32-C3、JIT RV32IM。完整默认构建不需要固件，12 个程序各有 AOT/JIT/rBPF 的 bin/json（共 36 个模式），保留原始 BPF 与 RV32 reference .o、C、report、index。不要把公开 JSON 换成 ELF 或变更消费者接口。Native base/entry_offset=0，真实 canonical 地址编码及完整 fixups、Map 布局按规范；rBPF 以 AOT 的 canonical map order/offset 为依据。XPOST 负责真实部署地址绑定/设备装载。libbpf-mcu 的独立 bind 库及 CLI 仅消费已发布的 image/layout/index 与目标布局，不读 C 或编译对象，不调用 Clang/LLD/JIT。旧固定地址生产路径删除；保留独立直接链接参考（只用于验收，与 binder 不共用地址修补算法）。

tools release 提供 prepare、verify、next-tag 等现有功能；按现有正式发布目录契约直接读取 G2 已构建的程序目录，不重编译为另一套发布物。可以在操作系统的系统临时目录创建本次归档/解包校验工作区；归档完成且验证后，将 12 个 .7z、release.json 等所需交付文件放入请求的最终位置并删除本次拥有的系统临时目录，失败也清理该目录，不删除正常 build/intermediates。不要把中间文件、Ninja 日志或测试数据打进正式归档。版本遵循 [共享 release-version 决定](https://gitea.nas.nan-mu.cc/mcp/libbpf-mcu/src/commit/6c82e8b01366848bd22bcd476d738bcd61a3cebd/decisions.md)：v0.1 patch 递增，重试复用已分配 tag。普通 build 不依赖归档器。无需真实 GitHub 上传。

**验收 G4：** 通过正常入口从空 build/ 生成 12×3 portable 矩阵，无目标固件/真实地址。通过 tools release prepare/verify 得到真实 12 个归档，独立解包检查全部成员、哈希、索引、真实 fixups，确认系统临时目录清理且正常中间文件未被删除、无中间文件入包；失败或重试保持原发布规则。用解包后唯一必要的发布成员对两个不同合法目标布局绑定 AOT/JIT（含真实 helper/map fixup 样例），与同布局独立直接链接比较机器码、map/helper/entry；保留 PR7 全矩阵参考验证，rBPF 字节码与 map index 不变。缺 fixup 即便重算哈希仍拒绝、真实地址伪造 base=0 不通过、超容量/溢出/未知 fixup/路径逃逸拒绝。记录不一致原因与证据。仅验证生产者与绑定库/CLI；XPOST 真实消费者接入及设备实测属于后续任务，不据本轮结果宣称完成。

现状：[make/native_image.py](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/make/native_image.py)、[make/rv32_release_elf.py](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/make/rv32_release_elf.py)、[make/compare_release.py](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/make/compare_release.py)、[make/retarget.py](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/make/retarget.py)、[make/layout.py](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/make/layout.py)、[make/release.py](https://github.com/nan-mu/libbpf-mcu/blob/c235b94ffa065ab132ae5ceb54a36db2e3e6d10a/make/release.py)。

## G5. 迁移、清理与测试入口

先核对所有第一方功能的真实消费者，逐项说明归属或删除依据：

| 现有路径 | 迁移线索（不是完整文件清单） |
| --- | --- |
| make/cli.py、build.py、build_state.py、build_steps.py、portable_build.py | G1–G3；删除旧状态/包装/快照路径 |
| btf.py、xdp_section.py、prevail_gate.py | 共享 BPF / verifier |
| rv32_release_elf.py、native_image.py、xpost_elf.py、xpost_mem.py | ELF/Image |
| obj_report.py、layout.py | Report/Index |
| release.py | tools release |
| retarget.py、compare_release.py | 独立直接链接参考 |
| tools/src/bpf_meta.rs、portable.rs、jit_image.rs、main.rs、jit/src | 对应唯一 Rust 库和二进制 |
| Sail、Oracle、stack_budget、tests/unused、其他辅助代码 | 查真实消费者和独立验证价值；必要功能迁移，无用才删除 |

删除所有第一方 Python、Pixi、旧 CLI/fallback、重复解析/调度及不再使用的历史生产路径。有效 Oracle/Sail/stack 功能以 Rust 或现有外部工具保留；不改第三方源码、必要 C、linker/Ninja 数据。不能凭 unused 目录名称删除有效 fixture。若存在跨仓库消费者仍需旧入口，定位并记录后续迁移，不擅改消费者或恢复 Python fallback。

测试按功能先定义输入输出与独立预期（tdd），保留已有有效用例而非机械移植。仅使用 Cargo 原生测试机制：单元测试置于对应 src 内，真正的二进制/工具链集成测试置于相应 crate 的 tests/ 下；外部工具依赖重的测试可用 #[ignore] 并在文档中给出原生 cargo test 命令。L0–L4 仅作验收范围分类，不实现测试调度器。

| 层级 | 运行范围 |
| --- | --- |
| L0 单元 | 确定性解析、计算、边界条件；固定 fixtures，无需 Ninja/LLVM |
| L1 工具契约 | 独立二进制或公开库的真实输入/输出与错误条件（G2） |
| L2 编排 | G1/G2 真实 Ninja、可用替身记录参数与局部增量/失败；关键调用必须实测 |
| L3 Smoke | 正常入口 + 真实 LLVM/PREVAIL/Ninja；just_drop、firewall、代表 EXB2、非法 BPF；各模式、报告/索引 |
| L4 Full | G3 全程序源码验证及 G4 完整矩阵、归档、独立参考 |

**验收 G5：** 实际运行 L0–L4（先 smoke 后 full），记录每项环境、命令、结果、产物及尚未通过项；未执行不得记通过。检查实际活动调用无旧 Python/Pixi 及重复实现，保留所有有价值功能和独立测试。更新 README、AGENTS.md、docs/artifacts.md、架构地图和各实验 README；架构决定只保留一个权威位置，其他文档引用，不重复完整段落、表或验收规则。验证新入口、说明和格式一致，完成迁移清单及 diff 检查。

## PR8 审查修订（2026-11-28）

以下是本轮增量验收的唯一出处。其他 G1–G5 契约不变。

### R1 · 直接 Cargo 入口

删除根目录 mcu Shell 文件、Rust Action::Test 及其参数和分层调度分支；不以脚本、Cargo alias、xtask 或其他自定义测试调度器替代。保留 build/clean/doctor 及其现有构建参数；Cargo 自动准备 mcu-object/mcu-jit 的行为不变。所有用户文档和调用点改为直接 Cargo/Rust 入口。集成测试直接使用 Cargo 提供的 CARGO_BIN_EXE_mcu 或其他实际二进制位置，不再依赖根目录脚本；从其他 cwd、含空格路径及自定义 CARGO_TARGET_DIR 的调用仍应工作（从其他 cwd 可明确指定 --manifest-path）。

验收：实际运行 cargo run --locked -p mcu -- --help、build、doctor 和 clean 的正例；确认 test 子命令被拒绝，根目录脚本及其所有活动引用已消失。

### R2 · 原生测试组织

将 crates/mcu/tests/experiments.rs、generate.rs 的单元测试迁至实现所属 src 模块，检查 crates/mcu-object/tests/ 中可直接在库中验证的逻辑是否应随实现放置。保留真正执行二进制、真实 Ninja/LLVM/PREVAIL、完整归档和独立链接对照的集成测试，以及独立 JIT Oracle。测试附有人类可读的说明，解释用例目的、独立预期和边界；不得通过降低断言、删除有效负例或将失败标为成功来通过。将 jit/scripts/check-xdp.sh 的有效检查迁到 Rust 测试并清理不再使用的脚本/清单；核对 linker/sail/build.sh 的真实消费者，有用则保留其独立验证功能并迁移第一方脚本逻辑至 Rust，无用才删除，不修改第三方工具或必要 C/linker/Ninja 数据。无新调度器。允许重测试使用 #[ignore]，但文档给出可直接复制的 Cargo 命令，并实际执行受影响的 L0–L4 及 Oracle。已有 Oracle 27 项失败为基线，不视为通过；核对是否新增失败。

验收：按真实功能核查测试位置；cargo test --locked --workspace --exclude xpost-jit-oracle，以及相应 --test/--ignored 真实工具链测试；独立 Oracle 运行并记录结果。

### R3 · 构建目录与清理安全

统一解析/检查 build 和 clean 的输出根。禁止覆盖或清理 checkout 本身、其祖先、Git 元数据、源码/SDK/测试/文档等仓库已有内容或任意已有非构建目录；处理 ..、符号链接和路径别名。正常默认 build/ 与合法自定义目录可使用。新目录、空目录、已有可信构建目录和失败后的可恢复状态需要有清晰策略；不能仅因任意目录里有一个带生成注释的 build.ninja 就许可删除其中的用户数据，不得引入通用状态管理系统。明确预期的输出目录所有权和 clean 清理范围，避免删除 Cargo 缓存及其他路径。

验收：在隔离临时 checkout 中针对 crates/、experiments/、仓库根/祖先、已有无关目录、符号链接、伪造/已有图、正常默认和自定义输出目录编写正负例；验证拒绝后原文件未变，合法 clean 确实有效，不触碰真实工作目录。

### R4 · Release 来源记录

修正 tools/src/release.rs 中归档阶段读取当前 HEAD、Ninja 图、工具 SHA-256 的语义。归档时的工具/源码环境不必然等于历史产物生成环境。不得将准备归档时测得的值宣称为已经独立验证的构建来源。优先最小修订：明确区分实际能验证的构建输入、归档时观测值和未经验证的历史来源；如果宣称实际构建来源，则须有真实构建时证据并在归档阶段校验。保留发布字节契约，避免新增第二套构建状态系统或不必要的新产物；正式发布文档继续要求从固定干净 checkout 的全新 build/ 生成。

验收：真实构建并在归档前替换/修改工具或相关输入，证明确有证据的来源不被伪造，或归档信息明确只表示归档时观测值而不冒充历史编译证明；正常 12×3 矩阵、归档验证及双布局独立直接链接仍通过。

### R5 · C 功能与最终清理

保留当前 12 个独立 C 实验程序；七个 EXB2 AOT 的额外边界检查/offset mask 属于用户接受的功能等价实现，不要求恢复旧机器码或在本 PR 测量设备性能。核查固定 8258 字节缓冲区、64 字节头、n/rounds/variant/长度验证、返回值、结果/摘要/输入与 scratch 写入、极限长度、Map/Helper 和网络帧行为；用原有独立参考/有效 fixture 和代表性反例确认功能，不做无关 C 重写。将受影响的 AOT 性能基线变化记录在适当文档中，旧实测结果不可直接归属于新产物，重新测量属于后续 XPOST 实验。更新 README、AGENTS.md、docs/artifacts.md、docs/architecture.md、tests/README.md 等所有实际调用点；清理本轮任务书临时输入，保留正式审计证据。

验收：无新 C 功能回归，CLI/测试文档与实现一致，实际本地完整归档/绑定验证及独立审查完成，git diff --check 通过。未执行的设备或模拟器验证应如实标记，不声称全域正确性证明。
