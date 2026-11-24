# libbpf-mcu PR #6 · 修正正式发布入口

续做 [PR #6](https://github.com/nan-mu/libbpf-mcu/pull/6)，在任务 worktree 使用该 PR 的实际 head。以下发现基于 `7ff219700c2e56231aa06978fe5dabf21a5030ce`。更新同一 PR，交维护者审核。

## 目标

给定已链接的固件 ELF，正式发布入口能产出完整的 12 个程序归档。每包按 [v3 归档结构](references/archive-layout.md) 提供原始 eBPF 对象和 AOT、rBPF、JIT 三种部署容器，共 36 项部署。

## 本轮改动

1. **从已有 ELF 读取构建输入。** 当前完整构建经 `make/build.py` 调用 `make/release_firmware.py::prepare_firmware`，自行从固定 XPOST 源码选择 Cargo feature 并编译固件。删除这条路径和对应的说明。让正式构建读取调用者提供的已链接 ELF，记录输入来源与摘要。缺输入时报告具体程序、模式和所需文件。保留单模式构建、显式输入、`--firmware`、`--build-dir`、默认 `build/` 与 `clean` 用法。
2. **用现有 JIT 生成产物。** 撤回 `414a2a10db79dd441b7da2c95005142ae43f7ad6` 中为压缩镜像所做的 JIT 访存代码生成改动。沿用 PREVAIL 和既有格式、容量检查。容量检查拒绝生成某个容器时，记录缺失项和诊断，批次保持未完成。
3. **删掉错配的测试和验收条件。** 删除 `make/test_build_state.py::test_default_selects_the_complete_release_build`，它只检查 mock 调用参数，旧的固件自编路径也能通过。移出与本轮撤回的 JIT 改动配套的 `jit/tests/diff.rs::unaligned_doubleword_load_can_replace_its_base`，供未来单独审查 JIT 时使用。清掉要求编译 XPOST 固件、选 feature 或缩小 JIT 镜像的验收步骤。保留已有 JIT 行为回归、最终包缺件回归及有效的索引和选版检查。

## 验收

先核对最终 diff 与正常入口的实际代码。在 PR 中指出三处依据：正式入口如何读取已有 ELF，JIT 生成代码相对原基线的变化，发布准备如何在缺件或容器无效时停止。实现改动和验收结果各自记录。跑绿的测试只能支持它实际断言的行为。

完整程序清单是 `firewall`、`just_drop`、`just_tx`、`noop`、`prime`、`log2`、`copy`、`fletcher32`、`bsort`、`strcmp`、`case_swap`、`case_mark`。每个程序都需三种部署容器。删掉必需容器及其索引行后，即使摘要重新计算正确，正式校验仍应报告缺件。用现有回归覆盖这个反例。

对最终提交经正常入口生成的候选归档，检查实际成员、v3 角色与路径、摘要及容器内容。用同批 `just_tx.7z` 核对三种容器和 `rxcnt`，记录原生对象对定址的支持及 rBPF map 绑定。复用适用的候选实物和 [XPOST 只读检查器](https://github.com/nan-mu/xpost/blob/b5a44072ed57657c7482758412cccf1fd93df6fa/xpost-artifact/src/bin/verify-medium-release.rs)。缺输入或实物就记录具体阻塞。容量和字节一致性的结果只用于判断对应的部署条件和归档内容。

运行仓库已有的 `pixi run test` 与适用检查。新 tag 在维护者指定的 `v0.1` 系列里按整数递增最后一段，重试同一次发布复用已分配的 tag。PR 附固定 head、代码依据、删除的测试、实测结果和未验证项。有候选时给出归档摘要及取得方式。正式 Release 待维护者另行授权，沿用现有摘要核验和续传规则。
