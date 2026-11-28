# PR #8 · Rust/Ninja 工具链审查修订

目标仓库：[nan-mu/libbpf-mcu](https://github.com/nan-mu/libbpf-mcu/pull/8)。在现有 PR #8 的 agent/rust-ninja-toolchain 分支及独立 worktree 上继续；审查基线为 `ef8b05ae9dfa2c84507cd2e45d335f6de0032dfa`。开始前核对实际 head，如有新提交先识别差异。不得创建替代 PR、重做已完成的迁移或修改 main。共享架构决定固定于 [Gitea main 71ec39c](https://gitea.nas.nan-mu.cc/mcp/libbpf-mcu/src/commit/71ec39c0e96063e70301f5fe5d4f41b667019abe)。

## Goal

保留已经实现的 Rust/Ninja 工具链、独立 C 实验源、发布和绑定契约，完成审查中用户确认的入口、测试组织、目录安全、发布来源记录及说明修订。行为规格为 [references/design.md](references/design.md)，本轮只执行其中的 R1–R5；G1–G5 的其余契约继续有效，复用仍适用的已完成证据，不重新实现。

使用 Matt implement / tdd：针对实际问题先定义失败用例，再做最小修复；用独立 Reviewer/Tester 从最终 head 复核真实调用链和反例。不得把历史证据当作本轮新运行结果。

## 本轮边界

- 保留四个 Rust 可执行程序及独立共享库、Generate/Execute 分离、Ninja 直接编排、原有 portable image v1、index v3、Compact ELF V0 和零地址绑定契约。
- 用户已确认 EXB2 的 AOT 机器码变化可以接受，只要求功能正确。审查已对照全部 12 个 C 源码：firewall/just_drop 字节一致，just_tx/case 为等价展开，七个 EXB2 kernel 与展开的协议逻辑一致。新增 AOT mask/边界检查不改变有效输入的功能。保持当前 C 实现，不为恢复机器码或性能基线而改写 C，不引入目标专属业务逻辑宏；若复测发现具体功能缺陷，给出可复现输入及证据后按最小范围修复。
- 仅修改 libbpf-mcu，不修改 XPOST、固件、数据库或历史实验数据；不烧录、不跑设备性能实验、不新增 GitHub CI、不自动发布 Release、不自动合并。不引入额外测试框架、启动包装脚本或生产状态管理层。

## 独立验证与交付

独立 Reviewer/Tester 应取得本版任务书、R1–R5、实际最终 head、真实执行命令及输出。分别核对 CLI 无包装器/测试入口、测试位置和运行真实性、构建与 clean 的破坏性反例、发布来源字段语义及 C 功能契约，检查相关原有验收没有回归。至少运行受影响单元/集成测试、真实 LLVM/PREVAIL/Ninja smoke、完整本地 Release 矩阵及独立双布局 AOT/JIT 对照，运行 Oracle 并区分已知失败/不支持与新失败。不能运行的检查标明阻塞及原因，不记为通过。复用旧证据时明确其适用的提交和未变化输入，不声称重新执行。主代理修复后复核最终 head。

在现有 PR #8 更新英文正文及审计记录，报告 R1–R5 的 PASS/FAIL/BLOCKED/NA、实际命令、证据、独立审查角色和未解决问题；运行 git diff --check。删除导入的 taskbook.md、GLOSSARY.md、decisions.md、references/ 与其他仅用于任务书交付的临时附件（不要删除正式源码、有效 fixture 或仓库固有文件）；保留必要的 .audit 审计记录，测试代码不得位于 .audit。提交并推送到现有 PR 分支，等待用户审核。
