# PR #8 · Rust/Ninja 工具链重构

目标仓库：nan-mu/libbpf-mcu。开发基线：已合并 [PR #7](https://github.com/nan-mu/libbpf-mcu/pull/7) 的 main `c235b94ffa065ab132ae5ceb54a36db2e3e6d10a`。从包含该基线的最新 main 建独立 worktree，PR base 为 main；执行时核对实际 PR 编号，当前尚无 GitHub PR #8。共享术语与决定固定于 Gitea main [6c82e8b](https://gitea.nas.nan-mu.cc/mcp/libbpf-mcu/src/commit/6c82e8b01366848bd22bcd476d738bcd61a3cebd)。交付开放 PR，等待用户审核；不自动合并或发布 GitHub Release。

## Goal

完成第一方工具全 Rust 迁移，让正常构建通过一个入口获得可直接阅读的 Ninja 图和现有 PR7 契约的真实程序产物。用户已确认的设计与各项目标的验收条件集中于 [references/design.md](references/design.md)，该文件是本任务的行为规格；不需要从旧版任务书拼凑要求。

用 Matt `implement` / `tdd` 执行以下工作组。先写能区分目标行为与旧行为的失败测试，再实现；允许本 PR 内逐步替换，最终必须清理旧路径。G1/G2 建立单程序端到端闭环，G3 补齐正式实验源码，G4 用完整矩阵验收，G5 完成清理。可并行处理无依赖的库功能。

| 目标 | 实施和验收出处 |
| --- | --- |
| G1 编译系统入口、workspace 与职责边界 | [design.md](references/design.md) G1 |
| G2 可阅读的 Ninja 构建图、独立功能及持久构建中间文件 | 同上 G2；生成图之前阅读 [完整 firewall Ninja 示例](references/firewall.build.ninja) 与 [示例说明](references/ninja-example.md) |
| G3 实验源码与双 SDK | design.md G3 |
| G4 发布、绑定及独立参考 | design.md G4 |
| G5 迁移删除、文档、测试入口 | design.md G5 |

[firewall.zero.ld](references/firewall.zero.ld) 是示例图的生成阶段输入。示例接口和路径可等价调整，不以节点数量或逐行一致为验收。不要将参考图硬编码为生产实现。

## 基线与已有证据

G1–G5 的源码依据列在 design.md 对应小节，均使用上述固定开发基线。[Ninja 示例测试记录](tests/ninja-example-static.md) 仅证明参考图在真实 Ninja 下的语法和替身调度行为，实际 Rust、LLVM、PREVAIL、镜像及 Release 尚需验证。复用条件未变的已有测试证据；历史版本的结果不直接套用于新图。先核对证据适用范围，发现不一致时记录具体差异及受影响验收；执行本轮尚未覆盖的检查。不得把参考图通过当成真实工具链已通过。

本任务仅改 libbpf-mcu；不修改 XPOST、设备固件或实验数据，不烧录/运行硬件或网络实验，不新增 GitHub CI。GitHub 读写走用户授权的独立 GitHub 插件；第一方工具迁移不要求改写第三方实现。PR7 后续 XPOST 部署接入仍由其对应任务承接。

## 独立模型验证要求

将本固定提交的任务书及全部引用附件、PR7 任务书及其有效决定、实际开发 PR 最终 head、真实命令和产物证据交给未参与实现的现有独立 Reviewer/Tester。核对历史任务书与本版 G1–G5，确认没有遗漏旧目标、未经授权的弱化或新旧接口偷换。独立从用户入口追踪真实调用链，不仅检查测试绿灯或实现者摘要。按 design.md 各 G 的验收条件直接判断，不另造第二套验收规格。

重点以 G2 的实际图与文件依赖核查中间文件是否确实跨构建保留、是否有隐藏的临时目录/业务解析/编排；以 G3 的真实源码和隔离编译判定迁移；以 G4 的真实归档和独立直接链接对照判断发布契约及地址绑定。针对每项验收考虑可能通过局部检查却失败的实现，以及会被错误拒绝的合理实现。没有实际调用链或独立依据不得判通过；未授权的 XPOST 端到端部署标明后续未验证。

报告 G1–G5 对应的通过/失败/阻塞/不适用、实际模型/角色、独立性、受审提交、代码位置与证据。主代理处理问题后复核受影响项和最终 head。缺独立模型能力允许交付开放待审 PR，但不得宣称整体验收通过。使用 Matt `code-review` 和 `pr` 整理最终交付。

## Delivery

创建开放的 GitHub PR，英文正文给出实际基线/head、正常入口、迁移删除对照、实际生成图、L0–L4 结果及独立审查结论、缺项。验收按 design.md G1–G5，不重复维护验收条件。运行 git diff --check；发布归档在本地完成验证即可，远端发布或合并须另行授权。
