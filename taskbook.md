# libbpf-mcu PR #5 · 修复源码快照并精简测试

在独立 worktree 中沿用 `agent/program-release-pipeline`，目标分支为 `main`。审核基线为 `f500f38e`。完成后更新同一条开放的 [PR #5](https://github.com/nan-mu/libbpf-mcu/pull/5)，交用户审核。

## 1. 让公开 C 保留头文件的编译语义

修复 `make/build_steps.py` 的 `source_snapshot()`。程序通过 `pixi run build bpf --inputs` 构建后，从产物取出顶层 C，仅配对应 SDK 和相同编译参数，应能在仓库外复编，且 BPF 可执行节与原对象逐字节一致。保留宿主、BPF、RV32 的条件分支、业务注释和 SDK 引用。带保护宏的互引应自然终止，`#pragma once` 按实际生效的包含去重。普通头仍可在不同宏定义下合法地重复包含。[现行产物约定](https://github.com/nan-mu/libbpf-mcu/blob/f500f38eccdeb950718ac0578fab0f777ff06dd6/docs/artifacts.md#L27-L29)

附件只有一个入口 `fixtures/header_graph.c`。每次将它和所选目录里的头文件放在同一目录，使用原始源码编译的对象作为独立参照。

| 布局 | 基线故障 | 修复后的验收 |
|---|---|---|
| `fixtures/guarded/`，放在仓库外，由绝对路径选入 | 两个头各有保护宏并相互引用。原件返回 `XDP_DROP`（1），快照生成报 `cyclic program include`。 | 正式构建成功，公开 C 的包外复编通过，指令与原件一致。 |
| `fixtures/once/`，放在仓库内的非默认夹具目录 | 两个业务头共用一个 `#pragma once` 定义头。原件返回 `XDP_PASS`（2），公开 C 复编时报枚举重复定义。 | 同样通过构建和指令比对。同一用例同时验证行尾注释、`#if 0` 之后的活跃 include，以及无保护的 `part.h` 在两种宏定义下都能生效。 |

## 2. 合并重复测试，留下能抓住不同错误的检查

| 现有测试或夹具 | 本轮处理 |
|---|---|
| `make/test_jit_build.py` 的显式输入快照测试 | 改成使用上述两种布局的一项参数化回归，覆盖仓内和仓外入口。用隔离复编和可执行节比对代替搜索特定 `#define`、`#include` 拼写。行尾注释保真只查一次。覆盖迁移后删除 `tests/unused/source_snapshot/` 下被替代的 `repo_comment.c`、`external_input.c` 和 `action.h`。 |
| `test_exact_executable_bytes_and_source` 与同名产物撤回测试 | 删除手拼 `/* Begin … */`、`/* End … */` 来预测快照全文的代码。直接用**实际交付的 C** 核对报告内嵌内容，保留机器码与容器字节比对。`make/test_build_state.py` 的同名撤回用例只需确认旧产物存在、失败后已撤回，移除其中重复的头文件文本断言。 |
| 真实程序的跨目标复编与增量构建 | 保留 `copy`、`case_mark` 对 BPF 和 RV32 可执行节的比对，以及修改编译依赖后重建能得到新对象的检查。前者能发现目标分支丢失，后者能发现仍在使用旧产物。 |
| 程序行为、验证器与容器 | `tests/xdp/` 的 12 个程序是发布输入。`tests/fixtures/` 的 EXB2 与网络期望帧用于发现两个引擎同时算错的情况。保留实际消费的 JIT 夹具、PREVAIL 拒绝用例和双 map 容器绑定检查。复用现有验证入口。 |

清理本 PR 为存档而复制的六份旧源码：`tests/unused/` 下的 `bsort.c`、`fletcher32.c`、`case_mark_legacy.c`、`case_swap_legacy.c`、`just_drop_legacy.c` 和 `just_tx_legacy.c`。已核实它们与基线 `80cb5b16` 中的对应文件逐字节相同，当前仓库的测试入口未使用这些副本。删除副本，并将 `docs/benchmarks.md` 的历史说明指向固定提交。如果接手时发现某份仍有实际调用，保留该份并在 PR 列出调用点。同时将 oracle README 中过期的用例数量改为指向当前用例清单或报告。[旧版源码](https://github.com/nan-mu/libbpf-mcu/tree/80cb5b16b4dc7a70209b18fa08a913b0bc94f994/tests/xdp)

## 3. 交付与合并判据

在最终提交运行 `pixi run build`、`pixi run test`、`pixi run python make/layout.py verify --build-dir build` 和 `git diff --check`。在 PR 中列出两种布局的包外复编及指令比对结果，确认默认构建仍产生 12 个程序，并用几行写明删了哪些测试或夹具、相应行为由哪里验证。以上结果通过，且已有独立覆盖仍在，即可结束本轮源码与测试清理验收。
