# libbpf-mcu PR #5 · 源码复编与 JIT 差分测试

在 `nan-mu/libbpf-mcu` 的独立 worktree 中，沿用 `agent/program-release-pipeline` 的最新提交，目标分支为 `main`。本轮审核基线是 `89df7f62`。完成后三项改动交回同一条开放的 [PR #5](https://github.com/nan-mu/libbpf-mcu/pull/5)，由用户审核。

## 1. 让发布的单个 C 文件能在仓库外复编

修正 `make/build_steps.py` 的源码快照生成。构建输入引用的程序私有头文件应随顶层 C 一起交付，保留条件编译分支和对目标 SDK 的引用。覆盖两种已复现的输入，均走 `pixi run build bpf --inputs`。

| 包内夹具 | 放置与触发方式 |
|---|---|
| `fixtures/source/repo_comment.c` 和 `action.h` | 放在临时 worktree 的 `tests/unused/` 子目录。引用头文件的行末带有合法的 C 注释。 |
| `fixtures/source/external_input.c` 和同一份 `action.h` | 放在仓库外同一目录，通过绝对路径选择 C 文件。这里使用普通的双引号 include。 |

分别从程序产物取出顶层 C，在只能访问对应 SDK 头的空目录复编，核对 BPF 可执行节与原始对象一致。把临时头里的 `XDP_DROP` 改成 `XDP_PASS`，在同一输出目录重建，确认程序返回值从 1 变为 2、`report.md` 展示新源码、`index.toml` 的长度和 SHA-256 与实际文件相符。回归默认 12 个程序的构建，并用已有跨目标样例检查 BPF 和 RV32 分支仍可复编。

## 2. 让常规 JIT 测试执行网络程序的收包逻辑

为 `jit/scripts/check-xdp.sh` 和 `jit/oracle/tests/differential.rs` 接入同一组包内夹具。每项使用 `fixtures/network/<程序>.input.bin` 作为输入，使用同目录的 `<程序>.expected.bin` 作为独立的整帧期望。两个入口的每个执行侧都要核对返回值和响应。

| 程序与输入 | 应观察到的结果 |
|---|---|
| `case_mark`，82 B | 返回 `XDP_TX`（3），交换 MAC，写入大端版本 1 和 `CAS2`，UDP 校验和清零，整帧匹配。 |
| `just_tx`，74 B | 返回 `XDP_TX`（3），交换 MAC，保留 UDP 校验和，整帧匹配。另按键读取每侧的 `rxcnt[17]`，确认从 0 增至 1。 |

保留两个入口原有的短输入作为负例，断言 `XDP_PASS`（2）、包内容原样，`just_tx` 计数仍为 0。将这两项正例列为必过用例。临时移除 `just_tx` 的计数递增后，即使两侧得到相同响应，两个入口也应因计数不符而失败。恢复后重跑。

## 3. 把六个 EXB2 用例写进本地差分报告

将 `bsort`、`noop`、`copy` 的完整包和短包结果接入 `jit/oracle/results.json`。每个用例在同一次完整运行中恰有一条记录，进入汇总，并能用现有 `query.py` 按程序名和状态查到。沿用仓库内的 `tests/fixtures/exb2/` 和逐侧断言：8258 B 完整输入返回 2 并匹配整个期望响应，前 8 B 的短输入返回 0 且原样保留。临时改动一个期望字节，确认对应记录变为失败，恢复后再生成最终报告。

## 交付验收

在最终提交运行 `pixi run build`、`pixi run test`、`sh jit/scripts/check-xdp.sh` 和 `cargo test --release --manifest-path jit/oracle/Cargo.toml`。在 PR 中给出提交号、两种源码的包外复编结果、网络正例各侧的返回值与计数、六条 EXB2 记录的查询结果。完整 Cargo oracle 在审核基线已有 27 个 ALU32 差异；按失败用例逐项比对，分别说明既有差异和本轮新增失败。
