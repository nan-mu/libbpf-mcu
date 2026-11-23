# libbpf-mcu 任务书 · 程序构建、人工报告与本地 Release

仓库 `nan-mu/libbpf-mcu`。从 `80cb5b16b4dc7a70209b18fa08a913b0bc94f994` 建独立 worktree，工作分支 `agent/program-release-pipeline`，一个 PR 合向 `main`。本次改动限于生产端。

维护者对 T3 中的 agent 说“发布 `nan-mu/libbpf-mcu` 当前 `main` 的程序产物”，agent 完成本地打包、用 `gh` 发布并返回 Release 链接。下载者按程序取得一个 7z。程序通过包根的 `index.toml` 选择并校验产物。人打开对应的 `report.toml`，可以在同一份文件里看到本次程序的完整 C 源码、实际生成的机器码和对应汇编，以及生成它们的命令和参数。

## 1. 构建产物与唯一索引

默认输出改为仓库内的 `build/`，包括 Ninja 工作文件。显式 `--build-dir` 继续控制整个输出根。`pixi run clean` 只清默认根。用 `pixi run build bpf -c just_tx` 做默认构建和显式目录构建，再运行 clean，验证显式目录及原有 `../build/` 中的文件完好。

同一程序保留一份原始 Clang eBPF 对象，供 classifier 等读取。三个部署容器均由各自的真实构建路径生成，维持现有固件 ABI 与 Compact ELF V0 格式。下表为全模式的 `just_tx.7z`。

| 内容 | 正式成员 | 人工报告 |
| --- | --- | --- |
| 程序索引、实际使用的 C 源码 | `index.toml`、`src/just_tx.c` | — |
| 原始 eBPF 对象 | `bpf/just_tx_bpf.o` | `bpf/report.toml` |
| `llvm-aot`，Clang 从 C 直接编译为 RV32IMC | `llvm-aot/just_tx-vm-aot.elf` | `llvm-aot/report.toml` |
| `ebpf`，MCU 上的 rBPF 解释器执行 | `ebpf/just_tx-vm-ebpf.elf` | `ebpf/report.toml` |
| `jit`，主机 JIT 将 eBPF 编译为 RV32IM | `jit/just_tx-vm-jit.elf` | `jit/report.toml` |

**产物索引只留 `index.toml`。** 本地位于 `build/<程序>/index.toml`，发布时在包根生成对应所选模式的索引。旧 `<程序>/manifest.toml` 中的程序名、源码身份和可用模式直接归入索引。源码、原始对象、部署 ELF 均有包内相对路径、大小、SHA-256 和可判别的角色或格式。索引有版本，可独立定位和校验全部机器消费的成员。程序、模式与报告的位置已由目录约定，索引不以报告内容或报告摘要作为有效性条件。

下面是只选择 JIT 时的包内索引示例。`H_*` 和字节数示意字段关系，正式值由打包端读取真实文件计算。

```toml
schema = "libbpf-mcu.program-index.v2"
program = "just_tx"
source = { path = "src/just_tx.c", size_bytes = 3200, sha256 = "H_SOURCE" }
bpf = { path = "bpf/just_tx_bpf.o", size_bytes = 4096, sha256 = "H_BPF" }

[[mode]]
name = "jit"
role = "xpost_container"
format = "xpost-compact-elf-v0"
elf = { path = "jit/just_tx-vm-jit.elf", size_bytes = 2048, sha256 = "H_ELF" }
```

失败或失效的模式从本地可消费集合撤回，保留诊断原因，其他有效模式仍可读取。发布端将该集合与维护者选定的模式逐项比对，少一个必需模式就中止。多程序本地构建可枚举各程序的 index。新构建树、正式包和发布配置均不生成 `manifest.toml`。

## 2. report.toml 只给人读

原始 BPF 对象和每个已构建的部署模式，都生成一份可独立阅读的报告。内容按源码、汇编、生成参数排列。

| 部分 | 人打开报告后应看到什么 |
| --- | --- |
| `[source]` | `path` 给出主 C 文件的仓库相对路径，`text` 直接内嵌本次构建使用的该文件全文。保留 `#include`、注释、空行、换行和源码中的 map 声明。JIT 和解释器沿输入对象追溯到同一份 C 源码快照 |
| `[assembly]` | 对应产物各可执行代码段的完整反汇编。给出段名、地址或明确标注的段内字节偏移，每条指令同一行显示原始十六进制字节、助记符与操作数。正式发布也保留完整指令清单 |
| `[[generation]]` | 按执行顺序列出实际产生这份产物的步骤、可执行文件和展开后的参数，包括适用的编译、链接、主机 JIT、转换与封装。目标架构、优化级别、链接脚本、固件、槽位等若参与生成，在相应调用中可见。进程内步骤记录实际调用和有效参数 |

下例用一个返回 2 的小端 eBPF 函数展示三部分如何对照。实施 PR 须交付真实程序的完整报告。

```toml
[source]
path = "example.c"
text = '''
__attribute__((section("xdp")))
int example(void *ctx)
{
    return 2;
}
'''

[assembly]
listing = """
xdp  (byte offset)
0000  b7 00 00 00 02 00 00 00  r0 = 2
0008  95 00 00 00 00 00 00 00  exit
"""

[[generation]]
step = "compile"
argv = ["clang", "-target", "bpfel", "-O2", "-c", "example.c", "-o", "example_bpf.o"]
```

**机器码的取数位置决定报告是否可信。** 原始 BPF 报告读原始对象的可执行节。解释器报告读最终部署容器里经过 map 引用改写的 eBPF 指令。AOT 和 JIT 报告读最终容器的已链接机器码。借助带符号 ELF 恢复符号名时，先将相应代码区间与最终载荷逐字节比对。只反汇编代码区，保留指令边界。命令来自本次实际调用，不能用顶层 `pixi run build` 代替底层生成步骤。

删除另外生成的 map 定义表、map 索引和地址表、helper 或 slot 元数据表、固件摘要、产物哈希、构建指纹、PREVAIL 状态、计时及与指令无关的节转储。源码里的声明、实际指令的操作数和实际命令中的参数照实展示。构建、打包选型、校验、失效判断和旧导出均不得解析、回写或以这份报告的哈希判定成功。归档器可以按约定路径原样收录报告，整个 7z 的附件摘要自然覆盖其字节。

## 3. 拆除旧报告的机器读取路径

| 基线读取点 | 本 PR 的替换要求 |
| --- | --- |
| `make/build.py`、`make/ninja/graph.ninja`、`make/obj_report.py --maps-from`、`tools/src/main.rs` 的 `pack` | 移除传递人工报告的 `--bpf-toml`、`--addr-toml` 构建边。优先从实际 BPF 对象、已链接 ELF 与固件取得所需数据。外部工具若需要结构化输入，由构建阶段直接提供最小输入 |
| `make/jit_publish.py`、`tools/src/jit_image.rs::JitArtifact::assemble`、`make/layout.py::cmd_commit_xpost` | JIT 和解释器从实际构建输入取得 map 描述与地址依据。用 `just_tx` 的 `rxcnt` 对照迁移前后的 map 索引、地址、helper、slot 和容器载荷。只有证明独立生成路径等价，才移除解释器对 RV32 构建步骤的依赖 |
| `make/prevail_gate.py::_record_gate`、`make/layout.py` 的提交、撤回与校验逻辑 | PREVAIL 继续检查原始 eBPF 对象。验证结果、固件变化和输入失效由构建图及其内部状态处理。索引只公布可消费产物。保留锁、失败撤回、未变输入的增量复用和固件变化触发的重建 |
| `make/layout.py::export_legacy`、`write_legacy_toml`、`scripts/publish_artifacts.py::verify_package` | 旧布局导出从对象、容器和必要构建数据生成旧调用方需要的文件。包校验从 index 和真实文件取证。两个入口均可在人工报告被移走后工作 |

机器需要的私有中间数据留在构建目录，按实际消费者限定字段。不得把整份旧 report 改名后继续传递。旧布局导出保留 `rv32/jit/bpf-xpost` 参数和现有输出文件名，拒绝在同一目录混入第二种模式。历史 v1 树能由实际对象与 ELF 恢复的组合应继续支持。若旧树只在已退役的报告里保存了必需信息，指出缺哪项并要求从源码重建，不猜造地址或产物。

## 4. 离线打包与 agent 发布

**构建配置。** 将维护者确认的程序、源码、部署模式和逐模式固件写在 `release/programs.toml`，随源码版本化。仓库根不放 release plan。该配置只描述要构建什么，不收录版本号、附件路径、上传状态或发布命令，也不进入 7z。包根的 `index.toml` 继续作为唯一产物索引。

原始 BPF 覆盖 `tests/xdp/` 的全部正式程序，基线为 17 个 `.c`，排除 `tests/unused/`。仅发原始对象无需固件。首发后端和固件由维护者确认，保留实际使用的 `image_name`、`slot_symbol` 等选项。下例节选 `just_tx` 的 JIT 配置，源码和固件路径均相对仓库根，固件路径与摘要为示意。

```toml
schema = "libbpf-mcu.release-plan.v2"

[[program]]
name = "just_tx"
source = "tests/xdp/just_tx.c"
modes = ["jit"]

[program.firmware.jit]
path = "firmware/just_tx-jit.elf"
sha256 = "H_FIRMWARE"
```

**仓库提供离线入口 `pixi run package`。** agent 运行它即可读取上述配置、构建、生成每程序一个 7z、解包回验，并取得本次的源码提交、本地 7z 路径、文件名和 SHA-256。缺固件、固件摘要不符、同名输出冲突或必需构建失败时，指出程序和模式并终止。该入口可在未登录 GitHub 的开发 worktree 中验证。保留已验证的归档原件供重试。

**发布由 agent 直接操作。** 在现有 `docs/artifacts.md` 写明下面的步骤，从 `AGENTS.md` 指向该节。维护者的一次明确发布指令授权本次打 tag、上传和公开。普通“按任务书实施并开 PR”的请求只走 PR 交付。仓库无需额外的发布脚本或 GitHub Actions。

1. **固定发布提交。** agent 核对 `gh` 的目标仓库和认证，确认干净本地 `main` 的 HEAD 与远端 `main` 一致。固定该 SHA，从它读取配置并离线打包。创建 tag 前复核已验证的提交和附件集合。若是中断重试，先找同一提交已分配的 tag 和草稿。
2. **创建 tag 和草稿。** 新发布从远端合法 `v0.1.N` 标签中按数值取最大 N 加一，首个版本为 `v0.1.0`。同机发布互斥。用 `gh api` 向目标仓库的 `git/refs` 发 POST，将新的 `refs/tags/<tag>` 指向已验证的完整 SHA。遇到竞争先核对已有 ref，不覆盖。确认 tag 实际指向该提交后，运行 `gh release create "$tag" -R nan-mu/libbpf-mcu --verify-tag --draft --generate-notes`。
3. **上传并公开。** agent 用 `gh release upload "$tag" "$archive" -R nan-mu/libbpf-mcu` 上传每个缺少的附件。通过 `gh api --paginate` 读取该草稿数字 Release ID 下的全部 assets，按名称、上传状态和 `digest` 与本地原件逐一核对。集合完整、状态均为 `uploaded`、每个 `sha256:…` 一致后，才执行 `gh release edit "$tag" -R nan-mu/libbpf-mcu --draft=false`。回读公开状态，将 Release URL、tag、提交及附件清单交给维护者。
4. **恢复中断。** tag 已建但没有草稿时，核对 tag 实际指向后补建草稿。草稿中同名同摘要的已上传附件直接复用，只用原始 7z 补缺件。同名不同内容、tag 指向其他提交或远端多出附件时，停止公开并报告差异。已公开的同一次发布返回原链接。恢复过程中不使用 `--clobber`。

## 5. 旧功能清理

| 基线对象 | 处理结果 |
| --- | --- |
| `pixi.toml` 的 `publish-artifacts`、`scripts/publish_artifacts.py::main`、`scripts/release-plan.example.toml` | 移除旧正式命令、强制手填 tag 的入口及旧 set 配置。将仍使用的选项迁入 `release/programs.toml`，保留本地构建、解包与校验。删除仓库脚本中操作远端 tag、草稿及附件的分支，由 agent 按第 4 节直接调用 `gh` |
| `sets/<id>/`、外层 `release-index.toml`、聚合 `libbpf-mcu-artifacts-<tag>.tar.gz`、内外两份 `SHA256SUMS` | 清除生成、专用校验和旧双附件上传路径，保留路径约束、哈希、容器检查和解包回验 |
| `make/layout.py::_write_manifest`、`_rewrite_index`、旧报告生成器和读取者 | 移除新树对 v1 总索引、程序 manifest、报告之间哈希链的读写。重写 `make/obj_report.py::format_disasm` 相关输出，保留指令字节并取消发布时省略指令清单的行为。继续使用对象/BTF 提取、JIT 入库、Ninja 调度和容器解码能力 |
| 本地中间对象、调试 ELF、裸镜像、stamp 与固件 ELF | 保留有实际构建、调试或旧导出调用的文件，正式 7z 按第 1 节收录。AOT 旧导出仍提供 `esp32c3.o/.elf/.bin` 与所需 `aot_addr`，JIT 仍提供 `jit.bin/jit.toml`，解释器仍提供 `<程序>.bin` |
| `artifacts/firewall-jit-artifacts.zip` | 这是使用合成固件的历史演示包。确认新样例能重建且无固定测试或下载调用后删除并更新引用。仍有调用时在 PR 写明用途 |
| 测试、文档与仓库规则 | 在 `scripts/test_publish_artifacts.py`、`make/test_layout.py` 等删除只断言旧布局或报告哈希链的检查，将有效行为迁到新入口。更新 README、`docs/artifacts.md`、`AGENTS.md`、Pixi 入口及 `.audit/` 术语清单 |

基线对照用固定提交中的[构建规则](https://github.com/nan-mu/libbpf-mcu/blob/80cb5b16b4dc7a70209b18fa08a913b0bc94f994/make/ninja/graph.ninja)、[旧报告生成器](https://github.com/nan-mu/libbpf-mcu/blob/80cb5b16b4dc7a70209b18fa08a913b0bc94f994/make/obj_report.py)、[布局与导出](https://github.com/nan-mu/libbpf-mcu/blob/80cb5b16b4dc7a70209b18fa08a913b0bc94f994/make/layout.py)及[发布器](https://github.com/nan-mu/libbpf-mcu/blob/80cb5b16b4dc7a70209b18fa08a913b0bc94f994/scripts/publish_artifacts.py)。

## 6. 验收与交付

1. 真实构建 `just_tx` 的原始 BPF 和三个部署模式。逐份读取报告的 `source.text`，与本次构建输入快照及包内 `src/just_tx.c` 逐字节比对，核对 `rxcnt` 声明、注释和末尾换行均可还原。此项是对报告生成器的验收。逐份对照报告的指令偏移、字节与对应代码区，抽查汇编与独立反汇编结果，核对生成参数与实际命令记录。解释器使用改写后的载荷。AOT 与 JIT 各自对照实际后端输出。正式包包含约定的人工报告。
2. 在隔离构建目录移走或改写所有人工报告，再运行产物选择、机器校验和单模式旧导出。用实际构建图和调用记录确认 AOT、JIT、解释器及 PREVAIL 在构建期间也没有把报告当输入。报告可按需重新生成。篡改真实 BPF 或部署 ELF 时，校验必须失败。
3. 至少用两个程序和不同模式选择演练打包，对正式清单逐包解压，核对源码及原始对象的字节、模式集合、容器内容、大小和哈希。覆盖文件缺失、模式重复、路径越界、同名冲突、固件变化和失败重建。在无 GitHub 凭据的环境验证 `pixi run package`。按文档用模拟 `gh` 或隔离远端演练首发、版本竞争、上传中断续传与摘要不符，核对命令、仓库、tag 和最终公开条件。
4. 主代理在最终 SHA 上运行 `pixi run test`、适用格式检查和 `git diff --check`，通过 T3 指定的 GitHub MCP 工具交付一个 PR。附一份包含源码全文的真实报告和对应产物字节、旧报告读取者迁移结果、清理清单、打包及发布恢复证据。列明缺少的固件和未执行的验收。维护者自行审核合并。后续收到维护者的发布指令，由 agent 依第 4 节发布正式产物。
