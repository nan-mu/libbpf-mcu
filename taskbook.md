# libbpf-mcu PR #6 · 修复 ELF 容器发布

续做 [libbpf-mcu PR #6](https://github.com/nan-mu/libbpf-mcu/pull/6)，本轮依据 `988349431981b84402f7ee54e73607d5c0ddcd2e`。在该 PR 的实际 head 上实施，更新同一 PR，交维护者审核。

## 目标

给定调用者提供的已链接 ELF，`prepare-release` 交付完整的 12 个程序归档。每包按 [v3 归档结构](references/archive-layout.md) 提供原始 eBPF 对象和 AOT、rBPF、JIT 三种部署容器。完整容器能按 Compact ELF V0 编解码，总字节数不构成格式或发布条件。

## 改动

- **修正容器编解码。** 删除 `make/xpost_elf.py` 的整文件上限及其编解码两侧的拒绝分支。保留 V0 的字段可表示性、节边界和镜像摘要校验。Rust 主机工具 `xpost-mcu-elf` 也通过 `xpost-elf::build_container` 封装，其返回值的固定容量同样会拒绝文件。配套改动限于 XPOST 的 `xpost-elf`，让主机编码使用按实际输出长度分配的缓冲区，保持同一 V0 布局和既有读法。该改动由 XPOST 单独合入 `main`，libbpf-mcu 的主机构建固定使用合入后的 `main` 提交。libbpf-mcu 端的修改可先进行，最终批次用合入后的主机工具验证。 [Python 编解码](https://github.com/nan-mu/libbpf-mcu/blob/988349431981b84402f7ee54e73607d5c0ddcd2e/make/xpost_elf.py#L121) · [主机调用](https://github.com/nan-mu/libbpf-mcu/blob/988349431981b84402f7ee54e73607d5c0ddcd2e/tools/src/main.rs#L199) · [Rust 编码](https://github.com/nan-mu/xpost/blob/3986c4f17a54e7c9bd830d558c40c8c13a066660/xpost-elf/src/encode.rs#L71)
- **移除发布流程自设的冷存储预算。** 用 Matt 的 `diagnosing-bugs` 沿 `prepare-release` 追到构建和解包校验，核对 `release_firmware.py`、`build.py`、`build_steps.py`、`release.py` 的预算传递与判断，然后一并删除它们及对应文档、测试断言。沿用 `--firmware-dir` 提供的 ELF 及实际链接信息。此次改动范围是 ELF 封装、读回和归档，固件构建、设备配置和 JIT 代码生成另有各自的工作。 [冷存储预算来源](https://github.com/nan-mu/libbpf-mcu/blob/988349431981b84402f7ee54e73607d5c0ddcd2e/make/release_firmware.py#L27) · [封装后的长度判定](https://github.com/nan-mu/libbpf-mcu/blob/988349431981b84402f7ee54e73607d5c0ddcd2e/make/build_steps.py#L256)

## 验收

先读最终 diff 和实际调用链，确认 `xpost-mcu-elf` 用上按实际长度分配的编码路径，核对 Python 编解码和正式发布路径的改动。删除把旧整文件上限写成契约的测试，包括 Python 的 `test_exact_container_limit` 和 Rust 的 `exact_container_limit`。用同一个合法的主机样例覆盖回归。其封装后长度超过 Python 和 Rust 各自的旧上限，分别经正式主机工具使用的 Rust 编码路径和 Python 编码，再用 Python 读回，核对元数据和镜像一致。已有缺件、坏结构和摘要错误的检查继续用于各自的行为。

从正式入口生成候选，用 `verify-release` 对实际归档核对成员、v3 索引和容器内容。预期程序是 `firewall`、`just_drop`、`just_tx`、`noop`、`prime`、`log2`、`copy`、`fletcher32`、`bsort`、`strcmp`、`case_swap`、`case_mark`，每个程序须有 AOT、rBPF、JIT，共 36 项。缺少输入就记录文件名及受影响的产物。PR 附代码依据和候选取得方式，实测结果与待验证项分别记录。

本轮交付候选批次与 PR 更新。公开 `v0.1.1` 由维护者另行授权，版本仅递增最后一段，前两段固定，同一次发布重试复用已分配的 tag。
