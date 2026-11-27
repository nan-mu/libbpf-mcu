# 当前 Ninja 示例检查

本轮使用真实 Ninja 1.12.1 检查 [firewall.build.ninja](../references/firewall.build.ninja)，只验证 G2 的参考图可达性、持久文件依赖和增量调度；不验证真实编译/验证器/镜像/报告语义，也未实际执行 tools release。

对象：6294 字节、140 行，SHA-256 `97904ada84200c926b88dfac55a542f6c31ca31cac6c11f54578bb49d16d97a9`，Git blob `983be102efeecab78b41d3fbddbc94edc701c6ec`。本地 /mnt/data/pr8-ninja-v6/firewall.build.ninja。

实际执行 `ninja -f <file> -t commands firewall`、`-t graph firewall`，分别展开 17 条命令与 140 行 DOT。17 条命令均通过 /bin/sh -n -c；展开命令无 mktemp/trap/sed/awk。

在本地 /mnt/data/pr8-ninja-v6/mock-checkout 创建固定的源码和 SDK fixture，仅把示例工具路径替换为本地 mock clang、lld、prevail、objdump、mcu-jit、mcu-object 与 /usr/bin/ninja。mock 写入标识文本及 depfile，verify 复制输入，report 检查四份反汇编与 recipes 文件存在。使用真实 Ninja 从 checkout 根运行 `ninja -f build/build.ninja firewall`：

| 操作 | 实际结果 |
| --- | --- |
| 首次执行 | exit 0；17/17；REPORT、INDEX 完成 |
| 不改输入再次执行 | exit 0；ninja: no work to do. |
| 删除 intermediates/firewall/report/jit.txt | exit 0；3/3：DISASSEMBLE、REPORT、INDEX；未执行编译/JIT |
| 更新 mock verifier 文件 mtime | exit 0；11/11；BPF VERIFY 和其下游重建；没有 BPF COMPILE、RV32 COMPILE 或 AOT LINK |

报告目录最终持续保留七个文件：aot.txt、bpf.txt、ebpf.elf、ebpf.txt、jit.elf、jit.txt、recipes.txt。该测试证明引用这些持久文件能获得预期局部重建；没有测试真正的 PREVAIL PASS 语义、错误清理、真实工具的内部目录创建及发布系统临时目录生命周期。实施端无需重复相同替身样例，但必须运行 G1–G5 的实际验收。

[旧版本测试记录](https://gitea.nas.nan-mu.cc/mcp/libbpf-mcu/src/commit/2df367105b457448842232e667626c2ff90e45c2/tests/ninja-example-static.md) 按原 Git 历史保留，涉及已淘汰的目录/规则，不直接用于当前图。
