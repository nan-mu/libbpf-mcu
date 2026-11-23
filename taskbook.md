# libbpf-mcu PR #5 · 修复 JIT 验证、发布源码与 map 元数据

在 [nan-mu/libbpf-mcu PR #5](https://github.com/nan-mu/libbpf-mcu/pull/5) 的最新 head 继续，沿用 `agent/program-release-pipeline`，目标分支为 `main`。本轮审核基线为 `4139e7ac`。四项修复交回同一条开放 PR，供用户审核。

### 1. 恢复独立 JIT 差分测试，让正例真正执行算法

修正 `jit/oracle/build.rs` 和 `jit/scripts/check-xdp.sh` 的样例选择。旧 `div2`、`bitswap` 已移到 `tests/unused/`，`xdp_drop` 已移到 `tests/diagnostics/`。保留历史夹具的覆盖，为正式的 `bsort` 使用 8258 B EXB2 请求。让 oracle 在相关业务头文件变化后也重新编译受影响的对象。

在干净工作树分别运行 `cargo test --release --manifest-path jit/oracle/Cargo.toml` 和 `sh jit/scripts/check-xdp.sh`。使用随包的 `fixtures/exb2/bsort.input.bin`，其中八个无符号整数逆序排列、含重复值，执行三轮。要求两侧均返回 `XDP_PASS`，完整响应与 `bsort.expected.bin` 一致，包括排序后的 scratch。保留短输入作为拒绝用例。验收时列出这个正例的实际状态、返回值和输出比较结果。

### 2. 隔离 JIT 测试环境中的输入缓冲区和上下文

同时修正 `jit/src/check.rs` 的自检和 `jit/oracle/src/run.rs` 的独立差分环境。当前数据区从 `0x1000` 开始，写入 `0x1800` 的上下文字段会覆盖帧中偏移 2048–2055。为各执行侧分别准备字节相同的原始输入，使完整数据区与上下文、栈、map 存储互不重叠。

在两个入口运行随包的 `noop` 和 `copy`。执行前核对整帧与输入文件相同。执行后核对 `XDP_PASS` 和对应的 8258 B 完整期望响应。`noop` 应保留偏移 2048–2055 的填充。满规模 `copy` 应在原位置保留这八个输入字节，并在 scratch 的帧偏移 6144–6151 复制出同样的值。独立比较每侧与期望文件的结果，可以发现两侧同时收到错误输入的情况。

### 3. 让 Release 的单个 C 文件包含实际实验源码

沿用每程序一个顶层 `.c`、一份 `report.md` 和 `index.toml` 的布局。将 EXB2 协议、计算内核、CAS2、JTX1 等本程序依赖的仓库业务头展开到公开源码快照，保留宿主、BPF 和 RV32 构建需要的条件分支。报告展示同一份快照，索引记录实际字节数和 SHA-256。同步调整 `make/build_steps.py` 的原生构建一致性检查，使 BPF 和 AOT 均可从同一版本的源构建。

逐包解压默认构建的 12 份 `.7z` 并核验索引。在仓库源码目录之外，仅使用包中源码和相应目标的标准 SDK 头复编。以 `copy` 验证宿主入口 `-DEB_HOST_ENTRY` 和其 BPF 程序的完整响应，以一个 CAS2 程序验证网络逻辑也已收全。用已有固件夹具回归 AOT 构建。临时修改一个实际参与计算的业务头，再次构建后，公开源码、报告和源码摘要应随之更新。

### 4. 从 ELF 中取得每张传统 map 的实际描述

修复 `make/btf.py` 对传统 `maps` 节中多个 `struct bpf_map_def` 的解析。对于可重定位 ELF，按各变量在目标节中的实际位置读取描述符，正确处理 `.rel.BTF`。按名称核对每条 XDP map 引用与容器 map 表的绑定关系。

用 `fixtures/maps/two_classic_maps.c` 经正式 BPF 构建和固定 PREVAIL，再通过带固件的 `rv32imc --engine rbpf` 入口打包。按随包 `expected.json` 分别读回原始对象的提取结果和最终容器。`count_by_case` 是 HASH，键和值均为 4 B、容量 5。`seq_log` 是 ARRAY，键 4 B、值 8 B、容量 7。两处指令使用的索引都应指向各自同名描述符。回归无 map 和仅声明 map 的对象均可打包，真实引用缺少绑定时仍应报错。

**交付**　在最终提交运行 `pixi run build`、`pixi run test` 及上述专项入口。PR 的验收记录注明提交、用到的夹具、实际输出和任何阻塞。软件差分结果与设备部署状态分别记录。
