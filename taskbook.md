# libbpf-mcu PR #5 · 对齐实验源码，修完构建与发布问题

在 `nan-mu/libbpf-mcu` 现有 PR #5 的最新 head 继续，目标分支为 `main`。本次对照提交为 `3a160407`。附件中的 `references/xpost-bench.zip` 是 11 月 12 日的原始交付，SHA-256 为 `48439942b21e340b974c778a40027cfb9a0cfd222a740a930cf06d7d79215785`。

1. **恢复计算基准的实验语义。** 以总包 `exec/` 为准接入 `prime、log2、copy、fletcher32、bsort、strcmp` 和空基线 `noop`。七项使用固定 8258 B 的 EXB2 缓冲区、64 B 头和程序内 `rounds`。按任务选择正确的编译入口，共享协议源和宿主测试源不得被默认发现为独立程序。用包内参考实现核对正常值、边界、轮数和输出，尤其逐字节核对复制和排序。旧 `memcpy` 的 1–12 B 修复保留为必要的回归参照，正式 `copy` 按新版协议验收。逐项检查生成的 ELF 没有 map 定义、map helper 调用或指向 map 的指令重定位。用仓库固定的 PREVAIL 验证实际发布的每个对象。拒绝或超时就保留具体原因、阻止该批发布；先修等价的边界表达，仍无法通过的项目列给用户裁决。
2. **核对其余程序和实际消费者。** 用 `audit/source-versions.tsv` 对照现行 17 个源、`references/old-upload/` 和重写总包。按实验分别核对 `just_tx` 的专项 JTX1、`just_drop` 的最小 DROP、`case` 的 CAS2、`firewall` 的真实 HASH，以及诊断程序的独立用途。后续各实验说明在 `references/design/`，标为待审的 Just TX 专项在 `references/just-tx/`。各版有冲突时标明依据。在 PR 中列清正式程序、诊断、被替换样例及各自的行为依据。XPOST #23 的旧 runner 仍通过 `workload[0/1]` 交换 32 B；另一个同名 EXB2 设计使用 88 B 和 `workload_v2`。把新输入、调用、输出和冷启动依赖交接给 #23，用已知请求核对接口；设备联调状态单列，留在 XPOST 的集成流程。
3. **按实际指令绑定 map。** 从真实 rBPF 打包入口验证三类对象。无 map 的新版计算对象保持原始指令；仅声明共享 map 的合法对象保留元数据、允许零处改写；真正引用 map 的程序按容器顺序写入正确索引，缺失绑定的真实引用应报错。用 `firewall` 的 `blacklist` 作正例，核对容器内指令和 map 表。该项和第 1 项分别验收。
4. **修正增量构建与诊断。** 更换头文件符号链接的目标，或改变生效的 `CPATH`、`C_INCLUDE_PATH` 后，普通构建生成的 BPF、原生目标代码应与同配置全新构建一致。用两个返回值不同、时间戳较老的头文件验证。拒绝一个程序后，在同一构建目录成功构建另一个，仍应能查到前者的程序名、失败阶段和 PREVAIL 原因。固件缺失只记录实际失败的预检。日志留在私有构建目录。
5. **修正工具选择与 Release 上传。** 在 PATH 找不到 `llvm-objdump`、仅设置 `LIBBPF_MCU_OBJDUMP` 时，以 `--engine rbpf` 完成节选择、提取和容器核验。按发布文档离线演练名字为 `probe#1.c` 的程序和含 `#` 的暂存路径，核对上传的文件字节、资产名、冲突检测及重试。发布集仍取自无参数 `pixi run build`，每个正式程序一份 `.7z`。

**交付**　在支持的环境运行 `pixi run build`、`pixi run test` 和上述入口回归，记录提交、实际通过项及剩余阻塞。保持既有产物布局和 `build/test/clean` 三个项目任务。交回同一条开放 PR，供用户审核。
