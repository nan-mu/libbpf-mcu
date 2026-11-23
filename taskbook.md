# libbpf-mcu PR #5 · 从默认构建生成 Release

在 `nan-mu/libbpf-mcu` 的现有 PR #5 继续，目标分支为 `main`。从 PR 当前分支接手。若起点为 `36fccc1`，按顺序应用 `patches/` 中的两份补丁。已应用上一轮 `add1e4e` 的工作树只需第二份。

1. **构建入口。** Pixi 只保留 `build`、`test`、`clean` 三个项目任务。无参数构建发现全部正式 C 源，编译原始 BPF，并逐个通过 PREVAIL。原生目标名统一为 `rv32imc`。显式传入固件时，保留 `pixi run build --firmware ELF` 的 AOT 用法。JIT 仍生成 RV32IM 指令。
2. **发布范围。** 收到正式发布指令后，代理在固定提交的干净工作树运行无参数 `pixi run build`。整批成功后，把每个程序目录的完整公开内容打成独立的 `<程序名>.7z`，逐包解压核对所有文件，再将完整批次上传到同一个 GitHub Release。删除发布清单和独立打包任务。任一程序验证失败，整批停止发布。
3. **保留 `memcpy`。** 使用仓库固定版本的 PREVAIL 验证 `xdp/memcpy_xdp`。长度为 0 时应零写入并返回 `XDP_ABORTED`，长度 1–12 时应按原语义复制。包内 `examples/memcpy.7z` 是已通过验证的实际产物。

在支持的 macOS 环境运行 `pixi run build` 和 `pixi run test`，将结果补到同一条 PR，交回审核。
