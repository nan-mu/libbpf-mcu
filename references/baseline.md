# 已核实的历史实现与失败基线

以下为任务书作者静态核查，不是本轮编译、二进制下载或实机测试。

- [PR6 初始任务书](https://gitea.nas.nan-mu.cc/mcp/libbpf-mcu/src/commit/67df9629dad9227580ee2b1de220bedd1043e145/taskbook.md) 明确要求包内原生重定位信息与直接链接对照；[最后一次容量修订](https://gitea.nas.nan-mu.cc/mcp/libbpf-mcu/src/commit/e46c06ca554f2367d7bd9ce4f4f26c56111a24c3/taskbook.md) 的验收集中在容器编解码与 36/36。
- libbpf-mcu main 07a4ea9a81a7fedf7bef2d6ced8d7fcfcccfd113：[AOT build_steps.py](https://github.com/nan-mu/libbpf-mcu/blob/07a4ea9a81a7fedf7bef2d6ced8d7fcfcccfd113/make/build_steps.py#L288-L345) 使用真实槽地址的链接脚本和 LLD；[JIT jit_image.rs](https://github.com/nan-mu/libbpf-mcu/blob/07a4ea9a81a7fedf7bef2d6ced8d7fcfcccfd113/tools/src/jit_image.rs) 在生产端 compile/link，按目标 slot 生成 map VMR；[retarget.py](https://github.com/nan-mu/libbpf-mcu/blob/07a4ea9a81a7fedf7bef2d6ced8d7fcfcccfd113/make/retarget.py) 对 AOT .o 重新链接，对 JIT BPF 对象重新编译和链接。
- [release_firmware.py](https://github.com/nan-mu/libbpf-mcu/blob/07a4ea9a81a7fedf7bef2d6ced8d7fcfcccfd113/make/release_firmware.py) 要求 8 份已链接 ELF。当前正式发布物不满足与固件布局解耦的要求。
- XPOST main 246d0427124f5b543ff2c536ec10e3270cbe67b5：[deployment-design.md](https://github.com/nan-mu/xpost/blob/246d0427124f5b543ff2c536ec10e3270cbe67b5/docs/deployment-design.md) 说明 pinned native archives lack relocation records；[release.rs](https://github.com/nan-mu/xpost/blob/246d0427124f5b543ff2c536ec10e3270cbe67b5/xpost-agent/src/release.rs#L198-L245) 只校验 AOT .o 并取已经封装的 ELF；[deployment.rs](https://github.com/nan-mu/xpost/blob/246d0427124f5b543ff2c536ec10e3270cbe67b5/xpost-agent/src/deployment.rs#L113-L199) 比较地址并拒绝普通不匹配原生镜像，Case 特例保留机器码不变。
- [历史 PR6 报告](https://github.com/nan-mu/libbpf-mcu/pull/6#issuecomment-7122897323) 声称 Case A/B retarget 与直接构建字节一致；这不证明既有零地址机器码被加工，源码显示 retarget 会重新链接/编译。未独立复现实验。
- [v0.1.1](https://github.com/nan-mu/libbpf-mcu/releases/tag/v0.1.1) 公开列有 12 个 7z 及摘要；作者尝试直接下载 just_tx.7z 未成功，未取得归档原始字节，因此本轮另要求可经文本接口读回的无损镜像。历史数据不删除。
