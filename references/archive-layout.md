# 正式程序包结构预览

以 `just_tx.7z` 为例，打开归档即见以下内容。这里的顶层表示归档根，解压时由调用者选择目标目录。

```text
just_tx.7z
├── index.toml
├── just_tx.c
├── report.md
├── objects/
│   ├── just_tx_bpf.o
│   └── just_tx_rv32.o
└── containers/
    ├── just_tx-vm-aot.elf
    ├── just_tx-vm-ebpf.elf
    └── just_tx-vm-jit.elf
```

其余 11 个程序按各自程序名替换上述文件名中的 `just_tx`。每包应有这八个常规文件。目录条目是否显式写入 7z 不影响判定。索引中的 source、bpf、AOT object 和三种 mode ELF 必须分别指向上图对应文件。重定位信息按既定容器或对象承载方式验收。

结构依据是 [v3 全模式布局](https://github.com/nan-mu/libbpf-mcu/blob/ef1771d9c949771c707b93fd9da5c3e2602efee0/docs/artifacts.md#program-layout)。此前审阅的 `just_tx-v3.7z` 实物仅含源码、报告、索引及原始 BPF 对象，是缺件对照。
