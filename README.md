<div align="center">

# 🌲 Ternary-DPF

**A ternary-tree Distributed Point Function (DPF) in C**
**基于三叉树的分布式点函数（DPF）C 语言实现**

![C](https://img.shields.io/badge/C-A8B9CC?style=flat-square&logo=c&logoColor=black)
![C++](https://img.shields.io/badge/C++-00599C?style=flat-square&logo=cplusplus&logoColor=white)
![OpenSSL](https://img.shields.io/badge/OpenSSL-721412?style=flat-square&logo=openssl&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

</div>

---

## 📖 Overview · 简介

**English** — A Distributed Point Function lets a dealer split a point function \(f_{\alpha,\beta}\) (which outputs \(\beta\) at index \(\alpha\) and \(0\) elsewhere) into two keys. Each key alone reveals nothing, but the two parties' full-domain evaluations sum to \(f_{\alpha,\beta}\). This repo implements a DPF over a **ternary** (base-3) evaluation tree with an AES-based PRF, as used in the Trace-OLE PCG project.

**中文** — 分布式点函数（DPF）把一个点函数 \(f_{\alpha,\beta}\)（只在位置 \(\alpha\) 输出 \(\beta\)，其余位置为 0）拆成两把密钥：单独一把密钥不泄露任何信息，两方对全定义域求值后相加即可恢复 \(f_{\alpha,\beta}\)。本仓库实现了基于 **三叉树**（底数为 3）的 DPF，PRF 采用 AES 构造，是 Trace-OLE PCG 项目中的子模块。

## ✨ Features · 功能

- 🔑 `DPFGen` / `DPFFullDomainEval` — key generation & full-domain evaluation over a \(3^n\) domain · 三叉树 DPF 密钥生成与全域求值
- ✂️ `HalfDPFGen` / `HalfDPFFullDomainEval` — half-tree optimised variant · Half-Tree 优化变体
- 📏 `ExtendOutput` — output length extension via PRF · 输出长度扩展
- 🤝 `DPFParty` (`src/otdpf.cpp`) — two-party distributed key generation over the network with OT · 基于 OT 的两方分布式密钥生成
- ⚡ AES-NI accelerated PRF through OpenSSL EVP · 基于 OpenSSL EVP 的 AES-NI 加速 PRF

## 📁 Structure · 目录结构

```text
Ternary-DPF
├── include/
│   ├── dpf.h        # DPF / Half-DPF API
│   ├── otdpf.h      # two-party (OT-based) DPF generation
│   └── prf.h        # AES-based PRF keys
├── src/
│   ├── dpf.c        # ternary-tree DPF
│   ├── halfdpf.c    # half-tree DPF
│   ├── extensions.c # output extension
│   ├── otdpf.cpp    # distributed key generation
│   ├── prf.c        # PRF implementation
│   └── test.c       # correctness test & benchmark
└── Makefile
```

## 🚀 Quick Start · 快速开始

```bash
# Ubuntu
sudo apt-get install build-essential libssl-dev

make            # builds ./bin/test
./bin/test      # correctness check + timing
```

> On macOS the `Makefile` already adds `-I/opt/homebrew/opt/openssl/include`.
> macOS 下 `Makefile` 已包含 Homebrew OpenSSL 的头文件路径。

## 🙏 Acknowledgements · 致谢

Built on the DPF implementation from [FOLEAGE-PCG](https://github.com/sachaservan/FOLEAGE-PCG) by Sacha Servan-Schreiber (MIT License).
本项目基于 Sacha Servan-Schreiber 的 FOLEAGE-PCG 中的 DPF 实现进行二次开发（MIT 许可证）。

## ⚠️ Disclaimer · 声明

This code is for **research purposes only** and has not been audited. Do not use it in production.
本代码 **仅用于科研**，未经安全审计，请勿用于生产环境。
