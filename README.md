# wutong-core

> 梧桐协议（Wutong Protocol, WTP）Rust 核心实现 · The Rust core of the Wutong Protocol

[![CI](https://github.com/project-wutong/wutong-core/actions/workflows/ci.yml/badge.svg)](https://github.com/project-wutong/wutong-core/actions/workflows/ci.yml)
License: `AGPL-3.0-only` · Rust Edition 2024 · MSRV 1.85

## 中文

`wutong-core` 是梧桐协议 `wutong/0.1`（规范修订 v0.1.2，Schema `urn:wutong:schema:core:0.1.2`）的
**独立 Rust 实现**，对应规范 §18.2 发布阻断项 #2“Rust 2024 独立解析/验证器”。它被 CLI、`wutong-networkd`、
`wutong-server`、各语言 SDK 以及 Qt 桌面应用（经 `cxx` / C ABI 桥接）共同使用。

| Crate | 职责 |
|---|---|
| `wtp-types` | UUIDv7/摘要/时间戳等校验型标识、16 类错误码、信封、**24 类规范消息**的强类型荷载（由 Schema 生成） |
| `wtp-wire` | 严格 JSON 解析、受限 RFC 8785 JCS（UTF-16 键序）、RFC 8949 §4.2.1 dCBOR 编解码、Schema 校验 |
| `wtp-crypto` | 域分离 Ed25519 签名/验签（JCS 与 dCBOR）、`S < L`、弱公钥、时钟窗口、重放/分叉检测 |
| `wtp-agent` | Task 状态机（版本、租约、幂等键、终态不可逆） |
| `wtp-document` | 可移植相对路径、字节摘要、Source-First 最小范围补丁、PROV-O 校验 |
| `wtp-policy` | Capability 委托链（精确资源+动作、衰减、v0.1.2 签发时间单调性、撤销新鲜度失败关闭） |
| `wutong-core` | 门面 crate + 跨字段语义校验 |
| `wutong-ffi` | 稳定 C ABI（`include/wutong.h`），供 C++ SDK、C# P/Invoke 等使用 |

### 一致性

`conformance/` 是 `wutong-protocol` 的 Schema、24 个示例与测试向量的同步副本（CI 校验与上游一致）。
测试与 Python 参考实现生成的跨语言向量逐字节比对：24 类消息的 JCS/dCBOR 编码与 Ed25519 签名完全一致。

```bash
cargo test --workspace
```

## English

Independent Rust 2024 implementation of WTP `wutong/0.1` (revision v0.1.2). It strictly parses,
schema-validates, canonicalizes (JCS / dCBOR), signs and verifies all 24 normative message kinds and
is byte-for-byte cross-checked against the Python reference vectors in `conformance/`.

**Status:** pre-release. The Security/Sync/Federation profiles are experimental and unaudited.

### Language policy

Project Wutong is Rust-first: all non-GUI logic lives in Rust. Qt (C++) GUIs call into this core
through `cxx` bridges or the C ABI in `wutong-ffi`; the previous C++23 reference core in
`wutong-protocol/reference` is kept as an independent conformance implementation only.
