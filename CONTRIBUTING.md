# Contributing to wutong-core / 参与贡献

Thank you for helping build Project Wutong (梧桐计划)! This repository follows the
org-wide guide at https://github.com/project-wutong/.github/blob/main/CONTRIBUTING.md — summary:

1. **Discuss first** for anything non-trivial: open an issue (or a WIP — Wutong Improvement
   Proposal — in `wutong-protocol` for protocol changes).
2. **Branch** from `main` (`feat/…`, `fix/…`, `docs/…`); `main` is protected and only changes via PR.
3. **Conventional Commits** (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`, `ci:`; `!` for breaking).
4. **Sign off** every commit (`git commit -s`, DCO 1.1). All contributions are licensed `AGPL-3.0-only`.
5. **Every source file** starts with `SPDX-License-Identifier: AGPL-3.0-only` (REUSE 3.3).
6. **CI must be green**: formatting, lints, tests and conformance vectors.
7. **Security issues**: never open a public issue — see `SECURITY.md`.

中文简述：先开 Issue 讨论 → 从 `main` 拉分支 → 使用 Conventional Commits 并 `-s` 签署 DCO →
通过 CI 后提交 PR；协议变更需先在 `wutong-protocol` 提交 WIP。
