# win-unpack  —— 云推内部版PLUS10.26 云脱壳

目标: 云推内部版PLUS10.26.exe (PE32+ x86-64, 自研 mapo 壳, IAT 清空, .mapo/.mapo2 加密主映像)
本仓库只做一件事: 在 GitHub Actions 的 windows-latest 上把加壳程序跑起来, 扫描其内存, dump 出重建后的 PE 映像.

## 结构
- `.github/workflows/unpack.yml`  CI 主流程
- `tools/dump.ps1`                 启动目标 + VirtualQueryEx/ReadProcessMemory 扫描 + dump MZ 映像; 再调 pe-sieve `--imp 3` 尝试还原 IAT
- 结果回传: 末尾把 `out/**` 压成 `dumps.zip`, 用自带 GITHUB_TOKEN 推到本仓库的 `results` 分支 (无需用户 PAT)

## 手动跑
Actions 页 -> win-unpack -> Run workflow, 或对任意非 `results` 分支 push。
