# Pangolin — Design Document

## 定位

精簡版 CI/CD 供應鏈安全掃描器。用公開的漏洞模式掃 GitHub repo 的 pipeline 設定與程式碼，搭配 Sola 的環境上下文做風險排序。

## 比賽要求對照

| 要求 | 做法 |
|------|------|
| 至少一個 Sola 資料來源 | GitHub（主要）、Shodan（如有接） |
| agentic solution | 多階段自動掃描 pipeline，agent 自主決策掃描範圍與優先級 |
| contextual | Sola 環境上下文（team 權限、repo 設定、PR 動態）影響風險分數 |
| 1 分鐘影片 | 展示：接 Sola → 掃描 → 發現 → 報告 |

## 不開放的能力

- 私有攻擊模式（Pattern Library 的 hypothesis/confirmed 等級）
- Codex 掃描引擎的 prompt 編譯邏輯
- EV 計算公式與 bounty 策略
- Tamate 完整架構

## 架構

```
┌─ Sola MCP ─────────────────────────────────┐
│ github_workflows    → CI YAML 內容/設定      │
│ github_teams        → 存取權限              │
│ github_pull_requests → PR 動態              │
│ github_repos        → repo 設定/branch protection │
│ (shodan_hosts)      → 外部攻擊面（optional）  │
└────────────────────┬────────────────────────┘
                     │
┌────────────────────▼────────────────────────┐
│ Stage 0: Recon                               │
│ - 列出所有 repo + metadata                    │
│ - 拉 workflow 定義                            │
│ - 拉 team/permission mapping                  │
└────────────────────┬────────────────────────┘
                     │
┌────────────────────▼────────────────────────┐
│ Stage 1: Pattern Scan                        │
│ A) CI/CD Pipeline Patterns                   │
│   - TOOLCHAIN_EXEC_BOUNDARY_INJECTION        │
│   - FETCHER_DESTINATION_CONFUSION            │
│   - OBJECT_CAPABILITY_AUTHZ_GAP             │
│   - DESERIALIZATION_BEHAVIOR_REHYDRATION     │
│ B) Code Patterns (if repo cloned)            │
│   - pattern-scanner.py 公開模式子集           │
│ C) Posture Checks                            │
│   - branch protection                        │
│   - required reviews                         │
│   - secret scanning enabled                  │
│   - dependency review enabled                │
└────────────────────┬────────────────────────┘
                     │
┌────────────────────▼────────────────────────┐
│ Stage 2: Validation Gates (簡化版)            │
│ G1: 攻擊者能觸發嗎？（reachability）          │
│ G2: 打到什麼？（impact sink）                 │
│ G3: 有沒有防禦擋住？（defense check）          │
│ G4: 嚴重性分級（C/I/A scoring）               │
└────────────────────┬────────────────────────┘
                     │
┌────────────────────▼────────────────────────┐
│ Stage 3: Risk Score & Report                 │
│ risk = severity × exposure × posture_gap     │
│ - severity: 漏洞本身的嚴重性                  │
│ - exposure: 誰能碰（team size, public/private）│
│ - posture_gap: 防禦缺口數量                   │
│ → 結構化報告 + 建議修法                       │
└──────────────────────────────────────────────┘
```

## 技術棧

- **語言**: Python 3.12+
- **Sola 整合**: MCP（透過 Claude Code 或直接 HTTP）
- **掃描引擎**: 從 Bounty pattern-scanner.py 精簡 + CI-specific 新模式
- **輸出**: JSON finding list + markdown report

## 時程

| 日期 | 工作 |
|------|------|
| 6/15 | 架構設計、Sola 接通、repo 建立 |
| 6/16-17 | Stage 0-1 實作（Sola 查詢 + pattern scan） |
| 6/18-19 | Stage 2-3 實作（validation + scoring + report） |
| 6/20 | 端到端測試、用真實 repo 跑一遍 |
| 6/21 | 1 分鐘影片、文案、提交 |
| 6/22 | buffer / 最後修改 |

## 掃描模式清單（公開版）

### CI/CD Pipeline

1. **Shell injection in GitHub Actions** — `run:` block 使用未跳脫的 `${{ }}` 表達式
2. **Unsafe checkout of PR head** — `actions/checkout` 用 `ref: ${{ github.event.pull_request.head.sha }}` 但沒有限制後續操作權限
3. **Secret exposure in logs** — workflow 裡 echo/print 含 secret 變數
4. **Overly permissive workflow triggers** — `pull_request_target` + `workflow_run` 組合允許 fork 觸發特權 workflow
5. **Unpinned action versions** — 用 `@main` 或 `@v1` 而不是 SHA pin
6. **Artifact poisoning vector** — upload-artifact 後 download-artifact 跨 workflow 無驗證

### Repository Posture

7. **Branch protection disabled** — default branch 沒開保護
8. **No required reviews** — merge 不需要 review
9. **No status checks required** — CI 可以被繞過
10. **CODEOWNERS bypass** — 有 CODEOWNERS 但沒有 enforce

### Supply Chain

11. **Dependency confusion risk** — private registry + public fallback
12. **No dependency review** — PR 加新依賴不會被自動檢查
13. **Lock file not committed** — package-lock.json / yarn.lock 不在 repo
