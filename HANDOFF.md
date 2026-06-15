# Pangolin — Handoff

## 比賽資訊

- **比賽**: Boring.Security Hackathon by Sola
- **獎金**: $20K / $10K / $5K（社群投票前三名，投票 6/2-6/30）
- **截止**: 2026-06-22 23:59 EDT（台灣 6/23 11:59）
- **帳號**: cyh7789 (Shoreline) @ app.sola.security
- **規則**: 個人、一件、必須用 Sola 平台或 MCP、至少一個資料來源
- **提交需要**: 1 分鐘影片（100MB 以內）+ 短描述 + 長描述 + 封面圖 + 程式碼連結（可選）

## 專案路徑

`/Users/cyh/Development/hackathon/pangolin/`

## 完整 Pipeline（已全通）

```
Sola MCP 拉 26 repo / 105 workflow（sola-data.json, ~1MB）
  → Stage 1: Regex 快篩 117 candidates（17 模式，0.1s）→ Slack 通知 #1
  → Stage 2: LLM 深度分析（Codex gpt-5.5，5 workflow）→ 6 confirmed, 0 FP
  → Stage 3: Sola 環境上下文加權 + 態勢評估（avg 22%）
  → Stage 4: HTML 報告 + 29 PoC 檔案
  → Stage 5: Slack 通知 #2（深度結果 + zip 附件）
```

## CLI 指令

```bash
cd /Users/cyh/Development/hackathon/pangolin

# 本地 repo 掃描
python -m pangolin.cli scan /path/to/repo

# Sola 整合完整 pipeline（快篩 + Slack）
python -m pangolin.cli sola-scan --input output/sola-data.json --notify

# 完整深度模式（快篩 + LLM + PoC + Slack + zip）
python -m pangolin.cli sola-scan --input output/sola-data.json --deep --notify
```

## 認證存放

全部在 `.env`（不進 git），參考 `.env.example`：
- `SOLA_CLIENT_ID` / `SOLA_CLIENT_SECRET` — MCP OAuth
- `SLACK_WEBHOOK_URL` — Slack incoming webhook
- `SLACK_BOT_TOKEN` — Bot token for file uploads
- `SLACK_CHANNEL_ID` — Target channel ID
- Codex OAuth: `~/.codex/auth.json`（gpt-5.5）

## Sola 平台狀態

- ✅ Pangolin Project（app_id: `6a2f78dde8c8fd3e18ef9c0d`）
- ✅ GitHub 資料來源（37 表，POPULATED，integration: `GitHub Production`）
- ✅ Slack connector（pangolin，連到 Pangolin project）
- ✅ Sola Workflow「GitHub CI/CD Security Scanner」— 每天午夜 Asia/Taipei 自動掃 + Slack
- ✅ Sola MCP 認證通過
- ✅ Slack #pangolin 頻道 — Sola app + Pangolin CLI 都在裡面

## Sola 資料匯出

`output/sola-data.json` — 從 MCP 匯出的完整資料：
- 26 repos（metadata + visibility + security flags）
- 105 workflows（含完整 YAML content）
- MCP 匯出 SQL 結果存在 `/Users/cyh/.claude/projects/-Users-cyh-Development-Ryugu/3325b8fa-.../tool-results/mcp-sola-execute_sql-1781498735240.txt`

重新匯出：在 Claude Code 裡用 `mcp__sola__execute_sql` 跑 `sola_scanner.py` 裡的 `QUERIES` dict。

## 程式碼結構

```
pangolin/
├── __init__.py
├── __main__.py
├── cli.py              — CLI 入口（scan / sola-scan / sola-export）
├── patterns.py         — 17 個掃描模式（8 CI/CD + 4 供應鏈 + 5 程式碼）
├── scanner.py          — grep-based 引擎 + 風險評分 + 報告
├── posture.py          — 6 項 repo 態勢檢查（本地）
├── sola_scanner.py     — Sola MCP 整合：workflow 掃描 + 環境上下文加權 + SQL 模板
├── llm_analyzer.py     — LLM 深度分析：Codex gpt-5.5 + 攻擊模式推理
├── report_generator.py — 報告 + PoC 生成（Codex API）
├── html_report.py      — HTML 渲染：深色主題 + severity badge + PoC 下載按鈕
└── slack_notify.py     — Slack 通知：快篩 + 深度分析 + zip 附件上傳

output/
├── sola-data.json      — Sola 匯出資料
├── report.html         — HTML 報告
├── report.zip          — 報告 + PoC 打包
├── report-sample.md    — Markdown 報告範本
├── poc-sample.md       — PoC 範本
├── poc-raw.json        — PoC 檔案 JSON
└── poc/                — PoC 程式檔案目錄
```

## 已驗證的完整流程

1. ✅ Sola MCP SQL 查詢（26 repo、105 workflow、完整 YAML）
2. ✅ Sola explore_data 初篩（4 類風險、17+ findings）
3. ✅ Regex pattern engine 跑 Sola 資料（117 candidates，0.1s）
4. ✅ LLM 深度分析（gpt-5.5，6 confirmed，0 FP，正確判斷）
5. ✅ HTML 報告（嚴重性 badge、態勢條、證據區、PoC 下載按鈕）
6. ✅ PoC 程式檔案（29 檔，可執行安全示範）
7. ✅ Slack 快篩通知（格式化 finding 摘要，emoji badge）
8. ✅ Slack 深度分析通知（確認數 + 攻擊場景 + 修法）
9. ✅ Slack zip 上傳（報告 + PoC 打包下載）
10. ✅ 一鍵 CLI `sola-scan --deep --notify` 端到端

## 故事線

1. **Sola Workflow** 每天自動跑 SQL 快篩 → Slack 通知（輕量巡邏兵）
2. 收到通知 → 跑 **Pangolin CLI**（透過 MCP 拉 Sola 初篩結果 + 原始資料）
3. **LLM 引擎**二次深度分析（過濾誤報 + 推理攻擊鏈 + 生成 PoC）
4. 結果推回 **Slack**（分析摘要 + zip 附件）+ 本地 **HTML 報告**

Sola 做初篩 → 我們做深度。兩層互補，自動巡邏 + 按需專家分析。

## 競品分析

6 件全是雲端設定 / 身份 / 合規類。我們是唯一的：
- CI/CD pipeline 掃描
- LLM 深度推理（攻擊鏈、誤報過濾）
- PoC 自動生成
- 雙層通知（快篩 + 深度）
- HTML 報告 + zip 打包

## 已提交（2026-06-15）

- **平台**: boring.security
- **截止**: 2026-06-22 23:59 EDT（台灣 6/23 11:59）
- **投票**: 6/22 - 6/30 社群投票

### 提交內容

- ✅ Demo 影片：53 秒，HyperFrames 渲染，Gemini TTS Fenrir 旁白 + 字幕
- ✅ 封面圖：裝甲穿山甲 cyberpunk 風
- ✅ GitHub repo：https://github.com/cyh7789/pangolin
- ✅ 資料源：GitHub + Semgrep + Slack (connector) + CSV
- ✅ 短描述 + 長描述

### Git

- GitHub public repo: `cyh7789/pangolin`
- `.env` 在 `.gitignore`，不含任何 secrets
- PR #1 on `cyh7789/chainlink`：auto-fix demo（Script injection via untrusted context）
