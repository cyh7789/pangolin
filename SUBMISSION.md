# Pangolin — Submission Text

## Short Description (~150 chars)

CI/CD security scanner that uses Sola MCP for live workflow data, LLM deep analysis to confirm real vulnerabilities, and auto-generates fix PRs.

## Long Description

### The Problem

CI/CD pipelines are the new attack surface. Script injection, unpinned actions, secrets exposure, and supply chain vulnerabilities hide in plain sight across hundreds of workflow files. Manual review doesn't scale.

### The Solution

Pangolin is an armored CI/CD security scanner that connects to Sola's MCP to pull live GitHub workflow data and runs a three-stage analysis pipeline:

**Stage 1 — Regex Pattern Engine**: 17 battle-tested vulnerability patterns scan all workflows in under 0.1 seconds, catching script injection, unpinned actions, curl-pipe-to-shell, excessive permissions, and more.

**Stage 2 — LLM Deep Analysis**: GPT-5.5 reasons through real attack chains using 5 specialized attack pattern lenses (toolchain injection, SSRF in CI, capability gaps, deserialization risks, resource amplification). Filters false positives with context-aware judgment.

**Stage 3 — Auto-Fix & PR**: One command generates a security fix using LLM and opens a GitHub pull request with full context — vulnerability description, attack scenario, and diff.

### What Makes It Different

- **Sola as the data backbone**: All repo and workflow data comes from Sola MCP — no local cloning needed, real-time visibility across your entire GitHub organization.
- **Two-layer scanning**: Regex for speed, LLM for depth. Neither alone is enough.
- **PoC generation**: 29 proof-of-concept exploit files generated automatically for validated findings.
- **Complete loop**: Detect → Analyze → Fix → Notify. Results push to Slack with downloadable report bundles.
- **Environmental context scoring**: Risk scores factor in repo visibility, branch protection, review requirements, and security policy — not just pattern severity.

### Tech Stack

- **Sola MCP**: Live data source (26 repos, 105 workflows, 37 GitHub tables)
- **Sola Workflow**: Automated daily scanning pipeline
- **Sola Alert**: Threshold-based vulnerability monitoring
- **Python CLI**: Pattern engine + orchestration
- **Codex GPT-5.5**: Deep analysis + fix generation + PoC generation
- **Slack Integration**: Webhook notifications + bot file uploads
- **GitHub API**: Automated fix PR creation

### Results

In our demo scan of 26 repositories:
- 117 vulnerability candidates found in 0.1 seconds
- 6 confirmed by LLM deep analysis (0 false positives)
- 29 PoC exploit files generated
- 1 automated fix PR created
- Average security posture score: 22% (significant room for improvement)
