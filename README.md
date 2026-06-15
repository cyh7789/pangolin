# Pangolin

**Armored CI/CD Pipeline Security Scanner** — powered by Sola Security.

Pangolin scans your GitHub repositories for supply chain attack surfaces and CI/CD pipeline vulnerabilities using battle-tested vulnerability hunting patterns, enriched with Sola's environmental context.

## What It Does

While other security tools check your cloud configs and identity permissions, Pangolin checks what's actually running in your pipelines:

- **CI/CD Pipeline Analysis** — Scans GitHub Actions workflows for shell injection, unsafe checkout, secret exposure
- **Supply Chain Risk Detection** — Dependency confusion, untrusted package sources, artifact poisoning vectors
- **Repository Posture Assessment** — Branch protection gaps, review bypass risks, over-privileged access
- **Contextual Prioritization** — Combines findings with Sola's environment data for real-world risk scoring

## Architecture

```
Sola MCP (GitHub connector)
├─ Workflows table → CI/CD pipeline YAML analysis
├─ Teams table → Access control & privilege mapping
├─ Pull Requests table → High-risk change detection
└─ Repository Entities → Security posture baseline

Pangolin Scanner
├─ Stage 0: Reconnaissance (Sola data discovery)
├─ Stage 1: Pattern Scan (vulnerability pattern matching)
├─ Stage 2: Validation Gates (noise filtering)
└─ Stage 3: Risk Scoring & Report (severity × exposure)
```

## Patterns

Pangolin uses curated, publicly-known vulnerability patterns derived from real CVEs:

| Category | Examples |
|----------|---------|
| Toolchain Injection | Shell injection in CI, PATH manipulation, env var poisoning |
| SSRF / Fetch Confusion | Untrusted URL in CI fetch, redirect to internal endpoints |
| Capability Gap | Secrets without scope binding, over-permissive tokens |
| Deserialization | Unsafe loaders in build pipelines (pickle, yaml.load) |
| Dependency Confusion | Namespace scoping gaps, registry priority manipulation |

## Built For

[Boring.Security Hackathon](https://www.boring.security) by Sola — making security less annoying.

## License

MIT
