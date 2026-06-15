"""
Pangolin — Sola-Integrated Scanner

Pulls workflow content and repository context directly from Sola,
runs battle-tested vulnerability patterns against them, and enriches
findings with environmental context for real-world risk scoring.

This is the killer: professional-grade pattern detection on Sola's
live data — not just SQL LIKE, but regex + anti-pattern + cross-check.
"""

import re
import json
import tempfile
import os
from dataclasses import dataclass, asdict
from typing import Optional

from .patterns import (
    CICD_PATTERNS, SUPPLY_CHAIN_PATTERNS, CODE_PATTERNS,
    ALL_PATTERNS, Pattern,
)
from .scanner import Finding, SEVERITY_WEIGHT


# ============================================================
# Sola Data Fetchers (called by the orchestrator with MCP results)
# ============================================================

@dataclass
class RepoContext:
    name: str
    full_name: str
    visibility: str
    is_private: bool
    language: str
    has_vulnerability_alerts: bool
    has_security_policy: bool
    collaborator_count: int = 0
    admin_count: int = 0
    has_branch_protection: bool = False
    requires_reviews: bool = False
    requires_status_checks: bool = False
    allows_force_pushes: bool = False


@dataclass
class WorkflowData:
    repo_full_name: str
    name: str
    path: str
    content: str
    state: str


# ============================================================
# Pattern Engine — runs on raw YAML content from Sola
# ============================================================

def scan_workflow_content(workflow: WorkflowData, repo_ctx: Optional[RepoContext] = None) -> list[Finding]:
    """Run CI/CD and supply chain patterns against a single workflow's YAML content."""
    findings = []
    seen = set()
    content = workflow.content
    if not content:
        return []

    lines = content.split("\n")

    for pattern in CICD_PATTERNS + SUPPLY_CHAIN_PATTERNS:
        for regex_str, file_glob in pattern.grep_patterns:
            # file_glob is *.yml/*.yaml — we already know this is YAML
            if not (file_glob.endswith(".yml") or file_glob.endswith(".yaml")):
                continue

            regex = re.compile(regex_str)
            for line_num, line in enumerate(lines, 1):
                match = regex.search(line)
                if not match:
                    continue

                # Anti-pattern check against full content
                if any(re.search(ap, content) for ap in pattern.anti_patterns):
                    continue

                key = (pattern.id, workflow.path, line_num)
                if key in seen:
                    continue
                seen.add(key)

                finding = Finding(
                    pattern_id=pattern.id,
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    category=pattern.category,
                    file=f"{workflow.repo_full_name}/{workflow.path}",
                    line=line_num,
                    code=line.strip()[:150],
                    description=pattern.description,
                    source=pattern.source,
                    action=pattern.action,
                    context={
                        "workflow_name": workflow.name,
                        "repo": workflow.repo_full_name,
                    },
                )

                if repo_ctx:
                    finding.context["visibility"] = repo_ctx.visibility
                    finding.context["has_branch_protection"] = repo_ctx.has_branch_protection

                findings.append(finding)

    return findings


def scan_all_workflows(
    workflows: list[WorkflowData],
    repo_contexts: dict[str, RepoContext],
) -> list[Finding]:
    """Scan all workflows from Sola, enriched with repo context."""
    all_findings = []

    for wf in workflows:
        ctx = repo_contexts.get(wf.repo_full_name)
        findings = scan_workflow_content(wf, ctx)
        all_findings.extend(findings)

    return all_findings


# ============================================================
# Risk Scoring — combines severity with Sola environmental context
# ============================================================

def score_with_sola_context(
    findings: list[Finding],
    repo_contexts: dict[str, RepoContext],
) -> list[Finding]:
    """Score findings using Sola's environmental data.

    Risk = severity_weight × exposure_factor × posture_gap_factor

    exposure_factor: public repos, many collaborators, admin-heavy = higher
    posture_gap_factor: no branch protection, no reviews, force push allowed = higher
    """
    for f in findings:
        repo_name = f.context.get("repo", "") if f.context else ""
        ctx = repo_contexts.get(repo_name)

        base = SEVERITY_WEIGHT.get(f.severity, 1)
        exposure = 1.0
        posture_gap = 1.0

        if ctx:
            # Exposure: public repo = 1.5x, private = 1.0x
            if not ctx.is_private:
                exposure += 0.5

            # Exposure: more collaborators = higher blast radius
            exposure += min(ctx.collaborator_count, 20) * 0.05

            # Exposure: high admin ratio = more powerful compromise
            if ctx.collaborator_count > 0:
                admin_ratio = ctx.admin_count / ctx.collaborator_count
                if admin_ratio > 0.5:
                    exposure += 0.3

            # Posture gaps compound risk
            if not ctx.has_branch_protection:
                posture_gap += 0.3
            if not ctx.requires_reviews:
                posture_gap += 0.2
            if ctx.allows_force_pushes:
                posture_gap += 0.4
            if not ctx.has_vulnerability_alerts:
                posture_gap += 0.1
            if not ctx.has_security_policy:
                posture_gap += 0.1

        f.risk_score = round(base * exposure * posture_gap, 2)

        if f.context is None:
            f.context = {}
        f.context["exposure_factor"] = round(exposure, 2)
        f.context["posture_gap_factor"] = round(posture_gap, 2)

    findings.sort(key=lambda f: (-f.risk_score, f.severity))
    return findings


# ============================================================
# Posture Assessment — pure Sola data, no local clone needed
# ============================================================

def assess_repo_posture_from_sola(ctx: RepoContext) -> dict:
    """Assess repository security posture using Sola's data."""
    checks = []
    gaps = []

    # Branch protection
    checks.append({
        "id": "SOLA-BP-001",
        "name": "Branch protection enabled",
        "passed": ctx.has_branch_protection,
    })
    if not ctx.has_branch_protection:
        gaps.append("No branch protection — anyone with write access can push directly to default branch")

    # Required reviews
    checks.append({
        "id": "SOLA-BP-002",
        "name": "Required pull request reviews",
        "passed": ctx.requires_reviews,
    })
    if not ctx.requires_reviews:
        gaps.append("No required reviews — code can be merged without peer review")

    # Status checks
    checks.append({
        "id": "SOLA-BP-003",
        "name": "Required status checks",
        "passed": ctx.requires_status_checks,
    })
    if not ctx.requires_status_checks:
        gaps.append("No required status checks — CI can be bypassed")

    # Force push
    checks.append({
        "id": "SOLA-BP-004",
        "name": "Force push disabled",
        "passed": not ctx.allows_force_pushes,
    })
    if ctx.allows_force_pushes:
        gaps.append("Force push allowed — commit history can be rewritten, audit trail destroyed")

    # Vulnerability alerts
    checks.append({
        "id": "SOLA-VUL-001",
        "name": "Vulnerability alerts enabled",
        "passed": ctx.has_vulnerability_alerts,
    })
    if not ctx.has_vulnerability_alerts:
        gaps.append("Vulnerability alerts disabled — known CVEs in dependencies won't be flagged")

    # Security policy
    checks.append({
        "id": "SOLA-SEC-001",
        "name": "Security policy published",
        "passed": ctx.has_security_policy,
    })
    if not ctx.has_security_policy:
        gaps.append("No security policy — no documented vulnerability disclosure process")

    score = sum(1 for c in checks if c["passed"]) / max(len(checks), 1)

    return {
        "repo": ctx.full_name,
        "visibility": ctx.visibility,
        "language": ctx.language,
        "collaborators": ctx.collaborator_count,
        "admins": ctx.admin_count,
        "checks": checks,
        "gaps": gaps,
        "score": round(score, 2),
    }


# ============================================================
# Report Generation
# ============================================================

def generate_sola_report(
    findings: list[Finding],
    repo_postures: list[dict],
    scan_stats: dict = None,
) -> dict:
    """Generate full scan report combining findings and posture assessments."""
    by_severity = {"critical": [], "high": [], "medium": [], "low": []}
    by_category = {"cicd": [], "supply_chain": [], "code": [], "posture": []}
    by_repo = {}

    for f in findings:
        by_severity.get(f.severity, by_severity["low"]).append(f.to_dict())
        by_category.get(f.category, by_category["code"]).append(f.to_dict())
        repo = f.context.get("repo", "unknown") if f.context else "unknown"
        by_repo.setdefault(repo, []).append(f.to_dict())

    return {
        "scan_type": "sola_integrated",
        "total_findings": len(findings),
        "summary": {
            "critical": len(by_severity["critical"]),
            "high": len(by_severity["high"]),
            "medium": len(by_severity["medium"]),
            "low": len(by_severity["low"]),
        },
        "by_category": {k: len(v) for k, v in by_category.items()},
        "repos_scanned": len(repo_postures),
        "repos_with_findings": len(by_repo),
        "posture_summary": {
            "average_score": round(
                sum(p["score"] for p in repo_postures) / max(len(repo_postures), 1), 2
            ),
            "repos_without_branch_protection": sum(
                1 for p in repo_postures
                if not any(c["id"] == "SOLA-BP-001" and c["passed"] for c in p["checks"])
            ),
            "repos_without_vuln_alerts": sum(
                1 for p in repo_postures
                if not any(c["id"] == "SOLA-VUL-001" and c["passed"] for c in p["checks"])
            ),
        },
        "scan_stats": scan_stats or {},
        "postures": repo_postures,
        "findings": [f.to_dict() for f in findings],
        "findings_by_repo": {k: v for k, v in by_repo.items()},
    }


# ============================================================
# SQL Query Templates (for MCP execute_sql)
# ============================================================

QUERIES = {
    "list_repos": """
        SELECT name_with_owner, name, visibility, is_private,
               has_vulnerability_alerts_enabled, is_security_policy_enabled,
               primary_language
        FROM github_owned_repository
        WHERE is_archived = false
        ORDER BY name_with_owner
    """,

    "get_workflows": """
        SELECT repository_full_name, name, path, state, workflow_file_content
        FROM github_workflow
        WHERE workflow_file_content IS NOT NULL
          AND state = 'active'
    """,

    "get_branch_protection": """
        SELECT repository_full_name, pattern,
               requires_approving_reviews, required_approving_review_count,
               requires_status_checks, is_admin_enforced,
               allows_force_pushes, allows_deletions,
               requires_code_owner_reviews, requires_commit_signatures
        FROM github_branch_protection
    """,

    "get_collaborators": """
        SELECT repository_full_name, user_login, permission
        FROM github_repository_collaborator
    """,

    "get_dependabot_alerts": """
        SELECT repository_full_name, security_advisory_ghsa_id,
               security_advisory_severity, security_advisory_summary,
               state
        FROM github_repository_dependabot_alert
        WHERE state = 'open'
        ORDER BY security_advisory_severity
    """,

    "get_secrets": """
        SELECT repository_full_name, name, created_at, updated_at
        FROM github_actions_repository_secret
        ORDER BY repository_full_name, name
    """,

    "semgrep_rule_coverage": """
        SELECT category, severity, vulnerability_class, cwe_categories,
               count(*) as rule_count
        FROM semgrep_policy_rule
        WHERE category = 'security'
        GROUP BY category, severity, vulnerability_class, cwe_categories
        ORDER BY rule_count DESC
    """,

    "semgrep_findings": """
        SELECT repository_name, severity, confidence, rule_name, rule_message,
               rule_category, rule_cwe_names, rule_vulnerability_classes,
               location_file_path, location_line, state
        FROM semgrep_sast_finding
        WHERE state != 'dismissed'
        ORDER BY severity, repository_name
    """,

    "semgrep_sca_findings": """
        SELECT repository_name, severity, confidence, rule_name, rule_message,
               found_dependency_package, found_dependency_version,
               vulnerability_identifier, reachability, location_file_path
        FROM semgrep_sca_finding
        WHERE state != 'dismissed'
        ORDER BY severity
    """,

    "semgrep_secrets": """
        SELECT repository_name, severity, type, validation_state,
               finding_path, status
        FROM semgrep_secrets_finding
        WHERE status != 'dismissed'
        ORDER BY severity
    """,
}


# ============================================================
# Semgrep Cross-Validation
# ============================================================

PANGOLIN_TO_CWE = {
    "CICD-001": ["CWE-78", "CWE-94"],
    "CICD-002": ["CWE-269", "CWE-250"],
    "CICD-003": ["CWE-829", "CWE-494"],
    "CICD-004": ["CWE-250", "CWE-269"],
    "CICD-005": ["CWE-200", "CWE-312"],
    "CICD-006": ["CWE-284"],
    "CICD-007": ["CWE-494", "CWE-829"],
    "CICD-008": ["CWE-284", "CWE-269"],
    "SC-001": ["CWE-494"],
    "SC-002": ["CWE-494", "CWE-829"],
    "SC-003": ["CWE-494"],
    "SC-004": ["CWE-494"],
    "CODE-001": ["CWE-78"],
    "CODE-002": ["CWE-918"],
    "CODE-003": ["CWE-502"],
    "CODE-004": ["CWE-798", "CWE-312"],
    "CODE-005": ["CWE-22"],
}


def get_semgrep_rule_coverage(semgrep_rules: list[dict]) -> dict:
    """Analyze Semgrep rule coverage relative to Pangolin patterns."""
    coverage = {}
    for pattern_id, cwes in PANGOLIN_TO_CWE.items():
        matching_rules = []
        for rule in semgrep_rules:
            rule_cwes = rule.get("cwe_categories", "") or ""
            for cwe in cwes:
                if cwe in rule_cwes:
                    matching_rules.append({
                        "severity": rule.get("severity", ""),
                        "vuln_class": rule.get("vulnerability_class", ""),
                        "count": rule.get("rule_count", 1),
                    })
                    break
        coverage[pattern_id] = {
            "cwes": cwes,
            "semgrep_rules": len(matching_rules),
            "covered": len(matching_rules) > 0,
        }
    total = len(coverage)
    covered = sum(1 for v in coverage.values() if v["covered"])
    return {
        "total_patterns": total,
        "covered_by_semgrep": covered,
        "coverage_pct": round(covered / max(total, 1), 2),
        "details": coverage,
    }


def cross_validate_findings(
    pangolin_findings: list,
    semgrep_findings: list[dict],
) -> list:
    """Boost confidence of Pangolin findings that Semgrep also flagged."""
    semgrep_by_repo = {}
    for sf in semgrep_findings:
        repo = sf.get("repository_name", "")
        semgrep_by_repo.setdefault(repo, []).append(sf)

    for finding in pangolin_findings:
        repo = ""
        if hasattr(finding, "context") and finding.context:
            repo = finding.context.get("repo", "")
        elif isinstance(finding, dict):
            repo = finding.get("_repo", finding.get("context", {}).get("repo", ""))

        repo_short = repo.split("/")[-1] if "/" in repo else repo
        semgrep_hits = semgrep_by_repo.get(repo_short, [])

        if semgrep_hits:
            if hasattr(finding, "context") and finding.context:
                finding.context["semgrep_corroborated"] = True
                finding.context["semgrep_findings_in_repo"] = len(semgrep_hits)
            elif isinstance(finding, dict):
                finding["semgrep_corroborated"] = True
                finding["semgrep_findings_in_repo"] = len(semgrep_hits)

    return pangolin_findings
