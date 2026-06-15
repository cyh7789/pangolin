"""
Pangolin — Repository Posture Assessment

Checks repository security configuration using local git repo data
and optionally enriched with Sola platform context.
"""

import os
import json
from pathlib import Path


def check_branch_protection_local(repo_path: str) -> dict:
    """Assess what we can determine from local repo state."""
    gaps = []
    checks = []

    github_dir = os.path.join(repo_path, ".github")
    workflows_dir = os.path.join(github_dir, "workflows")

    # Check: CODEOWNERS exists
    codeowners = any(
        os.path.exists(os.path.join(repo_path, p))
        for p in ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]
    )
    checks.append({"id": "POSTURE-001", "name": "CODEOWNERS file", "passed": codeowners})
    if not codeowners:
        gaps.append("No CODEOWNERS file — no automatic review assignment")

    # Check: Security policy
    security_policy = any(
        os.path.exists(os.path.join(repo_path, p))
        for p in ["SECURITY.md", ".github/SECURITY.md"]
    )
    checks.append({"id": "POSTURE-002", "name": "Security policy", "passed": security_policy})
    if not security_policy:
        gaps.append("No SECURITY.md — no vulnerability disclosure process")

    # Check: Dependabot / Renovate config
    dep_mgmt = any(
        os.path.exists(os.path.join(repo_path, p))
        for p in [".github/dependabot.yml", ".github/dependabot.yaml",
                   "renovate.json", ".renovaterc", ".renovaterc.json"]
    )
    checks.append({"id": "POSTURE-003", "name": "Dependency update automation", "passed": dep_mgmt})
    if not dep_mgmt:
        gaps.append("No Dependabot/Renovate — dependencies may go stale with known vulnerabilities")

    # Check: Lock files present
    lock_files = any(
        os.path.exists(os.path.join(repo_path, p))
        for p in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml",
                   "Pipfile.lock", "poetry.lock", "go.sum",
                   "Cargo.lock", "Gemfile.lock", "composer.lock"]
    )
    checks.append({"id": "POSTURE-004", "name": "Lock file committed", "passed": lock_files})
    if not lock_files:
        gaps.append("No lock file — builds are non-deterministic, dependency confusion risk")

    # Check: CI/CD workflows exist
    has_ci = os.path.isdir(workflows_dir) and any(
        f.endswith((".yml", ".yaml")) for f in os.listdir(workflows_dir)
    ) if os.path.isdir(workflows_dir) else False
    checks.append({"id": "POSTURE-005", "name": "CI/CD workflows", "passed": has_ci})
    if not has_ci:
        gaps.append("No GitHub Actions workflows — no automated testing or security checks")

    # Check: .gitignore includes sensitive patterns
    gitignore_path = os.path.join(repo_path, ".gitignore")
    sensitive_protected = False
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r", errors="ignore") as f:
            content = f.read()
        sensitive_protected = any(
            p in content for p in [".env", "credentials", "secret", ".pem", ".key"]
        )
    checks.append({"id": "POSTURE-006", "name": "Sensitive files in .gitignore", "passed": sensitive_protected})
    if not sensitive_protected:
        gaps.append(".gitignore doesn't exclude common secret files (.env, .pem, credentials)")

    return {
        "checks": checks,
        "gaps": gaps,
        "score": sum(1 for c in checks if c["passed"]) / max(len(checks), 1),
    }


def assess_posture(repo_path: str, sola_context: dict = None) -> dict:
    """Full posture assessment combining local checks and Sola data."""
    result = check_branch_protection_local(repo_path)

    if sola_context:
        # Enrich with Sola data
        if sola_context.get("visibility"):
            result["visibility"] = sola_context["visibility"]
        if sola_context.get("team_size"):
            result["team_size"] = sola_context["team_size"]
        if sola_context.get("branch_protection"):
            bp = sola_context["branch_protection"]
            if not bp.get("required_reviews"):
                result["gaps"].append("Branch protection: no required reviews")
            if not bp.get("required_status_checks"):
                result["gaps"].append("Branch protection: no required status checks")
            if not bp.get("enforce_admins"):
                result["gaps"].append("Branch protection: admins can bypass")

    return result
