"""
Pangolin Scanner Engine

Adapted from battle-tested vulnerability hunting patterns.
Scans repositories for CI/CD, supply chain, and code-level vulnerabilities.
"""

import os
import re
import subprocess
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from .patterns import Pattern, ALL_PATTERNS, CICD_PATTERNS, SUPPLY_CHAIN_PATTERNS, CODE_PATTERNS


@dataclass
class Finding:
    pattern_id: str
    pattern_name: str
    severity: str
    category: str
    file: str
    line: int
    code: str
    description: str
    source: str
    action: str
    risk_score: float = 0.0
    context: dict = None

    def to_dict(self):
        d = asdict(self)
        if d["context"] is None:
            d["context"] = {}
        return d


SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def detect_languages(repo_path: str) -> list[str]:
    langs = set()
    ext_map = {
        ".go": "go", ".js": "js", ".ts": "js", ".py": "python",
        ".java": "java", ".c": "cpp", ".cc": "cpp", ".h": "cpp",
        ".rs": "rust", ".yml": "yaml", ".yaml": "yaml",
    }
    for ext, lang in ext_map.items():
        result = subprocess.run(
            ["find", repo_path, "-name", f"*{ext}",
             "-not", "-path", "*/node_modules/*",
             "-not", "-path", "*/.git/*",
             "-not", "-path", "*/vendor/*"],
            capture_output=True, text=True, timeout=15,
        )
        if result.stdout.strip():
            langs.add(lang)
    return list(langs)


def grep_pattern(repo_path: str, regex: str, file_glob: str) -> list[dict]:
    try:
        result = subprocess.run(
            ["grep", "-rn", "-E", regex,
             "--include", file_glob,
             "--exclude-dir=node_modules",
             "--exclude-dir=.git",
             "--exclude-dir=vendor",
             "--exclude-dir=third_party",
             "--exclude-dir=__pycache__",
             repo_path],
            capture_output=True, text=True, timeout=30,
        )
        hits = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split(":", 2)
            if len(parts) >= 3:
                hits.append({
                    "file": parts[0],
                    "line": int(parts[1]) if parts[1].isdigit() else 0,
                    "code": parts[2].strip(),
                })
        return hits
    except subprocess.TimeoutExpired:
        return []


def check_anti_patterns(filepath: str, anti_patterns: list[str]) -> bool:
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
        return any(re.search(ap, content) for ap in anti_patterns)
    except Exception:
        return False


def scan_repo(
    repo_path: str,
    patterns: list[Pattern] = None,
    category_filter: str = None,
    lang_filter: str = None,
) -> list[Finding]:
    repo_path = os.path.abspath(repo_path)
    langs = detect_languages(repo_path)

    if lang_filter:
        langs = [l for l in langs if l == lang_filter]

    if patterns is None:
        patterns = ALL_PATTERNS

    if category_filter:
        patterns = [p for p in patterns if p.category == category_filter]

    findings = []
    seen = set()

    for pattern in patterns:
        if not any(pattern.matches_lang(l) for l in langs):
            continue

        for regex, file_glob in pattern.grep_patterns:
            raw_hits = grep_pattern(repo_path, regex, file_glob)

            for hit in raw_hits:
                if "_test." in hit["file"] or "/test" in hit["file"] or "/testdata/" in hit["file"]:
                    continue

                if check_anti_patterns(hit["file"], pattern.anti_patterns):
                    continue

                key = (pattern.id, hit["file"], hit["line"])
                if key in seen:
                    continue
                seen.add(key)

                findings.append(Finding(
                    pattern_id=pattern.id,
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    category=pattern.category,
                    file=os.path.relpath(hit["file"], repo_path),
                    line=hit["line"],
                    code=hit["code"][:150],
                    description=pattern.description,
                    source=pattern.source,
                    action=pattern.action,
                ))

    return findings


def score_findings(findings: list[Finding], posture: dict = None) -> list[Finding]:
    """Apply risk scoring: severity × exposure × posture gaps."""
    posture = posture or {}
    posture_multiplier = 1.0

    gaps = posture.get("gaps", [])
    if gaps:
        posture_multiplier += 0.1 * len(gaps)

    is_public = posture.get("visibility") == "public"
    team_size = posture.get("team_size", 1)
    exposure = 1.0 + (0.5 if is_public else 0) + (0.1 * min(team_size, 10))

    for f in findings:
        base = SEVERITY_WEIGHT.get(f.severity, 1)
        f.risk_score = round(base * exposure * posture_multiplier, 2)

    findings.sort(key=lambda f: (-f.risk_score, f.severity))
    return findings


def scan_workflows_dir(repo_path: str) -> list[Finding]:
    """Scan only .github/workflows/ for CI/CD patterns."""
    wf_dir = os.path.join(repo_path, ".github", "workflows")
    if not os.path.isdir(wf_dir):
        return []
    return scan_repo(repo_path, patterns=CICD_PATTERNS + SUPPLY_CHAIN_PATTERNS)


def generate_report(findings: list[Finding], repo_name: str, posture: dict = None) -> dict:
    """Generate structured scan report."""
    by_severity = {"critical": [], "high": [], "medium": [], "low": []}
    by_category = {"cicd": [], "supply_chain": [], "code": [], "posture": []}

    for f in findings:
        by_severity.get(f.severity, by_severity["low"]).append(f.to_dict())
        by_category.get(f.category, by_category["code"]).append(f.to_dict())

    return {
        "repo": repo_name,
        "total_findings": len(findings),
        "summary": {
            "critical": len(by_severity["critical"]),
            "high": len(by_severity["high"]),
            "medium": len(by_severity["medium"]),
            "low": len(by_severity["low"]),
        },
        "by_category": {k: len(v) for k, v in by_category.items()},
        "posture": posture or {},
        "findings": [f.to_dict() for f in findings],
    }
