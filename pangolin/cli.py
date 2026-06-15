#!/usr/bin/env python3
"""
Pangolin CLI — CI/CD & Supply Chain Security Scanner

Usage:
  # Local repo scan
  python -m pangolin.cli scan /path/to/repo

  # Full Sola-integrated pipeline (from pre-exported data)
  python -m pangolin.cli sola-scan --deep --notify

  # Export Sola data first (run from Claude Code with MCP)
  python -m pangolin.cli sola-export --output sola-data.json

  # Deep analysis on exported data
  python -m pangolin.cli sola-scan --input sola-data.json --deep --notify
"""

import argparse
import json
import sys
import os
import time

from .scanner import scan_repo, score_findings, generate_report, Finding
from .posture import assess_posture
from .patterns import ALL_PATTERNS, CICD_PATTERNS, SUPPLY_CHAIN_PATTERNS
from .sola_scanner import (
    WorkflowData, RepoContext,
    scan_all_workflows, score_with_sola_context,
    assess_repo_posture_from_sola, generate_sola_report, QUERIES,
)
from .html_report import save_html_report
from .slack_notify import notify_scan_results, notify_deep_with_report


SEVERITY_ICONS = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
OUTPUT_DIR = "output"


def print_banner():
    print("""
  ╔═══════════════════════════════════════════╗
  ║  🐾 Pangolin — CI/CD Security Scanner     ║
  ║  Armored pipeline protection              ║
  ╚═══════════════════════════════════════════╝
""")


def print_stage(num, msg):
    print(f"  [Stage {num}] {msg}")


def print_findings_summary(findings, label=""):
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", f.severity if hasattr(f, "severity") else "low")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    total = len(findings)
    print(f"\n  {'='*55}")
    print(f"  {label}{total} findings "
          f"({SEVERITY_ICONS['critical']}{by_sev['critical']} "
          f"{SEVERITY_ICONS['high']}{by_sev['high']} "
          f"{SEVERITY_ICONS['medium']}{by_sev['medium']})")
    print(f"  {'='*55}")


# ============================================================
# Command: scan (local repo)
# ============================================================

def cmd_scan(args):
    print_banner()
    repo_path = os.path.abspath(args.repo)
    repo_name = os.path.basename(repo_path)

    if not os.path.isdir(repo_path):
        print(f"  Error: {repo_path} is not a directory", file=sys.stderr)
        sys.exit(1)

    print_stage(0, "Assessing repository posture...")
    posture = assess_posture(repo_path)
    _print_posture(posture, repo_name)

    print_stage(1, "Scanning for vulnerability patterns...")
    findings = scan_repo(
        repo_path,
        category_filter=getattr(args, "category", None),
    )

    print_stage(2, "Scoring findings...")
    findings = score_findings(findings, posture)

    print_findings_summary(findings, f"{repo_name}: ")
    for f in findings[:10]:
        sev = SEVERITY_ICONS.get(f.severity, "⚪")
        print(f"    {sev} [{f.pattern_id}] {f.pattern_name}")
        print(f"       {f.file}:{f.line}")

    if len(findings) > 10:
        print(f"    ... and {len(findings) - 10} more")

    if args.output:
        report = generate_report(findings, repo_name, posture)
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n  Report saved to {args.output}")

    return len(findings)


# ============================================================
# Command: sola-scan (full Sola-integrated pipeline)
# ============================================================

def cmd_sola_scan(args):
    print_banner()
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Load Sola data
    input_path = getattr(args, "input", None) or os.path.join(OUTPUT_DIR, "sola-data.json")
    if not os.path.exists(input_path):
        print(f"  Error: Sola data not found at {input_path}")
        print(f"  Run 'pangolin sola-export' first, or provide --input path")
        sys.exit(1)

    print(f"  Loading Sola data from {input_path}...")
    with open(input_path) as f:
        sola_data = json.load(f)

    workflows = [
        WorkflowData(
            repo_full_name=w["repo_full_name"],
            name=w["name"],
            path=w["path"],
            content=w["content"],
            state=w.get("state", "active"),
        )
        for w in sola_data.get("workflows", [])
        if w.get("content")
    ]

    repo_contexts = {}
    for r in sola_data.get("repos", []):
        ctx = RepoContext(
            name=r.get("name", ""),
            full_name=r["full_name"],
            visibility=r.get("visibility", "UNKNOWN"),
            is_private=r.get("is_private", False),
            language=r.get("language", ""),
            has_vulnerability_alerts=r.get("has_vulnerability_alerts", False),
            has_security_policy=r.get("has_security_policy", False),
            collaborator_count=r.get("collaborator_count", 0),
            admin_count=r.get("admin_count", 0),
            has_branch_protection=r.get("has_branch_protection", False),
            requires_reviews=r.get("requires_reviews", False),
            requires_status_checks=r.get("requires_status_checks", False),
            allows_force_pushes=r.get("allows_force_pushes", False),
        )
        repo_contexts[r["full_name"]] = ctx

    repo_count = len(repo_contexts)
    wf_count = len(workflows)
    print(f"  Loaded {repo_count} repos, {wf_count} workflows")

    # Stage 1: Regex pattern scan on Sola workflow data
    print_stage(1, f"Regex scanning {wf_count} workflows (17 patterns)...")
    t0 = time.time()
    regex_findings = scan_all_workflows(workflows, repo_contexts)
    regex_findings = score_with_sola_context(regex_findings, repo_contexts)
    t1 = time.time()
    print(f"           Found {len(regex_findings)} candidates in {t1-t0:.1f}s")

    print_findings_summary(
        [{"severity": f.severity} for f in regex_findings],
        "Regex scan: ",
    )

    # Slack notify #1: quick scan results
    if getattr(args, "notify", False):
        print("  📤 Sending quick scan notification to Slack...")
        notify_scan_results(
            [f.to_dict() for f in regex_findings],
            repo_count=repo_count,
            workflow_count=wf_count,
        )

    # Stage 2: LLM deep analysis (optional)
    llm_findings = []
    false_positives = 0
    if getattr(args, "deep", False):
        print_stage(2, "LLM deep analysis (gpt-5.5)...")
        from .llm_analyzer import analyze_workflow

        # Prioritize workflows with regex hits
        hit_paths = {f.file.split("/", 1)[-1] if "/" in f.file else f.file for f in regex_findings}
        priority_wfs = [w for w in workflows if w.path in hit_paths]
        other_wfs = [w for w in workflows if w.path not in hit_paths]

        analyze_targets = priority_wfs[:10]
        if not analyze_targets:
            analyze_targets = workflows[:5]

        for i, wf in enumerate(analyze_targets):
            ctx = repo_contexts.get(wf.repo_full_name)
            visibility = ctx.visibility if ctx else "UNKNOWN"
            print(f"           [{i+1}/{len(analyze_targets)}] {wf.repo_full_name}/{wf.path}...")

            candidates = [
                f for f in regex_findings
                if wf.path in f.file
            ]

            results = analyze_workflow(
                repo_name=wf.repo_full_name,
                workflow_name=wf.name,
                workflow_path=wf.path,
                workflow_content=wf.content,
                visibility=visibility,
                regex_candidates=candidates,
            )

            for r in results:
                r["_workflow"] = wf.path
                r["_repo"] = wf.repo_full_name
                if r.get("is_real", True) and not r.get("error"):
                    llm_findings.append(r)
                elif not r.get("is_real", True):
                    false_positives += 1

        print(f"           ✅ {len(llm_findings)} confirmed, {false_positives} false positives filtered")
    else:
        llm_findings = [f.to_dict() for f in regex_findings]

    # Stage 3: Posture assessment
    print_stage(3, "Repository posture assessment...")
    postures = []
    for name, ctx in repo_contexts.items():
        postures.append(assess_repo_posture_from_sola(ctx))

    avg_score = sum(p["score"] for p in postures) / max(len(postures), 1)
    print(f"           Average posture score: {avg_score:.0%}")

    # Stage 3b: Semgrep cross-validation
    semgrep_coverage = None
    semgrep_data = sola_data.get("semgrep", {})
    semgrep_rules = semgrep_data.get("rules", [])
    semgrep_findings_data = semgrep_data.get("findings", [])

    if semgrep_rules:
        from .sola_scanner import get_semgrep_rule_coverage, cross_validate_findings
        print_stage("3b", f"Semgrep cross-validation ({len(semgrep_rules)} rules)...")
        semgrep_coverage = get_semgrep_rule_coverage(semgrep_rules)
        print(f"           Rule coverage: {semgrep_coverage['covered_by_semgrep']}/{semgrep_coverage['total_patterns']} patterns")

        if semgrep_findings_data:
            target = llm_findings if args.deep and llm_findings else regex_findings
            cross_validate_findings(target, semgrep_findings_data)
            corroborated = sum(
                1 for f in target
                if (f.get("semgrep_corroborated") if isinstance(f, dict)
                    else getattr(f, "context", {}).get("semgrep_corroborated"))
            )
            print(f"           Semgrep corroborated: {corroborated} findings")
        else:
            print(f"           No Semgrep scan findings yet (rules loaded, scans pending)")
    else:
        print("  [Skip] No Semgrep data in input file")

    # Stage 4: Generate reports
    print_stage(4, "Generating reports...")

    # HTML report
    html_path = os.path.join(OUTPUT_DIR, "report.html")
    save_html_report(
        llm_findings if args.deep else [f.to_dict() for f in regex_findings],
        html_path,
        repo_name=f"{repo_count} repositories",
        posture=postures[0] if postures else None,
        scan_stats={"workflows_scanned": wf_count},
    )
    print(f"           📄 HTML report: {html_path}")

    # PoC generation (if deep mode)
    poc_dir = None
    poc_count = 0
    if args.deep and llm_findings:
        print("           💣 Generating PoC files...")
        from .report_generator import generate_poc_files

        wf_contents = {w.path: w.content for w in workflows}
        for i, finding in enumerate(llm_findings[:3]):
            try:
                files = generate_poc_files(finding, wf_contents.get(finding.get("_workflow", ""), ""), OUTPUT_DIR)
                poc_count += len(files)
            except Exception as e:
                print(f"           PoC generation error: {e}")

        poc_dir = os.path.join(OUTPUT_DIR, "poc")
        print(f"           💣 {poc_count} PoC files generated")

    # Stage 5: Slack notifications
    if getattr(args, "notify", False):
        print_stage(5, "Sending results to Slack...")
        notify_deep_with_report(
            llm_findings,
            report_path=html_path,
            poc_dir=poc_dir,
            poc_count=poc_count,
            false_positives=false_positives,
        )
        print("           ✅ Slack notification + report zip sent")

    # Save scan results for `fix` command
    findings_to_show = llm_findings if args.deep else [f.to_dict() for f in regex_findings]
    results_path = os.path.join(OUTPUT_DIR, "scan-results.json")
    with open(results_path, "w") as rf:
        json.dump(findings_to_show, rf, indent=2, ensure_ascii=False)

    # Final summary
    print(f"\n  {'='*55}")
    print(f"  🐾 Pangolin scan complete")
    print(f"  {'='*55}")
    print(f"  Repos:       {repo_count}")
    print(f"  Workflows:   {wf_count}")
    print(f"  Findings:    {len(findings_to_show)}")
    if args.deep:
        print(f"  Confirmed:   {len(llm_findings)} (LLM verified)")
        print(f"  Filtered:    {false_positives} false positives")
        print(f"  PoCs:        {poc_count} files")
    print(f"  Report:      {html_path}")
    print(f"  Results:     {results_path}")
    print(f"  Posture avg: {avg_score:.0%}")
    print(f"\n  Run `pangolin fix --finding 0` to auto-fix a finding")

    return len(findings_to_show)


# ============================================================
# Command: fix (auto-fix a finding and open PR)
# ============================================================

def _normalize_finding(f: dict) -> dict:
    """Normalize regex and LLM finding formats to a common shape."""
    if "_repo" in f:
        return f

    ctx = f.get("context", {})
    repo = ctx.get("repo", "")
    raw_file = f.get("file", "")
    wf_path = raw_file.split("/", 2)[-1] if "/" in raw_file else raw_file

    return {
        **f,
        "title": f.get("title", f.get("pattern_name", "Unknown")),
        "_repo": repo,
        "_workflow": wf_path,
        "attack_scenario": f.get("attack_scenario", f.get("description", "")),
        "impact": f.get("impact", f.get("description", "")),
        "evidence": f.get("evidence", f.get("code", "")),
        "fix": f.get("fix", ""),
        "confidence": f.get("confidence", "regex"),
    }


def cmd_fix(args):
    print_banner()

    # Load scan results
    results_path = getattr(args, "results", None) or os.path.join(OUTPUT_DIR, "scan-results.json")
    if not os.path.exists(results_path):
        print(f"  Error: No scan results at {results_path}")
        print(f"  Run `pangolin sola-scan --deep` first")
        sys.exit(1)

    with open(results_path) as f:
        raw_findings = json.load(f)

    findings = [_normalize_finding(f) for f in raw_findings]

    if not findings:
        print("  No findings to fix.")
        return 0

    # Load Sola data for workflow content
    sola_path = getattr(args, "sola_data", None) or os.path.join(OUTPUT_DIR, "sola-data.json")
    wf_contents = {}
    if os.path.exists(sola_path):
        with open(sola_path) as f:
            sola_data = json.load(f)
        for w in sola_data.get("workflows", []):
            if w.get("content"):
                wf_contents[w["path"]] = w["content"]

    poc_dir = os.path.join(OUTPUT_DIR, "poc")

    from .fixer import fix_finding

    # List findings
    if getattr(args, "list", False):
        print(f"  {len(findings)} findings available:\n")
        for i, f in enumerate(findings):
            sev = SEVERITY_ICONS.get(f.get("severity", "low"), "⚪")
            title = f.get("title", f"Finding {i}")
            repo = f.get("_repo", "")
            print(f"  [{i}] {sev} {title}")
            print(f"       {repo} → {f.get('_workflow', '')}")
        print(f"\n  Run `pangolin fix --finding N` to fix one")
        return 0

    # Determine which findings to fix
    if getattr(args, "all", False):
        targets = list(range(len(findings)))
    else:
        idx = getattr(args, "finding", 0)
        if idx >= len(findings):
            print(f"  Error: Finding #{idx} doesn't exist (max: {len(findings)-1})")
            sys.exit(1)
        targets = [idx]

    # Fix each target
    results = []
    for idx in targets:
        finding = findings[idx]
        wf_path = finding.get("_workflow", "")
        wf_content = wf_contents.get(wf_path, "")

        if not wf_content:
            print(f"  ⚠️  [{idx}] No workflow content for {wf_path}, skipping")
            continue

        # Gather PoC content
        poc_content = ""
        title_slug = finding.get("title", "").replace(" ", "-")[:60].lower()
        poc_finding_dir = os.path.join(poc_dir, title_slug)
        if os.path.isdir(poc_finding_dir):
            for fname in os.listdir(poc_finding_dir):
                fpath = os.path.join(poc_finding_dir, fname)
                if os.path.isfile(fpath) and os.path.getsize(fpath) < 10000:
                    poc_content += f"\n--- {fname} ---\n"
                    with open(fpath) as pf:
                        poc_content += pf.read()

        print(f"\n  [{idx}] Fixing: {finding.get('title', 'unknown')}")
        print(f"       Repo: {finding.get('_repo', 'unknown')}")
        print(f"       Path: {wf_path}")

        try:
            result = fix_finding(
                finding, wf_content, poc_content,
                dry_run=getattr(args, "dry_run", False),
            )
            results.append(result)
        except Exception as e:
            print(f"  ❌ Error: {e}")
            results.append({"error": str(e)})

    # Notify Slack if requested
    if getattr(args, "notify", False) and results:
        from .slack_notify import send_slack_message
        prs = [r.get("pr_url") for r in results if r.get("pr_url")]
        if prs:
            pr_list = "\n".join(f"• <{url}|View PR>" for url in prs)
            send_slack_message(
                f"🔧 Pangolin auto-fix: {len(prs)} PR(s) created",
                [{
                    "type": "header",
                    "text": {"type": "plain_text", "text": "🔧 Pangolin Auto-Fix Complete"}
                }, {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"Created {len(prs)} fix PR(s):\n{pr_list}"}
                }],
            )

    # Summary
    success = [r for r in results if r.get("pr_url")]
    dry = [r for r in results if r.get("dry_run")]
    errors = [r for r in results if r.get("error")]

    print(f"\n  {'='*55}")
    print(f"  🔧 Fix complete")
    print(f"  {'='*55}")
    if success:
        print(f"  PRs created: {len(success)}")
        for r in success:
            print(f"    → {r['pr_url']}")
    if dry:
        print(f"  Dry-run:     {len(dry)} (use without --dry-run to create PRs)")
    if errors:
        print(f"  Errors:      {len(errors)}")

    return len(errors)


# ============================================================
# Command: sola-export (export Sola data via SQL)
# ============================================================

def cmd_sola_export(args):
    """Print SQL queries for exporting Sola data. Run these via MCP."""
    print_banner()
    print("  Run these SQL queries via Sola MCP (execute_sql) and save results:\n")

    for name, sql in QUERIES.items():
        print(f"  --- {name} ---")
        print(f"  {sql.strip()}")
        print()

    print("  Or use the helper script: python -m pangolin.export_sola")


# ============================================================
# Main
# ============================================================

def _print_posture(posture, repo_name):
    print(f"\n  📋 Posture Assessment: {repo_name}")
    print(f"  Score: {posture['score']:.0%}")
    for check in posture.get("checks", []):
        icon = "✅" if check["passed"] else "❌"
        print(f"    {icon} [{check['id']}] {check['name']}")
    if posture.get("gaps"):
        print(f"\n  ⚠️  Gaps ({len(posture['gaps'])}):")
        for gap in posture["gaps"]:
            print(f"    - {gap}")


def main():
    parser = argparse.ArgumentParser(
        prog="pangolin",
        description="Pangolin — Armored CI/CD Pipeline Security Scanner",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan: local repo
    scan_p = subparsers.add_parser("scan", help="Scan a local repository")
    scan_p.add_argument("repo", help="Path to repository")
    scan_p.add_argument("--category", choices=["cicd", "supply_chain", "code"])
    scan_p.add_argument("--json", action="store_true")
    scan_p.add_argument("--output", "-o", help="Save JSON report")

    # sola-scan: full pipeline
    sola_p = subparsers.add_parser("sola-scan", help="Full Sola-integrated scan pipeline")
    sola_p.add_argument("--input", "-i", help="Path to sola-data.json")
    sola_p.add_argument("--deep", action="store_true", help="Enable LLM deep analysis")
    sola_p.add_argument("--notify", action="store_true", help="Send Slack notifications")

    # fix: auto-fix findings
    fix_p = subparsers.add_parser("fix", help="Auto-fix a finding and open GitHub PR")
    fix_p.add_argument("--finding", "-f", type=int, default=0, help="Finding index to fix")
    fix_p.add_argument("--all", action="store_true", help="Fix all findings")
    fix_p.add_argument("--list", "-l", action="store_true", help="List fixable findings")
    fix_p.add_argument("--dry-run", action="store_true", help="Generate fix without creating PR")
    fix_p.add_argument("--notify", action="store_true", help="Send Slack notification")
    fix_p.add_argument("--results", help="Path to scan-results.json")
    fix_p.add_argument("--sola-data", help="Path to sola-data.json")

    # sola-export: show SQL queries
    subparsers.add_parser("sola-export", help="Show SQL queries for Sola data export")

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(1 if cmd_scan(args) > 0 else 0)
    elif args.command == "sola-scan":
        sys.exit(1 if cmd_sola_scan(args) > 0 else 0)
    elif args.command == "fix":
        sys.exit(1 if cmd_fix(args) > 0 else 0)
    elif args.command == "sola-export":
        cmd_sola_export(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
