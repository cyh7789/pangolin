"""
Pangolin — Report & PoC Generator

Produces two parallel outputs per finding:
1. Security Report (Codex-style: summary + evidence + verification checklist)
2. Proof of Concept (exploit demonstration)
"""

import json
from pathlib import Path
from .llm_analyzer import call_codex


REPORT_INSTRUCTIONS = """You are a security report writer producing clear, actionable vulnerability reports.

Format: Markdown with these exact sections:

# [Title]

**Severity**: [Critical/High/Medium/Low]
**Repository**: [repo name]
**Workflow**: [workflow path]
**Pattern**: [attack pattern ID]

## Summary

[2-3 paragraphs explaining the vulnerability, the attack chain, and why it matters.
Be specific about what the attacker controls and what they can reach.]

## Verification

[Checklist of evidence items. Each item proves one link in the attack chain.
Use - [x] for verified items and - [ ] for items that need manual confirmation.]

## Evidence

[Show the specific code/YAML lines that prove the vulnerability.
Use code blocks with file paths and line annotations.
Add a brief explanation between code blocks connecting the dots.]

## Impact

[Concrete impact: what an attacker gains. Secrets theft? Code execution?
Supply chain poisoning? Be specific about the blast radius.]

## Remediation

[Step-by-step fix. Include code examples of the secure version.
Prioritize the most impactful fix first.]

RULES:
- Write for a security engineer who needs to decide whether to act today.
- Every claim must have a code reference.
- No filler. No "this could potentially maybe". State facts.
- If something is unverified, put it in the checklist as - [ ]."""


POC_INSTRUCTIONS = """You are a security researcher creating proof-of-concept demonstrations for CI/CD vulnerabilities.

For each vulnerability, generate a SAFE, DEMONSTRATIVE proof of concept that shows HOW the attack works without causing actual damage.

Format: Markdown with these sections:

# PoC: [Title]

**Target**: [repository/workflow]
**Attack Vector**: [how attacker triggers this]

## Prerequisites

[What the attacker needs: fork access? ability to open PR? ability to comment?]

## Steps to Reproduce

[Numbered steps. Be specific enough that a security engineer can verify.]

## Exploit Payload

[The actual payload — malicious workflow YAML, PR branch name, comment body, etc.
Show the exact content that would trigger the vulnerability.
Use code blocks.]

## Expected Result

[What happens if the exploit succeeds. What the attacker sees/gets.]

## Detection

[How a defender would notice this attack in logs/alerts.]

## Mitigation Applied

[Show the fixed version of the vulnerable code.]

RULES:
- PoC must be REPRODUCIBLE but SAFE — demonstrate the path, don't weaponize.
- For script injection: show the injection payload but use benign commands (echo, env).
- For secret theft: show the exfiltration path but use a dummy endpoint.
- Include both the attack AND the fix."""


def generate_finding_report(finding: dict, workflow_content: str) -> str:
    """Generate a Codex-style security report for a single finding."""
    user_input = f"""Generate a security report for this finding:

Finding: {json.dumps(finding, indent=2, ensure_ascii=False)}

Full workflow content:
```yaml
{workflow_content[:15000]}
```

Generate the report in Markdown format following the exact template."""

    return call_codex(REPORT_INSTRUCTIONS, user_input, timeout=90)


def generate_finding_poc(finding: dict, workflow_content: str) -> str:
    """Generate a proof-of-concept for a single finding."""
    user_input = f"""Generate a proof-of-concept for this vulnerability:

Finding: {json.dumps(finding, indent=2, ensure_ascii=False)}

Full workflow content:
```yaml
{workflow_content[:15000]}
```

Generate a safe, demonstrative PoC in Markdown format."""

    return call_codex(POC_INSTRUCTIONS, user_input, timeout=90)


def generate_full_report(
    findings: list[dict],
    workflow_contents: dict[str, str],
    output_dir: str = "output",
    max_findings: int = 5,
) -> dict:
    """Generate reports and PoCs for top findings.

    Returns dict with paths to generated files.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    real_findings = [
        f for f in findings
        if f.get("is_real", True) and not f.get("error")
    ][:max_findings]

    generated = {"reports": [], "pocs": [], "summary": None}

    # Generate individual reports and PoCs
    for i, finding in enumerate(real_findings):
        wf_path = finding.get("_workflow", "")
        wf_content = workflow_contents.get(wf_path, "")
        repo = finding.get("_repo", "unknown")
        title_slug = finding.get("title", f"finding-{i}").replace(" ", "-")[:50].lower()

        print(f"  Generating report for: {finding.get('title', 'unknown')}...")
        report_md = generate_finding_report(finding, wf_content)
        report_file = output_path / f"report-{i+1}-{title_slug}.md"
        report_file.write_text(report_md, encoding="utf-8")
        generated["reports"].append(str(report_file))

        print(f"  Generating PoC for: {finding.get('title', 'unknown')}...")
        poc_md = generate_finding_poc(finding, wf_content)
        poc_file = output_path / f"poc-{i+1}-{title_slug}.md"
        poc_file.write_text(poc_md, encoding="utf-8")
        generated["pocs"].append(str(poc_file))

    # Generate executive summary
    summary = generate_executive_summary(real_findings, workflow_contents)
    summary_file = output_path / "executive-summary.md"
    summary_file.write_text(summary, encoding="utf-8")
    generated["summary"] = str(summary_file)

    return generated


POC_FILES_INSTRUCTIONS = """You are a security researcher generating proof-of-concept exploit files for CI/CD vulnerabilities.

Generate ACTUAL, RUNNABLE exploit files that demonstrate the vulnerability safely.

For each file, output a JSON object with this exact structure:
```json
[
  {
    "path": "relative/path/to/file.ext",
    "content": "full file content here",
    "description": "what this file does",
    "language": "javascript|python|yaml|bash|json"
  }
]
```

RULES:
- Files must be SAFE demonstrations — use benign commands (echo, env), dummy endpoints (example.invalid).
- DO NOT include real secrets, real endpoints, or destructive commands.
- Include a README.md explaining how to use the PoC files.
- Include all necessary files to reproduce (scripts, configs, workflow yamls).
- For CI/CD exploits: include the malicious PR content, modified package.json, exploit scripts.
- For workflow injection: include the exact comment/PR body that triggers the vulnerability.
- Make files directly runnable — no placeholder code.
- Return ONLY the JSON array."""


def generate_poc_files(finding: dict, workflow_content: str, output_dir: str) -> list[str]:
    """Generate actual executable PoC files for a finding."""
    user_input = f"""Generate proof-of-concept exploit FILES for this vulnerability.

Finding: {json.dumps(finding, indent=2, ensure_ascii=False)}

Full workflow:
```yaml
{workflow_content[:15000]}
```

Return a JSON array of files to create. Each file needs: path, content, description, language."""

    try:
        response = call_codex(POC_FILES_INSTRUCTIONS, user_input, timeout=120)
        files = _extract_json_array(response)
    except Exception as e:
        files = [{
            "path": "README.md",
            "content": f"# PoC Generation Failed\n\nError: {e}",
            "description": "Error placeholder",
            "language": "markdown",
        }]

    poc_dir = Path(output_dir) / "poc" / _slugify(finding.get("title", "unknown"))
    poc_dir.mkdir(parents=True, exist_ok=True)

    created = []
    for f in files:
        filepath = poc_dir / f["path"]
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.write_text(f["content"], encoding="utf-8")
        created.append(str(filepath))

        if f.get("language") in ("bash", "python", "javascript"):
            filepath.chmod(0o755)

    return created


def _extract_json_array(text: str) -> list[dict]:
    """Extract JSON array from LLM response."""
    import re
    text = text.strip()

    # Try direct parse first (LLM returned clean JSON)
    try:
        result = json.loads(text)
        if isinstance(result, list):
            return result
    except json.JSONDecodeError:
        pass

    # Try extracting from markdown fences
    if "```json" in text:
        start = text.index("```json") + 7
        end = text.index("```", start)
        text = text[start:end].strip()
    elif "```" in text:
        start = text.index("```") + 3
        end = text.index("```", start)
        text = text[start:end].strip()

    # Find array bounds
    arr_start = text.find("[")
    arr_end = text.rfind("]")
    if arr_start >= 0 and arr_end > arr_start:
        text = text[arr_start:arr_end + 1]

    # Clean common JSON issues
    text = re.sub(r',\s*]', ']', text)
    text = re.sub(r',\s*}', '}', text)

    try:
        result = json.loads(text)
        return result if isinstance(result, list) else [result]
    except json.JSONDecodeError:
        return []


def _slugify(text: str) -> str:
    return text.replace(" ", "-").replace("/", "-")[:60].lower().strip("-")


SUMMARY_INSTRUCTIONS = """You are writing an executive summary of a CI/CD security scan.
Be concise. Highlight the most critical findings and overall risk posture.
Format as Markdown with:
- Scan Overview (repos scanned, workflows analyzed, findings count by severity)
- Critical Findings (one paragraph each)
- Risk Assessment (overall posture rating)
- Priority Actions (top 3 things to fix immediately)"""


def generate_executive_summary(findings: list[dict], workflow_contents: dict) -> str:
    """Generate executive summary across all findings."""
    findings_summary = json.dumps(
        [
            {
                "title": f.get("title"),
                "severity": f.get("severity"),
                "pattern_id": f.get("pattern_id"),
                "repo": f.get("_repo"),
                "workflow": f.get("_workflow"),
                "impact": f.get("impact"),
                "confidence": f.get("confidence"),
            }
            for f in findings
        ],
        indent=2,
        ensure_ascii=False,
    )

    user_input = f"""Generate an executive summary for this CI/CD security scan.

Total workflows analyzed: {len(workflow_contents)}
Total findings: {len(findings)}

Findings:
{findings_summary}

Write a concise executive summary in Markdown."""

    return call_codex(SUMMARY_INSTRUCTIONS, user_input, timeout=60)
