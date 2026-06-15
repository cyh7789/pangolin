"""
Pangolin — Auto-Fix & PR Generator

Takes a confirmed finding + original workflow YAML,
uses LLM to generate a fix, then opens a GitHub PR.
"""

import json
import os
import subprocess
from pathlib import Path

import httpx

from .llm_analyzer import call_codex


FIX_INSTRUCTIONS = """You are a CI/CD security engineer fixing a vulnerability in a GitHub Actions workflow.

Your job: produce the COMPLETE fixed workflow YAML that patches the vulnerability while keeping all other functionality intact.

Best practices for fixes:
- Script injection (${{ }}): move untrusted input to an environment variable, reference via $ENV_VAR in the script
- Unpinned actions: replace mutable tag (@v4) with full SHA pin (@sha256:...)
- Excessive permissions: add explicit `permissions:` block with minimum required scopes
- pull_request_target with checkout: add explicit ref check or switch to pull_request event
- Secrets in fork-accessible context: gate on `github.event.pull_request.head.repo.full_name == github.repository`
- Unsafe curl|sh: download first, verify checksum, then execute

RULES:
- Output ONLY valid JSON (no markdown fences, no explanation outside JSON)
- The fixed_yaml must be the COMPLETE workflow file, not a diff
- Only modify what's necessary to fix THIS vulnerability
- Do not remove or alter unrelated workflow functionality
- Add a brief inline YAML comment (# pangolin-fix: ...) on changed lines

Output format:
{
  "fixed_yaml": "complete fixed workflow YAML content",
  "summary": "one-line description of what was changed",
  "changes": ["change 1", "change 2"]
}"""


def get_github_token() -> str:
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        return token

    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.startswith("GITHUB_TOKEN="):
                return line.split("=", 1)[1].strip()

    try:
        result = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return ""


def generate_fix(
    finding: dict,
    workflow_content: str,
    poc_content: str = "",
) -> dict:
    """Use LLM to generate a fixed workflow YAML."""
    poc_section = ""
    if poc_content:
        poc_section = f"\nProof of Concept (shows how the vulnerability is exploited):\n{poc_content[:5000]}\n"

    user_input = f"""Fix this vulnerability in the GitHub Actions workflow.

Vulnerability:
- Title: {finding.get('title', 'Unknown')}
- Severity: {finding.get('severity', 'unknown')}
- Pattern: {finding.get('pattern_id', 'unknown')}
- Attack Scenario: {finding.get('attack_scenario', '')}
- Impact: {finding.get('impact', '')}
- Evidence: {finding.get('evidence', '')}
- Recommended Fix: {finding.get('fix', '')}
{poc_section}
Original workflow YAML:
```yaml
{workflow_content}
```

Return the fix as JSON."""

    response = call_codex(FIX_INSTRUCTIONS, user_input, timeout=120)
    return _parse_fix_response(response)


def _parse_fix_response(text: str) -> dict:
    """Parse LLM fix response into structured dict."""
    import re
    text = text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    if "```json" in text:
        start = text.index("```json") + 7
        end = text.index("```", start)
        text = text[start:end].strip()
    elif "```" in text:
        start = text.index("```") + 3
        end = text.index("```", start)
        text = text[start:end].strip()

    text = re.sub(r',\s*}', '}', text)
    text = re.sub(r',\s*]', ']', text)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"fixed_yaml": "", "summary": "Parse failed", "changes": []}


def create_github_pr(
    owner: str,
    repo: str,
    workflow_path: str,
    fixed_yaml: str,
    finding: dict,
    fix_summary: str,
    changes: list[str],
) -> str:
    """Create a GitHub PR with the fix. Returns PR URL."""
    token = get_github_token()
    if not token:
        raise RuntimeError(
            "No GitHub token. Set GITHUB_TOKEN env var or run `gh auth login`."
        )

    api = "https://api.github.com"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    with httpx.Client(headers=headers, timeout=30) as gh:
        # 1. Get default branch HEAD
        ref_resp = gh.get(f"{api}/repos/{owner}/{repo}")
        ref_resp.raise_for_status()
        default_branch = ref_resp.json()["default_branch"]

        branch_resp = gh.get(
            f"{api}/repos/{owner}/{repo}/git/ref/heads/{default_branch}"
        )
        branch_resp.raise_for_status()
        base_sha = branch_resp.json()["object"]["sha"]

        # 2. Create fix branch
        severity = finding.get("severity", "fix")
        slug = finding.get("title", "security-fix").replace(" ", "-")[:40].lower()
        branch_name = f"pangolin/{severity}-{slug}"
        branch_name = "".join(
            c if c.isalnum() or c in "-_/" else "-" for c in branch_name
        )

        create_ref = gh.post(
            f"{api}/repos/{owner}/{repo}/git/refs",
            json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
        )
        if create_ref.status_code == 422:
            branch_name += "-2"
            create_ref = gh.post(
                f"{api}/repos/{owner}/{repo}/git/refs",
                json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
            )
        create_ref.raise_for_status()

        # 3. Get current file to obtain its SHA
        file_path = workflow_path
        if not file_path.startswith(".github/"):
            file_path = f".github/workflows/{file_path}"

        file_resp = gh.get(
            f"{api}/repos/{owner}/{repo}/contents/{file_path}",
            params={"ref": default_branch},
        )
        file_resp.raise_for_status()
        file_sha = file_resp.json()["sha"]

        # 4. Commit fix
        import base64
        encoded = base64.b64encode(fixed_yaml.encode()).decode()

        commit_msg = f"fix({severity}): {finding.get('title', 'security fix')}\n\nPangolin auto-fix: {fix_summary}"

        update_resp = gh.put(
            f"{api}/repos/{owner}/{repo}/contents/{file_path}",
            json={
                "message": commit_msg,
                "content": encoded,
                "sha": file_sha,
                "branch": branch_name,
            },
        )
        update_resp.raise_for_status()

        # 5. Create PR
        changes_md = "\n".join(f"- {c}" for c in changes) if changes else "- Security fix applied"

        pr_body = f"""## 🐾 Pangolin Security Fix

**Severity**: {finding.get('severity', 'unknown').upper()}
**Pattern**: `{finding.get('pattern_id', 'N/A')}`
**Confidence**: {finding.get('confidence', 'N/A')}

### Vulnerability

{finding.get('attack_scenario', 'N/A')}

### Changes

{changes_md}

### Impact

{finding.get('impact', 'N/A')}

---
*Auto-generated by [Pangolin](https://github.com/cyh7789/pangolin) — CI/CD Security Scanner*
"""

        pr_resp = gh.post(
            f"{api}/repos/{owner}/{repo}/pulls",
            json={
                "title": f"🐾 fix({severity}): {finding.get('title', 'security fix')}",
                "body": pr_body,
                "head": branch_name,
                "base": default_branch,
            },
        )
        pr_resp.raise_for_status()
        return pr_resp.json()["html_url"]


def fix_finding(
    finding: dict,
    workflow_content: str,
    poc_content: str = "",
    dry_run: bool = False,
) -> dict:
    """Full fix pipeline: generate fix → create PR.

    Returns dict with fix details and PR URL.
    """
    print(f"  🔧 Generating fix for: {finding.get('title', 'unknown')}...")
    fix_result = generate_fix(finding, workflow_content, poc_content)

    fixed_yaml = fix_result.get("fixed_yaml", "")
    if not fixed_yaml:
        return {"error": "LLM failed to generate fix", "raw": fix_result}

    summary = fix_result.get("summary", "Security fix")
    changes = fix_result.get("changes", [])

    print(f"  ✅ Fix generated: {summary}")
    for c in changes:
        print(f"     • {c}")

    if dry_run:
        return {
            "fixed_yaml": fixed_yaml,
            "summary": summary,
            "changes": changes,
            "dry_run": True,
        }

    repo_full = finding.get("_repo", "")
    if "/" not in repo_full:
        return {"error": f"Invalid repo: {repo_full}", "fixed_yaml": fixed_yaml}

    owner, repo = repo_full.split("/", 1)
    workflow_path = finding.get("_workflow", "")

    print(f"  📤 Creating PR on {repo_full}...")
    pr_url = create_github_pr(
        owner, repo, workflow_path,
        fixed_yaml, finding, summary, changes,
    )

    print(f"  🎉 PR created: {pr_url}")
    return {
        "fixed_yaml": fixed_yaml,
        "summary": summary,
        "changes": changes,
        "pr_url": pr_url,
    }
