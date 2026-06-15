"""
Pangolin — LLM Deep Analysis Layer

Takes regex-filtered candidates + full workflow content,
feeds to LLM with attack pattern instructions for deep reasoning.
Uses the same Codex responses API as our production scanning system.
"""

import json
import os
import httpx
from pathlib import Path

from .scanner import Finding


CODEX_AUTH_PATH = Path.home() / ".codex" / "auth.json"
RESPONSES_URL = "https://chatgpt.com/backend-api/codex/responses"
MODEL = "gpt-5.5"
EFFORT = "high"
ORIGINATOR = "codex_sdk_ts"
CLIENT_VERSION = "0.130.0"


def load_credentials() -> dict:
    with open(CODEX_AUTH_PATH) as f:
        auth = json.load(f)
    return {
        "access_token": auth["tokens"]["access_token"],
        "account_id": auth["tokens"]["account_id"],
    }


SYSTEM_INSTRUCTIONS = """You are a CI/CD pipeline security auditor with expertise in supply chain attacks.

You apply these attack pattern lenses when analyzing GitHub Actions workflows:

1. TOOLCHAIN_EXEC_BOUNDARY_INJECTION: External input (issue title, PR body, branch name, commit message) used directly in shell commands via ${{ }} expressions without sanitization. The execution boundary is the shell — attacker controls what gets executed.

2. FETCHER_DESTINATION_CONFUSION (SSRF in CI): Workflow fetches URLs from untrusted sources (PR content, issue body), or uses `curl | sh` patterns. The URL resolves to an attacker-controlled destination.

3. OBJECT_CAPABILITY_AUTHZ_GAP: Secrets, tokens, or permissions are exposed to contexts that don't need them. pull_request_target gives write permissions and secrets access to code from forks. workflow_run inherits permissions.

4. DESERIALIZATION_BEHAVIOR_REHYDRATION: CI downloads and executes artifacts, packages, or scripts without integrity verification. Actions referenced by mutable tags instead of SHA pins.

5. ASYMMETRIC_RESOURCE_AMPLIFICATION: Patterns that allow denial-of-service through CI resource abuse — fork-triggered workflows consuming runner minutes, recursive workflow triggers.

CRITICAL RULES:
- Only flag REAL, EXPLOITABLE vulnerabilities. Not theoretical risks.
- Consider mitigations already in place (SHA-pinned actions, permission restrictions, fork checks).
- A workflow with `permissions: {}` and SHA-pinned actions has minimal attack surface.
- `pull_request_target` is only dangerous if the workflow checks out PR code AND runs it.
- Distinguish between first-party actions (e.g., `angular/dev-infra/...@sha`) and third-party unpinned actions.

Output a JSON array of findings. Each finding must have:
- pattern_id: which attack pattern applies
- title: concise vulnerability title
- severity: critical/high/medium/low
- is_real: boolean — true only if exploitable
- attack_scenario: step-by-step how an attacker exploits this
- impact: what damage results (secrets theft, code execution, supply chain poisoning)
- evidence: specific line(s) or expression(s) that prove the vulnerability
- fix: concrete remediation step
- confidence: high/medium/low

If NO real vulnerabilities exist, return an empty array [].
Do NOT invent findings to seem thorough."""


def call_codex(instructions: str, user_input: str, timeout: int = 120) -> str:
    """Call Codex responses API with streaming SSE parsing."""
    creds = load_credentials()

    body = {
        "model": MODEL,
        "store": False,
        "stream": True,
        "instructions": instructions,
        "input": [{"role": "user", "content": user_input}],
        "reasoning": {"effort": EFFORT, "summary": "auto"},
    }

    headers = {
        "Authorization": f"Bearer {creds['access_token']}",
        "chatgpt-account-id": creds["account_id"],
        "Content-Type": "application/json",
        "OpenAI-Beta": "responses=experimental",
        "originator": ORIGINATOR,
        "User-Agent": f"{ORIGINATOR}/{CLIENT_VERSION}",
    }

    with httpx.Client(timeout=timeout) as client:
        resp = client.post(RESPONSES_URL, json=body, headers=headers)
        if resp.status_code == 401:
            raise RuntimeError("Codex token expired — run `codex login`")
        resp.raise_for_status()
        return parse_sse(resp.text)


def parse_sse(raw: str) -> str:
    """Parse SSE stream from Codex responses API."""
    delta_text = []
    completed_text = []

    for line in raw.split("\n"):
        if not line.startswith("data: "):
            continue
        payload = line[6:]
        if payload == "[DONE]":
            break

        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            continue

        event_type = event.get("type", "")

        if event_type == "response.output_text.delta":
            delta_text.append(event.get("delta", ""))
        elif event_type == "response.output_item.done":
            # Extract text from completed output item
            item = event.get("item", {})
            if item.get("type") == "message":
                for content in item.get("content", []):
                    if content.get("type") == "output_text":
                        completed_text.append(content.get("text", ""))

    # Prefer completed text over delta accumulation
    if completed_text:
        return "".join(completed_text)
    return "".join(delta_text)


def extract_json_array(text: str) -> list[dict]:
    """Extract JSON array from LLM response."""
    text = text.strip()

    if "```json" in text:
        start = text.index("```json") + 7
        end = text.index("```", start)
        text = text[start:end].strip()
    elif "```" in text:
        start = text.index("```") + 3
        end = text.index("```", start)
        text = text[start:end].strip()

    arr_start = text.find("[")
    arr_end = text.rfind("]")
    if arr_start >= 0 and arr_end > arr_start:
        text = text[arr_start:arr_end + 1]

    try:
        result = json.loads(text)
        return result if isinstance(result, list) else [result]
    except json.JSONDecodeError:
        return []


ANALYSIS_TEMPLATE = """Analyze this GitHub Actions workflow for security vulnerabilities.

Repository: {repo_name} ({visibility})
Workflow: {workflow_name}
Path: {workflow_path}
{candidates_section}
Full workflow YAML:
```yaml
{workflow_content}
```

Return ONLY a JSON array of findings. Empty array [] if no real vulnerabilities."""


def analyze_workflow(
    repo_name: str,
    workflow_name: str,
    workflow_path: str,
    workflow_content: str,
    visibility: str = "unknown",
    regex_candidates: list[Finding] = None,
) -> list[dict]:
    """Deep LLM analysis of a single workflow."""
    candidates_section = ""
    if regex_candidates:
        lines = "\n".join(
            f"- [{f.severity.upper()}] {f.pattern_id}: {f.pattern_name} (line {f.line}): {f.code}"
            for f in regex_candidates
        )
        candidates_section = f"\nRegex pre-scan found these candidates:\n{lines}\n"

    user_input = ANALYSIS_TEMPLATE.format(
        repo_name=repo_name,
        visibility=visibility,
        workflow_name=workflow_name,
        workflow_path=workflow_path,
        candidates_section=candidates_section,
        workflow_content=workflow_content[:20000],
    )

    try:
        response = call_codex(SYSTEM_INSTRUCTIONS, user_input)
        return extract_json_array(response)
    except Exception as e:
        return [{"error": str(e), "workflow": workflow_path}]


def analyze_workflows_batch(
    workflows: list[dict],
    regex_findings_by_path: dict[str, list[Finding]] = None,
    max_workflows: int = 10,
) -> list[dict]:
    """Analyze multiple workflows, prioritizing those with regex candidates."""
    regex_findings_by_path = regex_findings_by_path or {}

    prioritized = sorted(
        workflows,
        key=lambda w: len(regex_findings_by_path.get(w["path"], [])),
        reverse=True,
    )[:max_workflows]

    all_results = []
    for wf in prioritized:
        candidates = regex_findings_by_path.get(wf["path"], [])
        results = analyze_workflow(
            repo_name=wf["repo"],
            workflow_name=wf["name"],
            workflow_path=wf["path"],
            workflow_content=wf["content"],
            visibility=wf.get("visibility", "unknown"),
            regex_candidates=candidates,
        )
        for r in results:
            r["_workflow"] = wf["path"]
            r["_repo"] = wf["repo"]
        all_results.extend(results)

    return all_results
