"""
Pangolin — Slack Notification

Pushes scan results to Slack via incoming webhook.
"""

import json
import os
import httpx


def _read_env(key: str) -> str:
    val = os.environ.get(key, "")
    if not val:
        env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
        if os.path.exists(env_path):
            for line in open(env_path):
                if line.startswith(f"{key}="):
                    val = line.split("=", 1)[1].strip()
    return val


def get_webhook_url() -> str:
    return _read_env("SLACK_WEBHOOK_URL")


def send_slack_message(text: str, blocks: list = None) -> bool:
    url = get_webhook_url()
    if not url:
        return False

    payload = {"text": text}
    if blocks:
        payload["blocks"] = blocks

    try:
        resp = httpx.post(url, json=payload, timeout=10)
        return resp.status_code == 200
    except Exception:
        return False


def notify_scan_results(findings: list[dict], repo_count: int = 0, workflow_count: int = 0) -> bool:
    """Send formatted scan results to Slack."""
    if not findings:
        return send_slack_message("🐾 Pangolin scan complete — no findings. All clear.")

    by_sev = {"critical": [], "high": [], "medium": [], "low": []}
    for f in findings:
        sev = f.get("severity", "low")
        by_sev.get(sev, by_sev["low"]).append(f)

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🐾 Pangolin Security Scan Complete"}
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{len(findings)} findings* across {repo_count} repos, {workflow_count} workflows"
            }
        },
        {"type": "divider"},
    ]

    severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}

    for sev in ["critical", "high", "medium", "low"]:
        items = by_sev[sev]
        if not items:
            continue

        emoji = severity_emoji[sev]
        lines = [f"{emoji} *{sev.upper()}* ({len(items)})"]
        for f in items[:5]:
            title = f.get("title", f.get("pattern_name", "Unknown"))
            repo = f.get("_repo", f.get("repo", ""))
            wf = f.get("_workflow", "")
            lines.append(f"• {title}")
            if repo:
                lines.append(f"  `{repo}` → `{wf}`")
        if len(items) > 5:
            lines.append(f"  _...and {len(items) - 5} more_")

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "\n".join(lines)}
        })

    blocks.append({"type": "divider"})
    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": "Run `pangolin scan --deep` for full LLM analysis with PoC generation"}
        ]
    })

    summary = f"🐾 Pangolin: {len(by_sev['critical'])} critical, {len(by_sev['high'])} high, {len(by_sev['medium'])} medium findings"
    return send_slack_message(summary, blocks)


def notify_deep_analysis(
    findings: list[dict],
    report_path: str = None,
    poc_count: int = 0,
    false_positives: int = 0,
) -> bool:
    """Send deep analysis results after LLM scan."""
    real = [f for f in findings if f.get("is_real", True) and not f.get("error")]
    fp = [f for f in findings if not f.get("is_real", True)]

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🔬 Pangolin Deep Analysis Complete"}
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"LLM engine (gpt-5.5) analyzed flagged workflows:\n"
                    f"• *{len(real)} confirmed vulnerabilities*\n"
                    f"• {len(fp) + false_positives} false positives filtered out\n"
                    f"• {poc_count} PoC exploit files generated"
                )
            }
        },
        {"type": "divider"},
    ]

    severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}

    for f in real[:5]:
        sev = f.get("severity", "medium")
        emoji = severity_emoji.get(sev, "⚪")
        title = f.get("title", "Unknown")
        confidence = f.get("confidence", "unknown")
        repo = f.get("_repo", "")
        workflow = f.get("_workflow", "")

        attack = f.get("attack_scenario", "")
        if isinstance(attack, list):
            attack = attack[0] if attack else ""
        if len(attack) > 200:
            attack = attack[:200] + "..."

        fix = f.get("fix", "")
        if len(fix) > 150:
            fix = fix[:150] + "..."

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{emoji} *{title}*\n"
                    f"Severity: *{sev.upper()}* | Confidence: {confidence}\n"
                    f"`{repo}` → `{workflow}`\n"
                    f"_{attack}_"
                )
            }
        })

        if fix:
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"💡 *Fix:* {fix}"}]
            })

    if len(real) > 5:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"_...and {len(real) - 5} more findings_"}]
        })

    blocks.append({"type": "divider"})

    output_lines = []
    if report_path:
        output_lines.append(f"📄 HTML Report: `{report_path}`")
    if poc_count > 0:
        output_lines.append(f"💣 {poc_count} PoC files ready for validation")

    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": "\n".join(output_lines) if output_lines else "Analysis complete."
        }
    })

    summary = f"🔬 Pangolin Deep: {len(real)} confirmed, {len(fp) + false_positives} filtered, {poc_count} PoCs"
    return send_slack_message(summary, blocks)


def upload_file(filepath: str, title: str = None, comment: str = None) -> bool:
    """Upload a file to Slack channel via bot token."""
    bot_token = _read_env("SLACK_BOT_TOKEN")
    channel_id = _read_env("SLACK_CHANNEL_ID")
    if not bot_token or not channel_id:
        return False

    try:
        with open(filepath, "rb") as f:
            content = f.read()

        headers = {"Authorization": f"Bearer {bot_token}"}
        filename = os.path.basename(filepath)

        resp = httpx.post(
            "https://slack.com/api/files.getUploadURLExternal",
            headers=headers,
            data={"filename": filename, "length": len(content)},
            timeout=15,
        )
        data = resp.json()
        if not data.get("ok"):
            return False

        httpx.post(data["upload_url"], content=content, timeout=30)

        resp3 = httpx.post(
            "https://slack.com/api/files.completeUploadExternal",
            headers={**headers, "Content-Type": "application/json"},
            json={
                "files": [{"id": data["file_id"], "title": title or filename}],
                "channel_id": channel_id,
                "initial_comment": comment or "",
            },
            timeout=15,
        )
        return resp3.json().get("ok", False)
    except Exception:
        return False


def _create_report_zip(report_path: str, poc_dir: str = None) -> str:
    """Bundle report + PoC files into a zip."""
    import zipfile
    import tempfile

    zip_path = report_path.replace(".html", ".zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        if os.path.exists(report_path):
            zf.write(report_path, "pangolin-report.html")

        if poc_dir and os.path.isdir(poc_dir):
            for root, dirs, files in os.walk(poc_dir):
                for f in files:
                    full = os.path.join(root, f)
                    arcname = os.path.join("poc", os.path.relpath(full, poc_dir))
                    zf.write(full, arcname)

    return zip_path


def notify_deep_with_report(
    findings: list[dict],
    report_path: str = None,
    poc_dir: str = None,
    poc_count: int = 0,
    false_positives: int = 0,
) -> bool:
    """Send deep analysis notification + upload report zip (report + PoC)."""
    ok = notify_deep_analysis(findings, report_path, poc_count, false_positives)

    if report_path and os.path.exists(report_path):
        zip_path = _create_report_zip(report_path, poc_dir)
        upload_file(
            zip_path,
            title="🐾 Pangolin Report + PoC Bundle",
            comment="🔬 Download, unzip, open `pangolin-report.html` in browser. PoC files in `poc/` folder.",
        )

    return ok
