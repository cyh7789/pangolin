"""
Pangolin — HTML Report Renderer

Renders scan findings into a dark-themed, professional HTML security report.
Designed for demo impact: severity badges, code highlighting, collapsible sections.
"""

import json
import html
from pathlib import Path
from datetime import datetime


SEVERITY_COLORS = {
    "critical": "#ff4444",
    "high": "#ff8800",
    "medium": "#ffcc00",
    "low": "#44cc44",
}

SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Pangolin Security Report — {repo_name}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
    background: #0d1117;
    color: #e6edf3;
    line-height: 1.6;
    padding: 2rem;
  }}
  .container {{ max-width: 960px; margin: 0 auto; }}

  /* Header */
  .header {{
    border-bottom: 1px solid #30363d;
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
  }}
  .header h1 {{
    font-size: 1.5rem;
    color: #58a6ff;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }}
  .header .logo {{ font-size: 2rem; }}
  .header .subtitle {{ color: #8b949e; margin-top: 0.3rem; font-size: 0.9rem; }}
  .header .meta {{
    display: flex;
    gap: 2rem;
    margin-top: 1rem;
    font-size: 0.85rem;
    color: #8b949e;
  }}
  .header .meta span {{ display: flex; align-items: center; gap: 0.3rem; }}

  /* Summary Cards */
  .summary {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .summary-card {{
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1rem;
    text-align: center;
  }}
  .summary-card .count {{
    font-size: 2rem;
    font-weight: bold;
  }}
  .summary-card .label {{
    font-size: 0.8rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}

  /* Finding Card */
  .finding {{
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    margin-bottom: 1.5rem;
    overflow: hidden;
  }}
  .finding-header {{
    padding: 1rem 1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #30363d;
    cursor: pointer;
  }}
  .finding-header:hover {{ background: #1c2128; }}
  .finding-title {{
    font-size: 1.1rem;
    font-weight: 600;
  }}
  .severity-badge {{
    padding: 0.2rem 0.8rem;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .finding-meta {{
    padding: 0.5rem 1.5rem;
    font-size: 0.8rem;
    color: #8b949e;
    display: flex;
    gap: 1.5rem;
    border-bottom: 1px solid #21262d;
  }}
  .finding-body {{
    padding: 1.5rem;
  }}
  .finding-body h3 {{
    color: #58a6ff;
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin: 1.5rem 0 0.5rem 0;
  }}
  .finding-body h3:first-child {{ margin-top: 0; }}
  .finding-body p {{ margin-bottom: 0.8rem; }}

  /* Verification Checklist */
  .checklist {{ list-style: none; padding: 0; }}
  .checklist li {{
    padding: 0.4rem 0;
    display: flex;
    align-items: flex-start;
    gap: 0.5rem;
  }}
  .check-pass {{ color: #3fb950; }}
  .check-pending {{ color: #d29922; }}

  /* Code Block */
  .code-block {{
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    margin: 0.8rem 0;
    overflow-x: auto;
  }}
  .code-block .file-path {{
    padding: 0.5rem 1rem;
    background: #161b22;
    border-bottom: 1px solid #30363d;
    font-size: 0.8rem;
    color: #8b949e;
    font-family: monospace;
  }}
  .code-block pre {{
    padding: 1rem;
    font-size: 0.85rem;
    line-height: 1.5;
    font-family: 'SF Mono', 'Fira Code', monospace;
    white-space: pre-wrap;
    word-wrap: break-word;
  }}
  .code-annotation {{
    background: #1f2937;
    border-left: 3px solid #58a6ff;
    padding: 0.5rem 1rem;
    margin: 0.5rem 0;
    font-size: 0.85rem;
    color: #c9d1d9;
  }}

  /* Risk Score */
  .risk-score {{
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    background: #21262d;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.85rem;
    font-weight: 600;
  }}

  /* PoC Section */
  .poc-section {{
    background: #1c1208;
    border: 1px solid #5a3e00;
    border-radius: 8px;
    padding: 1.5rem;
    margin-top: 1rem;
  }}
  .poc-section h3 {{ color: #d29922; }}

  /* Posture Section */
  .posture {{
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 2rem;
  }}
  .posture h2 {{
    font-size: 1.1rem;
    margin-bottom: 1rem;
    color: #58a6ff;
  }}
  .posture-bar {{
    height: 8px;
    background: #21262d;
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: 1rem;
  }}
  .posture-fill {{
    height: 100%;
    border-radius: 4px;
    transition: width 0.3s;
  }}

  /* Footer */
  .footer {{
    border-top: 1px solid #30363d;
    padding-top: 1rem;
    margin-top: 2rem;
    font-size: 0.8rem;
    color: #484f58;
    text-align: center;
  }}

  /* Responsive */
  @media (max-width: 600px) {{
    .summary {{ grid-template-columns: repeat(2, 1fr); }}
    .finding-meta {{ flex-wrap: wrap; }}
  }}
</style>
</head>
<body>
<div class="container">
{content}
</div>
</body>
</html>"""


def render_html_report(
    findings: list[dict],
    repo_name: str = "Scan Results",
    posture: dict = None,
    poc_files: dict = None,
    scan_stats: dict = None,
) -> str:
    """Render findings into a complete HTML report."""
    parts = []

    # Header
    stats = scan_stats or {}
    parts.append(f"""
    <div class="header">
      <h1><span class="logo">🐾</span> Pangolin Security Report</h1>
      <div class="subtitle">CI/CD & Supply Chain Vulnerability Scan</div>
      <div class="meta">
        <span>Repository: <strong>{esc(repo_name)}</strong></span>
        <span>Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
        <span>Workflows: {stats.get('workflows_scanned', 'N/A')}</span>
        <span>Powered by Sola Security</span>
      </div>
    </div>""")

    # Summary cards
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    parts.append('<div class="summary">')
    for sev in ["critical", "high", "medium", "low"]:
        color = SEVERITY_COLORS[sev]
        parts.append(f"""
        <div class="summary-card">
          <div class="count" style="color: {color}">{sev_counts[sev]}</div>
          <div class="label">{sev}</div>
        </div>""")
    parts.append('</div>')

    # Posture section
    if posture:
        score = posture.get("score", 0)
        bar_color = "#3fb950" if score >= 0.7 else "#d29922" if score >= 0.4 else "#ff4444"
        parts.append(f"""
        <div class="posture">
          <h2>Repository Security Posture</h2>
          <div class="posture-bar">
            <div class="posture-fill" style="width: {score*100:.0f}%; background: {bar_color}"></div>
          </div>""")
        for check in posture.get("checks", []):
            icon = '<span class="check-pass">&#10003;</span>' if check["passed"] else '<span class="check-pending">&#10007;</span>'
            parts.append(f'<div style="padding: 0.2rem 0; font-size: 0.9rem;">{icon} {esc(check["name"])}</div>')
        if posture.get("gaps"):
            parts.append('<div style="margin-top: 0.8rem; color: #d29922; font-size: 0.85rem;">')
            for gap in posture["gaps"]:
                parts.append(f'<div>&#9888; {esc(gap)}</div>')
            parts.append('</div>')
        parts.append('</div>')

    # Findings
    for i, f in enumerate(findings):
        sev = f.get("severity", "low")
        color = SEVERITY_COLORS.get(sev, "#888")
        parts.append(f"""
    <div class="finding">
      <div class="finding-header">
        <span class="finding-title">{esc(f.get('title', f'Finding {i+1}'))}</span>
        <span class="severity-badge" style="background: {color}22; color: {color}; border: 1px solid {color}55;">
          {SEVERITY_LABELS.get(sev, sev)}
        </span>
      </div>
      <div class="finding-meta">
        <span>Pattern: {esc(f.get('pattern_id', 'N/A'))}</span>
        <span>Repo: {esc(f.get('_repo', repo_name))}</span>
        <span>Workflow: {esc(f.get('_workflow', 'N/A'))}</span>
        <span>Confidence: {esc(f.get('confidence', 'N/A'))}</span>
      </div>
      <div class="finding-body">
        <h3>Attack Scenario</h3>
        <p>{esc(str(f.get('attack_scenario', '')))}</p>

        <h3>Impact</h3>
        <p>{esc(str(f.get('impact', '')))}</p>

        <h3>Evidence</h3>
        <div class="code-block">
          <div class="file-path">{esc(f.get('_workflow', ''))}</div>
          <pre>{esc(str(f.get('evidence', '')))}</pre>
        </div>

        <h3>Remediation</h3>
        <p>{esc(str(f.get('fix', '')))}</p>

        <div class="poc-section" id="poc-{i}">
          <h3>Proof of Concept</h3>
          <p>Downloadable PoC files demonstrating this vulnerability (safe, non-destructive).</p>
          <button onclick="downloadPoC({i})" style="
            background: #d29922; color: #0d1117; border: none; padding: 0.5rem 1.2rem;
            border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 0.9rem;
            margin-top: 0.5rem;
          ">Download PoC Files</button>
        </div>
      </div>
    </div>""")

    # Footer
    parts.append(f"""
    <div class="footer">
      Pangolin v0.1.0 — Armored CI/CD Pipeline Security Scanner<br>
      Built for <a href="https://www.boring.security" style="color: #58a6ff;">Boring.Security Hackathon</a> by Sola
    </div>""")

    # Inject PoC data + download script
    poc_json = json.dumps(poc_files or {}, ensure_ascii=False)
    parts.append(f"""
<script>
window.__pangolin_pocs = {poc_json};

function downloadPoC(findingIdx) {{
  const data = window.__pangolin_pocs[String(findingIdx)];
  if (!data || !data.length) {{ alert('No PoC files available for this finding.'); return; }}

  data.forEach(function(f) {{
    var blob = new Blob([f.content], {{type: 'application/octet-stream'}});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = f.path.replace(/\\//g, '_');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }});
}}
</script>""")

    content = "\n".join(parts)
    return HTML_TEMPLATE.format(repo_name=esc(repo_name), content=content)


def save_html_report(
    findings: list[dict],
    output_path: str,
    repo_name: str = "Scan Results",
    posture: dict = None,
    poc_files: dict = None,
    scan_stats: dict = None,
) -> str:
    """Generate and save HTML report to file.

    poc_files: dict mapping finding index (str) to list of
    {path, content, description} dicts for each PoC file.
    """
    html_content = render_html_report(
        findings, repo_name, posture, poc_files=poc_files, scan_stats=scan_stats,
    )
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_content, encoding="utf-8")
    return str(path)


def esc(text: str) -> str:
    return html.escape(str(text))
