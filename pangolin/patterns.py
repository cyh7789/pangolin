"""
Pangolin — CI/CD & Supply Chain Security Patterns

Public vulnerability patterns for defensive scanning.
Derived from known CVEs and published attack techniques.
"""

from dataclasses import dataclass


@dataclass
class Pattern:
    id: str
    name: str
    description: str
    severity: str  # critical / high / medium / low
    category: str  # cicd / supply_chain / posture / code
    source: str
    langs: list
    grep_patterns: list  # list of (regex, file_glob)
    anti_patterns: list  # if ANY matches same file, skip hit
    action: str  # "investigate" | "likely_vuln" | "fix_required"

    def matches_lang(self, lang):
        return "any" in self.langs or lang in self.langs


# ============================================================
# CI/CD Pipeline Patterns (GitHub Actions)
# ============================================================

CICD_PATTERNS = [
    Pattern(
        id="CICD-001",
        name="Script injection via untrusted context in workflow",
        description="GitHub Actions run: block uses ${{ }} expressions with attacker-controllable values (issue title, PR body, commit message) — direct shell injection",
        severity="critical",
        category="cicd",
        source="GHSA-known / TOOLCHAIN_EXEC_BOUNDARY_INJECTION",
        langs=["yaml"],
        grep_patterns=[
            (r'\$\{\{\s*github\.event\.(issue|pull_request|comment|review|discussion)\.(title|body|head\.ref)', "*.yml"),
            (r'\$\{\{\s*github\.event\.(issue|pull_request|comment|review|discussion)\.(title|body|head\.ref)', "*.yaml"),
            (r'\$\{\{\s*github\.head_ref\s*\}\}', "*.yml"),
            (r'\$\{\{\s*github\.head_ref\s*\}\}', "*.yaml"),
        ],
        anti_patterns=[],
        action="likely_vuln",
    ),
    Pattern(
        id="CICD-002",
        name="pull_request_target with unsafe checkout",
        description="Workflow uses pull_request_target trigger and checks out PR head — runs untrusted code with write permissions and secrets access",
        severity="critical",
        category="cicd",
        source="GHSA-known / GitHub Security Lab",
        langs=["yaml"],
        grep_patterns=[
            (r'pull_request_target', "*.yml"),
            (r'pull_request_target', "*.yaml"),
        ],
        anti_patterns=[],
        action="investigate",
    ),
    Pattern(
        id="CICD-003",
        name="Unpinned third-party action (tag reference)",
        description="Action uses @v1, @main, @master instead of SHA pin — vulnerable to tag mutation / supply chain attack",
        severity="high",
        category="cicd",
        source="OpenSSF Scorecard / StepSecurity",
        langs=["yaml"],
        grep_patterns=[
            (r'uses:\s+\S+/\S+@(?:v\d|main|master|latest|dev)', "*.yml"),
            (r'uses:\s+\S+/\S+@(?:v\d|main|master|latest|dev)', "*.yaml"),
        ],
        anti_patterns=[
            r'uses:\s+actions/',  # first-party GitHub actions are lower risk
        ],
        action="fix_required",
    ),
    Pattern(
        id="CICD-004",
        name="Excessive workflow permissions",
        description="Workflow or job has write-all permissions or contents: write without clear need",
        severity="high",
        category="cicd",
        source="GitHub Security Best Practices",
        langs=["yaml"],
        grep_patterns=[
            (r'permissions:\s*write-all', "*.yml"),
            (r'permissions:\s*write-all', "*.yaml"),
            (r'contents:\s*write', "*.yml"),
            (r'contents:\s*write', "*.yaml"),
        ],
        anti_patterns=[
            r'release',  # releases legitimately need write
        ],
        action="investigate",
    ),
    Pattern(
        id="CICD-005",
        name="Secret in environment variable echo/log",
        description="Workflow prints or logs a secret variable — credential exposure in CI logs",
        severity="critical",
        category="cicd",
        source="Common misconfiguration",
        langs=["yaml"],
        grep_patterns=[
            (r'echo.*\$\{\{\s*secrets\.', "*.yml"),
            (r'echo.*\$\{\{\s*secrets\.', "*.yaml"),
            (r'print.*\$\{\{\s*secrets\.', "*.yml"),
            (r'cat.*\$\{\{\s*secrets\.', "*.yml"),
        ],
        anti_patterns=[],
        action="likely_vuln",
    ),
    Pattern(
        id="CICD-006",
        name="Workflow triggered by fork with secret access",
        description="workflow_run or pull_request_target allows fork-originated runs to access repository secrets",
        severity="high",
        category="cicd",
        source="GitHub Security Lab",
        langs=["yaml"],
        grep_patterns=[
            (r'workflow_run', "*.yml"),
            (r'workflow_run', "*.yaml"),
        ],
        anti_patterns=[],
        action="investigate",
    ),
    Pattern(
        id="CICD-007",
        name="Artifact upload/download without integrity check",
        description="Cross-workflow artifact passing without hash verification — artifact poisoning vector",
        severity="medium",
        category="cicd",
        source="Legit Security research",
        langs=["yaml"],
        grep_patterns=[
            (r'actions/download-artifact', "*.yml"),
            (r'actions/download-artifact', "*.yaml"),
        ],
        anti_patterns=[
            r'sha256',
            r'checksum',
            r'digest',
            r'verify',
        ],
        action="investigate",
    ),
    Pattern(
        id="CICD-008",
        name="Self-hosted runner in public repo",
        description="Public repository uses self-hosted runners — any fork PR can execute arbitrary code on your infrastructure",
        severity="critical",
        category="cicd",
        source="GitHub Docs / Security Best Practices",
        langs=["yaml"],
        grep_patterns=[
            (r'runs-on:.*self-hosted', "*.yml"),
            (r'runs-on:.*self-hosted', "*.yaml"),
        ],
        anti_patterns=[],
        action="investigate",
    ),
]

# ============================================================
# Supply Chain Patterns
# ============================================================

SUPPLY_CHAIN_PATTERNS = [
    Pattern(
        id="SC-001",
        name="Dependency install without lockfile",
        description="CI runs npm install / pip install without lockfile — vulnerable to dependency confusion and version drift",
        severity="high",
        category="supply_chain",
        source="TOOLCHAIN_EXEC_BOUNDARY_INJECTION",
        langs=["yaml"],
        grep_patterns=[
            (r'npm\s+install(?!\s+--frozen)', "*.yml"),
            (r'pip\s+install(?!.*-r\s+requirements)', "*.yml"),
            (r'yarn\s+install(?!.*--frozen)', "*.yml"),
            (r'npm\s+install(?!\s+--frozen)', "*.yaml"),
        ],
        anti_patterns=[
            r'npm\s+ci\b',
            r'--frozen-lockfile',
            r'--immutable',
            r'pip.*--require-hashes',
        ],
        action="fix_required",
    ),
    Pattern(
        id="SC-002",
        name="curl pipe to shell in CI",
        description="CI downloads and executes remote script — FETCHER_DESTINATION_CONFUSION risk, MITM, and supply chain attack vector",
        severity="critical",
        category="supply_chain",
        source="FETCHER_DESTINATION_CONFUSION",
        langs=["yaml"],
        grep_patterns=[
            (r'curl.*\|\s*(?:sh|bash|zsh|python)', "*.yml"),
            (r'curl.*\|\s*(?:sh|bash|zsh|python)', "*.yaml"),
            (r'wget.*\|\s*(?:sh|bash|zsh|python)', "*.yml"),
            (r'wget.*\|\s*(?:sh|bash|zsh|python)', "*.yaml"),
        ],
        anti_patterns=[],
        action="likely_vuln",
    ),
    Pattern(
        id="SC-003",
        name="Docker image without digest pin",
        description="Container image uses tag instead of digest — vulnerable to image mutation attack",
        severity="medium",
        category="supply_chain",
        source="SLSA / Sigstore",
        langs=["yaml"],
        grep_patterns=[
            (r'(?:image|container):\s*\S+:\w+\s*$', "*.yml"),
            (r'(?:image|container):\s*\S+:\w+\s*$', "*.yaml"),
            (r'docker\s+pull\s+\S+:\w+\s', "*.yml"),
        ],
        anti_patterns=[
            r'@sha256:',
            r'digest',
        ],
        action="fix_required",
    ),
    Pattern(
        id="SC-004",
        name="Package publish without provenance",
        description="CI publishes package without SLSA provenance attestation — unverifiable supply chain",
        severity="medium",
        category="supply_chain",
        source="SLSA framework",
        langs=["yaml"],
        grep_patterns=[
            (r'npm\s+publish', "*.yml"),
            (r'twine\s+upload', "*.yml"),
            (r'gem\s+push', "*.yml"),
            (r'npm\s+publish', "*.yaml"),
        ],
        anti_patterns=[
            r'provenance',
            r'attestation',
            r'sigstore',
            r'slsa',
        ],
        action="investigate",
    ),
]

# ============================================================
# Code-level Patterns (subset from Bounty, public only)
# ============================================================

CODE_PATTERNS = [
    Pattern(
        id="CODE-001",
        name="Shell command injection via string concatenation",
        description="Building shell commands with string concatenation or f-strings — TOOLCHAIN_EXEC_BOUNDARY_INJECTION",
        severity="critical",
        category="code",
        source="TOOLCHAIN_EXEC_BOUNDARY_INJECTION / CWE-78",
        langs=["python", "js", "go"],
        grep_patterns=[
            (r'subprocess\.\w+\(.*f["\']', "*.py"),
            (r'os\.system\(.*f["\']', "*.py"),
            (r'exec\.Command\(.*fmt\.Sprintf', "*.go"),
            (r'child_process\.exec\(.*`', "*.js"),
            (r'child_process\.exec\(.*\+', "*.js"),
        ],
        anti_patterns=[
            r'shlex\.quote',
            r'shellescape',
            r'escapeshellarg',
        ],
        action="likely_vuln",
    ),
    Pattern(
        id="CODE-002",
        name="SSRF via unvalidated URL fetch",
        description="HTTP request to URL from user input without allowlist — FETCHER_DESTINATION_CONFUSION",
        severity="high",
        category="code",
        source="FETCHER_DESTINATION_CONFUSION / CWE-918",
        langs=["python", "js", "go"],
        grep_patterns=[
            (r'requests\.get\(.*(?:url|uri|endpoint|target|host)', "*.py"),
            (r'http\.Get\(.*(?:url|uri|endpoint|target|host)', "*.go"),
            (r'fetch\(.*(?:url|uri|endpoint|target|host)', "*.js"),
        ],
        anti_patterns=[
            r'allowlist',
            r'whitelist',
            r'allowed_hosts',
            r'ALLOWED_',
        ],
        action="investigate",
    ),
    Pattern(
        id="CODE-003",
        name="Unsafe deserialization",
        description="Loading serialized data without type restrictions — DESERIALIZATION_BEHAVIOR_REHYDRATION",
        severity="critical",
        category="code",
        source="DESERIALIZATION_BEHAVIOR_REHYDRATION / CWE-502",
        langs=["python", "java", "js"],
        grep_patterns=[
            (r'pickle\.loads?\(', "*.py"),
            (r'yaml\.(?:load|unsafe_load)\(', "*.py"),
            (r'ObjectInputStream', "*.java"),
            (r'JSON\.parse\(.*\beval\b', "*.js"),
        ],
        anti_patterns=[
            r'yaml\.safe_load',
            r'SafeLoader',
            r'ObjectInputFilter',
        ],
        action="likely_vuln",
    ),
    Pattern(
        id="CODE-004",
        name="Hardcoded secret or credential",
        description="API key, password, or token hardcoded in source — credential exposure",
        severity="critical",
        category="code",
        source="CWE-798",
        langs=["any"],
        grep_patterns=[
            (r'(?:api[_-]?key|password|secret|token|credential)\s*[=:]\s*["\'][A-Za-z0-9+/=]{16,}["\']', "*.py"),
            (r'(?:api[_-]?key|password|secret|token|credential)\s*[=:]\s*["\'][A-Za-z0-9+/=]{16,}["\']', "*.js"),
            (r'(?:api[_-]?key|password|secret|token|credential)\s*[=:]\s*["\'][A-Za-z0-9+/=]{16,}["\']', "*.go"),
            (r'(?:api[_-]?key|password|secret|token|credential)\s*[=:]\s*["\'][A-Za-z0-9+/=]{16,}["\']', "*.ts"),
        ],
        anti_patterns=[
            r'\.env',
            r'example',
            r'placeholder',
            r'your[-_]',
            r'xxx',
            r'TODO',
        ],
        action="likely_vuln",
    ),
    Pattern(
        id="CODE-005",
        name="Path traversal via user input",
        description="File path constructed from user input without sanitization — directory traversal",
        severity="high",
        category="code",
        source="CWE-22",
        langs=["python", "js", "go"],
        grep_patterns=[
            (r'os\.path\.join\(.*(?:request|input|param|arg|user)', "*.py"),
            (r'path\.Join\(.*(?:request|input|param|arg|user|r\.)', "*.go"),
            (r'path\.(?:join|resolve)\(.*(?:req|input|param|user)', "*.js"),
        ],
        anti_patterns=[
            r'realpath',
            r'abspath.*startswith',
            r'filepath\.Clean',
            r'sanitize',
        ],
        action="investigate",
    ),
]

ALL_PATTERNS = CICD_PATTERNS + SUPPLY_CHAIN_PATTERNS + CODE_PATTERNS
