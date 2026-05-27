# -*- coding: utf-8 -*-
"""
VibeSec — Tool Suite
Five real-action tools + two new GitHub tools. No mocked data, no simulated returns.
"""

import base64
import os
import re
import tempfile
from pathlib import Path

import requests

# When ALLOW_LOCAL_SCAN is not set, restrict local-path tools to the uploads sandbox.
_UPLOADS_ROOT = Path(tempfile.gettempdir()) / "vibesec_uploads"
_ALLOW_LOCAL_SCAN = os.getenv("ALLOW_LOCAL_SCAN", "").lower() in ("1", "true", "yes")


def _assert_safe_path(path: str) -> str | None:
    """Returns an error string if the path escapes the sandbox, else None."""
    if _ALLOW_LOCAL_SCAN:
        return None
    try:
        resolved = Path(path).resolve()
        _UPLOADS_ROOT.mkdir(parents=True, exist_ok=True)
        resolved.relative_to(_UPLOADS_ROOT.resolve())
        return None
    except ValueError:
        return (
            "For security reasons, VibeSec can only scan files you upload through the "
            "interface — not arbitrary paths on the server. Upload the file and try again."
        )


# ── Secret Scanner ─────────────────────────────────────────────────────────────

_SECRET_PATTERNS = {
    "AWS Access Key ID":      (r"AKIA[0-9A-Z]{16}", "CRITICAL"),
    "GitHub Personal Token":  (r"ghp_[a-zA-Z0-9]{36}", "CRITICAL"),
    "GitHub OAuth Token":     (r"gho_[a-zA-Z0-9]{36}", "CRITICAL"),
    "GitHub Actions Token":   (r"ghs_[a-zA-Z0-9]{36}", "CRITICAL"),
    "Google API Key":         (r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
    "Stripe Live Secret Key": (r"sk_live_[0-9a-zA-Z]{24}", "CRITICAL"),
    "Stripe Test Secret Key": (r"sk_test_[0-9a-zA-Z]{24}", "HIGH"),
    "Slack Bot Token":        (r"xoxb-[0-9A-Z]{10,12}-[0-9A-Z]{10,12}-[a-zA-Z0-9]{24}", "HIGH"),
    "SendGrid API Key":       (r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", "CRITICAL"),
    "PEM Private Key":        (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "CRITICAL"),
    "Generic Password":       (r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"\s]{4,})['\"]", "MEDIUM"),
    "Generic Secret/Token":   (r"(?i)(?:secret|token|api_key|apikey|auth_token|access_token)\s*[=:]\s*['\"]([^'\"\s]{8,})['\"]", "MEDIUM"),
    "Database Connection URL":(r"(?i)(?:mongodb|postgres|postgresql|mysql|redis|mssql|amqp):\/\/[^\s'\"<>]{8,}", "HIGH"),
    "Basic Auth in URL":      (r"https?:\/\/[a-zA-Z0-9_\-]{2,}:[a-zA-Z0-9_\-@!#$%^&*]{4,}@", "HIGH"),
    "Twilio Account SID":     (r"AC[a-z0-9]{32}", "HIGH"),
    "Mailgun API Key":        (r"key-[0-9a-zA-Z]{32}", "HIGH"),
}

_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf",
    ".eot", ".mp4", ".mp3", ".zip", ".tar", ".gz", ".pdf", ".pyc", ".pyo",
    ".bin", ".exe", ".dll", ".so", ".lock", ".DS_Store",
}

_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    ".mypy_cache", "dist", "build", ".tox", "coverage",
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_SEVERITY_PLAIN = {
    "CRITICAL": "🔴 CRITICAL — stop everything and fix this",
    "HIGH":     "🟠 HIGH — fix before you ship",
    "MEDIUM":   "🟡 MEDIUM — fix soon",
    "LOW":      "🔵 LOW — worth cleaning up",
    "INFO":     "ℹ️  INFO — good to know",
}


def scan_secrets(path: str) -> str:
    """
    Scans a file or directory for hardcoded passwords, API keys, and tokens.

    AI coding tools frequently hardcode credentials directly into source files
    because the training data is full of examples that do the same thing. This
    tool catches the most common patterns before they reach a public repo.

    Args:
        path: Path to a file or directory to scan.

    Returns:
        A report listing every credential found, where it is, and what to do.
        If nothing is found, confirms the scan completed cleanly.
    """
    err = _assert_safe_path(path)
    if err:
        return err

    target = Path(path)
    if not target.exists():
        return f"Can't find that path: {path}. Double-check the location and try again."

    findings = []
    files_scanned = 0

    def scan_file(fp: Path) -> None:
        nonlocal files_scanned
        if fp.suffix.lower() in _SKIP_EXTENSIONS:
            return
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return
        files_scanned += 1
        for line_no, line in enumerate(text.splitlines(), 1):
            for label, (pattern, severity) in _SECRET_PATTERNS.items():
                for match in re.finditer(pattern, line):
                    raw = match.group(0)
                    redacted = raw[:6] + "..." + raw[-2:] if len(raw) > 9 else "***"
                    findings.append({
                        "file": str(fp),
                        "line": line_no,
                        "type": label,
                        "severity": severity,
                        "preview": redacted,
                    })

    if target.is_file():
        scan_file(target)
    else:
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fname in files:
                scan_file(Path(root) / fname)

    if not findings:
        return (
            f"All clear — scanned {files_scanned} file(s) in '{path}' and found no "
            f"hardcoded passwords, API keys, or tokens. Nice work."
        )

    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 9))

    lines = [
        f"Secret Scan Report — '{path}'",
        f"Scanned: {files_scanned} file(s)  |  Problems found: {len(findings)}",
        "",
        "These credentials are sitting in your code. Anyone who reads the file — "
        "or sees your GitHub repo — can use them to access your accounts.",
        "",
    ]
    for f in findings:
        sev_label = _SEVERITY_PLAIN.get(f["severity"], f["severity"])
        lines.append(f"{sev_label}")
        lines.append(f"  Type    : {f['type']}")
        lines.append(f"  Location: {f['file']}, line {f['line']}")
        lines.append(f"  Found   : {f['preview']}")
        lines.append(
            f"  Fix     : Move this value to a .env file and load it with os.getenv(). "
            f"Add .env to your .gitignore. Rotate the credential immediately if this "
            f"file has ever been pushed to GitHub."
        )
        lines.append("")

    return "\n".join(lines)


# ── Dependency Auditor ─────────────────────────────────────────────────────────

def _parse_requirements(req_path: str) -> list[dict]:
    try:
        raw = Path(req_path).read_text(encoding="utf-8")
    except Exception:
        return []
    pkgs = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        line = re.sub(r"\[.*?\]", "", line)
        m = re.match(r"([A-Za-z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([^\s;,]+)", line)
        if m:
            pkgs.append({"name": m.group(1).lower(), "version": m.group(2)})
        else:
            m2 = re.match(r"([A-Za-z0-9_\-\.]+)", line)
            if m2:
                pkgs.append({"name": m2.group(1).lower(), "version": None})
    return pkgs


def audit_dependencies(requirements_path: str) -> str:
    """
    Checks your Python packages for known security vulnerabilities.

    AI coding tools often install older package versions because their training
    data references those versions most frequently. This tool checks every
    package in your requirements.txt against a live vulnerability database
    (OSV.dev) to catch problems before they reach production.

    Args:
        requirements_path: Path to your requirements.txt file.

    Returns:
        A plain-English report of which packages have security problems,
        what those problems mean for your app, and exactly how to fix them.
    """
    err = _assert_safe_path(requirements_path)
    if err:
        return err

    req_path = Path(requirements_path)
    if not req_path.exists():
        return f"Can't find that file: {requirements_path}. Check the path and try again."

    pkgs = _parse_requirements(requirements_path)
    if not pkgs:
        return f"No packages found in '{requirements_path}'. Is it a valid requirements.txt?"

    queries = []
    for pkg in pkgs:
        q = {"package": {"name": pkg["name"], "ecosystem": "PyPI"}}
        if pkg["version"]:
            q["version"] = pkg["version"]
        queries.append(q)

    try:
        resp = requests.post(
            "https://api.osv.dev/v1/querybatch",
            json={"queries": queries},
            timeout=20,
        )
        resp.raise_for_status()
        batch_results = resp.json().get("results", [])
    except requests.RequestException as e:
        return f"Couldn't reach the vulnerability database (OSV.dev): {e}. Check your internet connection."

    vuln_rows = []
    for pkg, result in zip(pkgs, batch_results):
        for v in result.get("vulns", []):
            severity = "UNKNOWN"
            if v.get("database_specific", {}).get("severity"):
                severity = v["database_specific"]["severity"]
            elif v.get("severity"):
                for s in v["severity"]:
                    if "CVSS" in s.get("type", ""):
                        score = s.get("score", "")
                        if score:
                            severity = score
                            break

            affected_ranges = []
            fix_versions = []
            for aff in v.get("affected", []):
                for rng in aff.get("ranges", []):
                    introduced, fixed = None, None
                    for event in rng.get("events", []):
                        if "introduced" in event:
                            introduced = event["introduced"]
                        if "fixed" in event:
                            fixed = event["fixed"]
                    if introduced:
                        affected_ranges.append(f">={introduced}" + (f", <{fixed}" if fixed else ""))
                    if fixed:
                        fix_versions.append(fixed)

            vuln_rows.append({
                "package": pkg["name"],
                "version": pkg["version"] or "unpinned",
                "id": v.get("id", "N/A"),
                "summary": (v.get("summary") or "No details available.")[:200],
                "severity": severity,
                "fix_versions": fix_versions,
                "affected_ranges": affected_ranges,
            })

    total_pkgs = len(pkgs)
    if not vuln_rows:
        return (
            f"All clear — checked {total_pkgs} package(s) against the OSV.dev vulnerability "
            f"database and found no known security problems."
        )

    affected_pkgs = len({r["package"] for r in vuln_rows})
    lines = [
        f"Dependency Audit Report — '{requirements_path}'",
        f"Packages checked: {total_pkgs}  |  Packages with problems: {affected_pkgs}  |  Total advisories: {len(vuln_rows)}",
        "",
        "The AI that wrote your requirements.txt may have used older versions because "
        "that's what most of its training data referenced. Here's what needs fixing:",
        "",
    ]

    for r in vuln_rows:
        sev_label = _SEVERITY_PLAIN.get(r["severity"], f"⚠️  {r['severity']}")
        lines.append(f"{sev_label}")
        lines.append(f"  Package : '{r['package']}' version {r['version']}")
        lines.append(f"  Problem : {r['summary']}")
        lines.append(f"  Advisory: {r['id']}")
        if r["affected_ranges"]:
            lines.append(f"  Affected: {' | '.join(r['affected_ranges'][:3])}")
        if r["fix_versions"]:
            fix = r["fix_versions"][0]
            lines.append(f"  Fix     : pip install {r['package']}=={fix}")
        else:
            lines.append(f"  Fix     : pip install --upgrade {r['package']}")
        lines.append("")

    return "\n".join(lines)


# ── Dockerfile Analyzer ────────────────────────────────────────────────────────

_DOCKERFILE_RULES = [
    (r"^FROM\s+\S+:latest\b",
     "HIGH",
     "You're using ':latest' — this means you'll get a different version every time you build. "
     "Pin a specific version like 'python:3.11-slim' so your app works the same everywhere."),
    (r"^FROM\s+(?!scratch)(?:[a-z0-9][a-z0-9\-\._\/]*)(?:\s+AS\s+\w+)?\s*$",
     "MEDIUM",
     "Your base image has no version tag — pin a specific version or digest for reproducible builds."),
    (r"^USER\s+root\s*$",
     "HIGH",
     "You're explicitly running as root. If someone breaks into your container, they get root "
     "access. Switch to a non-privileged user (e.g. 'USER 1000')."),
    (r"^ADD\s+https?://",
     "MEDIUM",
     "ADD with a URL is unpredictable and skips cache. Use 'RUN curl/wget' and verify the checksum instead."),
    (r"^ADD\s+(?!.*\.tar)",
     "LOW",
     "Use COPY instead of ADD unless you specifically need automatic tar extraction."),
    (r"apt-get install(?!.*--no-install-recommends)",
     "LOW",
     "Add '--no-install-recommends' to 'apt-get install' to keep your image small."),
    (r"(?i)ENV\s+(?:PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|TOKEN|PRIVATE_KEY|AUTH)\s*[=\s]",
     "CRITICAL",
     "You have a secret baked into the image. Anyone who pulls this Docker image can read it. "
     "Remove it and inject secrets at runtime via environment variables or a secrets manager."),
    (r"^COPY\s+\.\s+\.",
     "MEDIUM",
     "'COPY . .' copies everything, including .env files and private keys. "
     "Make sure your .dockerignore excludes sensitive files."),
    (r"^RUN\s+(?:curl|wget)\s+.+\|\s*(?:ba)?sh",
     "HIGH",
     "You're piping a downloaded script straight into bash — this is a supply chain attack waiting "
     "to happen. Download the file first, verify its checksum, then run it."),
    (r"^EXPOSE\s+22\b",
     "MEDIUM",
     "You're exposing port 22 (SSH) inside the container. Use 'docker exec' for shell access instead."),
    (r"^RUN\s+chmod\s+777",
     "MEDIUM",
     "'chmod 777' lets anyone read, write, and execute that file. Use the minimum permissions needed."),
    (r"--allow-root",
     "MEDIUM",
     "You're installing packages as root. Build and run as a non-root user instead."),
    (r"^RUN\s+pip install(?!.*--no-cache-dir)",
     "LOW",
     "Add '--no-cache-dir' to 'pip install' to keep your image smaller."),
    (r"^RUN\s+apt-get\s+update\s*$",
     "LOW",
     "Don't run 'apt-get update' alone in a separate RUN — combine it with 'apt-get install' "
     "in one RUN command to avoid stale cache layers."),
]


def analyze_dockerfile(dockerfile_path: str) -> str:
    """
    Checks your Dockerfile for security problems and misconfigurations.

    AI tools write Dockerfiles that work but often have security gaps — running
    as root, baking in secrets, using unpinned base images. This tool checks
    against known dangerous patterns so your containers don't become an easy
    target.

    Args:
        dockerfile_path: Path to your Dockerfile.

    Returns:
        A list of issues found with plain-English explanations and fixes.
        Returns a clean pass if no problems are detected.
    """
    err = _assert_safe_path(dockerfile_path)
    if err:
        return err

    df_path = Path(dockerfile_path)
    if not df_path.exists():
        return f"Can't find that Dockerfile: {dockerfile_path}. Check the path and try again."

    try:
        content = df_path.read_text(encoding="utf-8")
    except Exception as e:
        return f"Couldn't read the Dockerfile: {e}"

    lines = content.splitlines()
    has_non_root_user = False
    has_healthcheck = False
    findings = []

    for line_no, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if line.startswith("#") or not line:
            continue

        if re.match(r"^HEALTHCHECK\b", line, re.IGNORECASE):
            has_healthcheck = True
        if re.match(r"^USER\s+(?!0\b|root\b)", line, re.IGNORECASE):
            has_non_root_user = True

        for pattern, severity, message in _DOCKERFILE_RULES:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "line": line_no,
                    "severity": severity,
                    "message": message,
                    "snippet": line[:90],
                })
                break

    if not has_non_root_user:
        findings.append({
            "line": "N/A",
            "severity": "HIGH",
            "message": "Your container runs as root by default. Add a non-root user with "
                       "'RUN useradd -m appuser && USER appuser' to limit blast radius if compromised.",
            "snippet": "",
        })
    if not has_healthcheck:
        findings.append({
            "line": "N/A",
            "severity": "INFO",
            "message": "No HEALTHCHECK instruction — add one so your orchestrator knows when the "
                       "container is actually ready to serve traffic.",
            "snippet": "",
        })

    if not findings:
        return f"Looks good — no security problems found in '{dockerfile_path}'."

    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 9))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in _SEVERITY_ORDER}

    lines_out = [
        f"Dockerfile Security Report — '{dockerfile_path}'",
        f"Issues: {len(findings)}  "
        f"[Critical: {counts['CRITICAL']}  High: {counts['HIGH']}  "
        f"Medium: {counts['MEDIUM']}  Low: {counts['LOW']}  Info: {counts['INFO']}]",
        "",
    ]
    for f in findings:
        loc = f"Line {f['line']}" if f["line"] != "N/A" else "Overall"
        sev_label = _SEVERITY_PLAIN.get(f["severity"], f["severity"])
        lines_out.append(f"{sev_label} ({loc})")
        lines_out.append(f"  {f['message']}")
        if f["snippet"]:
            lines_out.append(f"  Code: {f['snippet']}")
        lines_out.append("")

    return "\n".join(lines_out)


# ── GitHub Repository Auditor ──────────────────────────────────────────────────

def github_repo_audit(repo: str) -> str:
    """
    Checks the security posture of a public GitHub repository.

    Looks at whether the repo has a security policy, a license, recent
    maintenance activity, and other health signals that affect how safe it is
    to depend on.

    Args:
        repo: Repository in 'owner/name' format (e.g. 'psf/requests').
              Full GitHub URLs are also accepted.

    Returns:
        A report on the repo's security posture with plain-English findings
        and recommended next steps.
    """
    repo = repo.strip().strip("/")
    if repo.startswith("https://github.com/"):
        parts = repo.replace("https://github.com/", "").split("/")
        repo = f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else parts[0]
    if "/" not in repo or repo.count("/") != 1:
        return "Please provide the repo in 'owner/name' format (e.g. 'django/django')."

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def gh_get(endpoint: str):
        try:
            r = requests.get(f"https://api.github.com{endpoint}", headers=headers, timeout=12)
            if r.status_code == 404:
                return None, "404"
            if r.status_code == 403:
                return None, "rate_limited"
            r.raise_for_status()
            return r.json(), None
        except requests.RequestException as e:
            return None, str(e)

    repo_data, err = gh_get(f"/repos/{repo}")
    if err == "rate_limited":
        return "GitHub API rate limit hit. Set GITHUB_TOKEN in your .env for 5000 requests/hour."
    if repo_data is None:
        return f"Repo '{repo}' not found or isn't public."

    community, _ = gh_get(f"/repos/{repo}/community/profile")
    security_md, _ = gh_get(f"/repos/{repo}/contents/SECURITY.md")
    commits, _ = gh_get(f"/repos/{repo}/commits?per_page=3")

    name         = repo_data.get("full_name", repo)
    description  = repo_data.get("description") or "(no description)"
    archived     = repo_data.get("archived", False)
    is_fork      = repo_data.get("fork", False)
    stars        = repo_data.get("stargazers_count", 0)
    open_issues  = repo_data.get("open_issues_count", 0)
    license_name = (repo_data.get("license") or {}).get("name", "None")
    default_br   = repo_data.get("default_branch", "main")
    pushed_at    = (repo_data.get("pushed_at") or "unknown")[:10]
    topics       = repo_data.get("topics", [])

    has_security_policy  = security_md is not None
    has_license          = license_name not in ("None", "Other", None)
    community_files      = (community or {}).get("files") or {}
    has_contributing     = bool(community_files.get("contributing"))
    has_code_of_conduct  = bool(community_files.get("code_of_conduct"))
    health_pct           = (community or {}).get("health_percentage", "N/A")

    last_commit = "unknown"
    if isinstance(commits, list) and commits:
        try:
            last_commit = commits[0]["commit"]["author"]["date"][:10]
        except (KeyError, IndexError, TypeError):
            pass

    out = [
        f"GitHub Security Audit — {name}",
        f"{'─' * 55}",
        f"Stars: {stars:,}   |  Open issues: {open_issues:,}   |  License: {license_name}",
        f"Default branch: {default_br}  |  Last push: {pushed_at}  |  Last commit: {last_commit}",
        f"Archived: {'⚠️  YES — no more security patches' if archived else 'No'}",
        f"Fork: {'Yes' if is_fork else 'No'}   |  Description: {description}",
    ]
    if topics:
        out.append(f"Topics: {', '.join(topics[:8])}")

    out += ["", "── Security Checks ──", ""]

    checks = [
        (has_security_policy,
         "Security Policy (SECURITY.md)",
         "CRITICAL",
         "No SECURITY.md — there's no clear way to report a vulnerability. Anyone who finds "
         "a bug has no official channel and may disclose it publicly. Add a SECURITY.md."),
        (has_license,
         "License",
         "MEDIUM",
         f"License is '{license_name}' — unclear licensing can create legal risk. Add a clear license."),
        (has_contributing,
         "Contributing Guidelines",
         "LOW",
         "No CONTRIBUTING file — makes it harder for contributors to follow safe practices."),
        (has_code_of_conduct,
         "Code of Conduct",
         "INFO",
         "No Code of Conduct found."),
        (not archived,
         "Actively Maintained",
         "HIGH",
         "This repo is archived — it will never receive security patches. Migrate to an alternative."),
        (open_issues < 1000,
         "Issue Volume",
         "LOW",
         f"High issue count ({open_issues:,}) may signal a maintenance backlog — patches might be slow."),
    ]

    recs = []
    for ok, label, severity, bad_msg in checks:
        status = "✅  PASS" if ok else "❌  FAIL"
        out.append(f"  {status}  {label}")
        if not ok:
            recs.append(f"  [{severity}] {bad_msg}")

    if health_pct != "N/A":
        out.append(f"\n  Community health score: {health_pct}%")

    if recs:
        out += ["", "── What to do ──", ""] + recs

    out.append(f"\n  🔗 https://github.com/{repo}")
    return "\n".join(out)


# ── Package CVE Lookup ─────────────────────────────────────────────────────────

def check_package_vulnerabilities(package_name: str, ecosystem: str = "PyPI") -> str:
    """
    Looks up the full vulnerability history of a package across all versions.

    Useful before adopting a new dependency or when you want to understand
    how often a package has had security problems. Checks the OSV.dev database
    which aggregates CVEs, GitHub Security Advisories, and other sources.

    Args:
        package_name: Name of the package (e.g. 'requests', 'lodash', 'log4j').
        ecosystem: Where the package lives. Default: 'PyPI'. Others: 'npm',
                   'Go', 'Maven', 'RubyGems', 'NuGet', 'crates.io'.

    Returns:
        A list of known vulnerabilities, what they mean, which versions are
        affected, and which version fixes each one.
    """
    try:
        resp = requests.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": package_name.lower(), "ecosystem": ecosystem}},
            timeout=12,
        )
        resp.raise_for_status()
        vulns = resp.json().get("vulns", [])
    except requests.RequestException as e:
        return f"Couldn't reach OSV.dev: {e}. Check your internet connection."

    if not vulns:
        return (
            f"No known vulnerabilities for '{package_name}' ({ecosystem}) in OSV.dev. "
            f"That's a good sign — but always check the package's changelog before upgrading."
        )

    lines = [
        f"Vulnerability History — {package_name} ({ecosystem})",
        f"Total advisories in OSV.dev: {len(vulns)}",
        "",
    ]

    for v in vulns[:25]:
        vid      = v.get("id", "N/A")
        summary  = (v.get("summary") or "No summary available")[:200]
        modified = (v.get("modified") or "")[:10]

        severity = "UNKNOWN"
        if v.get("database_specific", {}).get("severity"):
            severity = v["database_specific"]["severity"]
        elif v.get("severity"):
            for s in v["severity"]:
                if "CVSS" in s.get("type", ""):
                    severity = s.get("score", severity)
                    break

        ranges_txt = []
        fix_txt = []
        for aff in v.get("affected", []):
            for rng in aff.get("ranges", []):
                introduced, fixed = None, None
                for event in rng.get("events", []):
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                if introduced:
                    ranges_txt.append(f">={introduced}" + (f", <{fixed}" if fixed else ""))
                if fixed:
                    fix_txt.append(fixed)

        advisories = [
            r["url"] for r in v.get("references", [])
            if r.get("type") in ("ADVISORY", "WEB") and r.get("url")
        ][:2]

        sev_label = _SEVERITY_PLAIN.get(severity, f"⚠️  {severity}")
        lines.append(f"{sev_label}")
        lines.append(f"  Advisory: {vid}  (updated {modified})")
        lines.append(f"  What it means: {summary}")
        if ranges_txt:
            lines.append(f"  Affected versions: {' | '.join(ranges_txt[:3])}")
        if fix_txt:
            lines.append(f"  Fixed in: {', '.join(fix_txt[:3])}")
            lines.append(f"  Fix: pip install {package_name}=={fix_txt[0]}")
        for url in advisories:
            lines.append(f"  Details: {url}")
        lines.append("")

    if len(vulns) > 25:
        lines.append(
            f"...and {len(vulns) - 25} more. "
            f"Full list: https://osv.dev/list?q={package_name}&ecosystem={ecosystem}"
        )

    return "\n".join(lines)


# ── GitHub URL Helper ──────────────────────────────────────────────────────────

def _parse_github_url(repo_url: str) -> tuple:
    """Returns (owner/repo slug, None) or (None, error_message)."""
    url = repo_url.strip().rstrip("/")
    if url.startswith("http://"):
        return None, "Please use an https:// GitHub URL — plain http:// is not accepted."
    for prefix in ("https://github.com/", "github.com/"):
        if url.startswith(prefix):
            url = url[len(prefix):]
            break
    parts = url.split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return None, "Please provide a full GitHub URL like: https://github.com/owner/repo"
    return f"{parts[0]}/{parts[1]}", None


def _github_headers() -> dict:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


# ── Scan GitHub URL ────────────────────────────────────────────────────────────

def scan_github_url(repo_url: str) -> str:
    """
    Scans a public GitHub repository for security issues — no cloning needed.

    This is the main tool for vibe coders. Paste a GitHub URL and this tool
    fetches the repo's source files, runs all security checks (secrets,
    vulnerable packages, Dockerfile problems, exposed .env files), and returns
    a unified report.

    Args:
        repo_url: Full GitHub URL, e.g. https://github.com/owner/repo

    Returns:
        A unified security report covering all findings across the repo,
        with plain-English explanations and exact fix commands.
    """
    repo_slug, err = _parse_github_url(repo_url)
    if err:
        return err

    headers = _github_headers()

    try:
        resp = requests.get(
            f"https://api.github.com/repos/{repo_slug}", headers=headers, timeout=12
        )
        if resp.status_code == 404:
            return f"Repo not found: {repo_url}. Make sure it's public and the URL is correct."
        if resp.status_code == 403:
            return (
                "GitHub rate limit hit (60 requests/hour for unauthenticated access). "
                "Add GITHUB_TOKEN to your .env to raise the limit to 5000/hour."
            )
        resp.raise_for_status()
        repo_info = resp.json()
        default_branch = repo_info.get("default_branch", "main")
    except requests.RequestException as e:
        return f"Couldn't reach GitHub: {e}"

    try:
        tree_resp = requests.get(
            f"https://api.github.com/repos/{repo_slug}/git/trees/{default_branch}?recursive=1",
            headers=headers, timeout=20,
        )
        tree_resp.raise_for_status()
        tree = tree_resp.json().get("tree", [])
    except requests.RequestException as e:
        return f"Couldn't fetch the repo's file tree: {e}"

    TARGET_NAMES = {
        "requirements.txt", "Dockerfile", "package.json",
        "package-lock.json", "yarn.lock", "Pipfile",
    }
    TARGET_EXTS  = {".py", ".js", ".ts", ".jsx", ".tsx"}
    ENV_NAMES    = {
        ".env", ".env.local", ".env.production", ".env.staging",
        ".env.backup", ".env.development", ".env.example",
    }

    files_to_fetch = []
    for item in tree:
        if item.get("type") != "blob":
            continue
        path = item.get("path", "")
        name = Path(path).name
        ext  = Path(path).suffix
        if name in TARGET_NAMES or ext in TARGET_EXTS or name in ENV_NAMES:
            files_to_fetch.append(path)
        if len(files_to_fetch) >= 50:
            break

    if not files_to_fetch:
        return (
            f"No scannable files found in {repo_url}. "
            f"The repo may be empty or use only unsupported file types."
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path    = Path(tmpdir)
        downloaded  = []
        req_file    = None
        docker_file = None

        for path in files_to_fetch:
            try:
                content_resp = requests.get(
                    f"https://api.github.com/repos/{repo_slug}/contents/{path}",
                    headers=headers, timeout=10,
                )
                if content_resp.status_code != 200:
                    continue
                content_data = content_resp.json()
                if content_data.get("encoding") != "base64":
                    continue
                decoded = base64.b64decode(
                    content_data["content"].replace("\n", "")
                ).decode("utf-8", errors="ignore")

                file_path = tmp_path / path
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_text(decoded, encoding="utf-8")
                downloaded.append(str(file_path))

                name = Path(path).name
                if name == "requirements.txt" and req_file is None:
                    req_file = str(file_path)
                if name == "Dockerfile" and docker_file is None:
                    docker_file = str(file_path)

            except Exception as _dl_err:
                import sys as _sys
                print(f"[vibesec] download skip {path}: {_dl_err}", file=_sys.stderr)
                continue

        if not downloaded:
            return (
                f"Downloaded 0 files from {repo_url}. "
                f"GitHub API may be rate-limiting — set GITHUB_TOKEN in your .env."
            )

        all_results = []

        secrets_result = scan_secrets(tmpdir)
        all_results.append(("Secret Scan", secrets_result))

        if req_file:
            deps_result = audit_dependencies(req_file)
            all_results.append(("Dependency Audit", deps_result))
        else:
            all_results.append(("Dependency Audit", "No requirements.txt found in this repo."))

        if docker_file:
            docker_result = analyze_dockerfile(docker_file)
            all_results.append(("Dockerfile Analysis", docker_result))
        else:
            all_results.append(("Dockerfile Analysis", "No Dockerfile found in this repo."))

        repo_result = github_repo_audit(repo_slug)
        all_results.append(("Repo Security Posture", repo_result))

        env_result = detect_exposed_env(repo_url)
        all_results.append(("Exposed .env Files", env_result))

        lines = [
            f"VibeSec Scan Report — {repo_url}",
            f"Files scanned: {len(downloaded)}",
            "=" * 60,
            "",
        ]
        for section_name, result in all_results:
            lines.append(f"── {section_name} ──")
            lines.append(result)
            lines.append("")

        return "\n".join(lines)


# ── Detect Exposed .env Files ──────────────────────────────────────────────────

def detect_exposed_env(repo_url: str) -> str:
    """
    Checks whether .env files with real credentials are publicly visible on GitHub.

    This is one of the most common and dangerous mistakes when building with AI
    tools. The AI creates a .env file for you but often forgets to add it to
    .gitignore, meaning your database passwords, API keys, and payment credentials
    get pushed to GitHub where anyone can find them via search.

    Args:
        repo_url: Full GitHub URL, e.g. https://github.com/owner/repo

    Returns:
        A list of any exposed .env files found, with masked previews of their
        contents and step-by-step instructions for immediate remediation.
    """
    repo_slug, err = _parse_github_url(repo_url)
    if err:
        return err

    headers = _github_headers()

    ENV_FILES = [
        ".env", ".env.local", ".env.production",
        ".env.staging", ".env.backup", ".env.development",
    ]

    found = []

    for env_file in ENV_FILES:
        try:
            resp = requests.get(
                f"https://api.github.com/repos/{repo_slug}/contents/{env_file}",
                headers=headers, timeout=10,
            )
            if resp.status_code == 404:
                continue
            if resp.status_code == 403:
                return (
                    "GitHub rate limit hit. Set GITHUB_TOKEN in your .env "
                    "for 5000 requests/hour."
                )
            if resp.status_code != 200:
                continue

            data = resp.json()
            raw_url = data.get("html_url", "")

            preview_lines = []
            if data.get("encoding") == "base64":
                try:
                    decoded = base64.b64decode(
                        data["content"].replace("\n", "")
                    ).decode("utf-8", errors="ignore")
                    for line in decoded.splitlines()[:3]:
                        if "=" in line and not line.startswith("#"):
                            key, _, val = line.partition("=")
                            masked = val.strip()[:2] + "***" if val.strip() else "(empty)"
                            preview_lines.append(f"    {key.strip()}={masked}")
                        elif line.strip():
                            preview_lines.append(f"    {line}")
                except Exception:
                    preview_lines.append("    (could not decode content)")

            found.append({"name": env_file, "url": raw_url, "preview": preview_lines})

        except requests.RequestException:
            continue

    if not found:
        return (
            f"No exposed .env files found in {repo_url}. "
            f"Checked: {', '.join(ENV_FILES)}. "
            f"Make sure '.env' is in your .gitignore."
        )

    lines = [
        f"🚨 DANGER: {len(found)} .env file(s) are publicly visible in {repo_url}!",
        "Anyone on the internet can read these right now. This is how credentials get stolen.",
        "",
    ]
    for item in found:
        lines.append(f"  File: {item['name']}")
        lines.append(f"  URL : {item['url']}")
        if item["preview"]:
            lines.append("  First 3 lines (values masked):")
            lines.extend(item["preview"])
        lines.append("")

    lines += [
        "Fix this RIGHT NOW — in order:",
        "  1. Remove the file from git history:",
        "     git rm --cached .env && git commit -m 'remove exposed env file'",
        "  2. Add to .gitignore:",
        "     echo '.env' >> .gitignore && git add .gitignore && git commit -m 'ignore env files'",
        "  3. Push to GitHub: git push",
        "  4. Rotate EVERY credential that was in those files — treat them as stolen.",
        "     Change passwords, revoke API keys, generate new tokens.",
        "  5. Check your full git history:",
        "     git log --all --full-history -- .env",
    ]

    return "\n".join(lines)
