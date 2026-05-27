# VibeSec — Security scanner for AI-generated code

> You vibed your app into existence. Did the AI leave any backdoors?

Vibe coders ship fast. Cursor, Bolt, Lovable, v0, Replit Agent — they write real apps with real users and real payments. But the AI that wrote your code was trained on data that's months old. It hardcodes API keys because Stack Overflow does. It installs vulnerable packages because those versions are the most-referenced. It writes Dockerfiles that run as root.

VibeSec catches that before your users find it first.

---

## What it catches

| Check | What it finds |
|---|---|
| 🔑 Secret scan | Hardcoded API keys, passwords, tokens, private keys in source files |
| 📦 Dependency audit | Packages with known CVEs — the AI installed the wrong version |
| 🐳 Dockerfile analysis | Root user, baked-in secrets, unpinned images, pipe-to-shell patterns |
| 🌍 Exposed .env files | .env files accidentally committed and publicly readable on GitHub |
| 🔍 GitHub repo health | Security policy, license, maintenance status, community health |

---

## Who it's for

**Vibe coders** — you build real things with AI, you ship fast, and you don't want to read security docs. VibeSec speaks plain English: what's wrong, why it matters to your users, and exactly how to fix it.

**Security engineers and technical developers** — flip to **Expert Mode** for full CVE IDs, CVSS scores, CWE references, affected version ranges, PoC links, and exact remediation commands.

---

## Setup in 3 commands

```bash
git clone https://github.com/nicodiprospero/devsecops-agent
cp .env.example .env   # then add your GEMINI_API_KEY
python app.py
```

Open [http://localhost:5000](http://localhost:5000).

---

## Docker

```bash
docker build -t vibesec .
docker run -p 5000:5000 --env-file .env vibesec
```

---

## Expert Mode

By default, VibeSec explains everything in plain English — no jargon, no CVE IDs without context. Click the **VIBE / EXPERT** toggle in the top-right corner to switch to Expert Mode, which gives you the full technical picture: CVE IDs, CVSS v3 scores, CWE classifications, affected version ranges, PoC references, and exact upgrade paths.

Switching modes takes effect immediately on the next message. Each new session resets to Vibe Mode.

---

## Export

After any scan, click **↓ Export Report** below the response to download a print-ready HTML file. Open it in a browser and use Print → Save as PDF to share with a client, investor, or your own records.

---

## Tools

| Tool | Input | What it does |
|---|---|---|
| `scan_github_url` | GitHub URL | Fetches repo files and runs all checks — start here |
| `detect_exposed_env` | GitHub URL | Checks for public .env files with real credentials |
| `scan_secrets` | File/directory path | Scans for hardcoded credentials in source files |
| `audit_dependencies` | requirements.txt path | Checks packages against CVE database (OSV.dev) |
| `analyze_dockerfile` | Dockerfile path | 14 security rules for container hardening |
| `github_repo_audit` | owner/repo | Security posture: policy, license, maintenance health |
| `check_package_vulnerabilities` | Package name | Full CVE history for any package on PyPI, npm, and more |

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `GEMINI_API_KEY` | Yes (Gemini) | Get free at aistudio.google.com |
| `GITHUB_TOKEN` | No | Raises GitHub API limit from 60 to 5000 req/hr |
| `MODEL_PROVIDER` | No | `gemini` (default) or `ollama` |
| `FLASK_SECRET_KEY` | No | Set a real value in production |
