# -*- coding: utf-8 -*-
"""
VibeSec — Agno Agent Factory
Supports Gemini (cloud) and Ollama (local) via MODEL_PROVIDER in .env.
Accepts a mode param to switch between Vibe and Expert output styles.
"""

import os
from dotenv import load_dotenv

load_dotenv()

from agno.agent import Agent

try:
    from agno.db.sqlite import SqliteDb
    _DB_BACKEND = "sqlite"
except ImportError:
    from agno.db.in_memory import InMemoryDb
    _DB_BACKEND = "memory"

from tools import (
    scan_secrets,
    audit_dependencies,
    analyze_dockerfile,
    github_repo_audit,
    check_package_vulnerabilities,
    scan_github_url,
    detect_exposed_env,
)

_VIBE_PREFIX = """You are speaking to a non-technical builder who used AI to write their code.
Never use CVE IDs, CVSS scores, or security jargon without explaining them first.
Explain every finding in plain English: what the risk is in real-world terms (e.g. "someone
could steal your users' passwords"), how it could hurt their users or business, and exactly
how to fix it with a copy-paste command. Be friendly, direct, and never condescending.
If something is not a big deal, say so clearly so they don't panic.
"""

_EXPERT_PREFIX = """You are speaking to a security engineer or senior developer.
Use full technical detail: CVE IDs, CVSS v3 scores, CWE classifications, affected version
ranges, patched versions, attack vectors, exploitability scores, and PoC references where
publicly available. Include exact remediation commands, upgrade paths, and note any
breaking changes. Do not simplify or omit technical context. Assume the user can handle
the full picture.
"""

_BASE_SYSTEM_PROMPT = """You are VibeSec, a security scanner built for AI-generated code.

Your tools:
- scan_github_url(repo_url): scan a public GitHub repo for all security issues — use this when given a GitHub URL
- detect_exposed_env(repo_url): check if .env files are accidentally committed to a GitHub repo
- scan_secrets(path): scan local files/directories for hardcoded secrets and credentials
- audit_dependencies(requirements_path): check requirements.txt for known CVEs via OSV.dev
- analyze_dockerfile(dockerfile_path): audit a Dockerfile for security misconfigurations
- github_repo_audit(repo): evaluate a GitHub repository's security posture (owner/name format)
- check_package_vulnerabilities(package_name, ecosystem): research a package's full CVE history

Rules:
- Always call the right tool when a path, URL, package, or repo is mentioned.
- When given a GitHub URL, always call scan_github_url first — it runs all tools at once.
- After tool results, synthesize findings and prioritize what to fix first.
- Never invent CVE IDs or vulnerability data.
- Always end with a clear, prioritized action list.
"""


def _build_model():
    provider = os.getenv("MODEL_PROVIDER", "gemini").lower()

    if provider == "ollama":
        from agno.models.ollama import Ollama
        model_id = os.getenv("OLLAMA_MODEL", "llama3.2")
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        print(f"  [Model] Ollama / {model_id} @ {host}")
        return Ollama(id=model_id, host=host)

    from agno.models.google import Gemini
    model_id = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    print(f"  [Model] Gemini / {model_id}")
    return Gemini(id=model_id, api_key=os.getenv("GEMINI_API_KEY"))


def create_agent(session_id: str = "default", mode: str = "vibe") -> Agent:
    """Creates a VibeSec agent for the given session and output mode.

    Args:
        session_id: Unique identifier for the conversation session.
        mode: 'vibe' for plain-English output (default), 'expert' for full technical detail.
    """
    mode_prefix = _EXPERT_PREFIX if mode == "expert" else _VIBE_PREFIX
    system_message = mode_prefix + "\n" + _BASE_SYSTEM_PROMPT

    if _DB_BACKEND == "sqlite":
        db = SqliteDb(db_file="vibesec_agent.db")
    else:
        db = InMemoryDb()

    return Agent(
        model=_build_model(),
        tools=[
            scan_github_url,
            detect_exposed_env,
            scan_secrets,
            audit_dependencies,
            analyze_dockerfile,
            github_repo_audit,
            check_package_vulnerabilities,
        ],
        db=db,
        session_id=session_id,
        add_history_to_context=True,
        num_history_runs=10,
        system_message=system_message,
        markdown=True,
    )
