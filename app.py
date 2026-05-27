# -*- coding: utf-8 -*-
"""
VibeSec — Flask Web Interface
"""

import os
import re
import sys
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from flask import Flask, render_template, request, jsonify, session, make_response
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(32).hex())
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB upload limit

from agent import create_agent


# ── Simple markdown → HTML for export reports ──────────────────────────────────

def _md_to_html(text: str) -> str:
    text = re.sub(r"```[\w]*\n(.*?)```", r"<pre><code>\1</code></pre>", text, flags=re.DOTALL)
    text = re.sub(r"^### (.+)$", r"<h3>\1</h3>", text, flags=re.MULTILINE)
    text = re.sub(r"^## (.+)$",  r"<h2>\1</h2>", text, flags=re.MULTILINE)
    text = re.sub(r"^# (.+)$",   r"<h1>\1</h1>", text, flags=re.MULTILINE)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`([^`]+)`",  r"<code>\1</code>", text)
    paras = re.split(r"\n{2,}", text)
    parts = []
    for p in paras:
        p = p.strip()
        if not p:
            continue
        if p.startswith(("<h", "<pre")):
            parts.append(p)
        else:
            p = p.replace("\n", "<br>")
            parts.append(f"<p>{p}</p>")
    return "\n".join(parts)


def _render_export_html(content: str, mode: str, date_str: str, session_id: str) -> str:
    mode_label = "Expert Mode" if mode == "expert" else "Vibe Mode"
    body_html  = _md_to_html(content)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VibeSec Security Report — {session_id}</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Orbitron:wght@700;900&display=swap');
    :root {{
      --bg:     #03030e;
      --bg1:    #080818;
      --bg2:    #0d0d2a;
      --cyan:   #00f5ff;
      --pink:   #ff00aa;
      --green:  #00ff99;
      --text:   #d0d0ff;
      --dim:    #4a4a88;
      --border: #1c1c44;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: 'JetBrains Mono', monospace;
      font-size: 14px;
      line-height: 1.7;
      padding: 48px;
      max-width: 900px;
      margin: 0 auto;
    }}
    header {{
      border-bottom: 2px solid var(--cyan);
      padding-bottom: 20px;
      margin-bottom: 32px;
    }}
    .logo {{
      font-family: 'Orbitron', sans-serif;
      font-size: 1.6rem;
      font-weight: 900;
      color: var(--cyan);
      letter-spacing: 6px;
    }}
    .logo em {{ font-style: normal; color: var(--pink); }}
    .meta {{
      color: var(--dim);
      font-size: 0.75rem;
      margin-top: 8px;
      letter-spacing: 1px;
    }}
    .mode-badge {{
      display: inline-block;
      background: var(--bg2);
      border: 1px solid var(--cyan);
      color: var(--cyan);
      font-size: 0.65rem;
      padding: 2px 8px;
      border-radius: 3px;
      margin-left: 10px;
      letter-spacing: 2px;
    }}
    h1 {{ font-family: 'Orbitron', sans-serif; color: var(--cyan); font-size: 1rem; margin: 24px 0 8px; letter-spacing: 2px; }}
    h2 {{ font-family: 'Orbitron', sans-serif; color: var(--cyan); font-size: 0.9rem; margin: 20px 0 6px; letter-spacing: 1px; }}
    h3 {{ color: var(--pink); font-size: 0.82rem; margin: 16px 0 4px; }}
    p  {{ margin-bottom: 10px; }}
    code {{
      background: var(--bg2);
      color: var(--green);
      padding: 1px 6px;
      border-radius: 3px;
      font-size: 0.85em;
    }}
    pre {{
      background: var(--bg1);
      border: 1px solid var(--border);
      border-left: 3px solid var(--green);
      padding: 16px;
      border-radius: 4px;
      overflow-x: auto;
      margin: 12px 0;
    }}
    pre code {{ background: none; padding: 0; color: var(--green); }}
    strong {{ color: var(--cyan); }}
    .content {{ padding: 0; }}
    footer {{
      margin-top: 48px;
      padding-top: 16px;
      border-top: 1px solid var(--border);
      color: var(--dim);
      font-size: 0.7rem;
      letter-spacing: 1px;
    }}
    @media print {{
      body {{ background: white; color: black; padding: 24px; }}
      .logo {{ color: #0066aa; }}
      code, pre {{ background: #f0f0f0; color: #006600; }}
      strong {{ color: #004488; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="logo">VIBE<em>SEC</em></div>
    <div class="meta">
      Security Report &nbsp;|&nbsp; Session: {session_id}
      &nbsp;|&nbsp; Generated: {date_str}
      <span class="mode-badge">{mode_label}</span>
    </div>
  </header>
  <div class="content">
    {body_html}
  </div>
  <footer>
    Generated by VibeSec — Security scanner for AI-generated code.
    This report reflects findings at the time of scan. Re-scan after applying fixes.
  </footer>
</body>
</html>"""


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "session_id" not in session:
        session["session_id"] = str(uuid.uuid4())[:8]
    if "mode" not in session:
        session["mode"] = "vibe"
    return render_template("index.html", session_id=session["session_id"])


@app.route("/chat", methods=["POST"])
def chat():
    data    = request.get_json(force=True, silent=True) or {}
    message = (data.get("message") or "").strip()

    if not message:
        return jsonify({"error": "Message cannot be empty."}), 400

    session_id = session.get("session_id")
    if not session_id:
        session_id = str(uuid.uuid4())[:8]
        session["session_id"] = session_id

    mode = session.get("mode", "vibe")

    try:
        agent    = create_agent(session_id=session_id, mode=mode)
        response = agent.run(message)

        if response is None:
            content = "(no response from agent)"
        elif hasattr(response, "content") and response.content:
            content = str(response.content)
        elif hasattr(response, "message") and response.message:
            content = str(response.message)
        else:
            content = str(response)

    except Exception as exc:
        return jsonify({"error": f"Agent error: {exc}"}), 500

    session["last_response"]      = content
    session["last_response_mode"] = mode

    return jsonify({"response": content, "session_id": session_id})


@app.route("/set_mode", methods=["POST"])
def set_mode():
    data = request.get_json(force=True, silent=True) or {}
    mode = data.get("mode", "").strip().lower()
    if mode not in ("vibe", "expert"):
        return jsonify({"error": "mode must be 'vibe' or 'expert'"}), 400
    session["mode"] = mode
    return jsonify({"ok": True, "mode": mode})


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided."}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "No filename."}), 400

    safe_name = secure_filename(f.filename)
    if not safe_name:
        return jsonify({"error": "Invalid filename."}), 400

    session_id = session.get("session_id")
    if not session_id:
        session_id = str(uuid.uuid4())[:8]
        session["session_id"] = session_id

    upload_dir = Path(tempfile.gettempdir()) / "vibesec_uploads" / session_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    file_path = upload_dir / safe_name
    f.save(str(file_path))

    name_lower = safe_name.lower()
    if name_lower == "requirements.txt":
        message = f"Audit the dependencies in this uploaded file: {file_path}"
    elif name_lower == "dockerfile" or name_lower.startswith("dockerfile."):
        message = f"Analyze this uploaded Dockerfile: {file_path}"
    else:
        message = f"Scan this uploaded file for secrets and security issues: {file_path}"

    mode = session.get("mode", "vibe")

    try:
        agent    = create_agent(session_id=session_id, mode=mode)
        response = agent.run(message)

        if response is None:
            content = "(no response from agent)"
        elif hasattr(response, "content") and response.content:
            content = str(response.content)
        elif hasattr(response, "message") and response.message:
            content = str(response.message)
        else:
            content = str(response)

    except Exception as exc:
        return jsonify({"error": f"Agent error: {exc}"}), 500

    session["last_response"]      = content
    session["last_response_mode"] = mode

    return jsonify({"response": content, "filename": safe_name, "session_id": session_id})


@app.route("/export")
def export_report():
    content = session.get("last_response", "")
    if not content:
        return "No report to export yet. Run a scan first, then click Export.", 400

    mode       = session.get("last_response_mode", "vibe")
    session_id = session.get("session_id", "unknown")
    date_str   = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    html = _render_export_html(content, mode, date_str, session_id)

    resp = make_response(html)
    resp.headers["Content-Type"]        = "text/html; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="vibesec-report-{session_id}.html"'
    return resp


@app.route("/new-session", methods=["POST"])
def new_session():
    session["session_id"] = str(uuid.uuid4())[:8]
    session["mode"]       = "vibe"
    session.pop("last_response", None)
    session.pop("last_response_mode", None)
    return jsonify({"session_id": session["session_id"]})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    if not os.getenv("GEMINI_API_KEY"):
        print("\n[ERROR] GEMINI_API_KEY is not set in .env\n")
        raise SystemExit(1)

    port  = int(os.getenv("FLASK_PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    print(f"\n  VibeSec running → http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=debug)
