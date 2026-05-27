# ── Build stage ────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="VibeSec"
LABEL org.opencontainers.image.description="Security scanner for AI-generated code — Agno + Gemini"

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY tools.py agent.py app.py main.py ./
COPY templates/ ./templates/

# Create non-root user and transfer ownership
RUN useradd -m -u 1000 -s /bin/sh vibesec \
    && chown -R vibesec:vibesec /app

USER vibesec

# Railway injects $PORT; fall back to 5000 for local runs
ENV PORT=5000

EXPOSE $PORT

# Liveness check against the /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://localhost:{os.getenv(\"PORT\",5000)}/health')" || exit 1

CMD gunicorn --bind "0.0.0.0:${PORT}" --workers 2 --timeout 120 app:app
