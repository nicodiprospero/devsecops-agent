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

# Web interface port
EXPOSE 5000

# Liveness check against the /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

CMD ["python", "app.py"]
