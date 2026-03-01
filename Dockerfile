# ── Build stage ──────────────────────────────────────────────
FROM python:3.12-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN python setup.py build_ext --inplace && \
    pip install --no-cache-dir .

# ── Runtime stage ────────────────────────────────────────────
FROM python:3.12-slim

# S5 — Run as unprivileged user
RUN groupadd --gid 1000 nexaflow && \
    useradd --uid 1000 --gid nexaflow --create-home nexaflow

WORKDIR /app

# Copy installed packages and built extensions
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app /app

# Ensure data/certs directories exist and are writable
RUN mkdir -p /app/data /app/certs /app/logs && \
    chown -R nexaflow:nexaflow /app

EXPOSE 9001 8080

ENV NEXAFLOW_NODE_ID=validator-1 \
    NEXAFLOW_PORT=9001 \
    NEXAFLOW_API_PORT=8080 \
    NEXAFLOW_LOG_LEVEL=INFO

# S5 — Healthcheck: verify the API is responsive
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/status')" || exit 1

USER nexaflow

ENTRYPOINT ["python", "run_node.py"]
CMD ["--no-cli"]
