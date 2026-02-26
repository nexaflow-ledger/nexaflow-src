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

WORKDIR /app

# Copy installed packages and built extensions
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app /app

EXPOSE 9001 8080

ENV NEXAFLOW_NODE_ID=validator-1 \
    NEXAFLOW_PORT=9001 \
    NEXAFLOW_API_PORT=8080 \
    NEXAFLOW_LOG_LEVEL=INFO

ENTRYPOINT ["python", "run_node.py"]
CMD ["--no-cli"]
