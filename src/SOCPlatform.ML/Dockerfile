# ─── Stage 1: Build deps into a venv ─────────────────────────────────────────
FROM python:3.11-slim AS build
WORKDIR /build

# gcc needed to compile scientific wheels on slim base.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc g++ libopenblas-dev \
    && rm -rf /var/lib/apt/lists/*

COPY soc_platform/src/SOCPlatform.ML/requirements.txt ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        libopenblas0 curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 1001 soc

COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ML_MODEL_DIR=/app/data/models

COPY soc_platform/src/SOCPlatform.ML ./

# Persist retrained models to a named volume.
RUN mkdir -p /app/data/models && chown -R soc:soc /app
USER soc

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8001/api/ml/status || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "2"]
