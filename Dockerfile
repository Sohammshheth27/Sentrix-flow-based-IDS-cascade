# Sentrix flow-based intrusion-detection cascade
# Reference image for reviewers: brings the dashboard up on port 8080.

FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="Sentrix"
LABEL org.opencontainers.image.description="Flow-based intrusion-detection cascade with logit-space threat-intelligence fusion"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/Sohammshheth27/SENTRIX-A-flow-based-intrusion-detection-cascade-with-logit-space-threat-intelligence-fusion"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# OpenMP runtime for LightGBM / XGBoost ONNX inference; curl for healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Empty runtime mount points.
VOLUME ["/app/data", "/app/logs"]

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fs http://localhost:8080/api/health || exit 1

# Default: dashboard server only. Override with `python run.py --file /app/data/your.csv` for replay mode.
CMD ["python", "-u", "-c", "import uvicorn; from src.dashboard_server import app; uvicorn.run(app, host='0.0.0.0', port=8080)"]
