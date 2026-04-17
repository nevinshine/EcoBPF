# ═══════════════════════════════════════════════════════════════════════════════
# EcoBPF ML Service — Dockerfile
# ═══════════════════════════════════════════════════════════════════════════════

FROM python:3.11-slim-bookworm

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY ml/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy ML service code
COPY ml/ .

# Pre-train model on synthetic data (used as fallback)
RUN python train.py --generate

# Expose gRPC port
EXPOSE 50051

# Health check via gRPC reflection
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD python -c "import grpc; ch=grpc.insecure_channel('127.0.0.1:50051'); grpc.channel_ready_future(ch).result(timeout=3)" || exit 1

ENTRYPOINT ["python", "server.py"]
CMD ["--port", "50051"]
