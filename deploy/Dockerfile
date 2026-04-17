# ═══════════════════════════════════════════════════════════════════════════════
# EcoBPF Daemon — Multi-Stage Dockerfile
# ═══════════════════════════════════════════════════════════════════════════════
# Stage 1: BPF compilation
# Stage 2: Go compilation
# Stage 3: Minimal runtime image
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Stage 1: Compile eBPF probes ─────────────────────────────────────────────
FROM ubuntu:24.04 AS bpf-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang-14 \
    llvm-14 \
    libbpf-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY bpf/ bpf/
COPY Makefile .

RUN make bpf CLANG=clang-14

# ─── Stage 2: Build Go daemon ────────────────────────────────────────────────
FROM golang:1.22-bookworm AS go-builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=bpf-builder /src/bpf/*.bpf.o bpf/

ARG VERSION=docker
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.Version=${VERSION} -s -w" \
    -o /ecobpf ./cmd/ecobpf/

# ─── Stage 3: Runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# Install minimal runtime dependencies for BPF
RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (BPF caps added at runtime)
RUN useradd -r -s /bin/false ecobpf

WORKDIR /opt/ecobpf

# Copy artifacts
COPY --from=go-builder /ecobpf .
COPY --from=bpf-builder /src/bpf/*.bpf.o bpf/
COPY configs/ecobpf.yaml configs/

# Expose Prometheus and WebSocket ports
EXPOSE 9090 8080

# Health check
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

# Run as root for BPF capabilities (production: use CAP_BPF + CAP_PERFMON)
ENTRYPOINT ["./ecobpf"]
CMD ["--config", "configs/ecobpf.yaml"]
