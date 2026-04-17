# EcoBPF — Kernel-Level Carbon Observability Engine

[![CI](https://github.com/nevin/ecobpf/actions/workflows/ci.yml/badge.svg)](https://github.com/nevin/ecobpf/actions/workflows/ci.yml)

> **Mission**: Give developers actionable data to mitigate the trajectory of data centers consuming 20% of global electricity by 2030.

## The Problem: Invisible Carbon Footprints
The rapid growth of artificial intelligence and cloud computing has significantly increased global energy consumption, yet the carbon footprint of individual software processes remains largely invisible. Current sustainability tools rely on coarse billing estimates or infrastructure-level monitoring, making it difficult to attribute energy usage to specific workloads. This lack of visibility limits the ability of developers and organizations to optimize software systems for sustainability.

## The EcoBPF Solution
**EcoBPF is a kernel-level carbon observability engine designed to estimate per-process energy consumption in real time.**

Unlike container-centric monitoring systems that depend heavily on orchestration frameworks, EcoBPF operates as a lightweight host daemon capable of profiling both containerized and standalone workloads. The system attributes estimated joule consumption to individual processes—with a specific focus on **AI inference tasks**—and presents results through a real-time observability dashboard. 

By providing process-level energy transparency, EcoBPF enables carbon-aware optimization, supports GreenOps compliance, and promotes sustainable AI and cloud infrastructure. The project aligns with the theme of *Sustainable Innovations for Growth and Human Transformation* by making software energy efficiency measurable, actionable, and scalable.

### 1. Near-Zero Overhead eBPF Probes
EcoBPF leverages extended Berkeley Packet Filter (eBPF) technology to deploy compiled C telemetry probes within the host operating system. Because eBPF runs safely isolated inside the kernel directly at event triggers, the overhead is mathematically negligible. 

These probes capture **deterministic runtime signals**, including:
- **CPU Scheduling Events**: Granular tracking of execution timeslices per thread.
- **Context Switches**: Monitoring the structural overhead of multitasking.
- **Memory Pressure & Page Faults**: Capturing cache misses, physical memory loading, and heavy I/O operations.
- **GPU Activity**: Tracking device interaction for AI and compute workloads.

### 2. Linear Regression Energy Modeling (Machine Learning)
Direct hardware sensors (like Intel RAPL or NVIDIA NVML) exist on bare-metal servers, but accessing them in virtualized hypervisor environments is often impossible securely. To solve this, EcoBPF relies on software approximations.

The collected kernel metrics dynamically form a continuous **feature vector**. EcoBPF passes these vectors to a Python-based gRPC Machine Learning Estimator. This engine utilizes a rigorously trained **linear regression model**, originally calibrated against empirical bare-metal hardware benchmarks. This unique architecture guarantees EcoBPF maintains accurate energy estimation telemetry **even in virtualized cloud environments where direct hardware power sensors are unavailable.**

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Kernel Space                      │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │cpu_sched │  │mem_pressure  │  │gpu_activity  │  │
│  │ .bpf.c   │  │  .bpf.c      │  │  .bpf.c      │  │
│  └────┬─────┘  └──────┬───────┘  └──────┬───────┘  │
│       └───────────┬────┴─────────────────┘          │
│              Ring Buffers + Pinned Maps              │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────┐
│               User Space (Go Daemon)                 │
│  Collector → Feature Vectors → gRPC → ML Service    │
│  Cgroup Profiler → Container Attribution             │
│  Prometheus Exporter (:9090)                         │
│  WebSocket Feed (:8080/ws)                           │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────┐
│            Observability Stack                       │
│  Prometheus → Grafana Dashboard (:3000)              │
│  Real-time Carbon / Energy / GPU / Memory panels     │
└─────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Linux kernel ≥ 5.8 with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)
- Docker & Docker Compose
- Go 1.22+ (for development)
- Clang 14+ (for eBPF compilation)

## Getting Started: How to Access and Run EcoBPF

Follow these simple steps to deploy and view your carbon observability dashboards:

### 1. Launch the Stack

Start the entire observability stack (EcoBPF Daemon, ML Estimator, Prometheus, and Grafana) with a single command:

```bash
make up
```

### 2. Access the Dashboards

Once the containers are spinning, you can immediately access the web interfaces:

- **Grafana Dashboard**: Open [http://localhost:3000](http://localhost:3000) in your web browser. 
  *(Default credentials: Username = `admin`, Password = `ecobpf`)*
- **Prometheus Target**: Access metrics directly at [http://localhost:9090](http://localhost:9090).
- **WebSocket Feed**: Listen to real-time telemetry events at `ws://localhost:8080/ws`.

### 3. Teardown

When you're finished, you can safely shut everything down:

```bash
make down
```

### Development Build

```bash
# Full pipeline
make all          # generate → bpf → build → test

# Individual targets
make bpf          # Compile eBPF probes
make build        # Build Go daemon
make test         # Run Go + Python tests
make lint         # Run all linters
make verify-bpf   # Run BPF verifier dry-run
```

### Bare-Metal Deployment

```bash
# 1. Build everything
make all

# 2. Deploy via Ansible
ansible-playbook -i deploy/ansible/inventory.ini deploy/ansible/playbook.yml
```

## Configuration

Edit `configs/ecobpf.yaml`:

| Key | Default | Description |
|-----|---------|-------------|
| `poll_interval` | `1s` | BPF map polling frequency |
| `estimator_addr` | `localhost:50051` | ML service gRPC address |
| `carbon_intensity` | `475.0` | Grid carbon intensity (gCO₂/kWh) |
| `bpf_pin_path` | `/sys/fs/bpf/ecobpf` | BPF map pin path |

## Key Features

- **Near-zero overhead** — eBPF probes run in kernel, no kernel module required
- **Container-aware** — profiles Docker/containerd/Podman workloads via cgroup v1/v2
- **No K8s dependency** — works on bare-metal, VMs, and cloud instances
- **ML energy estimation** — linear regression trained on RAPL/NVML calibration data
- **AI workload attribution** — explicitly attributes energy to inference tasks
- **Circuit breaker** — degrades gracefully when ML service is unavailable
- **Map pinning** — kernel metrics survive daemon restarts
- **CO-RE portable** — runs across kernel versions without recompilation

## Project Structure

```
EcoBPF/
├── bpf/            # eBPF C probe sources
├── cmd/ecobpf/     # Daemon entry point
├── internal/       # Go packages (collector, cgroup, estimator, exporter, telemetry)
├── ml/             # Python ML pipeline (model, training, gRPC server)
├── deploy/         # Docker, Compose, Ansible
├── grafana/        # Dashboard + provisioning
├── configs/        # Runtime configuration
└── .github/        # CI/CD pipeline
```

## License

Dual BSD-3-Clause / GPL-2.0 (eBPF probes are GPL-2.0, user-space code is BSD-3-Clause)
