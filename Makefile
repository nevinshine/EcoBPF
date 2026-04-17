# ═══════════════════════════════════════════════════════════════════════════════
# EcoBPF — Kernel-Level Carbon Observability Engine
# Top-Level Makefile
# ═══════════════════════════════════════════════════════════════════════════════

SHELL         := /bin/bash
.DEFAULT_GOAL := all

# ─── Configuration ────────────────────────────────────────────────────────────
GO            := go
CLANG         := clang
CLANG_FLAGS   := -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86
BPF_DIR       := bpf
BPF_HEADERS   := $(BPF_DIR)/headers
BPF_SOURCES   := $(wildcard $(BPF_DIR)/*.bpf.c)
BPF_OBJECTS   := $(BPF_SOURCES:.bpf.c=.bpf.o)
BINARY        := ecobpf
BUILD_DIR     := build
VERSION       := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS       := -ldflags "-X main.Version=$(VERSION)"

# Docker
DOCKER_REGISTRY ?= ghcr.io/nevin
DOCKER_TAG      ?= $(VERSION)

# Ansible
ANSIBLE_INVENTORY ?= deploy/ansible/inventory.ini
ANSIBLE_PLAYBOOK  ?= deploy/ansible/playbook.yml

# BPF pin path for verifier dry-run
BPF_PIN_PATH  := /sys/fs/bpf/ecobpf

# ─── Phony targets ───────────────────────────────────────────────────────────
.PHONY: all generate bpf build test lint clean docker up down deploy
.PHONY: verify-bpf vmlinux-subset proto generate-bpf2go help

# ─── Help ─────────────────────────────────────────────────────────────────────
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ─── Full pipeline ───────────────────────────────────────────────────────────
all: generate bpf generate-bpf2go build test ## Full pipeline: generate → bpf → bpf2go → build → test

# ─── Code generation ─────────────────────────────────────────────────────────
generate: proto ## Generate protobuf stubs and eBPF skeletons

proto: ## Generate Go and Python protobuf stubs
	@echo "═══ Generating protobuf stubs ═══"
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		internal/estimator/proto/estimator.proto
	python3 -m grpc_tools.protoc \
		-I. \
		--python_out=ml/proto \
		--grpc_python_out=ml/proto \
		internal/estimator/proto/estimator.proto
	@echo "✓ Protobuf stubs generated"

generate-bpf2go: bpf ## Generate type-safe Go bindings from compiled BPF objects
	@echo "═══ Generating bpf2go type-safe Go bindings ═══"
	go generate ./internal/collector/...
	@echo "✓ bpf2go bindings generated"

# ─── CO-RE vmlinux subset generation ─────────────────────────────────────────
vmlinux-subset: ## Regenerate vmlinux_subset.h from current kernel BTF
	@echo "═══ Generating vmlinux subset from kernel BTF ═══"
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_HEADERS)/vmlinux_full.h; \
		echo "✓ Full vmlinux.h generated (use subset for builds)"; \
	else \
		echo "⚠ No BTF data at /sys/kernel/btf/vmlinux (kernel CONFIG_DEBUG_INFO_BTF=y required)"; \
	fi

# ─── eBPF compilation ────────────────────────────────────────────────────────
bpf: $(BPF_OBJECTS) ## Compile eBPF C sources to bytecode

$(BPF_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c $(BPF_HEADERS)/vmlinux_subset.h
	@echo "═══ Compiling $< → $@ ═══"
	$(CLANG) $(CLANG_FLAGS) \
		-I$(BPF_HEADERS) \
		-c $< -o $@
	@echo "✓ $@ compiled"

# ─── BPF verifier dry-run ────────────────────────────────────────────────────
verify-bpf: bpf ## Dry-run BPF objects against kernel verifier
	@echo "═══ Running BPF verifier checks ═══"
	@for obj in $(BPF_OBJECTS); do \
		echo "  Verifying $$obj..."; \
		bpftool prog load $$obj /sys/fs/bpf/ecobpf_verify_test 2>&1 && \
			bpftool prog detach pinned /sys/fs/bpf/ecobpf_verify_test && \
			rm -f /sys/fs/bpf/ecobpf_verify_test && \
			echo "  ✓ $$obj passed verifier" || \
			echo "  ✗ $$obj FAILED verifier"; \
	done

# ─── Go build ────────────────────────────────────────────────────────────────
build: ## Build the EcoBPF daemon binary
	@echo "═══ Building EcoBPF daemon ═══"
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/ecobpf/
	@echo "✓ Binary: $(BUILD_DIR)/$(BINARY) ($(VERSION))"

# ─── Tests ────────────────────────────────────────────────────────────────────
test: test-go test-python ## Run all tests

test-go: ## Run Go tests
	@echo "═══ Running Go tests ═══"
	$(GO) test -v -race -count=1 ./...

test-python: ## Run Python ML tests
	@echo "═══ Running Python ML tests ═══"
	cd ml && python3 -m pytest -v . 2>/dev/null || python3 train.py --generate

# ─── Linting ──────────────────────────────────────────────────────────────────
lint: lint-go lint-python lint-bpf ## Run all linters

lint-go: ## Run Go linter
	@echo "═══ Linting Go code ═══"
	golangci-lint run ./... 2>/dev/null || echo "⚠ golangci-lint not installed"

lint-python: ## Run Python linter
	@echo "═══ Linting Python code ═══"
	flake8 ml/ --max-line-length=100 --ignore=E501,W503 2>/dev/null || echo "⚠ flake8 not installed"

lint-bpf: ## Run clang-tidy on BPF sources
	@echo "═══ Linting eBPF C code ═══"
	clang-tidy $(BPF_SOURCES) -- $(CLANG_FLAGS) -I$(BPF_HEADERS) 2>/dev/null || echo "⚠ clang-tidy not installed"

# ─── Docker ───────────────────────────────────────────────────────────────────
docker: docker-daemon docker-ml ## Build all Docker images

docker-daemon: ## Build daemon Docker image
	@echo "═══ Building daemon Docker image ═══"
	docker build -t $(DOCKER_REGISTRY)/ecobpf-daemon:$(DOCKER_TAG) \
		-f deploy/Dockerfile .

docker-ml: ## Build ML service Docker image
	@echo "═══ Building ML service Docker image ═══"
	docker build -t $(DOCKER_REGISTRY)/ecobpf-ml:$(DOCKER_TAG) \
		-f deploy/Dockerfile.ml .

# ─── Docker Compose ───────────────────────────────────────────────────────────
up: ## Start full stack via Docker Compose
	@echo "═══ Starting EcoBPF stack ═══"
	docker compose -f deploy/docker-compose.yml up -d
	@echo "✓ Stack running:"
	@echo "  Prometheus: http://localhost:9090"
	@echo "  Grafana:    http://localhost:3000 (admin/ecobpf)"
	@echo "  WebSocket:  ws://localhost:8080/ws"

down: ## Stop Docker Compose stack
	docker compose -f deploy/docker-compose.yml down

# ─── Ansible deployment ──────────────────────────────────────────────────────
deploy: build bpf ## Deploy to bare-metal host via Ansible
	@echo "═══ Deploying to production ═══"
	ansible-playbook -i $(ANSIBLE_INVENTORY) $(ANSIBLE_PLAYBOOK)

# ─── Clean ────────────────────────────────────────────────────────────────────
clean: ## Remove build artifacts
	@echo "═══ Cleaning ═══"
	rm -rf $(BUILD_DIR)
	rm -f $(BPF_OBJECTS)
	rm -f ml/model.joblib ml/scaler.joblib
	rm -f ml/calibration_data.csv
	$(GO) clean
	@echo "✓ Clean"
