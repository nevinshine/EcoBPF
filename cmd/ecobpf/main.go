// Package main provides the entry point for the EcoBPF daemon.
//
// EcoBPF is a kernel-level carbon observability engine that uses eBPF probes
// to collect CPU, memory, and GPU telemetry, then estimates per-process energy
// consumption using a machine learning model.
//
// Usage:
//
//	ecobpf [--config /path/to/ecobpf.yaml]
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/btf"

	"github.com/nevin/ecobpf/internal/collector"
	"github.com/nevin/ecobpf/internal/estimator"
	"github.com/nevin/ecobpf/internal/exporter"
	"github.com/nevin/ecobpf/internal/telemetry"

	"gopkg.in/yaml.v3"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// Config represents the daemon runtime configuration.
type Config struct {
	// BPF pin path for map persistence across daemon restarts.
	BPFPinPath string `yaml:"bpf_pin_path"`

	// Polling interval for reading BPF maps.
	PollInterval time.Duration `yaml:"poll_interval"`

	// ML estimator gRPC target address.
	EstimatorAddr string `yaml:"estimator_addr"`

	// Prometheus metrics exporter listen address.
	PrometheusAddr string `yaml:"prometheus_addr"`

	// WebSocket telemetry feed listen address.
	WebSocketAddr string `yaml:"websocket_addr"`

	// Carbon intensity factor (gCO2/kWh) for the deployment region.
	CarbonIntensity float64 `yaml:"carbon_intensity"`

	// Log level: debug, info, warn, error.
	LogLevel string `yaml:"log_level"`

	// BPF object file paths.
	BPFObjects BPFObjectPaths `yaml:"bpf_objects"`

	// Backpressure tuning.
	ChannelSize   int           `yaml:"channel_size"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
}

// BPFObjectPaths locates the compiled eBPF object files.
type BPFObjectPaths struct {
	CPUSched    string `yaml:"cpu_sched"`
	MemPressure string `yaml:"mem_pressure"`
	GPUActivity string `yaml:"gpu_activity"`
}

// DefaultConfig returns sensible defaults for development.
func DefaultConfig() *Config {
	return &Config{
		BPFPinPath:      "/sys/fs/bpf/ecobpf",
		PollInterval:    time.Second,
		EstimatorAddr:   "localhost:50051",
		PrometheusAddr:  ":9090",
		WebSocketAddr:   ":8080",
		CarbonIntensity: 475.0, // Global average gCO2/kWh
		LogLevel:        "info",
		BPFObjects: BPFObjectPaths{
			CPUSched:    "bpf/cpu_sched.bpf.o",
			MemPressure: "bpf/mem_pressure.bpf.o",
			GPUActivity: "bpf/gpu_activity.bpf.o",
		},
		ChannelSize:   4096,
		BatchSize:     50,
		FlushInterval: 100 * time.Millisecond,
	}
}

func main() {
	// ─── CLI Flags ───────────────────────────────────────────────────
	configPath := flag.String("config", "configs/ecobpf.yaml", "Path to configuration file")
	version := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *version {
		fmt.Printf("ecobpf %s\n", Version)
		os.Exit(0)
	}

	// ─── Configuration ──────────────────────────────────────────────
	cfg := DefaultConfig()
	if data, err := os.ReadFile(*configPath); err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			slog.Error("Failed to parse config", "path", *configPath, "error", err)
			os.Exit(1)
		}
		slog.Info("Loaded configuration", "path", *configPath)
	} else {
		slog.Warn("Config file not found, using defaults", "path", *configPath)
	}

	// ─── Logging ────────────────────────────────────────────────────
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	slog.Info("Starting EcoBPF daemon",
		"version", Version,
		"bpf_pin_path", cfg.BPFPinPath,
		"estimator_addr", cfg.EstimatorAddr,
		"carbon_intensity", cfg.CarbonIntensity,
	)

	// ─── Pre-flight BTF check ───────────────────────────────────────
	if _, err := btf.LoadKernelSpec(); err != nil {
		slog.Warn("Host kernel BTF unavailable — CO-RE relocation disabled",
			"error", err,
			"hint", "Ensure CONFIG_DEBUG_INFO_BTF=y in kernel config")
	} else {
		slog.Info("Host kernel BTF available — CO-RE relocation enabled")
	}

	// ─── Context with signal handling ───────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("Received shutdown signal", "signal", sig)
		cancel()
	}()

	// ─── Initialize subsystems ──────────────────────────────────────
	var wg sync.WaitGroup

	// 1. BPF Collector — loads probes, consumes ring buffers
	coll, err := collector.New(collector.Config{
		PinPath:         cfg.BPFPinPath,
		PollInterval:    cfg.PollInterval,
		CPUSchedObj:     cfg.BPFObjects.CPUSched,
		MemPressureObj:  cfg.BPFObjects.MemPressure,
		GPUActivityObj:  cfg.BPFObjects.GPUActivity,
		ChannelSize:     cfg.ChannelSize,
		BatchSize:       cfg.BatchSize,
		FlushInterval:   cfg.FlushInterval,
	})
	if err != nil {
		slog.Error("Failed to initialize BPF collector", "error", err)
		os.Exit(1)
	}
	defer coll.Close()

	// Start Routine A: ring buffer consumer → backpressure channel
	wg.Add(1)
	go func() {
		defer wg.Done()
		coll.ConsumeRingBuffers(ctx)
	}()

	// 2. ML Estimator client (with circuit breaker)
	est, err := estimator.NewClient(estimator.ClientConfig{
		Addr:            cfg.EstimatorAddr,
		CarbonIntensity: cfg.CarbonIntensity,
	})
	if err != nil {
		slog.Warn("ML estimator unavailable, running in degraded mode", "error", err)
		// Daemon continues — circuit breaker will use heuristic fallback
	} else {
		defer est.Close()
	}

	// 3. Prometheus exporter
	promExporter := exporter.NewPrometheus(cfg.CarbonIntensity)
	wg.Add(1)
	go func() {
		defer wg.Done()
		mux := http.NewServeMux()
		mux.Handle("/metrics", promExporter.Handler())
		server := &http.Server{Addr: cfg.PrometheusAddr, Handler: mux}

		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			if err := server.Shutdown(shutdownCtx); err != nil {
				slog.Warn("Prometheus server shutdown error", "error", err)
			}
		}()
		slog.Info("Prometheus exporter listening", "addr", cfg.PrometheusAddr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("Prometheus server error", "error", err)
		}
	}()

	// 4. WebSocket telemetry feed
	wsFeed := telemetry.NewWebSocketFeed()
	wg.Add(1)
	go func() {
		defer wg.Done()
		mux := http.NewServeMux()
		mux.HandleFunc("/ws", wsFeed.HandleConnection)
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"status":"ok","version":"` + Version + `"}`)); err != nil {
				slog.Debug("Health response write error", "error", err)
			}
		})
		server := &http.Server{Addr: cfg.WebSocketAddr, Handler: mux}

		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			if err := server.Shutdown(shutdownCtx); err != nil {
				slog.Warn("WebSocket server shutdown error", "error", err)
			}
		}()

		slog.Info("WebSocket feed listening", "addr", cfg.WebSocketAddr)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("WebSocket server error", "error", err)
		}
	}()

	// ─── Main collection loop (Routine B: batched collector) ────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		droppedLast := uint64(0)

		for {
			select {
			case <-ctx.Done():
				slog.Info("Collection loop shutting down")
				return
			default:
			}

			// BatchedCollect blocks until batch is ready or flush interval fires
			vectors, err := coll.BatchedCollect(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return // Shutdown
				}
				slog.Error("Collection error", "error", err)
				continue
			}

			if len(vectors) == 0 {
				continue
			}

			// Report backpressure drops periodically
			dropped := coll.DroppedEvents.Load()
			if dropped > droppedLast {
				slog.Warn("Ring buffer backpressure — events dropped",
					"dropped_total", dropped,
					"dropped_since_last", dropped-droppedLast,
				)
				droppedLast = dropped
			}

			// Send to ML estimator for energy estimates
			var estimates []estimator.EnergyEstimate
			if est != nil {
				estimates, err = est.Estimate(ctx, vectors)
				if err != nil {
					slog.Warn("Estimation failed, using heuristic", "error", err)
					estimates = estimator.HeuristicEstimate(vectors, cfg.CarbonIntensity)
				}
			} else {
				estimates = estimator.HeuristicEstimate(vectors, cfg.CarbonIntensity)
			}

			// Update Prometheus metrics
			promExporter.Update(estimates)

			// Broadcast to WebSocket clients
			wsFeed.Broadcast(estimates)

			slog.Debug("Collection cycle complete",
				"processes", len(vectors),
				"estimates", len(estimates),
			)
		}
	}()

	// ─── Wait for shutdown ──────────────────────────────────────────
	<-ctx.Done()
	slog.Info("Shutting down EcoBPF daemon...")
	wg.Wait()
	slog.Info("EcoBPF daemon stopped")
}
