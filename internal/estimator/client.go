// Package estimator provides the gRPC client for the Python ML energy
// estimation service, with circuit breaker pattern for graceful degradation.
package estimator

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/nevin/ecobpf/internal/collector"
	pb "github.com/nevin/ecobpf/internal/estimator/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// EnergyEstimate represents the ML model output for a single process.
type EnergyEstimate struct {
	PID            uint32
	Comm           string
	ContainerID    string
	ContainerName  string
	EnergyJoules   float64
	PowerWatts     float64
	Confidence     float64
	CPUEnergy      float64
	MemoryEnergy   float64
	GPUEnergy      float64
	CarbonGramsCO2 float64
	IsAIInference  bool
	Timestamp      time.Time
}

// ClientConfig configures the ML estimator gRPC client.
type ClientConfig struct {
	Addr            string
	CarbonIntensity float64 // gCO2/kWh
	MaxRetries      int
	RetryBaseDelay  time.Duration
}

// circuitState represents the current state of the circuit breaker.
type circuitState int

const (
	circuitClosed   circuitState = iota // Normal operation
	circuitOpen                         // Failing, use fallback
	circuitHalfOpen                     // Testing recovery
)

// CircuitBreaker implements the circuit breaker pattern for
// graceful ML service degradation.
type CircuitBreaker struct {
	mu              sync.Mutex
	state           circuitState
	failures        int
	successesNeeded int
	threshold       int
	lastFailure     time.Time
	cooldown        time.Duration
}

// Client wraps the gRPC connection to the Python ML service.
type Client struct {
	conn     *grpc.ClientConn
	pbClient pb.EstimatorServiceClient
	cfg      ClientConfig
	breaker  *CircuitBreaker

	// Feature vector cache for circuit breaker recovery
	cachedVectors []collector.FeatureVector
	cacheMu       sync.Mutex
}

// NewClient creates a new estimator client with circuit breaker.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.RetryBaseDelay == 0 {
		cfg.RetryBaseDelay = 100 * time.Millisecond
	}

	conn, err := grpc.NewClient(cfg.Addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial estimator at %s: %w", cfg.Addr, err)
	}

	return &Client{
		conn:     conn,
		pbClient: pb.NewEstimatorServiceClient(conn),
		cfg:      cfg,
		breaker: &CircuitBreaker{
			threshold:       5,
			successesNeeded: 3,
			cooldown:        30 * time.Second,
		},
	}, nil
}

// Estimate sends feature vectors to the ML service and returns energy estimates.
// If the circuit breaker is open, it caches vectors and returns heuristic estimates.
func (c *Client) Estimate(ctx context.Context, vectors []collector.FeatureVector) ([]EnergyEstimate, error) {
	// Check circuit breaker state
	if !c.breaker.Allow() {
		slog.Debug("Circuit breaker open, caching vectors for retry")
		c.cacheVectors(vectors)
		return HeuristicEstimate(vectors, c.cfg.CarbonIntensity), nil
	}

	// Attempt gRPC call with retries
	var lastErr error
	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := c.cfg.RetryBaseDelay * time.Duration(math.Pow(2, float64(attempt-1)))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		estimates, err := c.doEstimate(ctx, vectors)
		if err == nil {
			c.breaker.RecordSuccess()
			// Retry any cached vectors
			c.retryCachedVectors(ctx)
			return estimates, nil
		}
		lastErr = err
		slog.Warn("Estimation attempt failed",
			"attempt", attempt+1, "error", err)
	}

	// All retries exhausted
	c.breaker.RecordFailure()
	c.cacheVectors(vectors)

	slog.Warn("ML estimator unavailable, falling back to heuristic",
		"error", lastErr)
	return HeuristicEstimate(vectors, c.cfg.CarbonIntensity), nil
}

// doEstimate performs a single gRPC estimation call.
func (c *Client) doEstimate(ctx context.Context, vectors []collector.FeatureVector) ([]EnergyEstimate, error) {
	pbVectors := make([]*pb.FeatureVector, 0, len(vectors))
	for _, v := range vectors {
		pbVectors = append(pbVectors, &pb.FeatureVector{
			Pid:                    v.PID,
			Tgid:                   v.TGID,
			Comm:                   v.Comm,
			ContainerId:            v.ContainerID,
			CpuTimeNs:              uint64(v.CPUTimeNs),
			CtxSwitches:            uint64(v.CtxSwitches),
			VoluntaryCtxSwitches:   v.VoluntaryCtxSwitches,
			InvoluntaryCtxSwitches: v.InvoluntaryCtxSwitches,
			CpuFreqMhz:             v.CPUFreqMHz,
			CpuId:                  v.CPUID,
			MajorFaults:            v.MajorFaults,
			MinorFaults:            v.MinorFaults,
			RssBytes:               v.RSSBytes,
			DirectReclaimCount:     v.DirectReclaimCnt,
			GpuJobsSubmitted:       v.GPUJobsSubmitted,
			GpuActiveNs:            v.GPUActiveNs,
			TimestampNs:            v.TimestampNs,
		})
	}

	req := &pb.FeatureVectorBatch{
		Vectors:               pbVectors,
		CollectionTimestampNs: uint64(time.Now().UnixNano()),
	}

	resp, err := c.pbClient.Estimate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gRPC estimation failed: %w", err)
	}

	estimates := make([]EnergyEstimate, 0, len(resp.Estimates))
	for _, est := range resp.Estimates {
		estimates = append(estimates, EnergyEstimate{
			PID:            est.Pid,
			Comm:           est.Comm,
			ContainerID:    est.ContainerId,
			ContainerName:  est.ContainerId,
			EnergyJoules:   est.EnergyJoules,
			PowerWatts:     est.PowerWatts,
			Confidence:     est.Confidence,
			CPUEnergy:      est.CpuEnergyJoules,
			MemoryEnergy:   est.MemoryEnergyJoules,
			GPUEnergy:      est.GpuEnergyJoules,
			CarbonGramsCO2: est.CarbonGramsCo2,
			IsAIInference:  est.IsAiInference,
			Timestamp:      time.Now(),
		})
	}
	return estimates, nil
}

// cacheVectors stores feature vectors for retry when the ML service recovers.
func (c *Client) cacheVectors(vectors []collector.FeatureVector) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	// Keep at most 1000 cached vectors (rolling window)
	c.cachedVectors = append(c.cachedVectors, vectors...)
	if len(c.cachedVectors) > 1000 {
		c.cachedVectors = c.cachedVectors[len(c.cachedVectors)-1000:]
	}
}

// retryCachedVectors attempts to send cached vectors when the service recovers.
func (c *Client) retryCachedVectors(ctx context.Context) {
	c.cacheMu.Lock()
	cached := c.cachedVectors
	c.cachedVectors = nil
	c.cacheMu.Unlock()

	if len(cached) > 0 {
		slog.Info("Retrying cached feature vectors", "count", len(cached))
		// Fire-and-forget retry of cached vectors
		go func() {
			_, err := c.doEstimate(ctx, cached)
			if err != nil {
				slog.Debug("Cached vector retry failed", "error", err)
			}
		}()
	}
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// ─── Circuit Breaker ─────────────────────────────────────────────────────

// Allow returns true if the circuit allows a request through.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case circuitClosed:
		return true
	case circuitOpen:
		// Check if cooldown has elapsed
		if time.Since(cb.lastFailure) > cb.cooldown {
			cb.state = circuitHalfOpen
			cb.failures = 0
			return true
		}
		return false
	case circuitHalfOpen:
		return true
	}
	return true
}

// RecordSuccess records a successful request.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == circuitHalfOpen {
		cb.failures++
		if cb.failures >= cb.successesNeeded {
			cb.state = circuitClosed
			cb.failures = 0
			slog.Info("Circuit breaker closed (ML service recovered)")
		}
	}
}

// RecordFailure records a failed request.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	if cb.failures >= cb.threshold {
		cb.state = circuitOpen
		slog.Warn("Circuit breaker opened (ML service unavailable)",
			"failures", cb.failures)
	}
}

// ─── Heuristic Fallback ─────────────────────────────────────────────────

// HeuristicEstimate provides simple energy estimates when the ML service
// is unavailable. Uses linear coefficients calibrated against Intel RAPL
// measurements on reference hardware.
//
// Reference TDP coefficients (conservative estimates):
//   - CPU: ~5 nJ per nanosecond of CPU time at base frequency
//   - Memory: ~0.5 μJ per page fault (TLB miss + page walk)
//   - GPU: ~100 μJ per GPU job submission
func HeuristicEstimate(vectors []collector.FeatureVector, carbonIntensity float64) []EnergyEstimate {
	const (
		cpuNJPerNs     = 5.0e-9  // Joules per ns of CPU time
		memUJPerFault  = 0.5e-6  // Joules per page fault
		gpuUJPerJob    = 100e-6  // Joules per GPU job
		kWhToJoules    = 3.6e6
	)

	estimates := make([]EnergyEstimate, 0, len(vectors))
	for _, v := range vectors {
		cpuEnergy := float64(v.CPUTimeNs) * cpuNJPerNs
		memEnergy := float64(v.MajorFaults+v.MinorFaults) * memUJPerFault
		gpuEnergy := float64(v.GPUJobsSubmitted) * gpuUJPerJob

		totalEnergy := cpuEnergy + memEnergy + gpuEnergy

		// Carbon = energy_kWh × gCO2/kWh
		carbonGrams := (totalEnergy / kWhToJoules) * carbonIntensity

		estimates = append(estimates, EnergyEstimate{
			PID:            v.PID,
			Comm:           v.Comm,
			ContainerID:    v.ContainerID,
			ContainerName:  v.ContainerName,
			EnergyJoules:   totalEnergy,
			PowerWatts:     totalEnergy, // Instantaneous (1s window)
			Confidence:     0.3,         // Low confidence for heuristic
			CPUEnergy:      cpuEnergy,
			MemoryEnergy:   memEnergy,
			GPUEnergy:      gpuEnergy,
			CarbonGramsCO2: carbonGrams,
			IsAIInference:  isLikelyAIWorkload(v.Comm),
			Timestamp:      time.Now(),
		})
	}
	return estimates
}

// isLikelyAIWorkload heuristically identifies AI/ML processes by name.
func isLikelyAIWorkload(comm string) bool {
	aiPatterns := []string{
		"python", "python3",
		"torch", "tensorflow",
		"triton", "onnxruntime",
		"trtexec", "nvidia-smi",
		"ollama", "vllm",
		"mlserver", "bentoml",
	}
	for _, p := range aiPatterns {
		if comm == p {
			return true
		}
	}
	return false
}
