// Package collector provides the BPF ring buffer consumer and map reader
// that collects kernel telemetry from the eBPF probes.
//
// Architecture:
//
//	Routine A (consumeRingBuffers): reads ring buffers → pushes to channel
//	Routine B (BatchedCollect):     reads channel → batches → returns to caller
//
// This decouples eBPF ingestion from downstream gRPC latency, preventing
// ring buffer drops when the ML estimator is slow.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/nevin/ecobpf/internal/cgroup"
)

// Config holds the collector configuration.
type Config struct {
	PinPath        string
	PollInterval   time.Duration
	CPUSchedObj    string
	MemPressureObj string
	GPUActivityObj string

	// Backpressure tuning
	ChannelSize    int           // Buffered channel capacity (default: 4096)
	BatchSize      int           // Max events per batch (default: 50)
	FlushInterval  time.Duration // Max time before flushing partial batch (default: 100ms)
}

// FeatureVector represents the kernel telemetry signals for a single process.
type FeatureVector struct {
	PID         uint32
	TGID        uint32
	Comm        string
	ContainerID string
	ContainerName string // Enriched via runtime watcher

	// CPU metrics
	CPUTimeNs              uint64
	CtxSwitches            uint64
	VoluntaryCtxSwitches   uint64
	InvoluntaryCtxSwitches uint64
	CPUFreqMHz             uint32
	CPUID                  uint32

	// Memory metrics
	MajorFaults      uint64
	MinorFaults      uint64
	RSSBytes         uint64
	DirectReclaimCnt uint64

	// GPU metrics
	GPUJobsSubmitted uint64
	GPUActiveNs      uint64

	TimestampNs uint64
}

// Collector manages eBPF probe lifecycle and data collection.
type Collector struct {
	cfg    Config
	cgProf *cgroup.Profiler

	// eBPF collections (programs + maps)
	cpuColl *ebpf.Collection
	memColl *ebpf.Collection
	gpuColl *ebpf.Collection

	// Tracepoint links
	links []link.Link

	// Ring buffer readers
	cpuReader *ringbuf.Reader
	memReader *ringbuf.Reader
	gpuReader *ringbuf.Reader

	// Backpressure: ring buffer consumer → batched collector
	vectorCh chan FeatureVector

	// Metrics
	DroppedEvents atomic.Uint64

	// Host BTF spec for CO-RE relocation
	hostBTF *btf.Spec
}

// New creates a new Collector, loading eBPF programs and attaching probes.
// It probes the host kernel BTF for CO-RE relocation support.
func New(cfg Config) (*Collector, error) {
	// Apply defaults
	if cfg.ChannelSize == 0 {
		cfg.ChannelSize = 4096
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 50
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 100 * time.Millisecond
	}

	c := &Collector{
		cfg:      cfg,
		cgProf:   cgroup.NewProfiler(),
		vectorCh: make(chan FeatureVector, cfg.ChannelSize),
	}

	// ─── Host BTF / CO-RE ───────────────────────────────────────────
	hostBTF, err := btf.LoadKernelSpec()
	if err != nil {
		slog.Warn("Host BTF unavailable — CO-RE relocation disabled, using exact-match",
			"error", err)
	} else {
		c.hostBTF = hostBTF
		slog.Info("Host BTF loaded for CO-RE relocation")
	}

	// Ensure BPF pin path exists for map persistence
	if err := os.MkdirAll(cfg.PinPath, 0700); err != nil {
		return nil, fmt.Errorf("create bpf pin path %s: %w", cfg.PinPath, err)
	}

	// Build common collection options with BTF and pin path
	collOpts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: cfg.PinPath},
	}
	if c.hostBTF != nil {
		collOpts.Programs.KernelTypes = c.hostBTF
	}

	// ─── Load CPU scheduler probe ───────────────────────────────────
	cpuSpec, err := ebpf.LoadCollectionSpec(cfg.CPUSchedObj)
	if err != nil {
		return nil, fmt.Errorf("load cpu_sched spec: %w", err)
	}

	c.cpuColl, err = ebpf.NewCollectionWithOptions(cpuSpec, collOpts)
	if err != nil {
		return nil, fmt.Errorf("create cpu_sched collection: %w", err)
	}

	// Attach sched_switch
	if prog, ok := c.cpuColl.Programs["handle_sched_switch"]; ok {
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			// Try raw tracepoint fallback
			l, err = link.AttachRawTracepoint(link.RawTracepointOptions{
				Name:    "sched_switch",
				Program: prog,
			})
			if err != nil {
				return nil, fmt.Errorf("attach sched_switch: %w", err)
			}
		}
		c.links = append(c.links, l)
	}

	// Attach sched_process_exec
	if prog, ok := c.cpuColl.Programs["handle_sched_exec"]; ok {
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			slog.Warn("Failed to attach sched_process_exec", "error", err)
		} else {
			c.links = append(c.links, l)
		}
	}

	// CPU ring buffer reader
	if cpuEvents, ok := c.cpuColl.Maps["cpu_events"]; ok {
		c.cpuReader, err = ringbuf.NewReader(cpuEvents)
		if err != nil {
			return nil, fmt.Errorf("create cpu ring buffer reader: %w", err)
		}
	}

	// ─── Load memory pressure probe ─────────────────────────────────
	memSpec, err := ebpf.LoadCollectionSpec(cfg.MemPressureObj)
	if err != nil {
		return nil, fmt.Errorf("load mem_pressure spec: %w", err)
	}

	c.memColl, err = ebpf.NewCollectionWithOptions(memSpec, collOpts)
	if err != nil {
		return nil, fmt.Errorf("create mem_pressure collection: %w", err)
	}

	// Attach page fault and reclaim tracepoints
	memProgs := map[string]string{
		"handle_page_fault_user":   "page_fault_user",
		"handle_page_fault_kernel": "page_fault_kernel",
		"handle_direct_reclaim":    "mm_vmscan_direct_reclaim_begin",
	}
	for progName, tpName := range memProgs {
		if prog, ok := c.memColl.Programs[progName]; ok {
			l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
				Name:    tpName,
				Program: prog,
			})
			if err != nil {
				slog.Warn("Failed to attach memory tracepoint",
					"program", progName, "tracepoint", tpName, "error", err)
				continue
			}
			c.links = append(c.links, l)
		}
	}

	if memEvents, ok := c.memColl.Maps["mem_events"]; ok {
		c.memReader, err = ringbuf.NewReader(memEvents)
		if err != nil {
			return nil, fmt.Errorf("create mem ring buffer reader: %w", err)
		}
	}

	// ─── Load GPU activity probe (graceful degradation) ─────────────
	gpuSpec, err := ebpf.LoadCollectionSpec(cfg.GPUActivityObj)
	if err != nil {
		slog.Warn("GPU probe not available, GPU metrics disabled", "error", err)
	} else {
		c.gpuColl, err = ebpf.NewCollectionWithOptions(gpuSpec, collOpts)
		if err != nil {
			slog.Warn("Failed to load GPU collection, GPU metrics disabled", "error", err)
		} else {
			gpuProgs := []string{"handle_gpu_job_submit", "handle_gpu_sched_job"}
			for _, progName := range gpuProgs {
				if prog, ok := c.gpuColl.Programs[progName]; ok {
					l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
						Name:    progName,
						Program: prog,
					})
					if err != nil {
						slog.Debug("GPU tracepoint not available", "program", progName, "error", err)
						continue
					}
					c.links = append(c.links, l)
				}
			}

			if gpuEvents, ok := c.gpuColl.Maps["gpu_events"]; ok {
				c.gpuReader, err = ringbuf.NewReader(gpuEvents)
				if err != nil {
					slog.Warn("Failed to create GPU ring buffer reader", "error", err)
				}
			}
		}
	}

	slog.Info("BPF collector initialized",
		"links_attached", len(c.links),
		"pin_path", cfg.PinPath,
		"btf_available", c.hostBTF != nil,
		"channel_size", cfg.ChannelSize,
	)

	return c, nil
}

// ConsumeRingBuffers starts Routine A: reads BPF ring buffers as fast as
// possible and pushes raw FeatureVectors into the backpressure channel.
// This MUST run in its own goroutine. It returns when ctx is cancelled.
func (c *Collector) ConsumeRingBuffers(ctx context.Context) {
	var wg sync.WaitGroup

	// Helper to drain a single ring buffer into the channel
	drainRing := func(name string, reader *ringbuf.Reader) {
		defer wg.Done()
		if reader == nil {
			return
		}
		slog.Debug("Ring buffer consumer started", "probe", name)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			record, err := reader.Read()
			if err != nil {
				if ctx.Err() != nil {
					return // Context cancelled
				}
				slog.Debug("Ring buffer read error", "probe", name, "error", err)
				continue
			}

			// Parse the raw record into a partial FeatureVector.
			// The record bytes correspond to the packed C struct.
			fv := parseRingRecord(name, record.RawSample)

			select {
			case c.vectorCh <- fv:
				// Delivered
			default:
				// Channel full — backpressure: drop oldest semantics
				c.DroppedEvents.Add(1)
			}
		}
	}

	wg.Add(3)
	go drainRing("cpu", c.cpuReader)
	go drainRing("mem", c.memReader)
	go drainRing("gpu", c.gpuReader)

	wg.Wait()
}

// BatchedCollect implements Routine B: reads from the backpressure channel,
// batches events, and returns enriched FeatureVectors.
// Blocks until either BatchSize events are collected or FlushInterval elapses.
func (c *Collector) BatchedCollect(ctx context.Context) ([]FeatureVector, error) {
	vectors := make(map[uint32]*FeatureVector)
	timer := time.NewTimer(c.cfg.FlushInterval)
	defer timer.Stop()
	count := 0

	for {
		select {
		case <-ctx.Done():
			return c.finalizeVectors(vectors), ctx.Err()

		case fv := <-c.vectorCh:
			mergeVector(vectors, &fv)
			count++
			if count >= c.cfg.BatchSize {
				return c.finalizeVectors(vectors), nil
			}

		case <-timer.C:
			// Flush partial batch on timeout
			if len(vectors) > 0 {
				return c.finalizeVectors(vectors), nil
			}
			// No events yet — reset timer and keep waiting
			timer.Reset(c.cfg.FlushInterval)
		}
	}
}

// Collect reads the BPF hash maps directly (legacy path, also used for
// aggregated stats that don't go through the ring buffer).
func (c *Collector) Collect(ctx context.Context) ([]FeatureVector, error) {
	vectors := make(map[uint32]*FeatureVector)
	now := uint64(time.Now().UnixNano())

	// ─── Read CPU stats map ─────────────────────────────────────────
	if cpuMap, ok := c.cpuColl.Maps["cpu_stats_map"]; ok {
		var key uint32
		var value cpuStatsValue

		iter := cpuMap.Iterate()
		for iter.Next(&key, &value) {
			fv := getOrCreate(vectors, key)
			fv.CPUTimeNs = value.TotalCPUTimeNs
			fv.CtxSwitches = value.CtxSwitches
			fv.VoluntaryCtxSwitches = value.VoluntaryCtxSwitches
			fv.InvoluntaryCtxSwitches = value.InvoluntaryCtxSwitches
			fv.CPUID = value.LastCPUID
			fv.Comm = nullTermString(value.Comm[:])
			fv.TimestampNs = now
		}
		if err := iter.Err(); err != nil {
			slog.Warn("Error iterating cpu_stats_map", "error", err)
		}
	}

	// ─── Read memory stats map ──────────────────────────────────────
	if memMap, ok := c.memColl.Maps["mem_stats_map"]; ok {
		var key uint32
		var value memStatsValue

		iter := memMap.Iterate()
		for iter.Next(&key, &value) {
			fv := getOrCreate(vectors, key)
			fv.MajorFaults = value.MajorFaults
			fv.MinorFaults = value.MinorFaults
			fv.DirectReclaimCnt = value.DirectReclaimCount
			// RSS approximation: page count × 4KB
			fv.RSSBytes = value.EstimatedRSSPages * 4096
			if fv.Comm == "" {
				fv.Comm = nullTermString(value.Comm[:])
			}
		}
		if err := iter.Err(); err != nil {
			slog.Warn("Error iterating mem_stats_map", "error", err)
		}
	}

	// ─── Read GPU stats map (if available) ──────────────────────────
	if c.gpuColl != nil {
		if gpuMap, ok := c.gpuColl.Maps["gpu_stats_map"]; ok {
			var key uint32
			var value gpuStatsValue

			iter := gpuMap.Iterate()
			for iter.Next(&key, &value) {
				fv := getOrCreate(vectors, key)
				fv.GPUJobsSubmitted = value.TotalJobsSubmitted
				fv.GPUActiveNs = value.TotalGPUActiveNs
			}
			if err := iter.Err(); err != nil {
				slog.Warn("Error iterating gpu_stats_map", "error", err)
			}
		}
	}

	return c.finalizeVectors(vectors), nil
}

// finalizeVectors enriches vectors with container info and flattens to slice.
func (c *Collector) finalizeVectors(vectors map[uint32]*FeatureVector) []FeatureVector {
	for pid, fv := range vectors {
		info := c.cgProf.Resolve(pid)
		fv.ContainerID = info.ID
		fv.ContainerName = info.Name
	}
	result := make([]FeatureVector, 0, len(vectors))
	for _, fv := range vectors {
		result = append(result, *fv)
	}
	return result
}

// Close detaches all probes and releases resources.
func (c *Collector) Close() {
	// Close the backpressure channel
	close(c.vectorCh)

	for _, l := range c.links {
		l.Close()
	}
	if c.cpuReader != nil {
		c.cpuReader.Close()
	}
	if c.memReader != nil {
		c.memReader.Close()
	}
	if c.gpuReader != nil {
		c.gpuReader.Close()
	}
	if c.cpuColl != nil {
		c.cpuColl.Close()
	}
	if c.memColl != nil {
		c.memColl.Close()
	}
	if c.gpuColl != nil {
		c.gpuColl.Close()
	}
	slog.Info("BPF collector closed")
}

// ─── Map value types (must match C struct layout with packed attribute) ──

type cpuStatsValue struct {
	TotalCPUTimeNs         uint64
	CtxSwitches            uint64
	VoluntaryCtxSwitches   uint64
	InvoluntaryCtxSwitches uint64
	LastCPUID              uint32
	LastSeenNs             uint64
	Comm                   [16]byte
}

type memStatsValue struct {
	MajorFaults       uint64
	MinorFaults       uint64
	TotalFaults       uint64
	DirectReclaimCount uint64
	LastFaultNs       uint64
	EstimatedRSSPages uint64
	Comm              [16]byte
}

type gpuStatsValue struct {
	TotalJobsSubmitted uint64
	TotalGPUActiveNs   uint64
	LastSubmitNs       uint64
	LastCompleteNs     uint64
	ActiveJobs         uint32
	Comm               [16]byte
}

// ─── Helpers ─────────────────────────────────────────────────────────────

func getOrCreate(m map[uint32]*FeatureVector, pid uint32) *FeatureVector {
	if fv, ok := m[pid]; ok {
		return fv
	}
	fv := &FeatureVector{PID: pid}
	m[pid] = fv
	return fv
}

func mergeVector(m map[uint32]*FeatureVector, incoming *FeatureVector) {
	existing := getOrCreate(m, incoming.PID)
	// Accumulate metrics from ring buffer events
	existing.CPUTimeNs += incoming.CPUTimeNs
	existing.CtxSwitches += incoming.CtxSwitches
	existing.MajorFaults += incoming.MajorFaults
	existing.MinorFaults += incoming.MinorFaults
	existing.GPUJobsSubmitted += incoming.GPUJobsSubmitted
	existing.GPUActiveNs += incoming.GPUActiveNs
	if incoming.Comm != "" {
		existing.Comm = incoming.Comm
	}
	if incoming.TimestampNs > existing.TimestampNs {
		existing.TimestampNs = incoming.TimestampNs
	}
}

func nullTermString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// parseRingRecord converts raw ring buffer bytes into a partial FeatureVector.
// The byte layout depends on which probe produced the event (CPU/MEM/GPU).
func parseRingRecord(probe string, data []byte) FeatureVector {
	// Minimal parsing — extract PID and comm from the common header
	// (all event structs share: u64 timestamp_ns, u32 pid, u32 tgid, ...)
	fv := FeatureVector{}
	if len(data) < 16 {
		return fv
	}

	fv.TimestampNs = nativeEndian.Uint64(data[0:8])
	fv.PID = nativeEndian.Uint32(data[8:12])
	fv.TGID = nativeEndian.Uint32(data[12:16])

	switch probe {
	case "cpu":
		if len(data) >= 56 {
			// cpu_event: after cpu_id(4) + event_type(4) + comm(16) → delta_ns at offset 32
			fv.Comm = nullTermString(data[24:40])
			fv.CPUTimeNs = nativeEndian.Uint64(data[40:48])
			fv.CtxSwitches = 1 // Each event is one context switch
		}
	case "mem":
		if len(data) >= 40 {
			fv.Comm = nullTermString(data[24:40])
			// Count each event as a fault
			fv.MinorFaults = 1
		}
	case "gpu":
		if len(data) >= 40 {
			fv.Comm = nullTermString(data[24:40])
			fv.GPUJobsSubmitted = 1
		}
	}

	return fv
}
