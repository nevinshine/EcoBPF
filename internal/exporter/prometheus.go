// Package exporter provides a Prometheus metrics exporter for EcoBPF
// energy and carbon telemetry.
package exporter

import (
	"net/http"
	"strconv"

	"github.com/nevin/ecobpf/internal/estimator"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus implements the Prometheus metrics exporter for EcoBPF.
type Prometheus struct {
	carbonIntensity float64
	registry        *prometheus.Registry

	// Gauges (current values, reset each cycle)
	energyJoules   *prometheus.GaugeVec
	powerWatts     *prometheus.GaugeVec
	carbonGrams    *prometheus.GaugeVec
	cpuEnergy      *prometheus.GaugeVec
	memEnergy      *prometheus.GaugeVec
	gpuEnergy      *prometheus.GaugeVec

	// Counters (monotonically increasing)
	energyTotal    *prometheus.CounterVec
	carbonTotal    *prometheus.CounterVec

	// Histogram for estimation confidence
	confidence     prometheus.Histogram

	// Info metrics
	aiWorkloads    *prometheus.GaugeVec
	processCount   prometheus.Gauge
}

// NewPrometheus creates a new Prometheus exporter with EcoBPF metrics registered.
func NewPrometheus(carbonIntensity float64) *Prometheus {
	reg := prometheus.NewRegistry()

	// Register default Go and process collectors
	reg.MustRegister(prometheus.NewGoCollector())
	reg.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	labels := []string{"pid", "comm", "container_id", "container_name"}

	p := &Prometheus{
		carbonIntensity: carbonIntensity,
		registry:        reg,

		energyJoules: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "ecobpf",
			Name:      "energy_joules",
			Help:      "Estimated energy consumption in joules (current interval).",
		}, labels),

		powerWatts: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "ecobpf",
			Name:      "power_watts",
			Help:      "Estimated instantaneous power consumption in watts.",
		}, labels),

		carbonGrams: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "ecobpf",
			Name:      "carbon_grams_co2",
			Help:      "Estimated carbon emissions in grams of CO2.",
		}, labels),

		cpuEnergy: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "ecobpf",
			Subsystem: "cpu",
			Name:      "energy_joules",
			Help:      "CPU component energy consumption in joules.",
		}, labels),

		memEnergy: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "ecobpf",
			Subsystem: "memory",
			Name:      "energy_joules",
			Help:      "Memory component energy consumption in joules.",
		}, labels),

		gpuEnergy: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "ecobpf",
			Subsystem: "gpu",
			Name:      "energy_joules",
			Help:      "GPU component energy consumption in joules.",
		}, labels),

		energyTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "ecobpf",
			Name:      "energy_joules_total",
			Help:      "Cumulative estimated energy consumption in joules.",
		}, labels),

		carbonTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "ecobpf",
			Name:      "carbon_grams_co2_total",
			Help:      "Cumulative estimated carbon emissions in grams of CO2.",
		}, labels),

		confidence: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "ecobpf",
			Name:      "estimation_confidence",
			Help:      "Distribution of ML model confidence scores.",
			Buckets:   []float64{0.1, 0.2, 0.3, 0.5, 0.7, 0.8, 0.9, 0.95, 0.99},
		}),

		aiWorkloads: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "ecobpf",
			Name:      "ai_workload_detected",
			Help:      "Whether a process is identified as an AI/ML workload (1=yes, 0=no).",
		}, labels),

		processCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "ecobpf",
			Name:      "tracked_processes",
			Help:      "Number of processes currently being tracked.",
		}),
	}

	// Register all metrics
	reg.MustRegister(
		p.energyJoules, p.powerWatts, p.carbonGrams,
		p.cpuEnergy, p.memEnergy, p.gpuEnergy,
		p.energyTotal, p.carbonTotal,
		p.confidence, p.aiWorkloads, p.processCount,
	)

	return p
}

// Handler returns the HTTP handler for the /metrics endpoint.
func (p *Prometheus) Handler() http.Handler {
	return promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// Update refreshes all Prometheus metrics with the latest estimates.
func (p *Prometheus) Update(estimates []estimator.EnergyEstimate) {
	// Reset gauges to reflect only current interval
	p.energyJoules.Reset()
	p.powerWatts.Reset()
	p.carbonGrams.Reset()
	p.cpuEnergy.Reset()
	p.memEnergy.Reset()
	p.gpuEnergy.Reset()
	p.aiWorkloads.Reset()

	p.processCount.Set(float64(len(estimates)))

	for _, est := range estimates {
		pid := strconv.FormatUint(uint64(est.PID), 10)
		cid := est.ContainerID
		if cid == "" {
			cid = "host"
		}
		cname := est.ContainerName
		if cname == "" {
			cname = cid
		}
		labels := prometheus.Labels{
			"pid":            pid,
			"comm":           est.Comm,
			"container_id":   cid,
			"container_name": cname,
		}

		// Current interval gauges
		p.energyJoules.With(labels).Set(est.EnergyJoules)
		p.powerWatts.With(labels).Set(est.PowerWatts)
		p.carbonGrams.With(labels).Set(est.CarbonGramsCO2)
		p.cpuEnergy.With(labels).Set(est.CPUEnergy)
		p.memEnergy.With(labels).Set(est.MemoryEnergy)
		p.gpuEnergy.With(labels).Set(est.GPUEnergy)

		// Cumulative counters
		p.energyTotal.With(labels).Add(est.EnergyJoules)
		p.carbonTotal.With(labels).Add(est.CarbonGramsCO2)

		// Confidence histogram
		p.confidence.Observe(est.Confidence)

		// AI workload flag
		if est.IsAIInference {
			p.aiWorkloads.With(labels).Set(1)
		} else {
			p.aiWorkloads.With(labels).Set(0)
		}
	}
}
