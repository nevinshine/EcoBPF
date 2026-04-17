package proto

// FeatureVector represents the kernel telemetry signals for a single process.
type FeatureVector struct {
	Pid                    uint32
	Tgid                   uint32
	Comm                   string
	ContainerId            string
	CpuTimeNs              uint64
	CtxSwitches            uint64
	VoluntaryCtxSwitches   uint64
	InvoluntaryCtxSwitches uint64
	CpuFreqMhz             uint32
	CpuId                  uint32
	MajorFaults            uint64
	MinorFaults            uint64
	RssBytes               uint64
	DirectReclaimCount     uint64
	GpuJobsSubmitted       uint64
	GpuActiveNs            uint64
	TimestampNs            uint64
}

// FeatureVectorBatch is a collection of feature vectors
type FeatureVectorBatch struct {
	Vectors               []*FeatureVector
	CollectionTimestampNs uint64
}

// EnergyEstimate is the ML model's output for a single process.
type EnergyEstimate struct {
	Pid                uint32
	Comm               string
	ContainerId        string
	EnergyJoules       float64
	PowerWatts         float64
	Confidence         float64
	CpuEnergyJoules    float64
	MemoryEnergyJoules float64
	GpuEnergyJoules    float64
	CarbonGramsCo2     float64
	IsAiInference      bool
	AttributionLabel   string
}

// EnergyEstimateBatch is the response containing estimates
type EnergyEstimateBatch struct {
	Estimates          []*EnergyEstimate
	InferenceLatencyNs uint64
	ModelVersion       string
}
