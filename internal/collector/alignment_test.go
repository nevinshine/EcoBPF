package collector

import (
	"testing"
	"unsafe"
)

// TestStructAlignment verifies that Go struct sizes exactly match the
// packed C struct sizes from the eBPF probes. A mismatch here means the
// Go side will deserialize ring buffer / map data incorrectly.
//
// These sizes correspond to the C structs with __attribute__((packed)).
func TestStructAlignment(t *testing.T) {
	tests := []struct {
		name     string
		goSize   uintptr
		expected uintptr
	}{
		{
			name:   "cpuStatsValue",
			goSize: unsafe.Sizeof(cpuStatsValue{}),
			// u64×4 + u32 + u64 + [16]byte = 32 + 4 + 8 + 16 = 60
			expected: 60,
		},
		{
			name:   "memStatsValue",
			goSize: unsafe.Sizeof(memStatsValue{}),
			// u64×6 + [16]byte = 48 + 16 = 64
			expected: 64,
		},
		{
			name:   "gpuStatsValue",
			goSize: unsafe.Sizeof(gpuStatsValue{}),
			// u64×4 + u32 + [16]byte = 32 + 4 + 16 = 52
			expected: 52,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.goSize != tt.expected {
				t.Errorf("Go sizeof(%s) = %d, want %d (C packed struct size)",
					tt.name, tt.goSize, tt.expected)
			}
		})
	}
}
