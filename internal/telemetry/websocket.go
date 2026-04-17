// Package telemetry provides a real-time WebSocket feed for streaming
// EcoBPF energy and carbon telemetry to dashboard clients.
package telemetry

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/nevin/ecobpf/internal/estimator"
)

// TelemetryEvent is the JSON payload sent to WebSocket clients.
type TelemetryEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	Type        string                 `json:"type"`
	ProcessData []ProcessTelemetry     `json:"process_data"`
	Summary     SystemSummary          `json:"summary"`
}

// ProcessTelemetry contains per-process energy data.
type ProcessTelemetry struct {
	PID            uint32  `json:"pid"`
	Comm           string  `json:"comm"`
	ContainerID    string  `json:"container_id,omitempty"`
	ContainerName  string  `json:"container_name,omitempty"`
	EnergyJoules   float64 `json:"energy_joules"`
	PowerWatts     float64 `json:"power_watts"`
	CarbonGramsCO2 float64 `json:"carbon_grams_co2"`
	CPUEnergy      float64 `json:"cpu_energy_joules"`
	MemoryEnergy   float64 `json:"memory_energy_joules"`
	GPUEnergy      float64 `json:"gpu_energy_joules"`
	Confidence     float64 `json:"confidence"`
	IsAIWorkload   bool    `json:"is_ai_workload"`
}

// SystemSummary aggregates system-wide telemetry.
type SystemSummary struct {
	TotalEnergyJoules   float64 `json:"total_energy_joules"`
	TotalPowerWatts     float64 `json:"total_power_watts"`
	TotalCarbonGrams    float64 `json:"total_carbon_grams_co2"`
	TrackedProcesses    int     `json:"tracked_processes"`
	AIWorkloadCount     int     `json:"ai_workload_count"`
	ContainerCount      int     `json:"container_count"`
	AvgConfidence       float64 `json:"avg_confidence"`
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins in development
	},
}

// WebSocketFeed manages WebSocket connections and broadcasts telemetry events.
type WebSocketFeed struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]bool
}

// NewWebSocketFeed creates a new WebSocket feed manager.
func NewWebSocketFeed() *WebSocketFeed {
	return &WebSocketFeed{
		clients: make(map[*websocket.Conn]bool),
	}
}

// HandleConnection upgrades an HTTP connection to WebSocket and registers
// the client for telemetry broadcasts.
func (f *WebSocketFeed) HandleConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("WebSocket upgrade failed", "error", err)
		return
	}

	f.mu.Lock()
	f.clients[conn] = true
	clientCount := len(f.clients)
	f.mu.Unlock()

	slog.Info("WebSocket client connected",
		"remote", conn.RemoteAddr(),
		"total_clients", clientCount,
	)

	// Send welcome message
	welcome := map[string]interface{}{
		"type":    "connected",
		"message": "EcoBPF telemetry feed active",
		"version": "1.0.0",
	}
	if err := conn.WriteJSON(welcome); err != nil {
		slog.Warn("Failed to send WebSocket welcome message", "error", err)
	}

	// Read loop (handles client disconnect detection)
	defer func() {
		f.mu.Lock()
		delete(f.clients, conn)
		f.mu.Unlock()
		conn.Close()
		slog.Info("WebSocket client disconnected", "remote", conn.RemoteAddr())
	}()

	for {
		// We don't expect client messages, but read to detect close
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// Broadcast sends energy estimates to all connected WebSocket clients.
func (f *WebSocketFeed) Broadcast(estimates []estimator.EnergyEstimate) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if len(f.clients) == 0 {
		return
	}

	// Build telemetry event
	event := buildTelemetryEvent(estimates)

	data, err := json.Marshal(event)
	if err != nil {
		slog.Error("Failed to marshal telemetry event", "error", err)
		return
	}

	// Broadcast to all clients
	var disconnected []*websocket.Conn
	for conn := range f.clients {
		err := conn.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			slog.Debug("Write to WebSocket client failed",
				"remote", conn.RemoteAddr(), "error", err)
			disconnected = append(disconnected, conn)
		}
	}

	// Clean up disconnected clients (upgrade to write lock)
	if len(disconnected) > 0 {
		f.mu.RUnlock()
		f.mu.Lock()
		for _, conn := range disconnected {
			delete(f.clients, conn)
			conn.Close()
		}
		f.mu.Unlock()
		f.mu.RLock()
	}
}

// ClientCount returns the number of connected WebSocket clients.
func (f *WebSocketFeed) ClientCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.clients)
}

func buildTelemetryEvent(estimates []estimator.EnergyEstimate) TelemetryEvent {
	processes := make([]ProcessTelemetry, 0, len(estimates))
	summary := SystemSummary{}
	containers := make(map[string]bool)

	var totalConfidence float64

	for _, est := range estimates {
		pt := ProcessTelemetry{
			PID:            est.PID,
			Comm:           est.Comm,
			ContainerID:    est.ContainerID,
			ContainerName:  est.ContainerName,
			EnergyJoules:   est.EnergyJoules,
			PowerWatts:     est.PowerWatts,
			CarbonGramsCO2: est.CarbonGramsCO2,
			CPUEnergy:      est.CPUEnergy,
			MemoryEnergy:   est.MemoryEnergy,
			GPUEnergy:      est.GPUEnergy,
			Confidence:     est.Confidence,
			IsAIWorkload:   est.IsAIInference,
		}
		processes = append(processes, pt)

		summary.TotalEnergyJoules += est.EnergyJoules
		summary.TotalPowerWatts += est.PowerWatts
		summary.TotalCarbonGrams += est.CarbonGramsCO2
		totalConfidence += est.Confidence

		if est.IsAIInference {
			summary.AIWorkloadCount++
		}
		if est.ContainerID != "" {
			containers[est.ContainerID] = true
		}
	}

	summary.TrackedProcesses = len(estimates)
	summary.ContainerCount = len(containers)
	if len(estimates) > 0 {
		summary.AvgConfidence = totalConfidence / float64(len(estimates))
	}

	return TelemetryEvent{
		Timestamp:   time.Now(),
		Type:        "telemetry",
		ProcessData: processes,
		Summary:     summary,
	}
}
