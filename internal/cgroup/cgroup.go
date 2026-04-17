// Package cgroup provides container-aware process-to-cgroup mapping
// with optional container runtime enrichment via Docker/containerd socket.
//
// Two-tier resolution:
//  1. Fast path: /proc/<pid>/cgroup → raw container ID (always available)
//  2. Enrichment: Docker/containerd API → container name, image, labels
//
// The RuntimeWatcher connects to the container runtime socket (if available)
// and maintains a live map of container ID → ContainerInfo. If no socket
// is available, enrichment gracefully degrades to cgroup-only mode.
package cgroup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ContainerInfo holds enriched container metadata resolved from the
// container runtime socket.
type ContainerInfo struct {
	ID           string            // Short container ID (12 chars)
	Name         string            // Human-readable container name
	ImageName    string            // Container image name
	Labels       map[string]string // Container labels (includes K8s pod info)
	PodName      string            // Kubernetes pod name (from labels)
	PodNamespace string            // Kubernetes pod namespace (from labels)
}

// Common container ID patterns in cgroup paths.
var containerIDPatterns = []*regexp.Regexp{
	// Docker: /docker/<container_id>
	regexp.MustCompile(`/docker/([a-f0-9]{12,64})`),
	// containerd: /cri-containerd-<container_id>.scope
	regexp.MustCompile(`/cri-containerd-([a-f0-9]{12,64})\.scope`),
	// Podman: /libpod-<container_id>.scope
	regexp.MustCompile(`/libpod-([a-f0-9]{12,64})\.scope`),
	// systemd slice: /system.slice/<service>-<container_id>.scope
	regexp.MustCompile(`-([a-f0-9]{12,64})\.scope`),
	// Generic: any 64-char hex string in path
	regexp.MustCompile(`([a-f0-9]{64})`),
}

// Well-known Kubernetes label keys for pod identification.
const (
	k8sPodNameLabel      = "io.kubernetes.pod.name"
	k8sPodNamespaceLabel = "io.kubernetes.pod.namespace"
)

// Profiler resolves PIDs to container information by reading cgroup
// filesystems and optionally enriching via the container runtime.
type Profiler struct {
	mu    sync.RWMutex
	cache map[uint32]ContainerInfo

	// Runtime watcher (nil if no socket available)
	watcher *RuntimeWatcher
}

// NewProfiler creates a new cgroup profiler with optional runtime enrichment.
// It attempts to connect to Docker or containerd sockets in order of preference.
func NewProfiler() *Profiler {
	p := &Profiler{
		cache: make(map[uint32]ContainerInfo),
	}

	// Try Docker socket first, then containerd
	socketPaths := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
	}

	for _, sockPath := range socketPaths {
		if _, err := os.Stat(sockPath); err == nil {
			watcher, err := newRuntimeWatcher(sockPath)
			if err != nil {
				slog.Warn("Container runtime socket found but connection failed",
					"path", sockPath, "error", err)
				continue
			}
			p.watcher = watcher
			slog.Info("Container runtime enrichment enabled",
				"socket", sockPath)
			break
		}
	}

	if p.watcher == nil {
		slog.Info("No container runtime socket found — using cgroup-only mode")
	}

	return p
}

// Resolve returns the enriched ContainerInfo for a given PID.
// Returns a zero-value ContainerInfo for host (non-containerized) processes.
func (p *Profiler) Resolve(pid uint32) ContainerInfo {
	p.mu.RLock()
	if info, ok := p.cache[pid]; ok {
		p.mu.RUnlock()
		return info
	}
	p.mu.RUnlock()

	// Resolve raw container ID from cgroup
	rawID := p.resolveFromCgroup(pid)
	info := ContainerInfo{ID: rawID}

	// Enrich from runtime watcher if available
	if rawID != "" && p.watcher != nil {
		enriched := p.watcher.Lookup(rawID)
		if enriched.Name != "" {
			info = enriched
			info.ID = rawID // Keep our truncated ID
		}
	}

	p.mu.Lock()
	p.cache[pid] = info
	p.mu.Unlock()

	return info
}

// ResolveContainerID returns the container ID for a given PID (legacy compat).
func (p *Profiler) ResolveContainerID(pid uint32) string {
	return p.Resolve(pid).ID
}

// resolveFromCgroup reads /proc/<pid>/cgroup to extract container identity.
func (p *Profiler) resolveFromCgroup(pid uint32) string {
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		slog.Debug("Cannot read cgroup", "pid", pid, "error", err)
		return ""
	}

	content := string(data)

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}

		cgroupPath := parts[2]
		if cgroupPath == "/" || cgroupPath == "" {
			continue
		}

		for _, pat := range containerIDPatterns {
			matches := pat.FindStringSubmatch(cgroupPath)
			if len(matches) >= 2 {
				containerID := matches[1]
				if len(containerID) > 12 {
					containerID = containerID[:12]
				}
				return containerID
			}
		}
	}

	return ""
}

// ClearCache invalidates the PID cache. Call periodically to handle
// PID recycling.
func (p *Profiler) ClearCache() {
	p.mu.Lock()
	p.cache = make(map[uint32]ContainerInfo)
	p.mu.Unlock()
}

// StartWatcher begins the background container events listener.
// Returns immediately if no runtime socket is available.
func (p *Profiler) StartWatcher(ctx context.Context) {
	if p.watcher == nil {
		return
	}
	go p.watcher.Watch(ctx)
}

// Close stops the runtime watcher.
func (p *Profiler) Close() {
	if p.watcher != nil {
		p.watcher.Close()
	}
}

// IsCgroupV2 checks if the system uses unified cgroup v2 hierarchy.
func IsCgroupV2() bool {
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}

// GetCgroupMemoryLimit returns the memory limit for a cgroup path in bytes.
func GetCgroupMemoryLimit(cgroupPath string) (uint64, error) {
	var limitPath string
	if IsCgroupV2() {
		limitPath = fmt.Sprintf("/sys/fs/cgroup%s/memory.max", cgroupPath)
	} else {
		limitPath = fmt.Sprintf("/sys/fs/cgroup/memory%s/memory.limit_in_bytes", cgroupPath)
	}

	data, err := os.ReadFile(limitPath)
	if err != nil {
		return 0, err
	}

	content := strings.TrimSpace(string(data))
	if content == "max" || content == "9223372036854771712" {
		return 0, nil
	}

	var limit uint64
	if _, err := fmt.Sscanf(content, "%d", &limit); err != nil {
		return 0, fmt.Errorf("parsing cgroup memory limit %q: %w", content, err)
	}
	return limit, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// RuntimeWatcher — Docker/containerd socket enrichment
// ═══════════════════════════════════════════════════════════════════════════

// RuntimeWatcher connects to a container runtime HTTP API via Unix socket
// and maintains a live map of container ID → ContainerInfo.
type RuntimeWatcher struct {
	mu         sync.RWMutex
	containers map[string]ContainerInfo // keyed by full container ID
	client     *http.Client
	socketPath string
}

// dockerContainer is the minimal JSON shape for Docker API /containers/json.
type dockerContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	Labels map[string]string `json:"Labels"`
}

func newRuntimeWatcher(socketPath string) (*RuntimeWatcher, error) {
	transport := &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	// Test connectivity
	resp, err := client.Get("http://docker/v1.41/version")
	if err != nil {
		return nil, fmt.Errorf("docker API handshake: %w", err)
	}
	resp.Body.Close()

	rw := &RuntimeWatcher{
		containers: make(map[string]ContainerInfo),
		client:     client,
		socketPath: socketPath,
	}

	// Initial container list
	if err := rw.refresh(); err != nil {
		slog.Warn("Initial container list failed", "error", err)
	}

	return rw, nil
}

// Lookup returns the ContainerInfo for a short container ID.
func (rw *RuntimeWatcher) Lookup(shortID string) ContainerInfo {
	rw.mu.RLock()
	defer rw.mu.RUnlock()

	// Try exact match first (full ID stored)
	for fullID, info := range rw.containers {
		if strings.HasPrefix(fullID, shortID) {
			return info
		}
	}
	return ContainerInfo{}
}

// Watch listens for Docker container events and refreshes the container map.
func (rw *RuntimeWatcher) Watch(ctx context.Context) {
	slog.Info("Container runtime event watcher started", "socket", rw.socketPath)

	// Poll-based approach for compatibility (events API can be finicky)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Container runtime watcher stopped")
			return
		case <-ticker.C:
			if err := rw.refresh(); err != nil {
				slog.Debug("Container list refresh failed", "error", err)
			}
		}
	}
}

// refresh queries the Docker API for the current container list.
func (rw *RuntimeWatcher) refresh() error {
	resp, err := rw.client.Get("http://docker/v1.41/containers/json?all=true")
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return fmt.Errorf("read container list: %w", err)
	}

	var containers []dockerContainer
	if err := json.Unmarshal(body, &containers); err != nil {
		return fmt.Errorf("parse container list: %w", err)
	}

	rw.mu.Lock()
	defer rw.mu.Unlock()

	// Rebuild the map
	rw.containers = make(map[string]ContainerInfo, len(containers))
	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		info := ContainerInfo{
			ID:        c.ID[:12],
			Name:      name,
			ImageName: c.Image,
			Labels:    c.Labels,
		}

		// Extract Kubernetes metadata from labels
		if podName, ok := c.Labels[k8sPodNameLabel]; ok {
			info.PodName = podName
		}
		if podNS, ok := c.Labels[k8sPodNamespaceLabel]; ok {
			info.PodNamespace = podNS
		}

		rw.containers[c.ID] = info
	}

	slog.Debug("Container map refreshed", "count", len(rw.containers))
	return nil
}

// Close cleans up the runtime watcher resources.
func (rw *RuntimeWatcher) Close() {
	rw.client.CloseIdleConnections()
}
