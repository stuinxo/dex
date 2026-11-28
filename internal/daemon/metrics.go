package daemon

import (
	"strings"
	"sync"
	"time"

	"github.com/stuinxo/dex/internal/state"
)

// NodeProbeSample captures one timestamped node health probe result.
type NodeProbeSample struct {
	Timestamp  string `json:"timestamp"`
	Healthy    bool   `json:"healthy"`
	LatencyMS  int64  `json:"latency_ms"`
	StatusCode int    `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
}

// NodeMetricsSummary summarizes recent probe samples for a single node.
type NodeMetricsSummary struct {
	NodeID        string            `json:"node_id"`
	Name          string            `json:"name,omitempty"`
	Protocol      string            `json:"protocol,omitempty"`
	SampleCount   int               `json:"sample_count"`
	SuccessCount  int               `json:"success_count"`
	LossPercent   float64           `json:"loss_percent"`
	LastHealthy   bool              `json:"last_healthy"`
	LastLatencyMS int64             `json:"last_latency_ms"`
	AvgLatencyMS  int64             `json:"avg_latency_ms"`
	MinLatencyMS  int64             `json:"min_latency_ms"`
	MaxLatencyMS  int64             `json:"max_latency_ms"`
	LastCheckedAt string            `json:"last_checked_at,omitempty"`
	LastError     string            `json:"last_error,omitempty"`
	Recent        []NodeProbeSample `json:"recent,omitempty"`
}

// NodeMetricsTracker maintains a bounded in-memory ring buffer of probe samples per node.
type NodeMetricsTracker struct {
	mu      sync.RWMutex
	maxPer  int
	samples map[string][]NodeProbeSample
}

// NewNodeMetricsTracker constructs a tracker keeping up to maxPer samples per node (default 60).
func NewNodeMetricsTracker(maxPer int) *NodeMetricsTracker {
	if maxPer <= 0 {
		maxPer = 60
	}
	return &NodeMetricsTracker{
		maxPer:  maxPer,
		samples: make(map[string][]NodeProbeSample),
	}
}

// Record appends a probe result for a node.
func (m *NodeMetricsTracker) Record(res ProbeNodeResult) {
	if m == nil || strings.TrimSpace(res.NodeID) == "" {
		return
	}
	sample := NodeProbeSample{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Healthy:    res.Healthy,
		LatencyMS:  res.LatencyMS,
		StatusCode: res.StatusCode,
		Error:      res.Error,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	list := append(m.samples[res.NodeID], sample)
	if len(list) > m.maxPer {
		list = append([]NodeProbeSample(nil), list[len(list)-m.maxPer:]...)
	}
	m.samples[res.NodeID] = list
}

// Summaries computes per-node latency and packet-loss summaries.
// Results follow the configured node order and include nodes with 0 samples.
// An empty inventory returns no summaries, even when historical samples remain.
func (m *NodeMetricsTracker) Summaries(nodes []state.OutboundNode) []NodeMetricsSummary {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	build := func(id, name, proto string, list []NodeProbeSample) NodeMetricsSummary {
		sum := NodeMetricsSummary{
			NodeID:      id,
			Name:        name,
			Protocol:    proto,
			SampleCount: len(list),
		}
		if len(list) == 0 {
			return sum
		}
		var totalLat int64
		var minLat, maxLat int64
		hasLat := false
		for _, s := range list {
			if s.Healthy {
				sum.SuccessCount++
				if !hasLat {
					minLat = s.LatencyMS
					maxLat = s.LatencyMS
					hasLat = true
				} else {
					if s.LatencyMS < minLat {
						minLat = s.LatencyMS
					}
					if s.LatencyMS > maxLat {
						maxLat = s.LatencyMS
					}
				}
				totalLat += s.LatencyMS
			}
		}
		last := list[len(list)-1]
		sum.LastHealthy = last.Healthy
		sum.LastLatencyMS = last.LatencyMS
		sum.LastCheckedAt = last.Timestamp
		sum.LastError = last.Error
		if sum.SuccessCount > 0 {
			sum.AvgLatencyMS = totalLat / int64(sum.SuccessCount)
			sum.MinLatencyMS = minLat
			sum.MaxLatencyMS = maxLat
		}
		failed := sum.SampleCount - sum.SuccessCount
		sum.LossPercent = float64(failed*1000/sum.SampleCount) / 10.0

		// Return up to the last 20 samples for compact sparkline/trend rendering.
		start := 0
		if len(list) > 20 {
			start = len(list) - 20
		}
		sum.Recent = append([]NodeProbeSample(nil), list[start:]...)
		return sum
	}

	out := make([]NodeMetricsSummary, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, build(n.ID, n.Name, n.Protocol, m.samples[n.ID]))
	}
	return out
}
