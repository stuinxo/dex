package daemon

import (
	"testing"

	"github.com/stuinxo/dex/internal/state"
)

func TestMetricsUsesConfiguredInventory(t *testing.T) {
	tracker := NewNodeMetricsTracker(3)
	tracker.Record(ProbeNodeResult{NodeID: "removed", Healthy: true, LatencyMS: 1})
	for _, nodes := range [][]state.OutboundNode{nil, {}} {
		if got := tracker.Summaries(nodes); len(got) != 0 {
			t.Fatal("empty configured inventory returned deleted node history")
		}
	}
	nodes := []state.OutboundNode{{ID: "second", Name: "Second"}, {ID: "first", Name: "First"}}
	got := tracker.Summaries(nodes)
	if len(got) != 2 || got[0].NodeID != "second" || got[1].NodeID != "first" || got[0].SampleCount != 0 {
		t.Fatalf("configured order and zero-sample nodes not preserved: %v", got)
	}
}

func TestMetricsRetentionAndSnapshotOwnership(t *testing.T) {
	tracker := NewNodeMetricsTracker(3)
	nodes := []state.OutboundNode{{ID: "n1"}}
	for _, result := range []ProbeNodeResult{
		{NodeID: "n1", Healthy: true, LatencyMS: 999},
		{NodeID: "n1", Healthy: true, LatencyMS: 20},
		{NodeID: "n1", Healthy: true, LatencyMS: 40},
		{NodeID: "n1", Healthy: false, Error: "unavailable"},
	} {
		tracker.Record(result)
	}
	got := tracker.Summaries(nodes)[0]
	if got.SampleCount != 3 || got.SuccessCount != 2 || got.AvgLatencyMS != 30 ||
		got.MinLatencyMS != 20 || got.MaxLatencyMS != 40 || got.LossPercent != 33.3 ||
		got.LastHealthy || got.LastError != "unavailable" {
		t.Fatalf("unexpected retained summary: %+v", got)
	}
	got.Recent[0].LatencyMS = 1234
	if next := tracker.Summaries(nodes)[0]; next.Recent[0].LatencyMS != 20 {
		t.Fatal("returned history aliases tracker-owned samples")
	}
}
