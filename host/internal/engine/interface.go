package engine

import (
	"context"

	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/events"
)

// ThreatEngine 威胁检测引擎接口
type ThreatEngine interface {
	LoadRule(name, wasmPath string) error
	LoadRulesFromDir(rulesDir string) error
	UnloadRule(name string) error
	DetectThreat(ctx context.Context, event *events.Event) ([]*events.DetectionResult, error)
	GetLoadedRules() []string
	// Stats returns a snapshot of per-rule counters (calls, traps, fuel, latency, memory).
	Stats() map[string]RuleStats
	Close() error
}
