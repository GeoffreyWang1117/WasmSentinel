package engine

import (
	"context"

	"github.com/wasm-threat-detector/host/internal/events"
)

// ThreatEngine 威胁检测引擎接口
type ThreatEngine interface {
	LoadRule(name, wasmPath string) error
	LoadRulesFromDir(rulesDir string) error
	UnloadRule(name string) error
	DetectThreat(ctx context.Context, event *events.Event) ([]*events.DetectionResult, error)
	GetLoadedRules() []string
	Close() error
}
