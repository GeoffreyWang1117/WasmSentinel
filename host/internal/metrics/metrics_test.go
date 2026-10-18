package metrics

import (
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wasm-threat-detector/host/internal/ebpf"
	"github.com/wasm-threat-detector/host/internal/engine"
	"github.com/wasm-threat-detector/host/internal/events"
)

type fakeEngine struct{ stats map[string]engine.RuleStats }

func (f fakeEngine) Stats() map[string]engine.RuleStats { return f.stats }

type fakeEBPF struct{ s *ebpf.Stats }

func (f fakeEBPF) Stats() *ebpf.Stats { return f.s }

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Result().Body)
	return string(body)
}

func TestCountersFollowThePipeline(t *testing.T) {
	m := New()
	m.SetBuildInfo("ebpf", "binary", "v17")
	m.RegisterEngine(fakeEngine{stats: map[string]engine.RuleStats{
		"shell": {MemoryBytes: 1179648, Reinstantiations: 2, Threats: 7},
	}})
	m.RegisterEBPF(fakeEBPF{s: &ebpf.Stats{Received: 100, Dropped: 3, ByType: map[string]uint64{"file_open": 90, "process_exec": 10}}})

	res := &events.DetectionResult{RuleName: "shell", Severity: "high"}
	_ = m.Handle(res)
	_ = m.Handle(res)
	_ = m.Handle(&events.DetectionResult{RuleName: "ml", Severity: "low"})
	m.ObserveInvoke("shell", false, 5*time.Microsecond, 63000, nil)
	m.ObserveInvoke("shell", true, 3*time.Microsecond, 61000, nil)
	m.ObserveInvoke("shell", true, 90*time.Millisecond, 50_000_000, &engine.RuleError{Rule: "shell", Kind: engine.TrapFuel, Err: errors.New("x")})
	m.ObserveInvoke("ml", false, time.Microsecond, 0, errors.New("plain error"))
	m.ObserveEvent(events.EventTypeProcess, 12*time.Microsecond)
	m.ObserveEvent(events.EventTypeFile, 8*time.Microsecond)
	m.ObserveDrop()

	body := scrape(t, m)
	for _, want := range []string{
		`wasmsentinel_threats_total{rule="shell",severity="high"} 2`,
		`wasmsentinel_threats_total{rule="ml",severity="low"} 1`,
		`wasmsentinel_rule_calls_total{encoding="json",rule="shell"} 1`,
		`wasmsentinel_rule_calls_total{encoding="binary",rule="shell"} 2`,
		`wasmsentinel_rule_errors_total{kind="fuel",rule="shell"} 1`,
		`wasmsentinel_rule_errors_total{kind="trap",rule="ml"} 1`,
		`wasmsentinel_rule_fuel_total{rule="shell"} 5.0124e+07`,
		`wasmsentinel_rule_latency_seconds_count{rule="shell"} 3`,
		`wasmsentinel_events_total{type="process"} 1`,
		`wasmsentinel_events_total{type="file"} 1`,
		`wasmsentinel_events_dropped_total 1`,
		`wasmsentinel_detect_latency_seconds_count 2`,
		`wasmsentinel_rule_memory_bytes{rule="shell"} 1.179648e+06`,
		`wasmsentinel_rule_reinstantiations_total{rule="shell"} 2`,
		`wasmsentinel_rule_positive_calls_total{rule="shell"} 7`,
		`wasmsentinel_collector_records_total 100`,
		`wasmsentinel_collector_dropped_total 3`,
		`wasmsentinel_collector_events_total{type="file_open"} 90`,
		`wasmsentinel_build_info{collector="ebpf",encoding="binary",wasmtime="v17"} 1`,
		`process_resident_memory_bytes`,
		`go_goroutines`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, "time.Now") {
		t.Error("fake timestamp counter survived")
	}
}
