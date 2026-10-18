package pipeline

import (
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bytecodealliance/wasmtime-go/v17"
	"github.com/sirupsen/logrus"
	"github.com/wasm-threat-detector/host/internal/collector"
	"github.com/wasm-threat-detector/host/internal/engine"
	"github.com/wasm-threat-detector/host/internal/events"
	"github.com/wasm-threat-detector/host/internal/metrics"
)

func quiet() *logrus.Logger {
	lg := logrus.New()
	lg.SetOutput(io.Discard)
	return lg
}

// sliceCollector emits a fixed list of events, then closes.
type sliceCollector struct {
	evs []*events.Event
	out chan *events.Event
}

func newSliceCollector(evs []*events.Event) *sliceCollector {
	return &sliceCollector{evs: evs, out: make(chan *events.Event)}
}

func (s *sliceCollector) Start(ctx context.Context) error {
	go func() {
		defer close(s.out)
		for _, ev := range s.evs {
			select {
			case s.out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}
func (s *sliceCollector) Stop() error                        { return nil }
func (s *sliceCollector) EventChannel() <-chan *events.Event { return s.out }

// recordingOutput keeps every detection.
type recordingOutput struct {
	mu      sync.Mutex
	results []*events.DetectionResult
}

func (r *recordingOutput) Handle(res *events.DetectionResult) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.results = append(r.results, res)
	return nil
}
func (r *recordingOutput) Close() error { return nil }

func loadWAT(t *testing.T, e *engine.Engine, name, file string) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "engine", "testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	wasm, err := wasmtime.Wat2Wasm(string(src))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.LoadRuleBytes(name, wasm); err != nil {
		t.Fatal(err)
	}
}

func TestRunDeliversEveryEventAndStopsWhenCollectorsClose(t *testing.T) {
	e := engine.New(quiet(), engine.DefaultLimits())
	defer e.Close()
	loadWAT(t, e, "nine", "always9.wat") // flags everything
	loadWAT(t, e, "echo", "echo_level.wat")

	const n = 50
	evs := make([]*events.Event, n)
	for i := range evs {
		evs[i] = &events.Event{ID: "e", Type: events.EventTypeProcess, Timestamp: time.Now(), Source: "test",
			Data: map[string]interface{}{"process": map[string]interface{}{"command_line": "ls"}}}
	}
	c1 := newSliceCollector(evs[:30])
	c2 := newSliceCollector(evs[30:])
	ctx := context.Background()
	_ = c1.Start(ctx)
	_ = c2.Start(ctx)
	out := &recordingOutput{}
	m := metrics.New()
	e.SetObserver(m) // main.go wires this the same way

	done := make(chan Stats, 1)
	go func() {
		done <- Run(ctx, Config{Engine: e, Collectors: []collector.Collector{c1, c2}, Output: out, Metrics: m, Logger: quiet()})
	}()
	select {
	case st := <-done:
		if st.Events != n || st.Alerts != n || st.DetectErrors != 0 || st.OutputErrors != 0 {
			t.Fatalf("stats %+v", st)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pipeline did not stop after the collectors closed")
	}
	if len(out.results) != n || out.results[0].RuleName != "nine" {
		t.Errorf("%d results, first %+v", len(out.results), out.results[0])
	}
	es := e.Stats()
	if es["nine"].Calls != n || es["echo"].Calls != n {
		t.Errorf("engine calls nine=%d echo=%d", es["nine"].Calls, es["echo"].Calls)
	}
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Result().Body)
	for _, want := range []string{
		`wasmsentinel_events_total{type="process"} 50`,
		`wasmsentinel_rule_calls_total{encoding="json",rule="nine"} 50`,
		`wasmsentinel_detect_latency_seconds_count 50`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	e := engine.New(quiet(), engine.DefaultLimits())
	defer e.Close()
	loadWAT(t, e, "nine", "always9.wat")
	c, err := collector.NewReplayCollector(quiet(), collector.ReplayConfig{Path: filepath.Join("testdata", "adfa_normal_utd0472.txt"), Loop: true, EventsPerSecond: 5000})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = c.Start(ctx)
	st := Run(ctx, Config{Engine: e, Collectors: []collector.Collector{c}, Output: &recordingOutput{}, Logger: quiet()})
	_ = c.Stop()
	if st.Events == 0 || st.Elapsed < 250*time.Millisecond || st.Elapsed > 5*time.Second {
		t.Errorf("stats %+v", st)
	}
}

// End to end on the real modules: replay an ADFA-LD attack trace as syscall
// events with the binary payload attached, under EncodingBinary.
func TestReplayADFATraceEndToEnd(t *testing.T) {
	rules := filepath.Join("..", "..", "..", "rules", "wasm")
	for _, mod := range []string{"suspicious_shell.wasm", "ml_detector.wasm"} {
		if _, err := os.Stat(filepath.Join(rules, mod)); err != nil {
			t.Skipf("%s not built (run scripts/build.sh)", mod)
		}
	}
	e := engine.New(quiet(), engine.DefaultLimits())
	defer e.Close()
	if err := e.LoadRulesFromDir(rules); err != nil {
		t.Fatal(err)
	}
	e.SetEncoding(engine.EncodingBinary)

	trace := filepath.Join("testdata", "adfa_attack_hydra_ftp.txt")
	nums, err := collector.LoadTrace(trace)
	if err != nil {
		t.Fatal(err)
	}
	c, err := collector.NewReplayCollector(quiet(), collector.ReplayConfig{Path: trace, Binary: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_ = c.Start(ctx)
	out := &recordingOutput{}
	st := Run(ctx, Config{Engine: e, Collectors: []collector.Collector{c}, Output: out, Logger: quiet()})
	_ = c.Stop()

	if st.Events != uint64(len(nums)) || st.DetectErrors != 0 {
		t.Fatalf("stats %+v for %d syscalls", st, len(nums))
	}
	es := e.Stats()
	for _, rule := range []string{"suspicious_shell", "ml_detector"} {
		if es[rule].Calls != uint64(len(nums)) || es[rule].CallsRaw != uint64(len(nums)) || es[rule].Errors != 0 {
			t.Errorf("%s stats %+v", rule, es[rule])
		}
	}
	// suspicious_shell ignores syscall events; ml_detector is the only possible source.
	mlAlerts := 0
	for _, r := range out.results {
		if r.RuleName != "ml_detector" {
			t.Errorf("unexpected alert from %s on a syscall event", r.RuleName)
		}
		mlAlerts++
	}
	if mlAlerts == 0 {
		t.Error("no alert from ml_detector on an attack trace")
	}
	t.Logf("%d syscalls -> %d ml_detector alerts in %s", len(nums), mlAlerts, st.Elapsed)
}
