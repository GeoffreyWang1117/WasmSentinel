package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/collector"
	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/ebpf"
	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/events"
	"github.com/bytecodealliance/wasmtime-go/v17"
	"github.com/sirupsen/logrus"
)

// quick is a tight but comfortable budget for the WAT guests in testdata/.
var quick = Limits{MaxMemoryBytes: 16 << 20, Fuel: 10_000_000, Timeout: 200 * time.Millisecond}

func newEngine(t *testing.T, l Limits) *Engine {
	t.Helper()
	lg := logrus.New()
	lg.SetOutput(io.Discard)
	e := New(lg, l)
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func wat(t *testing.T, file string) []byte {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	wasm, err := wasmtime.Wat2Wasm(string(src))
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return wasm
}

func load(t *testing.T, e *Engine, name, file string) {
	t.Helper()
	if err := e.LoadRuleBytes(name, wat(t, file)); err != nil {
		t.Fatalf("load %s: %v", file, err)
	}
}

func ruleErr(t *testing.T, err error, want TrapKind) *RuleError {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a %s error, got nil", want)
	}
	var re *RuleError
	if !errors.As(err, &re) {
		t.Fatalf("expected *RuleError, got %T: %v", err, err)
	}
	if re.Kind != want {
		t.Fatalf("expected kind %s, got %s: %v", want, re.Kind, err)
	}
	return re
}

// processEvent builds a root shell event; the suspicious-shell rule scores
// /bin/bash, the name "bash" and the user "root" on their own, so only the
// command line distinguishes "low" from "critical".
func processEvent(cmdline string) *events.Event {
	return procEvent("/bin/bash", "bash", "root", cmdline)
}

// benignEvent is an unprivileged ls, which the suspicious-shell rule scores 0.
func benignEvent() *events.Event {
	return procEvent("/usr/bin/ls", "ls", "alice", "ls -l /home")
}

func procEvent(executable, name, user, cmdline string) *events.Event {
	return &events.Event{
		ID:        "evt-1",
		Type:      events.EventTypeProcess,
		Timestamp: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC),
		Source:    "test",
		Data: map[string]interface{}{
			"process": map[string]interface{}{
				"pid":          4242,
				"executable":   executable,
				"name":         name,
				"command_line": cmdline,
				"user":         user,
			},
		},
	}
}

func TestInvokeReturnsGuestLevel(t *testing.T) {
	e := newEngine(t, quick)
	load(t, e, "echo", "echo_level.wat")

	for _, tc := range []struct {
		payload string
		want    int32
	}{{"7abc", 7}, {"0", 0}, {"xyz", 0}, {"", 0}, {"9", 9}} {
		got, err := e.Invoke("echo", []byte(tc.payload))
		if err != nil {
			t.Fatalf("Invoke(%q): %v", tc.payload, err)
		}
		if got != tc.want {
			t.Errorf("Invoke(%q) = %d, want %d", tc.payload, got, tc.want)
		}
	}
	st := e.Stats()["echo"]
	if st.Calls != 5 || st.Threats != 2 || st.Errors != 0 {
		t.Errorf("stats = %+v, want 5 calls / 2 threats / 0 errors", st)
	}
	if st.FuelLast == 0 || st.FuelTotal < st.FuelLast {
		t.Errorf("fuel accounting broken: %+v", st)
	}
	if st.Reinstantiations != 0 {
		t.Errorf("no trap happened, yet Reinstantiations = %d", st.Reinstantiations)
	}
}

func TestDetectThreatMapsLevelsAndOrdersRules(t *testing.T) {
	e := newEngine(t, quick)
	load(t, e, "zeta", "echo_level.wat") // JSON starts with '{' -> level 0 -> no result
	load(t, e, "alpha", "always9.wat")

	if got := e.GetLoadedRules(); strings.Join(got, ",") != "alpha,zeta" {
		t.Fatalf("rules = %v, want sorted [alpha zeta]", got)
	}
	ev := processEvent("ls -l")
	results, err := e.DetectThreat(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(results), results)
	}
	r := results[0]
	if r.RuleName != "alpha" || !r.Threat || r.Severity != "critical" || r.Confidence != 0.9 {
		t.Errorf("unexpected result %+v", r)
	}
	if r.Event.ID != ev.ID || r.Event.Type != ev.Type {
		t.Errorf("event not propagated: %+v", r.Event)
	}
}

func TestFuelBudgetStopsRunawayRule(t *testing.T) {
	e := newEngine(t, Limits{Fuel: 2_000_000})
	load(t, e, "spin", "spin.wat")
	load(t, e, "echo", "echo_level.wat")

	start := time.Now()
	_, err := e.Invoke("spin", []byte("x"))
	elapsed := time.Since(start)
	ruleErr(t, err, TrapFuel)
	if elapsed > 5*time.Second {
		t.Fatalf("fuel trap took %s", elapsed)
	}
	// The neighbour is untouched and the offender recovers.
	if got, err := e.Invoke("echo", []byte("3")); err != nil || got != 3 {
		t.Fatalf("echo after spin trap: %d, %v", got, err)
	}
	_, err = e.Invoke("spin", []byte("x"))
	ruleErr(t, err, TrapFuel)
	st := e.Stats()["spin"]
	if st.TrapsFuel != 2 || st.Errors != 2 || st.Reinstantiations != 1 {
		t.Errorf("spin stats = %+v", st)
	}
	if st.FuelLast < 1_900_000 {
		t.Errorf("fuel used on exhaustion = %d, want ~budget", st.FuelLast)
	}
}

func TestEpochDeadlineStopsRunawayRule(t *testing.T) {
	const timeout = 30 * time.Millisecond
	e := newEngine(t, Limits{Fuel: 0, Timeout: timeout})
	load(t, e, "spin", "spin.wat")

	start := time.Now()
	_, err := e.Invoke("spin", []byte("x"))
	elapsed := time.Since(start)
	ruleErr(t, err, TrapTimeout)
	if elapsed < timeout {
		t.Errorf("interrupted after %s, before the %s deadline", elapsed, timeout)
	}
	if elapsed > 2*time.Second {
		t.Errorf("deadline took %s to fire", elapsed)
	}
	if st := e.Stats()["spin"]; st.TrapsTimeout != 1 {
		t.Errorf("stats = %+v", st)
	}
}

func TestMemoryCapIsEnforcedInsideTheGuest(t *testing.T) {
	const pages = 8
	e := newEngine(t, Limits{MaxMemoryBytes: pages * wasmPageSize})
	load(t, e, "grow", "grow.wat")

	got, err := e.Invoke("grow", []byte("x"))
	if err != nil {
		t.Fatalf("grow: %v", err)
	}
	if got != pages {
		t.Errorf("guest reached %d pages, want exactly %d", got, pages)
	}
	if st := e.Stats()["grow"]; st.MemoryBytes != pages*wasmPageSize {
		t.Errorf("MemoryBytes = %d, want %d", st.MemoryBytes, pages*wasmPageSize)
	}
	// A module whose minimum memory already exceeds the cap must not load.
	tiny := newEngine(t, Limits{MaxMemoryBytes: wasmPageSize})
	if err := tiny.LoadRuleBytes("grow", wat(t, "grow.wat")); err == nil {
		t.Error("module with 2 initial pages loaded under a 1-page cap")
	}
}

func TestTrapIsIsolatedAndInstanceIsReplaced(t *testing.T) {
	e := newEngine(t, quick)
	load(t, e, "trap", "trap_on_t.wat")
	load(t, e, "echo", "echo_level.wat")

	_, err := e.Invoke("trap", []byte("Tx"))
	re := ruleErr(t, err, TrapOther)
	if re.Rule != "trap" {
		t.Errorf("error names rule %q", re.Rule)
	}
	if got, err := e.Invoke("echo", []byte("5")); err != nil || got != 5 {
		t.Fatalf("neighbour affected by trap: %d, %v", got, err)
	}
	if got, err := e.Invoke("trap", []byte("ok")); err != nil || got != 1 {
		t.Fatalf("trapped rule did not recover: %d, %v", got, err)
	}
	st := e.Stats()["trap"]
	if st.Calls != 2 || st.Errors != 1 || st.TrapsOther != 1 || st.Reinstantiations != 1 {
		t.Errorf("stats = %+v", st)
	}
	if e.Stats()["echo"].Errors != 0 {
		t.Error("echo recorded an error")
	}
}

func TestWasiHasNoCapabilities(t *testing.T) {
	e := newEngine(t, quick)
	load(t, e, "probe", "wasi_probe.wat")

	// Make sure a guest write to fd 1 never reaches our stdout.
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	v, invokeErr := e.Invoke("probe", []byte("LEAKED-TO-HOST-STDOUT\n"))
	w.Close()
	os.Stdout = oldStdout
	var captured bytes.Buffer
	_, _ = io.Copy(&captured, r)

	if invokeErr != nil {
		t.Fatalf("probe: %v", invokeErr)
	}
	envCount, argCount, errno := v/1000, (v%1000)/100, v%100
	if envCount != 0 {
		t.Errorf("guest sees %d environment variables", envCount)
	}
	if argCount != 0 {
		t.Errorf("guest sees %d arguments", argCount)
	}
	if errno != 0 && errno != 8 { // 0 = discarded, 8 = EBADF
		t.Errorf("fd_write(stdout) errno = %d", errno)
	}
	if strings.Contains(captured.String(), "LEAKED") {
		t.Error("guest output reached host stdout")
	}
}

func TestLoadRejectsModuleWithoutAllocator(t *testing.T) {
	e := newEngine(t, quick)
	err := e.LoadRuleBytes("old", wat(t, "no_alloc.wat"))
	if err == nil || !strings.Contains(err.Error(), `"alloc"`) {
		t.Fatalf("expected an alloc ABI error, got %v", err)
	}
	if len(e.GetLoadedRules()) != 0 {
		t.Error("failed load left a rule registered")
	}
}

func TestLargeEventGrowsGuestBuffer(t *testing.T) {
	e := newEngine(t, quick)
	load(t, e, "echo", "echo_level.wat")

	payload := bytes.Repeat([]byte("3"), 300<<10) // > DefaultEventBuffer
	got, err := e.Invoke("echo", payload)
	if err != nil {
		t.Fatal(err)
	}
	if got != 3 {
		t.Errorf("got %d", got)
	}
	// Still fine for small events afterwards (buffer stays grown).
	if got, err := e.Invoke("echo", []byte("4")); err != nil || got != 4 {
		t.Fatalf("after growth: %d, %v", got, err)
	}
}

func TestUnloadAndUnknownRule(t *testing.T) {
	e := newEngine(t, quick)
	load(t, e, "echo", "echo_level.wat")
	if err := e.UnloadRule("echo"); err != nil {
		t.Fatal(err)
	}
	if err := e.UnloadRule("echo"); err == nil {
		t.Error("second unload succeeded")
	}
	if _, err := e.Invoke("echo", []byte("1")); err == nil {
		t.Error("invoking an unloaded rule succeeded")
	}
	if n := len(e.GetLoadedRules()); n != 0 {
		t.Errorf("%d rules still listed", n)
	}
}

func TestConcurrentInvocations(t *testing.T) {
	e := newEngine(t, quick)
	load(t, e, "echo", "echo_level.wat")
	load(t, e, "nine", "always9.wat")

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				want := int32((g + i) % 10)
				got, err := e.Invoke("echo", []byte{byte('0' + want), 'x'})
				if err != nil || got != want {
					errs <- errors.New("echo mismatch")
					return
				}
				if got, err := e.Invoke("nine", []byte("x")); err != nil || got != 9 {
					errs <- errors.New("nine mismatch")
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if st := e.Stats()["echo"]; st.Calls != 1600 {
		t.Errorf("echo calls = %d", st.Calls)
	}
}

func TestCloseIsIdempotentAndStopsEngine(t *testing.T) {
	e := newEngine(t, quick)
	load(t, e, "echo", "echo_level.wat")
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.LoadRuleBytes("echo", wat(t, "echo_level.wat")); err == nil {
		t.Error("load after Close succeeded")
	}
}

// --- integration with the real rule modules (built by scripts/build.sh) -----

const builtRules = "../../../rules/wasm"

func realModule(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(builtRules, name)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("%s not built (run scripts/build.sh)", p)
	}
	return p
}

func TestRealSuspiciousShellRule(t *testing.T) {
	path := realModule(t, "suspicious_shell.wasm")
	e := newEngine(t, DefaultLimits())
	if err := e.LoadRule("suspicious_shell", path); err != nil {
		t.Fatal(err)
	}
	benign, err := e.DetectThreat(context.Background(), benignEvent())
	if err != nil {
		t.Fatal(err)
	}
	if len(benign) != 0 {
		t.Errorf("benign command flagged: %+v", benign[0])
	}
	hits, err := e.DetectThreat(context.Background(), processEvent("bash -c 'rm -rf /tmp/payload'"))
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Severity != "critical" {
		t.Fatalf("expected one critical hit, got %+v", hits)
	}
	st := e.Stats()["suspicious_shell"]
	if st.Errors != 0 || st.Calls != 2 || st.FuelLast == 0 {
		t.Errorf("stats = %+v", st)
	}
	if st.MemoryBytes > DefaultMaxMemoryBytes {
		t.Errorf("memory %d above cap", st.MemoryBytes)
	}
}

func TestRealMLDetectorLoadsAndRuns(t *testing.T) {
	path := realModule(t, "ml_detector.wasm")
	e := newEngine(t, DefaultLimits())
	if err := e.LoadRule("ml_detector", path); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []*events.Event{
		processEvent("ls -l"),
		{ID: "s1", Type: "syscall", Timestamp: time.Now(), Source: "test",
			Data: map[string]interface{}{"pid": 1, "syscall_name": "execve"}},
	} {
		if _, err := e.DetectThreat(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
	if st := e.Stats()["ml_detector"]; st.Errors != 0 || st.Calls != 2 {
		t.Errorf("stats = %+v", st)
	}
}

// The real module accepts {"model":"mlp"} (deep path on the embedded MLP
// instead of the default forest) and rejects a config naming an unknown model
// instead of silently falling back to the defaults.
func TestRealMLDetectorInitConfig(t *testing.T) {
	path := realModule(t, "ml_detector.wasm")
	e := newEngine(t, DefaultLimits())
	e.SetRuleConfig("ml_detector", []byte(`{"model":"mlp"}`))
	if err := e.LoadRule("ml_detector", path); err != nil {
		t.Fatal(err)
	}
	ev := &events.Event{ID: "s1", Type: "syscall", Timestamp: time.Now(), Source: "test",
		Data: map[string]interface{}{"pid": 1, "syscall_nr": 11, "syscall_name": "execve"}}
	if _, err := e.DetectThreat(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if st := e.Stats()["ml_detector"]; st.Errors != 0 || st.Calls != 1 {
		t.Errorf("stats = %+v", st)
	}
	e.SetRuleConfig("ml_detector_bad", []byte(`{"model":"forest"}`))
	err := e.LoadRule("ml_detector_bad", path)
	if err == nil || !strings.Contains(err.Error(), "init: returned -1") {
		t.Fatalf("unknown model accepted: %v", err)
	}
}

func TestRuleConfigReachesInit(t *testing.T) {
	e := newEngine(t, quick)
	// Without a config init is called with (0, 0): the module records 0.
	load(t, e, "plain", "init_config.wat")
	if level, err := e.Invoke("plain", []byte("payload")); err != nil || level != 0 {
		t.Fatalf("plain: level %d, err %v", level, err)
	}
	// With a config the bytes arrive in init: the module records '7'.
	e.SetRuleConfig("cfg", []byte("7 is the level"))
	load(t, e, "cfg", "init_config.wat")
	if level, err := e.Invoke("cfg", []byte("payload")); err != nil || level != 7 {
		t.Fatalf("cfg: level %d, err %v (config did not reach init)", level, err)
	}
	// A rejected config is a load error, not a rule running with defaults.
	e.SetRuleConfig("bad", []byte("x"))
	if err := e.LoadRuleBytes("bad", wat(t, "init_config.wat")); err == nil || !strings.Contains(err.Error(), "init: returned -1") {
		t.Fatalf("rejected config loaded: %v", err)
	}
	// A config for a module without init is a contract error.
	e.SetRuleConfig("noinit", []byte("1"))
	if err := e.LoadRuleBytes("noinit", wat(t, "echo_level.wat")); err == nil || !strings.Contains(err.Error(), "does not export init") {
		t.Fatalf("config accepted by a module without init: %v", err)
	}
	// Clearing the config restores init(0, 0).
	e.SetRuleConfig("cfg", nil)
	load(t, e, "cfg2", "init_config.wat")
	if level, err := e.Invoke("cfg2", []byte("payload")); err != nil || level != 0 {
		t.Fatalf("cfg2: level %d, err %v", level, err)
	}
}

func BenchmarkInvokeEcho(b *testing.B) {
	lg := logrus.New()
	lg.SetOutput(io.Discard)
	e := New(lg, DefaultLimits())
	defer e.Close()
	src, _ := os.ReadFile("testdata/echo_level.wat")
	wasm, _ := wasmtime.Wat2Wasm(string(src))
	if err := e.LoadRuleBytes("echo", wasm); err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte("5"), 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Invoke("echo", payload); err != nil {
			b.Fatal(err)
		}
	}
}

func TestBinaryEncodingFallsBackWithoutDetectRaw(t *testing.T) {
	e := newEngine(t, quick)
	load(t, e, "nine", "always9.wat")
	e.SetEncoding(EncodingBinary)
	if e.Encoding() != EncodingBinary {
		t.Fatal("SetEncoding did not stick")
	}
	ev := processEvent("ls")
	ev.Binary = []byte("opaque payload the WAT stub cannot read")
	res, err := e.DetectThreat(context.Background(), ev)
	if err != nil || len(res) != 1 || res[0].RuleName != "nine" {
		t.Fatalf("fallback result %+v, %v", res, err)
	}
	if st := e.Stats()["nine"]; st.Calls != 1 || st.CallsRaw != 0 {
		t.Errorf("stats %+v, want one JSON call", st)
	}
	_, err = e.InvokeRaw("nine", ev.Binary)
	re := ruleErr(t, err, TrapABI)
	if !strings.Contains(re.Error(), "detect_raw") {
		t.Errorf("error does not name the missing export: %v", re)
	}
	if got, err := e.Invoke("nine", []byte("x")); err != nil || got != 9 {
		t.Fatalf("instance should survive an ABI error: %d, %v", got, err)
	}
	if st := e.Stats()["nine"]; st.Errors != 1 || st.Reinstantiations != 0 || st.TrapsOther != 0 {
		t.Errorf("ABI error accounting %+v", st)
	}
	for in, want := range map[string]Encoding{"": EncodingJSON, "json": EncodingJSON, "binary": EncodingBinary, "raw": EncodingBinary} {
		if got, err := ParseEncoding(in); err != nil || got != want {
			t.Errorf("ParseEncoding(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseEncoding("xml"); err == nil {
		t.Error("ParseEncoding accepted xml")
	}
}

// parityCases are kernel events covering every type the collector emits.
func parityCases() []*ebpf.Event {
	return []*ebpf.Event{
		{Type: ebpf.EventProcessExec, TypeName: "process_exec", PID: 100, PPID: 1, UID: 0, GID: 0, Comm: "bash",
			Filename: "/usr/bin/bash", Argv: []string{"bash", "-c", "rm -rf /tmp/x"}},
		{Type: ebpf.EventProcessExec, TypeName: "process_exec", PID: 101, PPID: 1, UID: 65534, GID: 65534, Comm: "ls",
			Filename: "/usr/bin/ls", Argv: []string{"ls", "-l"}},
		{Type: ebpf.EventProcessExit, TypeName: "process_exit", PID: 100, Comm: "bash", ExitCode: 1},
		{Type: ebpf.EventFileOpen, TypeName: "file_open", PID: 102, UID: 0, Comm: "vi", Filename: "/etc/shadow", Flags: 0x241},
		{Type: ebpf.EventFileOpen, TypeName: "file_open", PID: 102, UID: 1000, Comm: "cat", Filename: "/home/alice/notes.txt"},
		{Type: ebpf.EventNetworkConnect, TypeName: "network_connect", PID: 103, Comm: "nc", Family: 2, Protocol: "tcp",
			SrcIP: net.IPv4(10, 0, 0, 2).To4(), DstIP: net.IPv4(1, 2, 3, 4).To4(), SrcPort: 40000, DstPort: 4444},
		{Type: ebpf.EventNetworkAccept, TypeName: "network_accept", PID: 104, Comm: "sshd", Family: 2, Protocol: "tcp",
			SrcIP: net.IPv4(10, 0, 0, 2).To4(), DstIP: net.IPv4(10, 0, 0, 9).To4(), SrcPort: 22, DstPort: 51000},
		{Type: ebpf.EventSyscall, TypeName: "syscall", PID: 105, PPID: 1, Comm: "gdb", SyscallNr: 101, SyscallName: "ptrace"},
		{Type: ebpf.EventSyscall, TypeName: "syscall", PID: 105, PPID: 1, Comm: "gdb", SyscallNr: 59, SyscallName: "execve"},
	}
}

// The P1.3 acceptance: the JSON path and the binary path give the same level
// for the same kernel event, for both real rules. Stateful rules get one
// instance per path so both see the same history.
func TestRawAndJSONPathsAgreeOnRealModules(t *testing.T) {
	shell := realModule(t, "suspicious_shell.wasm")
	ml := realModule(t, "ml_detector.wasm")
	e := newEngine(t, DefaultLimits())
	for name, path := range map[string]string{"shell_json": shell, "shell_raw": shell, "ml_json": ml, "ml_raw": ml} {
		if err := e.LoadRule(name, path); err != nil {
			t.Fatal(err)
		}
	}
	var names collector.NameCache
	positives := 0
	cases := parityCases()
	for i, ev := range cases {
		ev.Raw = ev.Record()
		out := collector.EventFromEBPF(ev, &names)
		if out.Binary == nil {
			t.Fatalf("case %d: no binary payload", i)
		}
		js, err := out.ToJSON()
		if err != nil {
			t.Fatal(err)
		}
		for _, pair := range [][2]string{{"shell_json", "shell_raw"}, {"ml_json", "ml_raw"}} {
			a, err := e.Invoke(pair[0], js)
			if err != nil {
				t.Fatalf("case %d %s json: %v", i, pair[0], err)
			}
			b, err := e.InvokeRaw(pair[1], out.Binary)
			if err != nil {
				t.Fatalf("case %d %s raw: %v", i, pair[1], err)
			}
			if a != b {
				t.Errorf("case %d (%s) %s: json=%d raw=%d", i, ev.TypeName, pair[0], a, b)
			}
			if a > 0 {
				positives++
			}
		}
	}
	if positives == 0 {
		t.Error("no case produced a detection; the comparison is vacuous")
	}
	st := e.Stats()
	if st["shell_raw"].CallsRaw != uint64(len(cases)) || st["shell_json"].CallsRaw != 0 {
		t.Errorf("raw call accounting: %+v / %+v", st["shell_raw"], st["shell_json"])
	}

	// Under EncodingBinary DetectThreat routes raw-capable rules through detect_raw.
	e.SetEncoding(EncodingBinary)
	out := collector.EventFromEBPF(cases[0], &names)
	if _, err := e.DetectThreat(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	for name, before := range st {
		if after := e.Stats()[name]; after.CallsRaw != before.CallsRaw+1 {
			t.Errorf("%s: CallsRaw %d -> %d, want +1", name, before.CallsRaw, after.CallsRaw)
		}
	}
}

func benchReal(b *testing.B, module string, raw bool) {
	p := filepath.Join(builtRules, module)
	if _, err := os.Stat(p); err != nil {
		b.Skip("module not built")
	}
	lg := logrus.New()
	lg.SetOutput(io.Discard)
	e := New(lg, DefaultLimits())
	defer e.Close()
	if err := e.LoadRule("r", p); err != nil {
		b.Fatal(err)
	}
	ev := parityCases()[0]
	ev.Raw = ev.Record()
	var names collector.NameCache
	out := collector.EventFromEBPF(ev, &names)
	js, _ := out.ToJSON()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		if raw {
			_, err = e.InvokeRaw("r", out.Binary)
		} else {
			_, err = e.Invoke("r", js)
		}
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRealSuspiciousShellJSON(b *testing.B) { benchReal(b, "suspicious_shell.wasm", false) }
func BenchmarkRealSuspiciousShellRaw(b *testing.B)  { benchReal(b, "suspicious_shell.wasm", true) }
func BenchmarkRealMLDetectorJSON(b *testing.B)      { benchReal(b, "ml_detector.wasm", false) }
func BenchmarkRealMLDetectorRaw(b *testing.B)       { benchReal(b, "ml_detector.wasm", true) }

// BenchmarkEventPathEndToEnd measures collector conversion plus rule call for
// one exec event, the way DetectThreat sees it, on each encoding.
func BenchmarkEventPathEndToEnd(b *testing.B) {
	p := filepath.Join(builtRules, "suspicious_shell.wasm")
	if _, err := os.Stat(p); err != nil {
		b.Skip("module not built")
	}
	for _, enc := range []Encoding{EncodingJSON, EncodingBinary} {
		b.Run(string(enc), func(b *testing.B) {
			lg := logrus.New()
			lg.SetOutput(io.Discard)
			e := New(lg, DefaultLimits())
			defer e.Close()
			if err := e.LoadRule("r", p); err != nil {
				b.Fatal(err)
			}
			e.SetEncoding(enc)
			ev := parityCases()[0]
			ev.Raw = ev.Record()
			var names collector.NameCache
			ctx := context.Background()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out := collector.EventFromEBPF(ev, &names)
				if _, err := e.DetectThreat(ctx, out); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

type recordingObserver struct {
	mu    sync.Mutex
	calls []string
	errs  int
	fuel  uint64
}

func (o *recordingObserver) ObserveInvoke(rule string, raw bool, d time.Duration, fuel uint64, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, rule)
	o.fuel += fuel
	if err != nil {
		o.errs++
	}
}

func TestObserverSeesEveryInvocation(t *testing.T) {
	e := newEngine(t, Limits{Fuel: 2_000_000})
	load(t, e, "echo", "echo_level.wat")
	load(t, e, "spin", "spin.wat")
	obs := &recordingObserver{}
	e.SetObserver(obs)
	if _, err := e.Invoke("echo", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Invoke("spin", []byte("x")); err == nil {
		t.Fatal("spin should trap")
	}
	e.SetObserver(nil)
	if _, err := e.Invoke("echo", []byte("1")); err != nil {
		t.Fatal(err)
	}
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if len(obs.calls) != 2 || obs.calls[0] != "echo" || obs.calls[1] != "spin" || obs.errs != 1 || obs.fuel == 0 {
		t.Errorf("observer saw %v errs=%d fuel=%d", obs.calls, obs.errs, obs.fuel)
	}
}

// Training STIDE through the generic export path: the normal trace that was
// trained on no longer alerts, an untrained instance alerts on most of it.
func TestInvokeExportTrainsSTIDE(t *testing.T) {
	path := realModule(t, "ml_detector.wasm")
	nums, err := collector.LoadTrace(filepath.Join("..", "pipeline", "testdata", "adfa_normal_utd0472.txt"))
	if err != nil {
		t.Fatal(err)
	}
	trace := make([]byte, 4*len(nums))
	for i, n := range nums {
		trace[4*i], trace[4*i+1], trace[4*i+2], trace[4*i+3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	}
	e := newEngine(t, DefaultLimits())
	for _, name := range []string{"trained", "untrained"} {
		if err := e.LoadRule(name, path); err != nil {
			t.Fatal(err)
		}
	}
	if !e.HasExport("trained", "train_sequence") || e.HasExport("trained", "no_such_export") {
		t.Fatal("HasExport wrong")
	}
	if n, err := e.InvokeExport("trained", "train_sequence", trace); err != nil || int(n) != len(nums) {
		t.Fatalf("train_sequence: %d, %v", n, err)
	}
	if ngrams, err := e.InvokeExport("trained", "train_finish", nil); err != nil || ngrams == 0 {
		t.Fatalf("train_finish: %d, %v", ngrams, err)
	}
	if _, err := e.InvokeExport("trained", "no_such_export", nil); err == nil {
		t.Error("missing export accepted")
	} else {
		ruleErr(t, err, TrapABI)
	}

	var names collector.NameCache
	alerts := map[string]int{}
	for i, n := range nums {
		ev := &ebpf.Event{Type: ebpf.EventSyscall, TypeName: "syscall", PID: 77, PPID: 1, Comm: "replay", SyscallNr: n, MonotonicNs: uint64(i)}
		js, _ := collector.EventFromEBPF(ev, &names).ToJSON()
		for _, name := range []string{"trained", "untrained"} {
			level, err := e.Invoke(name, js)
			if err != nil {
				t.Fatal(err)
			}
			if level > 0 {
				alerts[name]++
			}
		}
	}
	if alerts["trained"] != 0 {
		t.Errorf("trained instance still alerts %d/%d times on its own training trace", alerts["trained"], len(nums))
	}
	if alerts["untrained"] < len(nums)/2 {
		t.Errorf("untrained instance alerted only %d/%d times; the comparison is not meaningful", alerts["untrained"], len(nums))
	}
	t.Logf("alerts on the training trace: trained=%d untrained=%d of %d", alerts["trained"], alerts["untrained"], len(nums))
}
