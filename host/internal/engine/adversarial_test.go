package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// E6: deliberately misbehaving rule modules (rules/adversarial) against the
// engine under the default limits. Each case records what the sandbox did; the
// table is written to $WASMSENTINEL_RESULTS_DIR/isolation.{json,md} when set,
// so the paper's isolation table is produced by this test, not typed in.

const adversarialDir = "../../../rules/adversarial/target/wasm32-wasip1/release"

type isolationCase struct {
	Module   string     `json:"module"`
	Attempt  string     `json:"attempt"`
	Expect   string     `json:"expect"` // "level<=N", "level==N" or "trap:<kind>"
	wantKind TrapKind   // primary expected trap kind ("" = a returned level)
	altKinds []TrapKind // other acceptable kinds (same containment, different label)
	wantMax  int32
	wantEq   int32
	useEq    bool
	limits   Limits
}

type isolationResult struct {
	isolationCase
	Outcome       string  `json:"outcome"` // "level N" or "trap <kind>"
	Contained     bool    `json:"contained"`
	ElapsedMS     float64 `json:"elapsed_ms"`
	MemoryMiB     float64 `json:"memory_mib_after"`
	FuelUsed      uint64  `json:"fuel_used"`
	RecoveredNext bool    `json:"recovered_next_call"`
	Neighbour     bool    `json:"neighbour_unaffected"`
	Error         string  `json:"error,omitempty"`
}

func isolationCases() []isolationCase {
	def := DefaultLimits()
	noFuel := DefaultLimits()
	noFuel.Fuel = 0 // deadline only
	return []isolationCase{
		{Module: "fs_read", Attempt: "read /etc/passwd, list /, write /tmp via WASI", Expect: "level==0", useEq: true, wantEq: 0, limits: def},
		{Module: "env_leak", Attempt: "enumerate environment variables and argv", Expect: "level==0", useEq: true, wantEq: 0, limits: def},
		{Module: "net_connect", Attempt: "TCP connect to 127.0.0.1:22 via std::net", Expect: "level==0", useEq: true, wantEq: 0, limits: def},
		{Module: "stdout_flood", Attempt: "write 8 MiB to stdout and stderr", Expect: "level==0", useEq: true, wantEq: 0, limits: def},
		{Module: "clock", Attempt: "read the wall clock (permitted capability)", Expect: "level==1", useEq: true, wantEq: 1, limits: def},
		{Module: "mem_bomb_graceful", Attempt: "grow memory 16 MiB at a time until refused", Expect: "level<=64", wantMax: 64, limits: def},
		// A single 1 GiB request is refused outright, so linear memory never reaches
		// the cap; the allocator aborts and the engine can only label it a generic
		// trap. Both labels mean the same thing here: refused, instance replaced.
		{Module: "mem_bomb_abort", Attempt: "allocate and touch 1 GiB at once (refused before growing)", Expect: "trap:memory|trap", wantKind: TrapMemory, altKinds: []TrapKind{TrapOther}, limits: def},
		{Module: "cpu_spin", Attempt: "infinite loop (fuel budget 5e7)", Expect: "trap:fuel", wantKind: TrapFuel, limits: def},
		{Module: "cpu_spin", Attempt: "infinite loop (fuel off, 100 ms deadline)", Expect: "trap:timeout", wantKind: TrapTimeout, limits: noFuel},
		{Module: "proc_exit", Attempt: "proc_exit(3)", Expect: "trap:exit", wantKind: TrapExit, limits: def},
		{Module: "stack_overflow", Attempt: "unbounded recursion", Expect: "trap:trap", wantKind: TrapOther, limits: def},
	}
}

func (c isolationCase) acceptsKind(k TrapKind) bool {
	if k == c.wantKind {
		return true
	}
	for _, alt := range c.altKinds {
		if k == alt {
			return true
		}
	}
	return false
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func TestAdversarialModulesAreContained(t *testing.T) {
	if _, err := os.Stat(filepath.Join(adversarialDir, "fs_read.wasm")); err != nil {
		t.Skipf("adversarial modules not built (cd rules/adversarial && cargo build --release --target wasm32-wasip1)")
	}
	payload, _ := processEvent("ls").ToJSON()
	var results []isolationResult
	for _, c := range isolationCases() {
		c := c
		name := fmt.Sprintf("%s/%s", c.Module, strings.ReplaceAll(c.Expect, ":", "_"))
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, c.limits)
			load(t, e, "neighbour", "echo_level.wat")
			if err := e.LoadRule(c.Module, filepath.Join(adversarialDir, c.Module+".wasm")); err != nil {
				t.Fatalf("load: %v", err)
			}
			start := time.Now()
			level, err := e.Invoke(c.Module, payload)
			elapsed := time.Since(start)
			st := e.Stats()[c.Module]
			res := isolationResult{isolationCase: c, ElapsedMS: float64(elapsed.Microseconds()) / 1000, FuelUsed: st.FuelLast}

			if err != nil {
				var re *RuleError
				if !errors.As(err, &re) {
					t.Fatalf("non-rule error: %v", err)
				}
				res.Outcome = "trap " + string(re.Kind)
				res.Contained = c.wantKind != "" && c.acceptsKind(re.Kind)
				res.Error = firstLine(re.Err.Error())
			} else {
				res.Outcome = fmt.Sprintf("level %d", level)
				switch {
				case c.wantKind != "":
					res.Contained = false
				case c.useEq:
					res.Contained = level == c.wantEq
				default:
					res.Contained = level <= c.wantMax
				}
			}
			// The neighbour keeps working and the offender comes back on its next call
			// (or, for well-behaved modules, simply keeps working).
			if got, err := e.Invoke("neighbour", []byte("5")); err == nil && got == 5 {
				res.Neighbour = true
			}
			if c.Module == "cpu_spin" || c.Module == "mem_bomb_abort" || c.Module == "proc_exit" || c.Module == "stack_overflow" {
				// Offenders misbehave on every call; recovery means a fresh instance ran
				// again and failed the same controlled way instead of poisoning the engine.
				_, err2 := e.Invoke(c.Module, payload)
				var re2 *RuleError
				res.RecoveredNext = errors.As(err2, &re2) && c.acceptsKind(re2.Kind) && e.Stats()[c.Module].Reinstantiations >= 1
			} else {
				got, err2 := e.Invoke(c.Module, payload)
				res.RecoveredNext = err2 == nil && (c.useEq && got == c.wantEq || !c.useEq && got <= c.wantMax)
			}
			res.MemoryMiB = float64(e.Stats()[c.Module].MemoryBytes) / (1 << 20)
			if c.limits.MaxMemoryBytes > 0 && e.Stats()[c.Module].MemoryBytes > c.limits.MaxMemoryBytes {
				t.Errorf("memory %d above cap %d", e.Stats()[c.Module].MemoryBytes, c.limits.MaxMemoryBytes)
			}
			if c.wantKind == TrapTimeout && elapsed > 2*time.Second {
				t.Errorf("deadline took %s", elapsed)
			}
			if !res.Contained {
				t.Errorf("%s: expected %s, got %s (%s)", c.Module, c.Expect, res.Outcome, res.Error)
			}
			if !res.Neighbour {
				t.Errorf("%s: neighbour rule affected", c.Module)
			}
			if !res.RecoveredNext {
				t.Errorf("%s: engine did not recover for the next call", c.Module)
			}
			results = append(results, res)
			t.Logf("%-18s %-38s -> %-14s contained=%v %.2f ms mem=%.1f MiB", c.Module, c.Expect, res.Outcome, res.Contained, res.ElapsedMS, res.MemoryMiB)
		})
	}
	writeIsolationReport(t, results)
}

func writeIsolationReport(t *testing.T, results []isolationResult) {
	dir := os.Getenv("WASMSENTINEL_RESULTS_DIR")
	if dir == "" || len(results) == 0 {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	sort.SliceStable(results, func(i, j int) bool { return results[i].Module < results[j].Module })
	limits := DefaultLimits()
	report := map[string]interface{}{
		"generated": time.Now().UTC().Format(time.RFC3339),
		"limits":    map[string]interface{}{"memory_bytes": limits.MaxMemoryBytes, "fuel": limits.Fuel, "timeout": limits.Timeout.String()},
		"wasmtime":  "wasmtime-go/v17",
		"cases":     results,
		"contained": countContained(results),
		"total":     len(results),
		"test":      "host/internal/engine/adversarial_test.go",
		"modules":   "rules/adversarial",
	}
	js, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "isolation.json"), js, 0o644); err != nil {
		t.Fatal(err)
	}
	var md strings.Builder
	fmt.Fprintf(&md, "| module | attempt | expected | outcome | contained | time (ms) | memory after (MiB) | neighbour ok | recovers |\n|---|---|---|---|---|---|---|---|---|\n")
	for _, r := range results {
		fmt.Fprintf(&md, "| `%s` | %s | %s | %s | %v | %.2f | %.1f | %v | %v |\n",
			r.Module, r.Attempt, r.Expect, r.Outcome, r.Contained, r.ElapsedMS, r.MemoryMiB, r.Neighbour, r.RecoveredNext)
	}
	fmt.Fprintf(&md, "\n%d/%d contained under limits memory=%d B, fuel=%d, timeout=%s.\n", countContained(results), len(results), limits.MaxMemoryBytes, limits.Fuel, limits.Timeout)
	if err := os.WriteFile(filepath.Join(dir, "isolation.md"), []byte(md.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("isolation report written to %s", dir)
}

func countContained(results []isolationResult) int {
	n := 0
	for _, r := range results {
		if r.Contained && r.Neighbour && r.RecoveredNext {
			n++
		}
	}
	return n
}
