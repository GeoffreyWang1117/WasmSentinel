// Package engine executes detection rules compiled to WebAssembly.
//
// Every rule owns one long-lived wasmtime Store and Instance that are reused
// across events. The host writes each serialized event into a guest buffer
// obtained from the module's exported allocator and calls detect(ptr, len).
// Each call runs under three independent limits (see Limits): a linear-memory
// cap enforced by the store limiter, an instruction budget enforced with fuel,
// and a wall-clock budget enforced with epoch interruption. A rule that traps,
// for whatever reason, loses its instance and is re-instantiated from the
// compiled module on its next call; other rules are unaffected because each has
// its own store. Guests receive a WASI context with no capabilities: no
// inherited stdio, no environment, no arguments, no preopened directories.
//
// Guest ABI (v2). A rule module must export:
//
//	memory                       linear memory
//	alloc(size: i32) -> i32      allocate size bytes, return the pointer
//	dealloc(ptr: i32, size: i32) release a buffer from alloc
//	detect(ptr: i32, len: i32) -> i32   threat level 0..10 (0 = benign)
//
// and may export init(ptr: i32, len: i32) -> i32, which is called once per
// instance with (0, 0) right after instantiation.
package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/events"
	"github.com/bytecodealliance/wasmtime-go/v17"
	"github.com/sirupsen/logrus"
)

// Engine hosts a set of Wasm rules and runs them against events.
type Engine struct {
	cfg    Limits
	ticks  uint64
	engine *wasmtime.Engine
	logger *logrus.Logger

	mu     sync.RWMutex
	rules  map[string]*rule
	names  []string // sorted; fixes the evaluation order
	closed bool
	enc    Encoding

	observer atomic.Pointer[observerBox]

	stopEpoch chan struct{}
	epochWG   sync.WaitGroup
}

type rule struct {
	name   string
	path   string
	module *wasmtime.Module

	mu     sync.Mutex // serializes invocations and guards inst and stats
	inst   *instance  // nil after a trap until the next invocation
	stats  RuleStats
	hasRaw bool // module exports detect_raw
}

// instance is one store plus the exports the host needs from it.
type instance struct {
	store     *wasmtime.Store
	memory    *wasmtime.Memory
	alloc     *wasmtime.Func
	dealloc   *wasmtime.Func
	detect    *wasmtime.Func
	detectRaw *wasmtime.Func // optional

	bufPtr int32 // guest event buffer from alloc
	bufCap int32
}

// New creates an engine. A nil logger discards log output.
func New(logger *logrus.Logger, limits Limits) *Engine {
	if logger == nil {
		logger = logrus.New()
		logger.SetOutput(io.Discard)
	}
	limits = limits.normalized()

	cfg := wasmtime.NewConfig()
	// Both mechanisms trap immediately when enabled but never armed, so they are
	// only switched on when the corresponding limit is in use.
	cfg.SetConsumeFuel(limits.Fuel > 0)
	cfg.SetEpochInterruption(limits.Timeout > 0)

	e := &Engine{
		cfg:       limits,
		ticks:     limits.deadlineTicks(),
		engine:    wasmtime.NewEngineWithConfig(cfg),
		logger:    logger,
		rules:     make(map[string]*rule),
		stopEpoch: make(chan struct{}),
		enc:       EncodingJSON,
	}
	if limits.Timeout > 0 {
		e.epochWG.Add(1)
		go e.runEpoch()
	}
	return e
}

// Limits returns the effective limits (zero fields replaced by defaults).
func (e *Engine) Limits() Limits { return e.cfg }

// SetEncoding selects the event encoding DetectThreat prefers.
func (e *Engine) SetEncoding(enc Encoding) {
	e.mu.Lock()
	e.enc = enc
	e.mu.Unlock()
}

// Encoding returns the current preference.
func (e *Engine) Encoding() Encoding {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enc
}

// Observer receives one callback per rule invocation, after the rule's
// counters were updated. Implementations must be cheap and must not call back
// into the engine.
type Observer interface {
	ObserveInvoke(rule string, raw bool, d time.Duration, fuel uint64, err error)
}

type observerBox struct{ o Observer }

// SetObserver installs (or, with nil, removes) the invocation observer.
func (e *Engine) SetObserver(o Observer) {
	if o == nil {
		e.observer.Store(nil)
		return
	}
	e.observer.Store(&observerBox{o: o})
}

func (e *Engine) runEpoch() {
	defer e.epochWG.Done()
	t := time.NewTicker(e.cfg.EpochTick)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			e.engine.IncrementEpoch()
		case <-e.stopEpoch:
			return
		}
	}
}

// LoadRule compiles the module at wasmPath, instantiates it once and registers
// it under name. Loading the same name again replaces the previous rule.
func (e *Engine) LoadRule(name, wasmPath string) error {
	wasm, err := os.ReadFile(wasmPath)
	if err != nil {
		return fmt.Errorf("read wasm file %s: %w", wasmPath, err)
	}
	return e.load(name, wasmPath, wasm)
}

// LoadRuleBytes is LoadRule for an in-memory module.
func (e *Engine) LoadRuleBytes(name string, wasm []byte) error {
	return e.load(name, "<bytes>", wasm)
}

// LoadRulesFromDir loads every *.wasm below rulesDir, skipping cargo target/
// directories, using the file name without extension as the rule name.
func (e *Engine) LoadRulesFromDir(rulesDir string) error {
	return filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "target" && path != rulesDir {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".wasm" {
			return nil
		}
		return e.LoadRule(strings.TrimSuffix(info.Name(), ".wasm"), path)
	})
}

func (e *Engine) load(name, path string, wasm []byte) error {
	if name == "" {
		return errors.New("rule name must not be empty")
	}
	module, err := wasmtime.NewModule(e.engine, wasm)
	if err != nil {
		return fmt.Errorf("compile rule %s (%s): %w", name, path, err)
	}
	r := &rule{name: name, path: path, module: module}
	inst, err := e.instantiate(r) // surfaces ABI and limit problems at load time
	if err != nil {
		return err
	}
	r.inst = inst
	r.hasRaw = inst.detectRaw != nil

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("engine is closed")
	}
	if old, ok := e.rules[name]; ok {
		old.mu.Lock()
		old.inst = nil
		old.mu.Unlock()
	} else {
		e.names = append(e.names, name)
		sort.Strings(e.names)
	}
	e.rules[name] = r
	e.logger.WithFields(logrus.Fields{
		"rule":         name,
		"path":         path,
		"memory_bytes": inst.memory.DataSize(inst.store),
		"detect_raw":   r.hasRaw,
	}).Info("Loaded Wasm rule")
	return nil
}

// instantiate creates a fresh store and instance for r under the engine limits.
func (e *Engine) instantiate(r *rule) (*instance, error) {
	store := wasmtime.NewStore(e.engine)
	// memorySize caps each linear memory; one instance and one memory per store.
	store.Limiter(e.cfg.MaxMemoryBytes, -1, 1, -1, 1)
	// Zero-capability WASI: nothing inherited, no env, no args, no preopens.
	store.SetWasi(wasmtime.NewWasiConfig())

	linker := wasmtime.NewLinker(e.engine)
	if err := linker.DefineWasi(); err != nil {
		return nil, &RuleError{Rule: r.name, Kind: TrapOther, Err: fmt.Errorf("define wasi: %w", err)}
	}

	e.arm(store)
	wi, err := linker.Instantiate(store, r.module)
	if err != nil {
		return nil, &RuleError{Rule: r.name, Kind: e.classify(nil, nil, err), Err: fmt.Errorf("instantiate: %w", err)}
	}

	in := &instance{store: store}
	if ext := wi.GetExport(store, "memory"); ext != nil {
		in.memory = ext.Memory()
	}
	if in.memory == nil {
		return nil, abiError(r.name, "memory")
	}
	if in.alloc = wi.GetFunc(store, "alloc"); in.alloc == nil {
		return nil, abiError(r.name, "alloc")
	}
	if in.dealloc = wi.GetFunc(store, "dealloc"); in.dealloc == nil {
		return nil, abiError(r.name, "dealloc")
	}
	if in.detect = wi.GetFunc(store, "detect"); in.detect == nil {
		return nil, abiError(r.name, "detect")
	}
	in.detectRaw = wi.GetFunc(store, "detect_raw") // optional, binary path

	if initFn := wi.GetFunc(store, "init"); initFn != nil {
		if n := len(initFn.Type(store).Params()); n != 2 {
			e.logger.WithField("rule", r.name).Warnf("init export takes %d params, expected 2; not calling it", n)
		} else {
			e.arm(store)
			if _, err := initFn.Call(store, int32(0), int32(0)); err != nil {
				return nil, &RuleError{Rule: r.name, Kind: e.classify(in.memory, store, err), Err: fmt.Errorf("init: %w", err)}
			}
		}
	}

	if err := in.reserve(e, e.cfg.EventBuffer); err != nil {
		return nil, &RuleError{Rule: r.name, Kind: e.classify(in.memory, store, err), Err: fmt.Errorf("event buffer: %w", err)}
	}
	return in, nil
}

func abiError(rule, export string) error {
	return &RuleError{
		Rule: rule,
		Kind: TrapOther,
		Err:  fmt.Errorf("module does not export %q (guest ABI v2 requires memory, alloc, dealloc and detect)", export),
	}
}

// arm resets the per-call budgets on a store.
func (e *Engine) arm(store *wasmtime.Store) {
	if e.cfg.Fuel > 0 {
		_ = store.SetFuel(e.cfg.Fuel)
	}
	if e.cfg.Timeout > 0 {
		store.SetEpochDeadline(e.ticks)
	}
}

// fuelUsed reports how much of the per-call budget the last call consumed.
func (e *Engine) fuelUsed(store *wasmtime.Store) uint64 {
	if e.cfg.Fuel == 0 {
		return 0
	}
	left, err := store.GetFuel()
	if err != nil || left > e.cfg.Fuel {
		return 0
	}
	return e.cfg.Fuel - left
}

// reserve makes sure the guest event buffer can hold need bytes.
func (in *instance) reserve(e *Engine, need int) error {
	if in.bufCap > 0 && need <= int(in.bufCap) {
		return nil
	}
	newCap := int(in.bufCap) * 2
	if newCap < need {
		newCap = (need + 4095) &^ 4095
	}
	if newCap < e.cfg.EventBuffer {
		newCap = e.cfg.EventBuffer
	}
	if newCap > math.MaxInt32 {
		return fmt.Errorf("event of %d bytes exceeds the 32-bit guest address space", need)
	}
	if in.bufCap > 0 {
		e.arm(in.store)
		if _, err := in.dealloc.Call(in.store, in.bufPtr, in.bufCap); err != nil {
			return fmt.Errorf("dealloc(%d, %d): %w", in.bufPtr, in.bufCap, err)
		}
		in.bufPtr, in.bufCap = 0, 0
	}
	e.arm(in.store)
	res, err := in.alloc.Call(in.store, int32(newCap))
	if err != nil {
		return fmt.Errorf("alloc(%d): %w", newCap, err)
	}
	ptr, ok := res.(int32)
	if !ok {
		return fmt.Errorf("alloc returned %T, want i32", res)
	}
	if size := uint64(in.memory.DataSize(in.store)); ptr <= 0 || uint64(ptr)+uint64(newCap) > size {
		return fmt.Errorf("alloc(%d) returned pointer %d outside linear memory (%d bytes)", newCap, ptr, size)
	}
	in.bufPtr, in.bufCap = ptr, int32(newCap)
	return nil
}

// Invoke runs one rule on a raw payload and returns the threat level it
// reports. The payload is whatever the rule's detect export expects; the rules
// in this repository take the event JSON produced by events.Event.ToJSON.
func (e *Engine) Invoke(name string, payload []byte) (int32, error) {
	e.mu.RLock()
	r, ok := e.rules[name]
	e.mu.RUnlock()
	if !ok {
		return 0, fmt.Errorf("rule %q not loaded", name)
	}
	return e.invoke(r, payload, false)
}

// InvokeRaw runs one rule's detect_raw export on a binary payload (package
// wire). Rules without the export return a TrapABI error and keep their
// instance.
func (e *Engine) InvokeRaw(name string, payload []byte) (int32, error) {
	e.mu.RLock()
	r, ok := e.rules[name]
	e.mu.RUnlock()
	if !ok {
		return 0, fmt.Errorf("rule %q not loaded", name)
	}
	return e.invoke(r, payload, true)
}

func (e *Engine) invoke(r *rule, payload []byte, raw bool) (int32, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	start := time.Now()
	level, fuel, err := e.invokeLocked(r, payload, raw)
	d := time.Since(start)

	st := &r.stats
	st.Calls++
	if raw {
		st.CallsRaw++
	}
	st.LatencyLast = d
	st.LatencyTotal += d
	if d > st.LatencyMax {
		st.LatencyMax = d
	}
	st.FuelLast = fuel
	st.FuelTotal += fuel
	if r.inst != nil {
		st.MemoryBytes = int64(r.inst.memory.DataSize(r.inst.store))
	}
	if err != nil {
		st.Errors++
		var re *RuleError
		if errors.As(err, &re) {
			switch re.Kind {
			case TrapFuel:
				st.TrapsFuel++
			case TrapTimeout:
				st.TrapsTimeout++
			case TrapMemory:
				st.TrapsMemory++
			case TrapExit:
				st.TrapsExit++
			case TrapABI:
				// contract error, instance kept; counted in Errors only
			default:
				st.TrapsOther++
			}
		}
	} else if level > 0 {
		st.Threats++
	}
	if box := e.observer.Load(); box != nil {
		box.o.ObserveInvoke(r.name, raw, d, fuel, err)
	}
	if err != nil {
		return 0, err
	}
	return level, nil
}

func (e *Engine) invokeLocked(r *rule, payload []byte, raw bool) (int32, uint64, error) {
	if len(payload) > math.MaxInt32 {
		return 0, 0, &RuleError{Rule: r.name, Kind: TrapABI, Err: fmt.Errorf("payload of %d bytes is too large", len(payload))}
	}
	if raw && !r.hasRaw {
		return 0, 0, &RuleError{Rule: r.name, Kind: TrapABI, Err: errors.New("module does not export detect_raw")}
	}
	if r.inst == nil {
		inst, err := e.instantiate(r)
		if err != nil {
			return 0, 0, err
		}
		r.inst = inst
		r.stats.Reinstantiations++
	}
	in := r.inst

	// fail discards the instance: after a trap the guest heap and globals can
	// be inconsistent, and a fresh instance costs microseconds.
	fail := func(stage string, err error) (int32, uint64, error) {
		kind := e.classify(in.memory, in.store, err)
		r.inst = nil
		return 0, e.fuelUsed(in.store), &RuleError{Rule: r.name, Kind: kind, Err: fmt.Errorf("%s: %w", stage, err)}
	}

	if err := in.reserve(e, len(payload)); err != nil {
		return fail("event buffer", err)
	}
	// UnsafeData must be re-fetched after every guest call: memory may have grown.
	mem := in.memory.UnsafeData(in.store)
	copy(mem[in.bufPtr:int(in.bufPtr)+len(payload)], payload)

	fn, stage := in.detect, "detect"
	if raw {
		fn, stage = in.detectRaw, "detect_raw"
	}
	e.arm(in.store)
	res, err := fn.Call(in.store, in.bufPtr, int32(len(payload)))
	if err != nil {
		return fail(stage, err)
	}
	level, ok := res.(int32)
	if !ok {
		return fail(stage, fmt.Errorf("returned %T, want i32", res))
	}
	return level, e.fuelUsed(in.store), nil
}

// classify maps a wasmtime error to a TrapKind.
func (e *Engine) classify(mem *wasmtime.Memory, store *wasmtime.Store, err error) TrapKind {
	var trap *wasmtime.Trap
	if errors.As(err, &trap) {
		if code := trap.Code(); code != nil {
			switch *code {
			case wasmtime.OutOfFuel:
				return TrapFuel
			case wasmtime.Interrupt:
				return TrapTimeout
			}
		}
		if mem != nil && store != nil && int64(mem.DataSize(store))+wasmPageSize > e.cfg.MaxMemoryBytes {
			return TrapMemory
		}
		return TrapOther
	}
	var werr *wasmtime.Error
	if errors.As(err, &werr) {
		if _, ok := werr.ExitStatus(); ok {
			return TrapExit
		}
	}
	return TrapOther
}

// DetectThreat runs every loaded rule on the event, in rule-name order. With
// EncodingBinary, rules that export detect_raw receive event.Binary when it is
// set; everything else receives the JSON serialization, which is produced at
// most once per event. A rule that fails is logged and skipped; the error
// return is reserved for problems with the event itself or a cancelled context.
func (e *Engine) DetectThreat(ctx context.Context, event *events.Event) ([]*events.DetectionResult, error) {
	e.mu.RLock()
	enc := e.enc
	rules := make([]*rule, 0, len(e.names))
	for _, n := range e.names {
		rules = append(rules, e.rules[n])
	}
	e.mu.RUnlock()

	var jsonPayload []byte
	var results []*events.DetectionResult
	for _, r := range rules {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		raw := enc == EncodingBinary && len(event.Binary) > 0 && r.hasRaw
		payload := event.Binary
		if !raw {
			if jsonPayload == nil {
				var err error
				if jsonPayload, err = event.ToJSON(); err != nil {
					return nil, fmt.Errorf("serialize event: %w", err)
				}
			}
			payload = jsonPayload
		}
		level, err := e.invoke(r, payload, raw)
		if err != nil {
			e.logger.WithError(err).WithField("rule", r.name).Warn("Rule invocation failed")
			continue
		}
		if level > 0 {
			results = append(results, newResult(r.name, level, event))
		}
	}
	return results, nil
}

func newResult(ruleName string, level int32, event *events.Event) *events.DetectionResult {
	if level > 10 {
		level = 10
	}
	return &events.DetectionResult{
		RuleName:    ruleName,
		Severity:    severity(level),
		Threat:      true,
		Confidence:  float64(level) / 10.0,
		Description: fmt.Sprintf("Threat detected by rule %s (level %d)", ruleName, level),
		Event:       *event,
	}
}

func severity(level int32) string {
	switch {
	case level >= 8:
		return "critical"
	case level >= 6:
		return "high"
	case level >= 4:
		return "medium"
	case level >= 2:
		return "low"
	default:
		return "info"
	}
}

// UnloadRule removes a rule.
func (e *Engine) UnloadRule(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.rules[name]
	if !ok {
		return fmt.Errorf("rule %s not found", name)
	}
	delete(e.rules, name)
	for i, n := range e.names {
		if n == name {
			e.names = append(e.names[:i], e.names[i+1:]...)
			break
		}
	}
	r.mu.Lock()
	r.inst = nil
	r.mu.Unlock()
	e.logger.WithField("rule", name).Info("Unloaded Wasm rule")
	return nil
}

// GetLoadedRules lists rule names in evaluation order.
func (e *Engine) GetLoadedRules() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]string(nil), e.names...)
}

// Stats snapshots every rule's counters.
func (e *Engine) Stats() map[string]RuleStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]RuleStats, len(e.rules))
	for n, r := range e.rules {
		r.mu.Lock()
		out[n] = r.stats
		r.mu.Unlock()
	}
	return out
}

// Close stops the epoch ticker and drops every instance. It is idempotent.
func (e *Engine) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	rules := e.rules
	e.rules = make(map[string]*rule)
	e.names = nil
	e.mu.Unlock()

	if e.cfg.Timeout > 0 {
		close(e.stopEpoch)
		e.epochWG.Wait()
	}
	for _, r := range rules {
		r.mu.Lock()
		r.inst = nil
		r.mu.Unlock()
	}
	e.logger.Info("Wasm engine closed")
	return nil
}
