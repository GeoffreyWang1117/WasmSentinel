package engine

import (
	"fmt"
	"time"
)

// Defaults for Limits. They are deliberately generous for the rules in this
// repository (a full ADFA-LD MLP inference consumes well under 1M fuel and
// finishes in tens of microseconds) and tight enough that a runaway rule cannot
// stall the event loop or exhaust host memory.
const (
	DefaultMaxMemoryBytes int64         = 64 << 20
	DefaultFuel           uint64        = 50_000_000
	DefaultTimeout        time.Duration = 100 * time.Millisecond
	DefaultEventBuffer    int           = 64 << 10

	wasmPageSize = 64 << 10
)

// Limits bounds what a single rule invocation may consume. Each field is
// enforced by a different wasmtime mechanism and can be disabled independently.
type Limits struct {
	// MaxMemoryBytes caps the rule's linear memory, initial size plus growth,
	// through the store limiter. memory.grow beyond it fails inside the guest
	// (Rust's allocator then aborts, which the host reports as TrapMemory).
	// 0 selects DefaultMaxMemoryBytes.
	MaxMemoryBytes int64
	// Fuel is the per-call instruction budget in wasmtime fuel units (roughly
	// one per simple instruction). Exhaustion traps with TrapFuel. 0 disables
	// fuel metering entirely.
	Fuel uint64
	// Timeout is the per-call wall-clock budget, enforced with epoch
	// interruption: a background ticker advances the engine epoch every
	// EpochTick and a call whose deadline passes traps with TrapTimeout.
	// 0 disables the deadline.
	Timeout time.Duration
	// EpochTick is the epoch ticker period. 0 derives it from Timeout
	// (Timeout/10 clamped to [1ms, 10ms]). Ignored when Timeout is 0.
	EpochTick time.Duration
	// EventBuffer is the initial size of the guest-side event buffer obtained
	// from the module's alloc export. It grows on demand. 0 selects
	// DefaultEventBuffer.
	EventBuffer int
}

// DefaultLimits returns the limits used by the command-line defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxMemoryBytes: DefaultMaxMemoryBytes,
		Fuel:           DefaultFuel,
		Timeout:        DefaultTimeout,
		EventBuffer:    DefaultEventBuffer,
	}
}

func (l Limits) normalized() Limits {
	if l.MaxMemoryBytes <= 0 {
		l.MaxMemoryBytes = DefaultMaxMemoryBytes
	}
	if l.EventBuffer <= 0 {
		l.EventBuffer = DefaultEventBuffer
	}
	if l.Timeout > 0 && l.EpochTick <= 0 {
		l.EpochTick = l.Timeout / 10
		if l.EpochTick < time.Millisecond {
			l.EpochTick = time.Millisecond
		}
		if l.EpochTick > 10*time.Millisecond {
			l.EpochTick = 10 * time.Millisecond
		}
	}
	return l
}

// deadlineTicks is the number of epoch ticks a call may span. The first tick
// can arrive immediately after arming, hence the +1.
func (l Limits) deadlineTicks() uint64 {
	if l.Timeout <= 0 {
		return 0
	}
	return uint64((l.Timeout+l.EpochTick-1)/l.EpochTick) + 1
}

func (l Limits) String() string {
	return fmt.Sprintf("memory=%dB fuel=%d timeout=%s", l.MaxMemoryBytes, l.Fuel, l.Timeout)
}

// TrapKind classifies why a rule invocation failed.
type TrapKind string

const (
	// TrapFuel: the instruction budget (Limits.Fuel) was exhausted.
	TrapFuel TrapKind = "fuel"
	// TrapTimeout: the wall-clock deadline (Limits.Timeout) passed.
	TrapTimeout TrapKind = "timeout"
	// TrapMemory: the guest trapped while its linear memory sat at the cap,
	// i.e. an allocation failed under Limits.MaxMemoryBytes.
	TrapMemory TrapKind = "memory"
	// TrapExit: the guest called WASI proc_exit.
	TrapExit TrapKind = "exit"
	// TrapOther: unreachable, out-of-bounds access, stack overflow, a broken
	// ABI contract, or any other failure.
	TrapOther TrapKind = "trap"
)

// RuleError is returned when a rule cannot be invoked. The instance that
// produced it has been discarded; the next invocation re-instantiates the rule.
type RuleError struct {
	Rule string
	Kind TrapKind
	Err  error
}

func (e *RuleError) Error() string { return fmt.Sprintf("rule %s: %s: %v", e.Rule, e.Kind, e.Err) }
func (e *RuleError) Unwrap() error { return e.Err }

// Encoding selects how DetectThreat hands events to rules.
type Encoding string

const (
	// EncodingJSON serializes events.Event to JSON and calls detect.
	EncodingJSON Encoding = "json"
	// EncodingBinary hands the host-built binary payload (events.Event.Binary,
	// see package wire) to detect_raw when the event carries one and the rule
	// exports it; any other combination falls back to JSON for that rule.
	EncodingBinary Encoding = "binary"
)

// ParseEncoding accepts "json" (default), "binary" or "raw".
func ParseEncoding(s string) (Encoding, error) {
	switch s {
	case "", "json":
		return EncodingJSON, nil
	case "binary", "raw":
		return EncodingBinary, nil
	}
	return "", fmt.Errorf("unknown event encoding %q (use json or binary)", s)
}

// TrapABI marks a host-side contract error (missing export, bad payload); the
// instance is kept.
const TrapABI TrapKind = "abi"

// RuleStats is a snapshot of one rule's counters.
type RuleStats struct {
	Calls    uint64
	CallsRaw uint64 // subset of Calls that went through detect_raw
	Threats  uint64 // calls that returned a level > 0
	Errors   uint64 // calls that returned an error (sum of the Traps* fields plus ABI errors)

	TrapsFuel    uint64
	TrapsTimeout uint64
	TrapsMemory  uint64
	TrapsExit    uint64
	TrapsOther   uint64

	// Reinstantiations counts instances created after the initial load, i.e.
	// recoveries from a trap.
	Reinstantiations uint64

	FuelLast  uint64
	FuelTotal uint64

	LatencyLast  time.Duration
	LatencyMax   time.Duration
	LatencyTotal time.Duration

	// MemoryBytes is the current linear-memory size of the live instance.
	MemoryBytes int64
}
