package collector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/ebpf"
	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/events"
	"github.com/sirupsen/logrus"
)

// ReplayConfig configures ReplayCollector.
type ReplayConfig struct {
	// Path is an ADFA-LD style trace (whitespace-separated syscall numbers)
	// or a directory of such *.txt files, replayed in sorted order.
	Path string
	// EventsPerSecond paces the replay; 0 replays as fast as the pipeline accepts.
	EventsPerSecond int
	// Loop restarts from the first trace when the last one ends.
	Loop bool
	// Binary also attaches the wire payload, as the eBPF collector would.
	Binary bool
	// PID stamped on the events; each trace gets PID+index so per-process
	// state in the rules sees one process per trace. 0 means 4242.
	PID uint32
	// ChanSize is the output channel capacity; 0 means 4096.
	ChanSize int
}

// ReplayCollector feeds recorded syscall traces through the pipeline as
// syscall events shaped exactly like the eBPF collector's. It closes its
// channel when the replay ends, which lets the pipeline finish on its own.
type ReplayCollector struct {
	cfg    ReplayConfig
	logger *logrus.Logger
	traces [][]uint32
	out    chan *events.Event
	done   chan struct{}
	names  NameCache

	wg        sync.WaitGroup
	stopOnce  sync.Once
	closeOnce sync.Once
	emitted   atomic.Uint64
}

// NewReplayCollector loads the traces so that a bad path fails before Start.
func NewReplayCollector(logger *logrus.Logger, cfg ReplayConfig) (*ReplayCollector, error) {
	traces, err := LoadTraces(cfg.Path)
	if err != nil {
		return nil, err
	}
	if cfg.ChanSize <= 0 {
		cfg.ChanSize = 4096
	}
	if cfg.PID == 0 {
		cfg.PID = 4242
	}
	return &ReplayCollector{
		cfg:    cfg,
		logger: logger,
		traces: traces,
		out:    make(chan *events.Event, cfg.ChanSize),
		done:   make(chan struct{}),
	}, nil
}

// Traces returns the number of traces and the total number of syscalls loaded.
func (c *ReplayCollector) Traces() (int, int) {
	n := 0
	for _, t := range c.traces {
		n += len(t)
	}
	return len(c.traces), n
}

// Emitted returns how many events were sent so far.
func (c *ReplayCollector) Emitted() uint64 { return c.emitted.Load() }

// Start begins the replay in the background.
func (c *ReplayCollector) Start(ctx context.Context) error {
	c.wg.Add(1)
	go c.run(ctx)
	nTraces, nEvents := c.Traces()
	c.logger.WithFields(logrus.Fields{
		"traces": nTraces, "events": nEvents, "eps": c.cfg.EventsPerSecond, "loop": c.cfg.Loop, "binary": c.cfg.Binary,
	}).Info("Replay collector started")
	return nil
}

func (c *ReplayCollector) run(ctx context.Context) {
	defer c.wg.Done()
	defer c.closeOnce.Do(func() { close(c.out) })

	// Pacing: at most once per millisecond, send the events due in that slot.
	var ticker *time.Ticker
	perTick := 0
	if c.cfg.EventsPerSecond > 0 {
		ticker = time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		perTick = c.cfg.EventsPerSecond / 1000
		if perTick < 1 {
			perTick = 1
			ticker.Reset(time.Second / time.Duration(c.cfg.EventsPerSecond))
		}
	}

	var seq uint64
	for {
		for ti, trace := range c.traces {
			pid := c.cfg.PID + uint32(ti)
			for i := 0; i < len(trace); {
				budget := len(trace) - i
				if ticker != nil {
					select {
					case <-ticker.C:
					case <-ctx.Done():
						return
					case <-c.done:
						return
					}
					if perTick < budget {
						budget = perTick
					}
				}
				for ; budget > 0; budget-- {
					seq++
					ev := c.event(pid, trace[i], seq)
					select {
					case c.out <- ev:
						c.emitted.Add(1)
					case <-ctx.Done():
						return
					case <-c.done:
						return
					}
					i++
				}
			}
		}
		if !c.cfg.Loop {
			return
		}
	}
}

// event builds one syscall event through the same conversion the eBPF path uses.
func (c *ReplayCollector) event(pid, nr uint32, seq uint64) *events.Event {
	kev := &ebpf.Event{
		Type:        ebpf.EventSyscall,
		TypeName:    "syscall",
		MonotonicNs: seq,
		Timestamp:   time.Now(),
		PID:         pid,
		PPID:        1,
		Comm:        "replay",
		SyscallNr:   nr,
		// ADFA-LD numbers are i386; the x86_64 name table does not apply.
		SyscallName: "",
	}
	if c.cfg.Binary {
		kev.Raw = kev.Record()
	}
	ev := EventFromEBPF(kev, &c.names)
	ev.Source = "replay"
	return ev
}

// Stop ends the replay and closes the channel.
func (c *ReplayCollector) Stop() error {
	c.stopOnce.Do(func() {
		close(c.done)
		c.wg.Wait()
		c.closeOnce.Do(func() { close(c.out) })
		c.logger.WithField("emitted", c.emitted.Load()).Info("Replay collector stopped")
	})
	return nil
}

// EventChannel returns the replayed events; it is closed when the replay ends.
func (c *ReplayCollector) EventChannel() <-chan *events.Event { return c.out }

// LoadTraces reads one trace file or every *.txt under a directory (sorted).
func LoadTraces(path string) ([][]uint32, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("replay path: %w", err)
	}
	var files []string
	if info.IsDir() {
		err := filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !fi.IsDir() && strings.HasSuffix(fi.Name(), ".txt") {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
	} else {
		files = []string{path}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.txt traces under %s", path)
	}
	traces := make([][]uint32, 0, len(files))
	for _, f := range files {
		t, err := LoadTrace(f)
		if err != nil {
			return nil, err
		}
		if len(t) > 0 {
			traces = append(traces, t)
		}
	}
	return traces, nil
}

// LoadTrace parses whitespace-separated syscall numbers; other tokens are skipped.
func LoadTrace(path string) ([]uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []uint32
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	sc.Split(bufio.ScanWords)
	for sc.Scan() {
		if n, err := strconv.ParseUint(sc.Text(), 10, 32); err == nil {
			out = append(out, uint32(n))
		}
	}
	return out, sc.Err()
}
