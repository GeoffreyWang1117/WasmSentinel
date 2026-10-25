// Package pipeline connects collectors, the rule engine and the output
// handlers: it merges the collectors' event channels into one queue, runs
// every event through engine.DetectThreat and hands detections to the output.
// It stops when the context is cancelled or when every collector has closed
// its channel (which a replay does when the trace ends).
package pipeline

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/collector"
	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/engine"
	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/events"
	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/metrics"
	"github.com/GeoffreyWang1117/WasmSentinel/host/internal/output"
	"github.com/sirupsen/logrus"
)

// Config wires one pipeline run.
type Config struct {
	Engine     engine.ThreatEngine
	Collectors []collector.Collector
	Output     output.OutputHandler
	Metrics    *metrics.Metrics // optional
	Logger     *logrus.Logger   // optional
	QueueSize  int              // merged queue capacity; 0 means 1000
}

// Stats summarizes a run.
type Stats struct {
	Events       uint64 // events taken from the queue and run through the engine
	Alerts       uint64 // detections handed to the output
	DetectErrors uint64 // DetectThreat returned an error (event-level, not rule-level)
	OutputErrors uint64
	Elapsed      time.Duration

	// EndToEnd is the distribution of event timestamp -> output handled
	// (queue wait + detection + output), from up to MaxLatencySamples events.
	EndToEnd Percentiles
	// Detect is the distribution of DetectThreat alone.
	Detect Percentiles
}

// Percentiles of a latency sample.
type Percentiles struct {
	Samples             int
	P50, P90, P99, P999 time.Duration
	Max                 time.Duration
	Mean                time.Duration
}

// MaxLatencySamples bounds the memory used for latency recording (4 B each).
const MaxLatencySamples = 4_000_000

func percentiles(us []int32) Percentiles {
	if len(us) == 0 {
		return Percentiles{}
	}
	sorted := append([]int32(nil), us...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	q := func(f float64) time.Duration {
		i := int(f * float64(len(sorted)-1))
		return time.Duration(sorted[i]) * time.Microsecond
	}
	var sum int64
	for _, v := range sorted {
		sum += int64(v)
	}
	return Percentiles{
		Samples: len(sorted), P50: q(0.50), P90: q(0.90), P99: q(0.99), P999: q(0.999),
		Max:  time.Duration(sorted[len(sorted)-1]) * time.Microsecond,
		Mean: time.Duration(sum/int64(len(sorted))) * time.Microsecond,
	}
}

// Run drives the pipeline until ctx is done or all collectors closed their
// channels. Collectors are not started or stopped here. The merged queue
// applies back-pressure: a slow engine slows the collectors instead of
// silently losing events; the kernel-side collector counts its own drops.
func Run(ctx context.Context, cfg Config) (st Stats) {
	logger := cfg.Logger
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.PanicLevel)
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1000
	}
	start := time.Now()
	queue := make(chan *events.Event, cfg.QueueSize)

	var wg sync.WaitGroup
	for _, c := range cfg.Collectors {
		wg.Add(1)
		go func(c collector.Collector) {
			defer wg.Done()
			for ev := range c.EventChannel() {
				select {
				case queue <- ev:
				case <-ctx.Done():
					return
				}
			}
		}(c)
	}
	go func() {
		wg.Wait()
		close(queue)
	}()

	e2e := make([]int32, 0, 1<<16)
	det := make([]int32, 0, 1<<16)
	defer func() {
		st.Elapsed = time.Since(start)
		st.EndToEnd = percentiles(e2e)
		st.Detect = percentiles(det)
	}()
	for {
		select {
		case <-ctx.Done():
			return st
		case ev, ok := <-queue:
			if !ok {
				return st
			}
			st.Events++
			t0 := time.Now()
			results, err := cfg.Engine.DetectThreat(ctx, ev)
			dDetect := time.Since(t0)
			if cfg.Metrics != nil {
				cfg.Metrics.ObserveEvent(ev.Type, dDetect)
			}
			if err != nil {
				st.DetectErrors++
				logger.WithError(err).Warn("Threat detection failed")
				continue
			}
			for _, r := range results {
				st.Alerts++
				if err := cfg.Output.Handle(r); err != nil {
					st.OutputErrors++
					logger.WithError(err).Warn("Failed to handle detection result")
				}
			}
			if len(det) < MaxLatencySamples {
				det = append(det, int32(dDetect.Microseconds()))
				if !ev.Timestamp.IsZero() {
					if d := time.Since(ev.Timestamp); d >= 0 && d < 1<<31*time.Microsecond {
						e2e = append(e2e, int32(d.Microseconds()))
					}
				}
			}
		}
	}
}
