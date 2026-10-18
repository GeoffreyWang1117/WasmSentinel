// Package pipeline connects collectors, the rule engine and the output
// handlers: it merges the collectors' event channels into one queue, runs
// every event through engine.DetectThreat and hands detections to the output.
// It stops when the context is cancelled or when every collector has closed
// its channel (which a replay does when the trace ends).
package pipeline

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/wasm-threat-detector/host/internal/collector"
	"github.com/wasm-threat-detector/host/internal/engine"
	"github.com/wasm-threat-detector/host/internal/events"
	"github.com/wasm-threat-detector/host/internal/metrics"
	"github.com/wasm-threat-detector/host/internal/output"
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

	defer func() { st.Elapsed = time.Since(start) }()
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
			if cfg.Metrics != nil {
				cfg.Metrics.ObserveEvent(ev.Type, time.Since(t0))
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
		}
	}
}
