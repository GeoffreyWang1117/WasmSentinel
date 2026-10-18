// Package metrics exposes the detector's counters to Prometheus. Everything
// here is backed by real counters fed from the pipeline: threats from the
// output path, rule invocations from the engine observer, pipeline events from
// the event loop, and per-rule / collector snapshots read at scrape time.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/wasm-threat-detector/host/internal/ebpf"
	"github.com/wasm-threat-detector/host/internal/engine"
	"github.com/wasm-threat-detector/host/internal/events"
)

const namespace = "wasmsentinel"

// Metrics owns a private registry and the instruments on it.
type Metrics struct {
	reg *prometheus.Registry

	threats       *prometheus.CounterVec
	eventsTotal   *prometheus.CounterVec
	eventsDropped prometheus.Counter
	detectLatency prometheus.Histogram

	ruleCalls   *prometheus.CounterVec
	ruleErrors  *prometheus.CounterVec
	ruleFuel    *prometheus.CounterVec
	ruleLatency *prometheus.HistogramVec

	buildInfo *prometheus.GaugeVec
}

// New creates the registry with Go runtime and process collectors attached.
func New() *Metrics {
	m := &Metrics{reg: prometheus.NewRegistry()}
	m.threats = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "threats_total",
		Help: "Detections emitted by rules, by rule and severity.",
	}, []string{"rule", "severity"})
	m.eventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "events_total",
		Help: "Events handed to the rule engine, by event type.",
	}, []string{"type"})
	m.eventsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace, Name: "events_dropped_total",
		Help: "Events dropped because the pipeline queue was full.",
	})
	m.detectLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: namespace, Name: "detect_latency_seconds",
		Help:    "Wall time of DetectThreat per event (all rules).",
		Buckets: prometheus.ExponentialBuckets(1e-6, 2, 18), // 1 us .. 131 ms
	})
	m.ruleCalls = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "rule_calls_total",
		Help: "Rule invocations, by rule and event encoding.",
	}, []string{"rule", "encoding"})
	m.ruleErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "rule_errors_total",
		Help: "Failed rule invocations, by rule and kind (fuel, timeout, memory, exit, trap, abi).",
	}, []string{"rule", "kind"})
	m.ruleFuel = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "rule_fuel_total",
		Help: "Wasm fuel consumed by rule invocations.",
	}, []string{"rule"})
	m.ruleLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Name: "rule_latency_seconds",
		Help:    "Wall time of one rule invocation.",
		Buckets: prometheus.ExponentialBuckets(1e-6, 2, 16), // 1 us .. 32 ms
	}, []string{"rule"})
	m.buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Name: "build_info",
		Help: "Constant 1, labelled with the running configuration.",
	}, []string{"collector", "encoding", "wasmtime"})

	m.reg.MustRegister(
		m.threats, m.eventsTotal, m.eventsDropped, m.detectLatency,
		m.ruleCalls, m.ruleErrors, m.ruleFuel, m.ruleLatency, m.buildInfo,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// Handler serves the registry in the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// Registry exposes the registry (tests, additional collectors).
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// SetBuildInfo records the running configuration as labels on a constant gauge.
func (m *Metrics) SetBuildInfo(collector, encoding, wasmtime string) {
	m.buildInfo.WithLabelValues(collector, encoding, wasmtime).Set(1)
}

// Handle implements output.OutputHandler: one detection, one increment.
func (m *Metrics) Handle(result *events.DetectionResult) error {
	m.threats.WithLabelValues(result.RuleName, result.Severity).Inc()
	return nil
}

// Close implements output.OutputHandler.
func (m *Metrics) Close() error { return nil }

// ObserveInvoke implements engine.Observer.
func (m *Metrics) ObserveInvoke(rule string, raw bool, d time.Duration, fuel uint64, err error) {
	enc := "json"
	if raw {
		enc = "binary"
	}
	m.ruleCalls.WithLabelValues(rule, enc).Inc()
	m.ruleLatency.WithLabelValues(rule).Observe(d.Seconds())
	if fuel > 0 {
		m.ruleFuel.WithLabelValues(rule).Add(float64(fuel))
	}
	if err != nil {
		kind := "trap"
		var re *engine.RuleError
		if asRuleError(err, &re) && re.Kind != "" {
			kind = string(re.Kind)
		}
		m.ruleErrors.WithLabelValues(rule, kind).Inc()
	}
}

// ObserveEvent records one event going through the pipeline.
func (m *Metrics) ObserveEvent(t events.EventType, d time.Duration) {
	m.eventsTotal.WithLabelValues(string(t)).Inc()
	m.detectLatency.Observe(d.Seconds())
}

// ObserveDrop records an event dropped before detection.
func (m *Metrics) ObserveDrop() { m.eventsDropped.Inc() }

// RuleStatser is what RegisterEngine needs from the engine.
type RuleStatser interface {
	Stats() map[string]engine.RuleStats
}

// RegisterEngine adds scrape-time gauges derived from the engine's per-rule
// snapshot: live linear memory and re-instantiations.
func (m *Metrics) RegisterEngine(e RuleStatser) {
	m.reg.MustRegister(&engineCollector{stats: e.Stats})
}

type engineCollector struct {
	stats func() map[string]engine.RuleStats
}

var (
	descRuleMemory = prometheus.NewDesc(namespace+"_rule_memory_bytes",
		"Linear memory of the rule's live Wasm instance.", []string{"rule"}, nil)
	descRuleReinst = prometheus.NewDesc(namespace+"_rule_reinstantiations_total",
		"Instances created after a trap, by rule.", []string{"rule"}, nil)
	descRuleThreats = prometheus.NewDesc(namespace+"_rule_positive_calls_total",
		"Invocations that returned a level above zero, by rule.", []string{"rule"}, nil)
)

func (c *engineCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descRuleMemory
	ch <- descRuleReinst
	ch <- descRuleThreats
}

func (c *engineCollector) Collect(ch chan<- prometheus.Metric) {
	for name, st := range c.stats() {
		ch <- prometheus.MustNewConstMetric(descRuleMemory, prometheus.GaugeValue, float64(st.MemoryBytes), name)
		ch <- prometheus.MustNewConstMetric(descRuleReinst, prometheus.CounterValue, float64(st.Reinstantiations), name)
		ch <- prometheus.MustNewConstMetric(descRuleThreats, prometheus.CounterValue, float64(st.Threats), name)
	}
}

// EBPFStatser is what RegisterEBPF needs from the eBPF collector.
type EBPFStatser interface {
	Stats() *ebpf.Stats
}

// RegisterEBPF adds scrape-time counters from the eBPF collector.
func (m *Metrics) RegisterEBPF(c EBPFStatser) {
	m.reg.MustRegister(&ebpfCollector{stats: c.Stats})
}

type ebpfCollector struct {
	stats func() *ebpf.Stats
}

var (
	descCollReceived = prometheus.NewDesc(namespace+"_collector_records_total",
		"Ring buffer records read by the eBPF collector.", nil, nil)
	descCollDropped = prometheus.NewDesc(namespace+"_collector_dropped_total",
		"Records the eBPF collector could not deliver.", nil, nil)
	descCollByType = prometheus.NewDesc(namespace+"_collector_events_total",
		"Decoded kernel events, by type.", []string{"type"}, nil)
)

func (c *ebpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descCollReceived
	ch <- descCollDropped
	ch <- descCollByType
}

func (c *ebpfCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.stats()
	if s == nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(descCollReceived, prometheus.CounterValue, float64(s.Received))
	ch <- prometheus.MustNewConstMetric(descCollDropped, prometheus.CounterValue, float64(s.Dropped))
	for t, n := range s.ByType {
		ch <- prometheus.MustNewConstMetric(descCollByType, prometheus.CounterValue, float64(n), t)
	}
}

func asRuleError(err error, target **engine.RuleError) bool {
	for err != nil {
		if re, ok := err.(*engine.RuleError); ok {
			*target = re
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
