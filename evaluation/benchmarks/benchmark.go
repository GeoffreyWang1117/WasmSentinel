// Package benchmarks provides performance evaluation framework for WasmSentinel
package benchmarks

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// BenchmarkResult holds the results of a benchmark run
type BenchmarkResult struct {
	Name        string            `json:"name"`
	StartTime   time.Time         `json:"start_time"`
	EndTime     time.Time         `json:"end_time"`
	Duration    time.Duration     `json:"duration"`
	Iterations  int               `json:"iterations"`
	Metrics     PerformanceMetrics `json:"metrics"`
	Latencies   LatencyStats      `json:"latencies"`
	Throughput  ThroughputStats   `json:"throughput"`
	ResourceUse ResourceStats     `json:"resource_use"`
	Errors      []string          `json:"errors,omitempty"`
}

// PerformanceMetrics holds detailed performance measurements
type PerformanceMetrics struct {
	TotalEvents     int64   `json:"total_events"`
	ProcessedEvents int64   `json:"processed_events"`
	DroppedEvents   int64   `json:"dropped_events"`
	DetectedThreats int64   `json:"detected_threats"`
	FalsePositives  int64   `json:"false_positives"`
	FalseNegatives  int64   `json:"false_negatives"`
	Precision       float64 `json:"precision"`
	Recall          float64 `json:"recall"`
	F1Score         float64 `json:"f1_score"`
}

// LatencyStats holds latency statistics
type LatencyStats struct {
	Min    time.Duration `json:"min_ns"`
	Max    time.Duration `json:"max_ns"`
	Mean   time.Duration `json:"mean_ns"`
	Median time.Duration `json:"median_ns"`
	P90    time.Duration `json:"p90_ns"`
	P95    time.Duration `json:"p95_ns"`
	P99    time.Duration `json:"p99_ns"`
	P999   time.Duration `json:"p999_ns"`
	StdDev time.Duration `json:"stddev_ns"`

	// Breakdown by component
	EventCollection time.Duration `json:"event_collection_ns"`
	Serialization   time.Duration `json:"serialization_ns"`
	WasmTransfer    time.Duration `json:"wasm_transfer_ns"`
	Detection       time.Duration `json:"detection_ns"`
}

// ThroughputStats holds throughput statistics
type ThroughputStats struct {
	EventsPerSecond     float64 `json:"events_per_second"`
	BytesPerSecond      float64 `json:"bytes_per_second"`
	DetectionsPerSecond float64 `json:"detections_per_second"`
	PeakEventsPerSecond float64 `json:"peak_events_per_second"`
}

// ResourceStats holds resource usage statistics
type ResourceStats struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryMB      float64 `json:"memory_mb"`
	GoroutineCount int    `json:"goroutine_count"`
	HeapAllocMB   float64 `json:"heap_alloc_mb"`
}

// Benchmark represents a single benchmark configuration
type Benchmark struct {
	Name        string
	Description string
	Setup       func() error
	Run         func(ctx context.Context, collector LatencyCollector) error
	Teardown    func() error
	Iterations  int
	Warmup      int
	Timeout     time.Duration
}

// LatencyCollector interface for recording latencies during benchmark
type LatencyCollector interface {
	RecordLatency(duration time.Duration)
	RecordComponentLatency(component string, duration time.Duration)
	RecordEvent(isDetection bool, isTrue bool)
}

// DefaultLatencyCollector implements LatencyCollector
type DefaultLatencyCollector struct {
	latencies          []time.Duration
	componentLatencies map[string][]time.Duration
	mu                 sync.Mutex

	truePositives  atomic.Int64
	falsePositives atomic.Int64
	trueNegatives  atomic.Int64
	falseNegatives atomic.Int64
}

// NewLatencyCollector creates a new latency collector
func NewLatencyCollector() *DefaultLatencyCollector {
	return &DefaultLatencyCollector{
		latencies:          make([]time.Duration, 0, 100000),
		componentLatencies: make(map[string][]time.Duration),
	}
}

func (c *DefaultLatencyCollector) RecordLatency(d time.Duration) {
	c.mu.Lock()
	c.latencies = append(c.latencies, d)
	c.mu.Unlock()
}

func (c *DefaultLatencyCollector) RecordComponentLatency(component string, d time.Duration) {
	c.mu.Lock()
	if c.componentLatencies[component] == nil {
		c.componentLatencies[component] = make([]time.Duration, 0, 100000)
	}
	c.componentLatencies[component] = append(c.componentLatencies[component], d)
	c.mu.Unlock()
}

func (c *DefaultLatencyCollector) RecordEvent(isDetection bool, isTrue bool) {
	if isDetection {
		if isTrue {
			c.truePositives.Add(1)
		} else {
			c.falsePositives.Add(1)
		}
	} else {
		if isTrue {
			c.trueNegatives.Add(1)
		} else {
			c.falseNegatives.Add(1)
		}
	}
}

// GetStats calculates statistics from collected latencies
func (c *DefaultLatencyCollector) GetStats() LatencyStats {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.latencies) == 0 {
		return LatencyStats{}
	}

	sorted := make([]time.Duration, len(c.latencies))
	copy(sorted, c.latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	stats := LatencyStats{
		Min:    sorted[0],
		Max:    sorted[len(sorted)-1],
		Median: percentile(sorted, 50),
		P90:    percentile(sorted, 90),
		P95:    percentile(sorted, 95),
		P99:    percentile(sorted, 99),
		P999:   percentile(sorted, 99.9),
	}

	// Calculate mean
	var sum time.Duration
	for _, d := range sorted {
		sum += d
	}
	stats.Mean = time.Duration(int64(sum) / int64(len(sorted)))

	// Calculate stddev
	var sumSquares float64
	mean := float64(stats.Mean)
	for _, d := range sorted {
		diff := float64(d) - mean
		sumSquares += diff * diff
	}
	stats.StdDev = time.Duration(math.Sqrt(sumSquares / float64(len(sorted))))

	// Get component latencies
	if ec, ok := c.componentLatencies["event_collection"]; ok && len(ec) > 0 {
		stats.EventCollection = average(ec)
	}
	if s, ok := c.componentLatencies["serialization"]; ok && len(s) > 0 {
		stats.Serialization = average(s)
	}
	if wt, ok := c.componentLatencies["wasm_transfer"]; ok && len(wt) > 0 {
		stats.WasmTransfer = average(wt)
	}
	if d, ok := c.componentLatencies["detection"]; ok && len(d) > 0 {
		stats.Detection = average(d)
	}

	return stats
}

// GetMetrics returns performance metrics
func (c *DefaultLatencyCollector) GetMetrics() PerformanceMetrics {
	tp := float64(c.truePositives.Load())
	fp := float64(c.falsePositives.Load())
	fn := float64(c.falseNegatives.Load())

	var precision, recall, f1 float64
	if tp+fp > 0 {
		precision = tp / (tp + fp)
	}
	if tp+fn > 0 {
		recall = tp / (tp + fn)
	}
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}

	return PerformanceMetrics{
		TotalEvents:     int64(len(c.latencies)),
		DetectedThreats: c.truePositives.Load() + c.falsePositives.Load(),
		FalsePositives:  c.falsePositives.Load(),
		FalseNegatives:  c.falseNegatives.Load(),
		Precision:       precision,
		Recall:          recall,
		F1Score:         f1,
	}
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p / 100)
	return sorted[idx]
}

func average(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	var sum time.Duration
	for _, d := range durations {
		sum += d
	}
	return time.Duration(int64(sum) / int64(len(durations)))
}

// BenchmarkSuite manages multiple benchmarks
type BenchmarkSuite struct {
	name       string
	benchmarks []*Benchmark
	results    []*BenchmarkResult
	logger     Logger
}

// Logger interface for benchmark logging
type Logger interface {
	Printf(format string, args ...interface{})
}

// NewBenchmarkSuite creates a new benchmark suite
func NewBenchmarkSuite(name string, logger Logger) *BenchmarkSuite {
	return &BenchmarkSuite{
		name:       name,
		benchmarks: make([]*Benchmark, 0),
		results:    make([]*BenchmarkResult, 0),
		logger:     logger,
	}
}

// Add adds a benchmark to the suite
func (s *BenchmarkSuite) Add(b *Benchmark) {
	s.benchmarks = append(s.benchmarks, b)
}

// Run executes all benchmarks in the suite
func (s *BenchmarkSuite) Run(ctx context.Context) error {
	s.logger.Printf("Starting benchmark suite: %s", s.name)
	s.logger.Printf("Total benchmarks: %d", len(s.benchmarks))

	for i, b := range s.benchmarks {
		s.logger.Printf("[%d/%d] Running: %s", i+1, len(s.benchmarks), b.Name)

		result, err := s.runBenchmark(ctx, b)
		if err != nil {
			s.logger.Printf("  ERROR: %v", err)
			result.Errors = append(result.Errors, err.Error())
		}

		s.results = append(s.results, result)
		s.printResult(result)
	}

	return nil
}

func (s *BenchmarkSuite) runBenchmark(ctx context.Context, b *Benchmark) (*BenchmarkResult, error) {
	result := &BenchmarkResult{
		Name:       b.Name,
		StartTime:  time.Now(),
		Iterations: b.Iterations,
	}

	// Setup
	if b.Setup != nil {
		if err := b.Setup(); err != nil {
			return result, fmt.Errorf("setup failed: %w", err)
		}
	}

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()

	// Warmup
	if b.Warmup > 0 {
		s.logger.Printf("  Warmup: %d iterations", b.Warmup)
		warmupCollector := NewLatencyCollector()
		for i := 0; i < b.Warmup; i++ {
			if err := b.Run(timeoutCtx, warmupCollector); err != nil {
				return result, fmt.Errorf("warmup failed: %w", err)
			}
		}
	}

	// Run benchmark
	collector := NewLatencyCollector()
	for i := 0; i < b.Iterations; i++ {
		if err := b.Run(timeoutCtx, collector); err != nil {
			result.Errors = append(result.Errors, err.Error())
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Latencies = collector.GetStats()
	result.Metrics = collector.GetMetrics()

	// Calculate throughput
	durationSec := result.Duration.Seconds()
	if durationSec > 0 {
		result.Throughput = ThroughputStats{
			EventsPerSecond: float64(result.Metrics.TotalEvents) / durationSec,
		}
	}

	// Teardown
	if b.Teardown != nil {
		if err := b.Teardown(); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("teardown error: %v", err))
		}
	}

	return result, nil
}

func (s *BenchmarkSuite) printResult(r *BenchmarkResult) {
	s.logger.Printf("  Duration: %v", r.Duration)
	s.logger.Printf("  Iterations: %d", r.Iterations)
	s.logger.Printf("  Latency (mean): %v", r.Latencies.Mean)
	s.logger.Printf("  Latency (p99): %v", r.Latencies.P99)
	s.logger.Printf("  Throughput: %.2f events/sec", r.Throughput.EventsPerSecond)
	if r.Metrics.F1Score > 0 {
		s.logger.Printf("  F1 Score: %.4f", r.Metrics.F1Score)
	}
}

// Results returns all benchmark results
func (s *BenchmarkSuite) Results() []*BenchmarkResult {
	return s.results
}

// SaveResults saves results to a JSON file
func (s *BenchmarkSuite) SaveResults(filename string) error {
	data, err := json.MarshalIndent(s.results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// ComparisonResult holds comparison between two systems
type ComparisonResult struct {
	System1Name    string           `json:"system1_name"`
	System2Name    string           `json:"system2_name"`
	LatencyRatio   float64          `json:"latency_ratio"`   // system1/system2
	ThroughputRatio float64         `json:"throughput_ratio"`
	AccuracyDiff   float64          `json:"accuracy_diff"`   // system1 - system2
	System1Results *BenchmarkResult `json:"system1_results"`
	System2Results *BenchmarkResult `json:"system2_results"`
	Winner         string           `json:"winner"`
	Summary        string           `json:"summary"`
}

// Compare compares two benchmark results
func Compare(r1, r2 *BenchmarkResult) *ComparisonResult {
	comp := &ComparisonResult{
		System1Name:    r1.Name,
		System2Name:    r2.Name,
		System1Results: r1,
		System2Results: r2,
	}

	// Latency ratio (lower is better)
	if r2.Latencies.Mean > 0 {
		comp.LatencyRatio = float64(r1.Latencies.Mean) / float64(r2.Latencies.Mean)
	}

	// Throughput ratio (higher is better)
	if r2.Throughput.EventsPerSecond > 0 {
		comp.ThroughputRatio = r1.Throughput.EventsPerSecond / r2.Throughput.EventsPerSecond
	}

	// Accuracy difference
	comp.AccuracyDiff = r1.Metrics.F1Score - r2.Metrics.F1Score

	// Determine winner (simple heuristic)
	score1 := 0
	score2 := 0
	if comp.LatencyRatio < 1 {
		score1++
	} else {
		score2++
	}
	if comp.ThroughputRatio > 1 {
		score1++
	} else {
		score2++
	}
	if comp.AccuracyDiff > 0 {
		score1++
	} else if comp.AccuracyDiff < 0 {
		score2++
	}

	if score1 > score2 {
		comp.Winner = r1.Name
	} else if score2 > score1 {
		comp.Winner = r2.Name
	} else {
		comp.Winner = "tie"
	}

	comp.Summary = fmt.Sprintf(
		"%s vs %s: latency %.2fx, throughput %.2fx, accuracy diff %.4f",
		r1.Name, r2.Name, comp.LatencyRatio, comp.ThroughputRatio, comp.AccuracyDiff,
	)

	return comp
}
