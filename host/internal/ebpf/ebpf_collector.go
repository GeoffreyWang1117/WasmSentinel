// Package ebpf provides high-performance kernel-level event collection using eBPF
package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -target bpfel sentinel ./bpf/sentinel.bpf.c

// Event types matching eBPF definitions
const (
	EventProcessExec    = 1
	EventProcessExit    = 2
	EventFileOpen       = 3
	EventNetworkConnect = 4
	EventNetworkAccept  = 5
	EventSyscall        = 6
)

const (
	MaxFilenameLen = 256
	MaxCommLen     = 16
	MaxArgsLen     = 256
)

// RawEvent represents the event structure from eBPF (must match C struct)
type RawEvent struct {
	TimestampNs uint64
	PID         uint32
	PPID        uint32
	UID         uint32
	GID         uint32
	EventType   uint32
	RetVal      int64
	Comm        [MaxCommLen]byte
	Filename    [MaxFilenameLen]byte
	SAddr       uint32
	DAddr       uint32
	SPort       uint16
	DPort       uint16
	Family      uint16
	Protocol    uint16
	SyscallNr   uint32
	Flags       uint32
	Args        [MaxArgsLen]byte
	ArgsLen     uint32
}

// Event is the processed event structure for consumption
type Event struct {
	Timestamp time.Time
	PID       uint32
	PPID      uint32
	UID       uint32
	GID       uint32
	EventType uint32
	EventName string
	RetVal    int64
	Comm      string
	Filename  string
	Args      string
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	SyscallNr uint32
	Flags     uint32
}

// CollectorStats holds statistics about event collection
type CollectorStats struct {
	EventsReceived   uint64
	EventsDropped    uint64
	EventsProcessed  uint64
	ProcessExecCount uint64
	ProcessExitCount uint64
	FileOpenCount    uint64
	NetworkCount     uint64
	SyscallCount     uint64
	LastEventTime    time.Time
	StartTime        time.Time
}

// Collector is the eBPF-based event collector
type Collector struct {
	objs      *sentinelObjects
	links     []link.Link
	reader    *ringbuf.Reader
	eventChan chan *Event
	stopChan  chan struct{}
	wg        sync.WaitGroup
	stats     CollectorStats
	mu        sync.RWMutex
	logger    *logrus.Logger

	// Batch processing
	batchSize     int
	batchTimeout  time.Duration
	adaptiveBatch bool

	// Metrics
	eventsReceived  atomic.Uint64
	eventsProcessed atomic.Uint64
	eventsDropped   atomic.Uint64
}

// CollectorConfig holds configuration for the eBPF collector
type CollectorConfig struct {
	EventChanSize int
	BatchSize     int
	BatchTimeout  time.Duration
	AdaptiveBatch bool
	Logger        *logrus.Logger
}

// DefaultCollectorConfig returns default configuration
func DefaultCollectorConfig() *CollectorConfig {
	return &CollectorConfig{
		EventChanSize: 10000,
		BatchSize:     100,
		BatchTimeout:  10 * time.Millisecond,
		AdaptiveBatch: true,
		Logger:        logrus.StandardLogger(),
	}
}

// NewCollector creates a new eBPF-based event collector
func NewCollector(config *CollectorConfig) (*Collector, error) {
	if config == nil {
		config = DefaultCollectorConfig()
	}

	// Remove memory lock limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load pre-compiled eBPF programs and maps
	objs := &sentinelObjects{}
	if err := loadSentinelObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load eBPF objects: %w", err)
	}

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to create ring buffer reader: %w", err)
	}

	c := &Collector{
		objs:          objs,
		links:         make([]link.Link, 0),
		reader:        reader,
		eventChan:     make(chan *Event, config.EventChanSize),
		stopChan:      make(chan struct{}),
		logger:        config.Logger,
		batchSize:     config.BatchSize,
		batchTimeout:  config.BatchTimeout,
		adaptiveBatch: config.AdaptiveBatch,
		stats: CollectorStats{
			StartTime: time.Now(),
		},
	}

	return c, nil
}

// Start begins collecting events
func (c *Collector) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Attach tracepoints and kprobes
	if err := c.attachPrograms(); err != nil {
		return fmt.Errorf("failed to attach eBPF programs: %w", err)
	}

	// Start event reader goroutine
	c.wg.Add(1)
	go c.readEvents()

	c.logger.Info("eBPF collector started successfully")
	return nil
}

// attachPrograms attaches all eBPF programs to their hooks
func (c *Collector) attachPrograms() error {
	var err error
	var l link.Link

	// Attach execve tracepoint
	l, err = link.Tracepoint("syscalls", "sys_enter_execve", c.objs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		return fmt.Errorf("failed to attach execve tracepoint: %w", err)
	}
	c.links = append(c.links, l)
	c.logger.Debug("Attached sys_enter_execve tracepoint")

	// Attach process exit tracepoint
	l, err = link.Tracepoint("sched", "sched_process_exit", c.objs.TracepointSchedSchedProcessExit, nil)
	if err != nil {
		return fmt.Errorf("failed to attach process exit tracepoint: %w", err)
	}
	c.links = append(c.links, l)
	c.logger.Debug("Attached sched_process_exit tracepoint")

	// Attach openat tracepoint
	l, err = link.Tracepoint("syscalls", "sys_enter_openat", c.objs.TracepointSyscallsSysEnterOpenat, nil)
	if err != nil {
		return fmt.Errorf("failed to attach openat tracepoint: %w", err)
	}
	c.links = append(c.links, l)
	c.logger.Debug("Attached sys_enter_openat tracepoint")

	// Attach tcp_connect kprobe
	l, err = link.Kprobe("tcp_connect", c.objs.KprobeTcpConnect, nil)
	if err != nil {
		c.logger.Warnf("Failed to attach tcp_connect kprobe: %v (network events may be limited)", err)
	} else {
		c.links = append(c.links, l)
		c.logger.Debug("Attached tcp_connect kprobe")
	}

	// Attach inet_csk_accept kretprobe
	l, err = link.Kretprobe("inet_csk_accept", c.objs.KretprobeInetCskAccept, nil)
	if err != nil {
		c.logger.Warnf("Failed to attach inet_csk_accept kretprobe: %v (network events may be limited)", err)
	} else {
		c.links = append(c.links, l)
		c.logger.Debug("Attached inet_csk_accept kretprobe")
	}

	// Attach raw tracepoint for syscalls
	l, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: c.objs.RawTpSysEnter,
	})
	if err != nil {
		c.logger.Warnf("Failed to attach sys_enter raw tracepoint: %v", err)
	} else {
		c.links = append(c.links, l)
		c.logger.Debug("Attached sys_enter raw tracepoint")
	}

	return nil
}

// readEvents continuously reads events from the ring buffer
func (c *Collector) readEvents() {
	defer c.wg.Done()

	for {
		select {
		case <-c.stopChan:
			return
		default:
		}

		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			c.logger.Errorf("Error reading from ring buffer: %v", err)
			c.eventsDropped.Add(1)
			continue
		}

		c.eventsReceived.Add(1)

		event, err := c.parseEvent(record.RawSample)
		if err != nil {
			c.logger.Debugf("Error parsing event: %v", err)
			c.eventsDropped.Add(1)
			continue
		}

		// Non-blocking send to event channel
		select {
		case c.eventChan <- event:
			c.eventsProcessed.Add(1)
			c.updateStats(event)
		default:
			c.eventsDropped.Add(1)
		}
	}
}

// parseEvent parses a raw event from eBPF
func (c *Collector) parseEvent(data []byte) (*Event, error) {
	if len(data) < int(unsafe.Sizeof(RawEvent{})) {
		return nil, fmt.Errorf("event data too short: %d bytes", len(data))
	}

	var raw RawEvent
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse raw event: %w", err)
	}

	event := &Event{
		Timestamp: time.Unix(0, int64(raw.TimestampNs)),
		PID:       raw.PID,
		PPID:      raw.PPID,
		UID:       raw.UID,
		GID:       raw.GID,
		EventType: raw.EventType,
		RetVal:    raw.RetVal,
		Comm:      nullTerminatedString(raw.Comm[:]),
		Filename:  nullTerminatedString(raw.Filename[:]),
		Args:      nullTerminatedString(raw.Args[:]),
		SrcPort:   raw.SPort,
		DstPort:   raw.DPort,
		SyscallNr: raw.SyscallNr,
		Flags:     raw.Flags,
	}

	// Parse IP addresses
	if raw.SAddr != 0 {
		event.SrcIP = uint32ToIP(raw.SAddr)
	}
	if raw.DAddr != 0 {
		event.DstIP = uint32ToIP(raw.DAddr)
	}

	// Set event name and protocol
	event.EventName = eventTypeName(raw.EventType)
	if raw.Protocol == 6 {
		event.Protocol = "TCP"
	} else if raw.Protocol == 17 {
		event.Protocol = "UDP"
	}

	return event, nil
}

// updateStats updates internal statistics
func (c *Collector) updateStats(event *Event) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats.EventsProcessed++
	c.stats.LastEventTime = event.Timestamp

	switch event.EventType {
	case EventProcessExec:
		c.stats.ProcessExecCount++
	case EventProcessExit:
		c.stats.ProcessExitCount++
	case EventFileOpen:
		c.stats.FileOpenCount++
	case EventNetworkConnect, EventNetworkAccept:
		c.stats.NetworkCount++
	case EventSyscall:
		c.stats.SyscallCount++
	}
}

// Events returns the event channel for consuming events
func (c *Collector) Events() <-chan *Event {
	return c.eventChan
}

// Stats returns current collector statistics
func (c *Collector) Stats() CollectorStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := c.stats
	stats.EventsReceived = c.eventsReceived.Load()
	stats.EventsDropped = c.eventsDropped.Load()
	stats.EventsProcessed = c.eventsProcessed.Load()
	return stats
}

// Stop stops the collector and cleans up resources
func (c *Collector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Signal stop
	close(c.stopChan)

	// Close ring buffer reader
	if c.reader != nil {
		c.reader.Close()
	}

	// Wait for goroutines to finish
	c.wg.Wait()

	// Detach all programs
	for _, l := range c.links {
		l.Close()
	}

	// Close eBPF objects
	if c.objs != nil {
		c.objs.Close()
	}

	// Close event channel
	close(c.eventChan)

	c.logger.Info("eBPF collector stopped")
	return nil
}

// Helper functions

func nullTerminatedString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip
}

func eventTypeName(t uint32) string {
	switch t {
	case EventProcessExec:
		return "process_exec"
	case EventProcessExit:
		return "process_exit"
	case EventFileOpen:
		return "file_open"
	case EventNetworkConnect:
		return "network_connect"
	case EventNetworkAccept:
		return "network_accept"
	case EventSyscall:
		return "syscall"
	default:
		return "unknown"
	}
}

// BatchReader provides batch event reading for high-throughput scenarios
type BatchReader struct {
	collector     *Collector
	batchSize     int
	timeout       time.Duration
	adaptive      bool
	currentRate   float64
	lastRateCheck time.Time
}

// NewBatchReader creates a new batch reader
func NewBatchReader(collector *Collector, batchSize int, timeout time.Duration) *BatchReader {
	return &BatchReader{
		collector:     collector,
		batchSize:     batchSize,
		timeout:       timeout,
		adaptive:      true,
		lastRateCheck: time.Now(),
	}
}

// ReadBatch reads a batch of events
func (br *BatchReader) ReadBatch(ctx context.Context) ([]*Event, error) {
	batch := make([]*Event, 0, br.batchSize)
	timer := time.NewTimer(br.timeout)
	defer timer.Stop()

	for len(batch) < br.batchSize {
		select {
		case <-ctx.Done():
			return batch, ctx.Err()
		case event, ok := <-br.collector.Events():
			if !ok {
				return batch, nil
			}
			batch = append(batch, event)
		case <-timer.C:
			return batch, nil
		}
	}

	// Adaptive batch size adjustment
	if br.adaptive {
		br.adjustBatchSize()
	}

	return batch, nil
}

// adjustBatchSize dynamically adjusts batch size based on event rate
func (br *BatchReader) adjustBatchSize() {
	now := time.Now()
	elapsed := now.Sub(br.lastRateCheck).Seconds()
	if elapsed < 1.0 {
		return
	}

	stats := br.collector.Stats()
	rate := float64(stats.EventsReceived) / elapsed
	br.currentRate = rate
	br.lastRateCheck = now

	// Adjust batch size based on rate
	switch {
	case rate < 100:
		br.batchSize = 1
		br.timeout = 1 * time.Millisecond
	case rate < 1000:
		br.batchSize = 10
		br.timeout = 10 * time.Millisecond
	case rate < 10000:
		br.batchSize = 100
		br.timeout = 50 * time.Millisecond
	default:
		br.batchSize = 1000
		br.timeout = 100 * time.Millisecond
	}
}

// CurrentRate returns the current event rate
func (br *BatchReader) CurrentRate() float64 {
	return br.currentRate
}
