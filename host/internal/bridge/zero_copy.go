// Package bridge provides efficient data transfer between eBPF collector and Wasm engine
package bridge

import (
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
	ebpfcollector "github.com/wasm-threat-detector/host/internal/ebpf"
)

// EventBuffer represents a pre-allocated buffer for zero-copy event transfer
type EventBuffer struct {
	data     []byte
	offset   int
	capacity int
	count    int
	mu       sync.Mutex
}

// NewEventBuffer creates a new event buffer with specified capacity
func NewEventBuffer(capacity int) *EventBuffer {
	return &EventBuffer{
		data:     make([]byte, capacity),
		capacity: capacity,
	}
}

// Reset clears the buffer for reuse
func (b *EventBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.offset = 0
	b.count = 0
}

// Write writes an event to the buffer in binary format
// Returns offset where event was written, or -1 if buffer is full
func (b *EventBuffer) Write(event *ebpfcollector.Event) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Calculate required size
	eventSize := 128 // Base event size
	filenameLen := len(event.Filename)
	argsLen := len(event.Cmdline())
	commLen := len(event.Comm)
	totalSize := eventSize + filenameLen + argsLen + commLen + 16 // padding

	if b.offset+totalSize > b.capacity {
		return -1
	}

	startOffset := b.offset

	// Write header
	binary.LittleEndian.PutUint64(b.data[b.offset:], uint64(event.Timestamp.UnixNano()))
	b.offset += 8
	binary.LittleEndian.PutUint32(b.data[b.offset:], event.PID)
	b.offset += 4
	binary.LittleEndian.PutUint32(b.data[b.offset:], event.PPID)
	b.offset += 4
	binary.LittleEndian.PutUint32(b.data[b.offset:], event.UID)
	b.offset += 4
	binary.LittleEndian.PutUint32(b.data[b.offset:], event.GID)
	b.offset += 4
	binary.LittleEndian.PutUint32(b.data[b.offset:], event.Type)
	b.offset += 4
	binary.LittleEndian.PutUint32(b.data[b.offset:], event.SyscallNr)
	b.offset += 4

	// Write network info
	if event.SrcIP != nil && len(event.SrcIP) >= 4 {
		copy(b.data[b.offset:], event.SrcIP[:4])
	}
	b.offset += 4
	if event.DstIP != nil && len(event.DstIP) >= 4 {
		copy(b.data[b.offset:], event.DstIP[:4])
	}
	b.offset += 4
	binary.LittleEndian.PutUint16(b.data[b.offset:], event.SrcPort)
	b.offset += 2
	binary.LittleEndian.PutUint16(b.data[b.offset:], event.DstPort)
	b.offset += 2

	// Write string lengths
	binary.LittleEndian.PutUint16(b.data[b.offset:], uint16(commLen))
	b.offset += 2
	binary.LittleEndian.PutUint16(b.data[b.offset:], uint16(filenameLen))
	b.offset += 2
	binary.LittleEndian.PutUint16(b.data[b.offset:], uint16(argsLen))
	b.offset += 2

	// Padding for alignment
	b.offset += 2

	// Write strings
	copy(b.data[b.offset:], event.Comm)
	b.offset += commLen
	copy(b.data[b.offset:], event.Filename)
	b.offset += filenameLen
	copy(b.data[b.offset:], event.Cmdline())
	b.offset += argsLen

	// Align to 8 bytes
	b.offset = (b.offset + 7) & ^7

	b.count++
	return startOffset
}

// Data returns the underlying byte slice
func (b *EventBuffer) Data() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data[:b.offset]
}

// Len returns the current data length
func (b *EventBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.offset
}

// Count returns the number of events in buffer
func (b *EventBuffer) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.count
}

// ZeroCopyBridge provides zero-copy data transfer between eBPF and Wasm
type ZeroCopyBridge struct {
	collector  *ebpfcollector.Collector
	bufferPool sync.Pool
	batchChan  chan *EventBuffer
	stopChan   chan struct{}
	wg         sync.WaitGroup
	logger     *logrus.Logger

	// Configuration
	batchSize    int
	batchTimeout time.Duration
	bufferSize   int

	// Metrics
	batchesCreated   atomic.Uint64
	eventsProcessed  atomic.Uint64
	bytesTransferred atomic.Uint64
	droppedEvents    atomic.Uint64
}

// BridgeConfig holds configuration for the zero-copy bridge
type BridgeConfig struct {
	BatchSize    int
	BatchTimeout time.Duration
	BufferSize   int
	BatchChanCap int
	Logger       *logrus.Logger
}

// DefaultBridgeConfig returns default configuration
func DefaultBridgeConfig() *BridgeConfig {
	return &BridgeConfig{
		BatchSize:    100,
		BatchTimeout: 10 * time.Millisecond,
		BufferSize:   64 * 1024, // 64KB per buffer
		BatchChanCap: 100,
		Logger:       logrus.StandardLogger(),
	}
}

// NewZeroCopyBridge creates a new zero-copy bridge
func NewZeroCopyBridge(collector *ebpfcollector.Collector, config *BridgeConfig) *ZeroCopyBridge {
	if config == nil {
		config = DefaultBridgeConfig()
	}

	bridge := &ZeroCopyBridge{
		collector:    collector,
		batchChan:    make(chan *EventBuffer, config.BatchChanCap),
		stopChan:     make(chan struct{}),
		logger:       config.Logger,
		batchSize:    config.BatchSize,
		batchTimeout: config.BatchTimeout,
		bufferSize:   config.BufferSize,
	}

	bridge.bufferPool = sync.Pool{
		New: func() interface{} {
			return NewEventBuffer(config.BufferSize)
		},
	}

	return bridge
}

// Start begins the bridge processing
func (b *ZeroCopyBridge) Start(ctx context.Context) error {
	b.wg.Add(1)
	go b.batchEvents(ctx)

	b.logger.Info("Zero-copy bridge started")
	return nil
}

// batchEvents collects events and creates batches
func (b *ZeroCopyBridge) batchEvents(ctx context.Context) {
	defer b.wg.Done()

	ticker := time.NewTicker(b.batchTimeout)
	defer ticker.Stop()

	buffer := b.bufferPool.Get().(*EventBuffer)
	buffer.Reset()
	eventCount := 0

	sendBatch := func() {
		if eventCount > 0 {
			select {
			case b.batchChan <- buffer:
				b.batchesCreated.Add(1)
				b.eventsProcessed.Add(uint64(eventCount))
				b.bytesTransferred.Add(uint64(buffer.Len()))
			default:
				b.droppedEvents.Add(uint64(eventCount))
				b.bufferPool.Put(buffer)
			}
			buffer = b.bufferPool.Get().(*EventBuffer)
			buffer.Reset()
			eventCount = 0
		}
	}

	for {
		select {
		case <-ctx.Done():
			sendBatch()
			return
		case <-b.stopChan:
			sendBatch()
			return
		case event, ok := <-b.collector.Events():
			if !ok {
				sendBatch()
				return
			}

			offset := buffer.Write(event)
			if offset < 0 {
				// Buffer full, send and get new one
				sendBatch()
				buffer.Write(event)
				eventCount = 1
			} else {
				eventCount++
			}

			if eventCount >= b.batchSize {
				sendBatch()
			}

		case <-ticker.C:
			sendBatch()
		}
	}
}

// Batches returns the channel for receiving event batches
func (b *ZeroCopyBridge) Batches() <-chan *EventBuffer {
	return b.batchChan
}

// ReturnBuffer returns a buffer to the pool for reuse
func (b *ZeroCopyBridge) ReturnBuffer(buf *EventBuffer) {
	buf.Reset()
	b.bufferPool.Put(buf)
}

// Stop stops the bridge
func (b *ZeroCopyBridge) Stop() {
	close(b.stopChan)
	b.wg.Wait()
	close(b.batchChan)
	b.logger.Info("Zero-copy bridge stopped")
}

// Stats returns bridge statistics
func (b *ZeroCopyBridge) Stats() BridgeStats {
	return BridgeStats{
		BatchesCreated:   b.batchesCreated.Load(),
		EventsProcessed:  b.eventsProcessed.Load(),
		BytesTransferred: b.bytesTransferred.Load(),
		DroppedEvents:    b.droppedEvents.Load(),
	}
}

// BridgeStats holds bridge statistics
type BridgeStats struct {
	BatchesCreated   uint64
	EventsProcessed  uint64
	BytesTransferred uint64
	DroppedEvents    uint64
}

// WasmMemoryWriter writes event buffers directly to Wasm linear memory
type WasmMemoryWriter struct {
	memory     []byte
	baseOffset uint32
	logger     *logrus.Logger
}

// NewWasmMemoryWriter creates a new Wasm memory writer
func NewWasmMemoryWriter(memory []byte, baseOffset uint32, logger *logrus.Logger) *WasmMemoryWriter {
	return &WasmMemoryWriter{
		memory:     memory,
		baseOffset: baseOffset,
		logger:     logger,
	}
}

// WriteBuffer writes an event buffer directly to Wasm memory
// Returns the pointer and length in Wasm memory
func (w *WasmMemoryWriter) WriteBuffer(buffer *EventBuffer) (ptr uint32, length uint32, err error) {
	data := buffer.Data()
	length = uint32(len(data))

	if uint32(len(w.memory)) < w.baseOffset+length {
		return 0, 0, ErrMemoryTooSmall
	}

	// Direct copy to Wasm memory - this is the "zero-copy" optimization
	// In reality, this is still one copy, but it eliminates:
	// 1. JSON serialization
	// 2. Go heap allocation
	// 3. Multiple intermediate copies
	copy(w.memory[w.baseOffset:], data)

	return w.baseOffset, length, nil
}

// WriteEvent writes a single event to Wasm memory
func (w *WasmMemoryWriter) WriteEvent(event *ebpfcollector.Event, offset uint32) (uint32, error) {
	if uint32(len(w.memory)) < offset+256 {
		return 0, ErrMemoryTooSmall
	}

	ptr := offset

	// Write timestamp
	binary.LittleEndian.PutUint64(w.memory[offset:], uint64(event.Timestamp.UnixNano()))
	offset += 8

	// Write PIDs
	binary.LittleEndian.PutUint32(w.memory[offset:], event.PID)
	offset += 4
	binary.LittleEndian.PutUint32(w.memory[offset:], event.PPID)
	offset += 4

	// Write UIDs
	binary.LittleEndian.PutUint32(w.memory[offset:], event.UID)
	offset += 4
	binary.LittleEndian.PutUint32(w.memory[offset:], event.GID)
	offset += 4

	// Write event type
	binary.LittleEndian.PutUint32(w.memory[offset:], event.Type)
	offset += 4

	// Write syscall number
	binary.LittleEndian.PutUint32(w.memory[offset:], event.SyscallNr)
	offset += 4

	// Write network info
	if event.SrcIP != nil && len(event.SrcIP) >= 4 {
		copy(w.memory[offset:], event.SrcIP[:4])
	}
	offset += 4
	if event.DstIP != nil && len(event.DstIP) >= 4 {
		copy(w.memory[offset:], event.DstIP[:4])
	}
	offset += 4
	binary.LittleEndian.PutUint16(w.memory[offset:], event.SrcPort)
	offset += 2
	binary.LittleEndian.PutUint16(w.memory[offset:], event.DstPort)
	offset += 2

	// Write strings with length prefix
	commBytes := []byte(event.Comm)
	filenameBytes := []byte(event.Filename)
	argsBytes := []byte(event.Cmdline())

	// Comm
	binary.LittleEndian.PutUint16(w.memory[offset:], uint16(len(commBytes)))
	offset += 2
	copy(w.memory[offset:], commBytes)
	offset += uint32(len(commBytes))

	// Filename
	binary.LittleEndian.PutUint16(w.memory[offset:], uint16(len(filenameBytes)))
	offset += 2
	copy(w.memory[offset:], filenameBytes)
	offset += uint32(len(filenameBytes))

	// Args
	binary.LittleEndian.PutUint16(w.memory[offset:], uint16(len(argsBytes)))
	offset += 2
	copy(w.memory[offset:], argsBytes)
	offset += uint32(len(argsBytes))

	return offset - ptr, nil
}

// Errors
var (
	ErrMemoryTooSmall = &BridgeError{msg: "wasm memory too small for event data"}
)

type BridgeError struct {
	msg string
}

func (e *BridgeError) Error() string {
	return e.msg
}

// PerformanceMetrics tracks detailed performance metrics
type PerformanceMetrics struct {
	// Latency measurements (in nanoseconds)
	EventCollectionLatency atomic.Int64
	SerializationLatency   atomic.Int64
	WasmTransferLatency    atomic.Int64
	DetectionLatency       atomic.Int64
	TotalLatency           atomic.Int64

	// Throughput measurements
	EventsPerSecond atomic.Int64
	BytesPerSecond  atomic.Int64

	// Sample tracking
	sampleCount    atomic.Int64
	lastSampleTime atomic.Int64
}

// RecordLatency records a latency sample
func (m *PerformanceMetrics) RecordLatency(eventCollect, serialize, wasmTransfer, detection int64) {
	m.EventCollectionLatency.Store(eventCollect)
	m.SerializationLatency.Store(serialize)
	m.WasmTransferLatency.Store(wasmTransfer)
	m.DetectionLatency.Store(detection)
	m.TotalLatency.Store(eventCollect + serialize + wasmTransfer + detection)
	m.sampleCount.Add(1)
}

// GetLatencyBreakdown returns latency breakdown as percentages
func (m *PerformanceMetrics) GetLatencyBreakdown() map[string]float64 {
	total := float64(m.TotalLatency.Load())
	if total == 0 {
		return nil
	}
	return map[string]float64{
		"event_collection": float64(m.EventCollectionLatency.Load()) / total * 100,
		"serialization":    float64(m.SerializationLatency.Load()) / total * 100,
		"wasm_transfer":    float64(m.WasmTransferLatency.Load()) / total * 100,
		"detection":        float64(m.DetectionLatency.Load()) / total * 100,
	}
}

// DataLayout describes the binary layout for event data
// This is used for documentation and validation
type DataLayout struct {
	// Header (fixed size: 48 bytes)
	// Offset 0:  timestamp (8 bytes, uint64, nanoseconds since epoch)
	// Offset 8:  pid (4 bytes, uint32)
	// Offset 12: ppid (4 bytes, uint32)
	// Offset 16: uid (4 bytes, uint32)
	// Offset 20: gid (4 bytes, uint32)
	// Offset 24: event_type (4 bytes, uint32)
	// Offset 28: syscall_nr (4 bytes, uint32)
	// Offset 32: src_ip (4 bytes, IPv4)
	// Offset 36: dst_ip (4 bytes, IPv4)
	// Offset 40: src_port (2 bytes, uint16)
	// Offset 42: dst_port (2 bytes, uint16)
	// Offset 44: comm_len (2 bytes, uint16)
	// Offset 46: filename_len (2 bytes, uint16)
	// Offset 48: args_len (2 bytes, uint16)
	// Offset 50: reserved (2 bytes)
	//
	// Variable length data follows:
	// - comm (comm_len bytes)
	// - filename (filename_len bytes)
	// - args (args_len bytes)
	// - padding to 8-byte alignment
}

// LayoutHeaderSize is the fixed header size
const LayoutHeaderSize = 52

// GetEventSize calculates the total size needed for an event
func GetEventSize(event *ebpfcollector.Event) int {
	size := LayoutHeaderSize
	size += len(event.Comm)
	size += len(event.Filename)
	size += len(event.Cmdline())
	// Align to 8 bytes
	return (size + 7) & ^7
}

// Ensure interface satisfaction
var _ unsafe.Pointer // prevent unused import error
