// Package ebpf collects kernel events with eBPF. Six hooks (see
// bpf/sentinel.bpf.c) write fixed-size records into one ring buffer, which
// Collector drains into a channel of decoded Events.
//
// Loading and attaching needs CAP_BPF and CAP_PERFMON (in practice: root) and a
// kernel with BTF at /sys/kernel/btf/vmlinux. The package itself compiles and
// its decoding is testable without privileges: the generated bindings embed the
// BPF object, so no clang is needed at run time.
package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -target bpfel -type event sentinel ./bpf/sentinel.bpf.c

// Event types, matching EVENT_* in bpf/sentinel.bpf.c.
const (
	EventProcessExec    uint32 = 1
	EventProcessExit    uint32 = 2
	EventFileOpen       uint32 = 3
	EventNetworkConnect uint32 = 4
	EventNetworkAccept  uint32 = 5
	EventSyscall        uint32 = 6
)

// Hook names accepted by Config.Hooks, one per BPF program.
const (
	HookExec    = "exec"    // tracepoint sched/sched_process_exec
	HookExit    = "exit"    // tracepoint sched/sched_process_exit
	HookOpen    = "open"    // tracepoint syscalls/sys_enter_openat
	HookConnect = "connect" // kprobe tcp_connect
	HookAccept  = "accept"  // kretprobe inet_csk_accept
	HookSyscall = "syscall" // raw tracepoint sys_enter (allow-listed syscalls)
)

// AllHooks lists every hook in attach order.
var AllHooks = []string{HookExec, HookExit, HookOpen, HookConnect, HookAccept, HookSyscall}

// ParseHooks turns a comma-separated list such as "exec,open" into a validated,
// de-duplicated hook list. "" and "all" select AllHooks.
func ParseHooks(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "all" {
		return append([]string(nil), AllHooks...), nil
	}
	seen := map[string]bool{}
	var out []string
	for _, h := range strings.Split(s, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		valid := false
		for _, known := range AllHooks {
			if h == known {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("unknown eBPF hook %q (valid: %s)", h, strings.Join(AllHooks, ","))
		}
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no eBPF hooks selected")
	}
	return out, nil
}

// Event is one decoded kernel event.
type Event struct {
	Timestamp   time.Time // wall clock, derived from the kernel's monotonic stamp
	MonotonicNs uint64
	Type        uint32
	TypeName    string

	PID  uint32
	PPID uint32
	UID  uint32
	GID  uint32
	Comm string

	Filename      string   // EXEC: resolved executable path; FILE_OPEN: path argument
	Argv          []string // EXEC: argv (first 256 bytes of the argument block)
	ArgvTruncated bool     // EXEC: argv block was longer than the record can carry
	ExitCode      int32    // EXIT

	Flags uint32 // FILE_OPEN: open(2) flags

	Family   uint16 // NETWORK: AF_INET or AF_INET6
	Protocol string // NETWORK: "tcp"
	SrcIP    net.IP // NETWORK: nil for AF_INET6 (addresses not carried yet)
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16

	SyscallNr   uint32 // SYSCALL
	SyscallName string

	// Raw is the record exactly as the kernel wrote it (recordSize bytes); the
	// binary event path copies it into the rule's memory without re-encoding.
	Raw []byte
}

// Cmdline joins Argv with spaces (empty for non-exec events).
func (e *Event) Cmdline() string { return strings.Join(e.Argv, " ") }

// Config configures a Collector.
type Config struct {
	Hooks    []string // nil means AllHooks
	ChanSize int      // decoded-event channel capacity; 0 means 16384
	Logger   *logrus.Logger
}

// Stats is a snapshot of the collector's counters.
type Stats struct {
	Received uint64 // ring buffer records read
	Decoded  uint64 // records delivered to Events()
	Dropped  uint64 // records lost because Events() was full or undecodable
	ByType   map[string]uint64
	Attached []string
	Since    time.Time
}

// Collector owns the loaded BPF objects, the attached links and the ring buffer
// reader.
type Collector struct {
	objs     *sentinelObjects
	links    []link.Link
	reader   *ringbuf.Reader
	out      chan *Event
	logger   *logrus.Logger
	hooks    []string
	attached []string
	bootWall time.Time // wall clock corresponding to monotonic 0

	wg       sync.WaitGroup
	started  atomic.Bool
	stopOnce sync.Once
	since    time.Time

	received atomic.Uint64
	decoded  atomic.Uint64
	dropped  atomic.Uint64
	byType   [EventSyscall + 1]atomic.Uint64
}

// NewCollector loads the BPF programs and maps into the kernel and opens the
// ring buffer. Nothing is attached until Start.
func NewCollector(cfg Config) (*Collector, error) {
	if cfg.Logger == nil {
		cfg.Logger = logrus.StandardLogger()
	}
	if cfg.ChanSize <= 0 {
		cfg.ChanSize = 16384
	}
	hooks := cfg.Hooks
	if len(hooks) == 0 {
		hooks = append([]string(nil), AllHooks...)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}
	objs := &sentinelObjects{}
	if err := loadSentinelObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		reader.Close()
		objs.Close()
		return nil, fmt.Errorf("clock_gettime: %w", err)
	}
	return &Collector{
		objs:     objs,
		reader:   reader,
		out:      make(chan *Event, cfg.ChanSize),
		logger:   cfg.Logger,
		hooks:    hooks,
		bootWall: time.Now().Add(-time.Duration(ts.Nano())),
	}, nil
}

// Start attaches the configured hooks and begins draining the ring buffer.
// Every requested hook must attach; a failure detaches what was attached and
// names the hook in the error.
func (c *Collector) Start() error {
	if !c.started.CompareAndSwap(false, true) {
		return errors.New("ebpf collector already started")
	}
	for _, h := range c.hooks {
		l, err := c.attach(h)
		if err != nil {
			for _, done := range c.links {
				done.Close()
			}
			c.links = nil
			return fmt.Errorf("attach hook %q: %w", h, err)
		}
		c.links = append(c.links, l)
		c.attached = append(c.attached, h)
		c.logger.WithField("hook", h).Debug("Attached eBPF hook")
	}
	c.since = time.Now()
	c.wg.Add(1)
	go c.readLoop()
	c.logger.WithField("hooks", strings.Join(c.attached, ",")).Info("eBPF collector started")
	return nil
}

func (c *Collector) attach(hook string) (link.Link, error) {
	switch hook {
	case HookExec:
		return link.Tracepoint("sched", "sched_process_exec", c.objs.TracepointSchedSchedProcessExec, nil)
	case HookExit:
		return link.Tracepoint("sched", "sched_process_exit", c.objs.TracepointSchedSchedProcessExit, nil)
	case HookOpen:
		return link.Tracepoint("syscalls", "sys_enter_openat", c.objs.TracepointSyscallsSysEnterOpenat, nil)
	case HookConnect:
		return link.Kprobe("tcp_connect", c.objs.KprobeTcpConnect, nil)
	case HookAccept:
		return link.Kretprobe("inet_csk_accept", c.objs.KretprobeInetCskAccept, nil)
	case HookSyscall:
		return link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: c.objs.RawTpSysEnter})
	}
	return nil, fmt.Errorf("unknown hook %q", hook)
}

func (c *Collector) readLoop() {
	defer c.wg.Done()
	for {
		rec, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			c.logger.WithError(err).Warn("Ring buffer read failed")
			continue
		}
		c.received.Add(1)
		ev, err := decode(rec.RawSample, c.bootWall)
		if err != nil {
			c.dropped.Add(1)
			continue
		}
		select {
		case c.out <- ev:
			c.decoded.Add(1)
			if int(ev.Type) < len(c.byType) {
				c.byType[ev.Type].Add(1)
			}
		default:
			c.dropped.Add(1)
		}
	}
}

// Events returns the decoded-event channel. It is closed by Stop.
func (c *Collector) Events() <-chan *Event { return c.out }

// Attached lists the hooks that Start attached.
func (c *Collector) Attached() []string { return append([]string(nil), c.attached...) }

// Stats snapshots the counters.
func (c *Collector) Stats() Stats {
	s := Stats{
		Received: c.received.Load(),
		Decoded:  c.decoded.Load(),
		Dropped:  c.dropped.Load(),
		ByType:   make(map[string]uint64, len(c.byType)),
		Attached: c.Attached(),
		Since:    c.since,
	}
	for t := range c.byType {
		if n := c.byType[t].Load(); n > 0 {
			s.ByType[TypeName(uint32(t))] = n
		}
	}
	return s
}

// Stop detaches the hooks, closes the ring buffer and the BPF objects, waits
// for the reader and closes Events. It is idempotent.
func (c *Collector) Stop() error {
	c.stopOnce.Do(func() {
		for _, l := range c.links {
			l.Close()
		}
		c.links = nil
		if c.reader != nil {
			c.reader.Close() // unblocks readLoop
		}
		c.wg.Wait()
		if c.objs != nil {
			c.objs.Close()
		}
		close(c.out)
		s := c.Stats()
		c.logger.WithFields(logrus.Fields{
			"received": s.Received, "decoded": s.Decoded, "dropped": s.Dropped, "by_type": s.ByType,
		}).Info("eBPF collector stopped")
	})
	return nil
}

// recordSize is the size of one ring buffer record; it must equal sizeof(struct event) in C.
const recordSize = int(unsafe.Sizeof(sentinelEvent{}))

// decode converts one raw ring buffer record into an Event.
func decode(raw []byte, bootWall time.Time) (*Event, error) {
	if len(raw) < recordSize {
		return nil, fmt.Errorf("record of %d bytes, want %d", len(raw), recordSize)
	}
	var rec sentinelEvent
	copy((*[recordSize]byte)(unsafe.Pointer(&rec))[:], raw[:recordSize])

	ev := &Event{
		Raw:         append([]byte(nil), raw[:recordSize]...),
		MonotonicNs: rec.TimestampNs,
		Timestamp:   bootWall.Add(time.Duration(rec.TimestampNs)),
		Type:        rec.EventType,
		TypeName:    TypeName(rec.EventType),
		PID:         rec.Pid,
		PPID:        rec.Ppid,
		UID:         rec.Uid,
		GID:         rec.Gid,
		Comm:        cString(rec.Comm[:]),
	}
	switch rec.EventType {
	case EventProcessExec:
		ev.Filename = cString(rec.Filename[:])
		ev.Argv, ev.ArgvTruncated = splitArgv(rec.Args[:], rec.ArgsLen)
	case EventProcessExit:
		ev.ExitCode = int32(rec.Retval)
	case EventFileOpen:
		ev.Filename = cString(rec.Filename[:])
		ev.Flags = rec.Flags
	case EventNetworkConnect, EventNetworkAccept:
		ev.Family = rec.Family
		ev.Protocol = "tcp"
		ev.SrcPort = rec.Sport
		ev.DstPort = rec.Dport
		if rec.Family == unix.AF_INET {
			ev.SrcIP = ipv4(rec.Saddr)
			ev.DstIP = ipv4(rec.Daddr)
		}
	case EventSyscall:
		ev.SyscallNr = rec.SyscallNr
		ev.SyscallName = SyscallName(rec.SyscallNr)
	default:
		return nil, fmt.Errorf("unknown event type %d", rec.EventType)
	}
	return ev, nil
}

// Record encodes the event back into the kernel record layout. It is the
// inverse of decode and exists for tests and trace replay; a live Event
// already carries the original bytes in Raw.
func (e *Event) Record() []byte {
	var rec sentinelEvent
	rec.TimestampNs = e.MonotonicNs
	rec.EventType = e.Type
	rec.Pid, rec.Ppid, rec.Uid, rec.Gid = e.PID, e.PPID, e.UID, e.GID
	putC(rec.Comm[:], e.Comm)
	putC(rec.Filename[:], e.Filename)
	switch e.Type {
	case EventProcessExec:
		if len(e.Argv) > 0 {
			block := []byte(strings.Join(e.Argv, "\x00") + "\x00")
			if len(block) > len(rec.Args) {
				block = block[:len(rec.Args)]
			}
			for i, c := range block {
				rec.Args[i] = int8(c)
			}
			rec.ArgsLen = uint32(len(block))
		}
	case EventProcessExit:
		rec.Retval = int64(e.ExitCode)
	case EventFileOpen:
		rec.Flags = e.Flags
	case EventNetworkConnect, EventNetworkAccept:
		rec.Family = e.Family
		if e.Protocol == "tcp" {
			rec.Protocol = unix.IPPROTO_TCP
		}
		rec.Sport, rec.Dport = e.SrcPort, e.DstPort
		if ip := e.SrcIP.To4(); ip != nil {
			rec.Saddr = uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
		}
		if ip := e.DstIP.To4(); ip != nil {
			rec.Daddr = uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
		}
	case EventSyscall:
		rec.SyscallNr = e.SyscallNr
	}
	out := make([]byte, recordSize)
	copy(out, (*[recordSize]byte)(unsafe.Pointer(&rec))[:])
	return out
}

func putC(dst []int8, s string) {
	n := len(s)
	if n > len(dst)-1 {
		n = len(dst) - 1
	}
	for i := 0; i < n; i++ {
		dst[i] = int8(s[i])
	}
}

func cString(b []int8) string {
	bs := unsafe.Slice((*byte)(unsafe.Pointer(&b[0])), len(b))
	if i := bytes.IndexByte(bs, 0); i >= 0 {
		bs = bs[:i]
	}
	return string(bs)
}

// splitArgv splits the NUL-separated argument block captured from mm->arg_start.
func splitArgv(b []int8, n uint32) (argv []string, truncated bool) {
	if n == 0 {
		return nil, false
	}
	if int(n) > len(b) {
		n = uint32(len(b))
	}
	bs := unsafe.Slice((*byte)(unsafe.Pointer(&b[0])), int(n))
	truncated = int(n) == len(b) && bs[len(bs)-1] != 0
	for _, part := range bytes.Split(bytes.TrimRight(bs, "\x00"), []byte{0}) {
		argv = append(argv, string(part))
	}
	return argv, truncated
}

func ipv4(n uint32) net.IP {
	ip := make(net.IP, 4)
	// Stored in network byte order; the u32 was copied verbatim from the kernel.
	ip[0], ip[1], ip[2], ip[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
	return ip
}

// TypeName names an event type.
func TypeName(t uint32) string {
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
	}
	return fmt.Sprintf("unknown_%d", t)
}

// SyscallName names a syscall number (x86_64 table) or returns syscall_<nr>.
func SyscallName(nr uint32) string {
	if name, ok := syscallNames[nr]; ok {
		return name
	}
	return fmt.Sprintf("syscall_%d", nr)
}

// KnownSyscalls lists the syscall numbers the table can name, sorted.
func KnownSyscalls() []uint32 {
	out := make([]uint32, 0, len(syscallNames))
	for nr := range syscallNames {
		out = append(out, nr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
