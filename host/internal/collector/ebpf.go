package collector

import (
	"context"
	"fmt"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"github.com/wasm-threat-detector/host/internal/ebpf"
	"github.com/wasm-threat-detector/host/internal/events"
	"github.com/wasm-threat-detector/host/internal/wire"
)

// EBPFConfig configures the eBPF-backed collector.
type EBPFConfig struct {
	Hooks    string // comma-separated ebpf hook names; "" or "all" = every hook
	ChanSize int    // output channel capacity; 0 = 4096
}

// EBPFCollector adapts ebpf.Collector to the Collector interface and converts
// kernel events into the events.Event shape the Wasm rules consume.
type EBPFCollector struct {
	logger *logrus.Logger
	cfg    EBPFConfig
	inner  *ebpf.Collector
	out    chan *events.Event
	names  NameCache

	wg       sync.WaitGroup
	stopOnce sync.Once
	dropped  atomic.Uint64
}

// NewEBPFCollector prepares the collector; nothing touches the kernel until Start.
func NewEBPFCollector(logger *logrus.Logger, cfg EBPFConfig) *EBPFCollector {
	if cfg.ChanSize <= 0 {
		cfg.ChanSize = 4096
	}
	return &EBPFCollector{
		logger: logger,
		cfg:    cfg,
		out:    make(chan *events.Event, cfg.ChanSize),
	}
}

// Start loads and attaches the BPF programs and begins forwarding events.
func (c *EBPFCollector) Start(ctx context.Context) error {
	hooks, err := ebpf.ParseHooks(c.cfg.Hooks)
	if err != nil {
		return err
	}
	inner, err := ebpf.NewCollector(ebpf.Config{Hooks: hooks, Logger: c.logger})
	if err != nil {
		return fmt.Errorf("%w (loading eBPF programs needs CAP_BPF and CAP_PERFMON, in practice root, and a kernel with BTF at /sys/kernel/btf/vmlinux)", err)
	}
	if err := inner.Start(); err != nil {
		inner.Stop()
		return err
	}
	c.inner = inner
	c.wg.Add(1)
	go c.forward(ctx)
	return nil
}

func (c *EBPFCollector) forward(ctx context.Context) {
	defer c.wg.Done()
	trace := c.logger.IsLevelEnabled(logrus.TraceLevel)
	for ev := range c.inner.Events() {
		if trace {
			c.logger.WithFields(logrus.Fields{
				"type": ev.TypeName, "pid": ev.PID, "comm": ev.Comm, "file": ev.Filename,
				"argv": ev.Argv, "dst": fmt.Sprintf("%s:%d", ev.DstIP, ev.DstPort), "syscall": ev.SyscallName,
			}).Trace("eBPF event")
		}
		select {
		case c.out <- EventFromEBPF(ev, &c.names):
		case <-ctx.Done():
			// Drain without forwarding until Stop closes the inner channel.
			c.dropped.Add(1)
		}
	}
}

// Stop detaches the BPF programs and closes the event channel.
func (c *EBPFCollector) Stop() error {
	c.stopOnce.Do(func() {
		if c.inner != nil {
			c.inner.Stop() // closes inner.Events(), which ends forward
		}
		c.wg.Wait()
		close(c.out)
		if n := c.dropped.Load(); n > 0 {
			c.logger.WithField("dropped_after_cancel", n).Info("eBPF collector stopped")
		}
	})
	return nil
}

// EventChannel returns the converted event stream.
func (c *EBPFCollector) EventChannel() <-chan *events.Event { return c.out }

// Stats exposes the underlying collector counters (nil before Start).
func (c *EBPFCollector) Stats() *ebpf.Stats {
	if c.inner == nil {
		return nil
	}
	s := c.inner.Stats()
	return &s
}

// EventFromEBPF converts a kernel event into the JSON shape the rules read:
//
//	process      data.process.{pid,ppid,name,executable,command_line,user,group}, data.action = "exec"
//	process_exit same process block, data.action = "exit", data.exit_code
//	file         data.file.{path,operation,process_name,user}, data.flags
//	network      data.network.{protocol,source_ip,source_port,dest_ip,dest_port,direction,process_name}
//	syscall      data.{syscall_nr,syscall_name,process_name}
//
// Every event also carries data.pid, data.uid and data.comm.
func EventFromEBPF(ev *ebpf.Event, names *NameCache) *events.Event {
	out := &events.Event{
		ID:        fmt.Sprintf("ebpf_%s_%d_%d", ev.TypeName, ev.PID, ev.MonotonicNs),
		Timestamp: ev.Timestamp,
		Source:    "ebpf",
		Data: map[string]interface{}{
			"pid":  ev.PID,
			"uid":  ev.UID,
			"comm": ev.Comm,
		},
	}
	switch ev.Type {
	case ebpf.EventProcessExec, ebpf.EventProcessExit:
		out.Type = events.EventTypeProcess
		proc := events.ProcessInfo{
			PID:         int32(ev.PID),
			PPID:        int32(ev.PPID),
			Name:        ev.Comm,
			Executable:  ev.Filename,
			CommandLine: strings.Join(ev.Argv, " "),
			User:        names.user(ev.UID),
			Group:       names.group(ev.GID),
		}
		out.Data["process"] = proc
		if ev.Type == ebpf.EventProcessExec {
			out.Data["action"] = "exec"
			if ev.ArgvTruncated {
				out.Data["command_line_truncated"] = true
			}
		} else {
			// Not a plain "process" event: rules key on type and would score the
			// same executable twice; a distinct type keeps exits visible but inert.
			out.Type = events.EventType("process_exit")
			out.Data["action"] = "exit"
			out.Data["exit_code"] = ev.ExitCode
		}
	case ebpf.EventFileOpen:
		out.Type = events.EventTypeFile
		out.Data["file"] = events.FileInfo{
			Path:        ev.Filename,
			Operation:   openOperation(ev.Flags),
			ProcessName: ev.Comm,
			User:        names.user(ev.UID),
		}
		out.Data["flags"] = ev.Flags
	case ebpf.EventNetworkConnect, ebpf.EventNetworkAccept:
		out.Type = events.EventTypeNetwork
		direction := "outbound"
		if ev.Type == ebpf.EventNetworkAccept {
			direction = "inbound"
		}
		out.Data["network"] = events.NetworkInfo{
			Protocol:    ev.Protocol,
			SourceIP:    ipString(ev.SrcIP),
			SourcePort:  int(ev.SrcPort),
			DestIP:      ipString(ev.DstIP),
			DestPort:    int(ev.DstPort),
			Direction:   direction,
			ProcessName: ev.Comm,
		}
		out.Data["family"] = ev.Family
	case ebpf.EventSyscall:
		out.Type = events.EventType("syscall")
		out.Data["syscall_nr"] = ev.SyscallNr
		out.Data["syscall_name"] = ev.SyscallName
		out.Data["process_name"] = ev.Comm
		out.Data["ppid"] = ev.PPID
	default:
		out.Type = events.EventType(ev.TypeName)
	}
	// Binary form for rules that export detect_raw: the kernel record verbatim
	// plus the names resolved above. Built once per event, used by every rule.
	if len(ev.Raw) == wire.RecordLen {
		var user, group string
		if ev.Type == ebpf.EventProcessExec || ev.Type == ebpf.EventProcessExit || ev.Type == ebpf.EventFileOpen {
			user = names.user(ev.UID)
		}
		if ev.Type == ebpf.EventProcessExec || ev.Type == ebpf.EventProcessExit {
			group = names.group(ev.GID)
		}
		if b, err := wire.Encode(ev.Raw, user, group, ev.SyscallName); err == nil {
			out.Binary = b
		}
	}
	return out
}

// open(2) flag bits (asm-generic, also x86_64).
const (
	oWronly = 0x1
	oRdwr   = 0x2
	oCreat  = 0x40
	oTrunc  = 0x200
	oAppend = 0x400
)

// openOperation classifies open(2) flags the way the rules expect.
func openOperation(flags uint32) string {
	switch {
	case flags&oCreat != 0:
		return "create"
	case flags&(oWronly|oRdwr) != 0 || flags&(oTrunc|oAppend) != 0:
		return "write"
	default:
		return "read"
	}
}

func ipString(ip []byte) string {
	if len(ip) == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

// NameCache resolves uids and gids to names once.
type NameCache struct {
	mu     sync.Mutex
	users  map[uint32]string
	groups map[uint32]string
}

func (n *NameCache) user(uid uint32) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.users == nil {
		n.users = map[uint32]string{}
	}
	if name, ok := n.users[uid]; ok {
		return name
	}
	name := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(name); err == nil && u.Username != "" {
		name = u.Username
	}
	n.users[uid] = name
	return name
}

func (n *NameCache) group(gid uint32) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.groups == nil {
		n.groups = map[uint32]string{}
	}
	if name, ok := n.groups[gid]; ok {
		return name
	}
	name := strconv.FormatUint(uint64(gid), 10)
	if g, err := user.LookupGroupId(name); err == nil && g.Name != "" {
		name = g.Name
	}
	n.groups[gid] = name
	return name
}
