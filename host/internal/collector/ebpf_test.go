package collector

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/wasm-threat-detector/host/internal/ebpf"
	"github.com/wasm-threat-detector/host/internal/wire"
)

func toJSON(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestEventFromEBPFExecMatchesRuleSchema(t *testing.T) {
	var names NameCache
	ev := &ebpf.Event{
		Timestamp: time.Now(), MonotonicNs: 7, Type: ebpf.EventProcessExec, TypeName: "process_exec",
		PID: 4242, PPID: 1, UID: 0, GID: 0, Comm: "bash", Filename: "/usr/bin/bash",
		Argv: []string{"bash", "-c", "rm -rf /tmp/x"},
	}
	m := toJSON(t, EventFromEBPF(ev, &names))
	if m["type"] != "process" || m["source"] != "ebpf" {
		t.Fatalf("type/source: %v %v", m["type"], m["source"])
	}
	data := m["data"].(map[string]interface{})
	proc := data["process"].(map[string]interface{})
	if proc["command_line"] != "bash -c rm -rf /tmp/x" || proc["executable"] != "/usr/bin/bash" || proc["name"] != "bash" {
		t.Errorf("process block: %v", proc)
	}
	if proc["user"] != "root" {
		t.Errorf("uid 0 resolved to %q", proc["user"])
	}
	if data["action"] != "exec" || data["pid"].(float64) != 4242 {
		t.Errorf("data: %v", data)
	}
}

func TestEventFromEBPFExitIsInert(t *testing.T) {
	var names NameCache
	m := toJSON(t, EventFromEBPF(&ebpf.Event{Type: ebpf.EventProcessExit, TypeName: "process_exit", PID: 9, Comm: "sh", ExitCode: 3}, &names))
	if m["type"] != "process_exit" {
		t.Errorf("exit event typed %v", m["type"])
	}
	if m["data"].(map[string]interface{})["exit_code"].(float64) != 3 {
		t.Errorf("exit code missing: %v", m["data"])
	}
}

func TestEventFromEBPFFileOperations(t *testing.T) {
	var names NameCache
	for _, tc := range []struct {
		flags uint32
		want  string
	}{{0, "read"}, {oWronly, "write"}, {oRdwr | oTrunc, "write"}, {oWronly | oCreat, "create"}, {oAppend, "write"}} {
		m := toJSON(t, EventFromEBPF(&ebpf.Event{Type: ebpf.EventFileOpen, TypeName: "file_open", Filename: "/etc/shadow", Flags: tc.flags, Comm: "cat"}, &names))
		file := m["data"].(map[string]interface{})["file"].(map[string]interface{})
		if m["type"] != "file" || file["path"] != "/etc/shadow" || file["operation"] != tc.want {
			t.Errorf("flags %#x: type=%v file=%v want op %s", tc.flags, m["type"], file, tc.want)
		}
	}
}

func TestEventFromEBPFNetworkAndSyscall(t *testing.T) {
	var names NameCache
	m := toJSON(t, EventFromEBPF(&ebpf.Event{
		Type: ebpf.EventNetworkConnect, TypeName: "network_connect", Comm: "curl", Protocol: "tcp", Family: 2,
		SrcIP: net.IPv4(10, 0, 0, 2).To4(), DstIP: net.IPv4(1, 2, 3, 4).To4(), SrcPort: 40000, DstPort: 4444,
	}, &names))
	netw := m["data"].(map[string]interface{})["network"].(map[string]interface{})
	if m["type"] != "network" || netw["dest_ip"] != "1.2.3.4" || netw["dest_port"].(float64) != 4444 || netw["direction"] != "outbound" || netw["protocol"] != "tcp" {
		t.Errorf("network: %v %v", m["type"], netw)
	}
	m = toJSON(t, EventFromEBPF(&ebpf.Event{Type: ebpf.EventNetworkAccept, TypeName: "network_accept", Family: 10}, &names))
	netw = m["data"].(map[string]interface{})["network"].(map[string]interface{})
	if netw["direction"] != "inbound" || netw["dest_ip"] != "" {
		t.Errorf("accept/ipv6: %v", netw)
	}

	m = toJSON(t, EventFromEBPF(&ebpf.Event{Type: ebpf.EventSyscall, TypeName: "syscall", PID: 5, SyscallNr: 101, SyscallName: "ptrace", Comm: "gdb"}, &names))
	data := m["data"].(map[string]interface{})
	if m["type"] != "syscall" || data["syscall_name"] != "ptrace" || data["pid"].(float64) != 5 {
		t.Errorf("syscall: %v %v", m["type"], data)
	}
}

func TestEventFromEBPFCarriesBinaryPayload(t *testing.T) {
	var names NameCache
	ev := &ebpf.Event{Type: ebpf.EventProcessExec, TypeName: "process_exec", PID: 1, UID: 0, GID: 0,
		Comm: "sh", Filename: "/bin/sh", Argv: []string{"sh"}}
	ev.Raw = ev.Record()
	out := EventFromEBPF(ev, &names)
	if out.Binary == nil {
		t.Fatal("no binary payload")
	}
	p, err := wire.Decode(out.Binary)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Record, ev.Raw) || p.User != "root" || p.Group != "root" {
		t.Errorf("payload %+v", p)
	}
	js, _ := json.Marshal(out)
	if bytes.Contains(js, []byte("Binary")) || bytes.Contains(js, []byte("WSB1")) {
		t.Error("binary payload leaked into JSON")
	}
	// Events without a raw record (e.g. synthetic) get no binary form.
	if EventFromEBPF(&ebpf.Event{Type: ebpf.EventSyscall, TypeName: "syscall"}, &names).Binary != nil {
		t.Error("binary payload without raw record")
	}
}
