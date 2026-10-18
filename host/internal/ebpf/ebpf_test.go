package ebpf

import (
	"testing"
	"time"
	"unsafe"
)

// The C struct is laid out so every member is naturally aligned; the Go type
// bpf2go generated from its BTF must therefore be exactly as large.
func TestRecordSizeMatchesC(t *testing.T) {
	if recordSize != 592 {
		t.Fatalf("sizeof(sentinelEvent) = %d, want 592 (see struct event in bpf/sentinel.bpf.c)", recordSize)
	}
}

func rawRecord(rec sentinelEvent) []byte {
	return (*[recordSize]byte)(unsafe.Pointer(&rec))[:]
}

func setC(dst []int8, s string) uint32 {
	for i := 0; i < len(s) && i < len(dst); i++ {
		dst[i] = int8(s[i])
	}
	return uint32(len(s))
}

func TestDecodeExec(t *testing.T) {
	var rec sentinelEvent
	rec.TimestampNs = 5_000_000_000
	rec.EventType = EventProcessExec
	rec.Pid, rec.Ppid, rec.Uid, rec.Gid = 1234, 1, 1000, 1000
	setC(rec.Comm[:], "bash")
	setC(rec.Filename[:], "/usr/bin/bash")
	rec.ArgsLen = setC(rec.Args[:], "bash\x00-c\x00rm -rf /tmp/x\x00")

	boot := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	ev, err := decode(rawRecord(rec), boot)
	if err != nil {
		t.Fatal(err)
	}
	if ev.TypeName != "process_exec" || ev.PID != 1234 || ev.PPID != 1 || ev.UID != 1000 {
		t.Errorf("header mismatch: %+v", ev)
	}
	if ev.Comm != "bash" || ev.Filename != "/usr/bin/bash" {
		t.Errorf("strings mismatch: comm=%q filename=%q", ev.Comm, ev.Filename)
	}
	if len(ev.Argv) != 3 || ev.Argv[1] != "-c" || ev.Argv[2] != "rm -rf /tmp/x" || ev.ArgvTruncated {
		t.Errorf("argv = %q truncated=%v", ev.Argv, ev.ArgvTruncated)
	}
	if !ev.Timestamp.Equal(boot.Add(5 * time.Second)) {
		t.Errorf("timestamp = %s", ev.Timestamp)
	}
}

func TestDecodeTruncatedArgv(t *testing.T) {
	var rec sentinelEvent
	rec.EventType = EventProcessExec
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	rec.ArgsLen = setC(rec.Args[:], string(long)) // setC stops at 256
	rec.ArgsLen = 256
	ev, err := decode(rawRecord(rec), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if !ev.ArgvTruncated || len(ev.Argv) != 1 || len(ev.Argv[0]) != 256 {
		t.Errorf("argv=%d parts, first len %d, truncated=%v", len(ev.Argv), len(ev.Argv[0]), ev.ArgvTruncated)
	}
}

func TestDecodeNetworkAndSyscall(t *testing.T) {
	var rec sentinelEvent
	rec.EventType = EventNetworkConnect
	rec.Family = 2
	rec.Protocol = 6
	rec.Saddr = 0x0100007f // 127.0.0.1 in network byte order on a little-endian host
	rec.Daddr = 0x0101a8c0 // 192.168.1.1
	rec.Sport, rec.Dport = 54321, 443
	ev, err := decode(rawRecord(rec), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if ev.SrcIP.String() != "127.0.0.1" || ev.DstIP.String() != "192.168.1.1" || ev.DstPort != 443 || ev.Protocol != "tcp" {
		t.Errorf("network decode: %+v", ev)
	}

	rec = sentinelEvent{EventType: EventSyscall, SyscallNr: 59}
	ev, err = decode(rawRecord(rec), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if ev.SyscallName != "execve" {
		t.Errorf("syscall 59 named %q", ev.SyscallName)
	}
	if got := SyscallName(999999); got != "syscall_999999" {
		t.Errorf("unknown syscall named %q", got)
	}

	rec = sentinelEvent{EventType: 42}
	if _, err := decode(rawRecord(rec), time.Time{}); err == nil {
		t.Error("unknown event type decoded")
	}
	if _, err := decode(make([]byte, 10), time.Time{}); err == nil {
		t.Error("short record decoded")
	}
}

func TestParseHooks(t *testing.T) {
	for _, in := range []string{"", "all"} {
		got, err := ParseHooks(in)
		if err != nil || len(got) != len(AllHooks) {
			t.Errorf("ParseHooks(%q) = %v, %v", in, got, err)
		}
	}
	got, err := ParseHooks(" open, exec ,open")
	if err != nil || len(got) != 2 || got[0] != "open" || got[1] != "exec" {
		t.Errorf("ParseHooks dedupe = %v, %v", got, err)
	}
	if _, err := ParseHooks("exec,bogus"); err == nil {
		t.Error("bogus hook accepted")
	}
	if _, err := ParseHooks(","); err == nil {
		t.Error("empty selection accepted")
	}
}

func TestSyscallTableCoversWatchedSyscalls(t *testing.T) {
	// Numbers allow-listed in bpf/sentinel.bpf.c must all have names.
	for _, nr := range []uint32{56, 57, 59, 62, 101, 105, 106, 155, 157, 161, 165, 166, 175, 272, 308, 313, 319, 321, 322, 435} {
		if name := SyscallName(nr); len(name) > 8 && name[:8] == "syscall_" {
			t.Errorf("syscall %d has no name", nr)
		}
	}
}
