package wire

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	rec := bytes.Repeat([]byte{0xab}, RecordLen)
	b, err := Encode(rec, "root", "wheel", "ptrace")
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != HeaderLen+RecordLen+len("root")+len("wheel")+len("ptrace")+3 {
		t.Fatalf("payload length %d", len(b))
	}
	p, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Record, rec) || p.User != "root" || p.Group != "wheel" || p.SyscallName != "ptrace" {
		t.Errorf("decoded %+v", p)
	}
}

func TestEmptyStringsAndErrors(t *testing.T) {
	b, err := Encode(make([]byte, RecordLen), "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode(b)
	if err != nil || p.User != "" || p.SyscallName != "" {
		t.Errorf("empty strings: %+v %v", p, err)
	}
	if _, err := Encode(make([]byte, 10), "", "", ""); err == nil {
		t.Error("short record accepted")
	}
	if _, err := Decode(b[:HeaderLen+10]); err == nil {
		t.Error("truncated payload accepted")
	}
	bad := append([]byte(nil), b...)
	bad[0] ^= 1
	if _, err := Decode(bad); err == nil {
		t.Error("bad magic accepted")
	}
}
