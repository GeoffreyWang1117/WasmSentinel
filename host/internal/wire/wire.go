// Package wire defines the binary event payload the host hands to a rule's
// detect_raw export: a 16-byte header, the kernel record exactly as the BPF
// program wrote it, and the strings the host resolved (user, group, syscall
// name) as NUL-terminated text. The Rust side is rules/sentinel-abi.
//
//	offset 0   u32 magic 0x31425357 ("WSB1" little-endian)
//	offset 4   u16 version = 1
//	offset 6   u16 flags (0)
//	offset 8   u32 record length (= RecordLen)
//	offset 12  u32 strings length
//	offset 16  record
//	then       user\0 group\0 syscall_name\0
package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	Magic     uint32 = 0x31425357
	Version   uint16 = 1
	HeaderLen        = 16
	// RecordLen is sizeof(struct event) in host/internal/ebpf/bpf/sentinel.bpf.c.
	RecordLen = 592
)

// Payload is a decoded binary event.
type Payload struct {
	Record      []byte
	User        string
	Group       string
	SyscallName string
}

// Encode builds a payload. record must be exactly RecordLen bytes.
func Encode(record []byte, user, group, syscallName string) ([]byte, error) {
	if len(record) != RecordLen {
		return nil, fmt.Errorf("wire: record is %d bytes, want %d", len(record), RecordLen)
	}
	stringsLen := len(user) + len(group) + len(syscallName) + 3
	out := make([]byte, HeaderLen+RecordLen+stringsLen)
	binary.LittleEndian.PutUint32(out[0:], Magic)
	binary.LittleEndian.PutUint16(out[4:], Version)
	binary.LittleEndian.PutUint16(out[6:], 0)
	binary.LittleEndian.PutUint32(out[8:], RecordLen)
	binary.LittleEndian.PutUint32(out[12:], uint32(stringsLen))
	copy(out[HeaderLen:], record)
	p := HeaderLen + RecordLen
	for _, s := range []string{user, group, syscallName} {
		p += copy(out[p:], s)
		out[p] = 0
		p++
	}
	return out, nil
}

// Decode parses a payload built by Encode (or by rules/sentinel-abi).
func Decode(b []byte) (Payload, error) {
	if len(b) < HeaderLen {
		return Payload{}, errors.New("wire: payload shorter than header")
	}
	if m := binary.LittleEndian.Uint32(b[0:]); m != Magic {
		return Payload{}, fmt.Errorf("wire: bad magic %#x", m)
	}
	if v := binary.LittleEndian.Uint16(b[4:]); v != Version {
		return Payload{}, fmt.Errorf("wire: unsupported version %d", v)
	}
	recLen := int(binary.LittleEndian.Uint32(b[8:]))
	strLen := int(binary.LittleEndian.Uint32(b[12:]))
	if recLen != RecordLen || len(b) < HeaderLen+recLen+strLen {
		return Payload{}, errors.New("wire: bad lengths")
	}
	p := Payload{Record: b[HeaderLen : HeaderLen+recLen]}
	parts := bytes.SplitN(b[HeaderLen+recLen:HeaderLen+recLen+strLen], []byte{0}, 4)
	get := func(i int) string {
		if i < len(parts) {
			return string(parts[i])
		}
		return ""
	}
	p.User, p.Group, p.SyscallName = get(0), get(1), get(2)
	return p, nil
}
