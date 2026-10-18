//go:build !amd64

package ebpf

// syscallNames is only populated on amd64; other architectures fall back to syscall_<nr>.
var syscallNames = map[uint32]string{}
