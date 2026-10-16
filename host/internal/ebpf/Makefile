# Makefile for eBPF program compilation
# WasmSentinel eBPF Collector

CLANG ?= clang
BPFTOOL ?= bpftool
GO ?= go
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_SRC := bpf/sentinel.bpf.c
BPF_OBJ := bpf/sentinel.bpf.o
VMLINUX := bpf/vmlinux.h

# Clang flags for eBPF compilation
CLANG_BPF_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 | \
	sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

BPF_CFLAGS := -g -O2 -Wall -Werror \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	$(CLANG_BPF_SYS_INCLUDES)

.PHONY: all clean generate vmlinux

all: generate

# Generate Go bindings from eBPF object
generate: $(BPF_OBJ)
	$(GO) generate ./...

# Compile eBPF program
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)

# Generate vmlinux.h from running kernel
vmlinux: $(VMLINUX)

$(VMLINUX):
	@echo "Generating vmlinux.h..."
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX); \
	else \
		echo "BTF not available, downloading pre-generated vmlinux.h..."; \
		curl -sL https://raw.githubusercontent.com/libbpf/libbpf-bootstrap/master/vmlinux/vmlinux_$(ARCH).h -o $(VMLINUX); \
	fi
	@echo "vmlinux.h generated successfully"

# Clean generated files
clean:
	rm -f $(BPF_OBJ) $(VMLINUX)
	rm -f sentinel_bpfel.go sentinel_bpfel.o
	rm -f sentinel_bpfeb.go sentinel_bpfeb.o

# Install dependencies
deps:
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest

# Verify eBPF program
verify: $(BPF_OBJ)
	llvm-objdump -S $(BPF_OBJ)

# Format eBPF source
format:
	clang-format -i $(BPF_SRC)

.PHONY: help
help:
	@echo "WasmSentinel eBPF Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build eBPF program and generate Go bindings (default)"
	@echo "  vmlinux  - Generate vmlinux.h from running kernel"
	@echo "  clean    - Remove generated files"
	@echo "  deps     - Install build dependencies"
	@echo "  verify   - Dump eBPF object for verification"
	@echo "  format   - Format eBPF source code"
