# WasmSentinel: High-Performance eBPF-Wasm Cooperative Threat Detection

## Research Framework for Top-tier Security Conferences

---

## 1. Research Problem

**Core Question**: How to efficiently integrate eBPF kernel-level event collection with WebAssembly-based detection engines while maintaining security isolation and high performance?

### 1.1 Motivation

Current runtime threat detection systems face a fundamental trade-off:

| Approach | Pros | Cons |
|----------|------|------|
| **Kernel-based (eBPF)** | Low overhead, comprehensive visibility | Complex development, kernel version dependency |
| **User-space agents** | Flexible, easy deployment | Higher overhead, limited visibility |
| **Wasm sandboxed** | Safe, portable rules | Memory copy overhead, limited host access |

**Our Insight**: By carefully designing the eBPF-Wasm interface, we can achieve the best of all worlds: kernel-level visibility, user-space flexibility, and sandboxed safety.

### 1.2 Research Challenges

1. **Data Transfer Overhead**: How to minimize memory copies between eBPF maps and Wasm linear memory?
2. **Event Batching Strategy**: What is the optimal batch size for different workloads?
3. **Rule Isolation**: How to ensure malicious detection rules cannot escape the Wasm sandbox?
4. **Latency Guarantee**: How to meet real-time detection requirements under high event rates?

---

## 2. Threat Model

### 2.1 Attacker Capabilities

We consider attackers who can:
- Execute arbitrary code in user space with unprivileged access
- Attempt to evade detection through obfuscation techniques
- Potentially compromise detection rules (supply chain attack)

We assume attackers **cannot**:
- Directly modify kernel memory or eBPF programs
- Bypass hardware memory protection
- Compromise the Wasm runtime itself

### 2.2 Security Goals

| Goal | Description | Mechanism |
|------|-------------|-----------|
| **Detection Integrity** | Accurate threat identification | eBPF-based syscall tracing |
| **Rule Isolation** | Malicious rules cannot harm host | Wasm sandbox + WASI restrictions |
| **Data Confidentiality** | Sensitive events protected | Memory isolation between rules |
| **Availability** | System remains responsive | Resource limits, timeout mechanisms |

### 2.3 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED COMPUTING BASE                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Kernel    │  │  Wasmtime   │  │    Host Program     │  │
│  │  + eBPF     │  │   Runtime   │  │      (Go)           │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    UNTRUSTED DOMAIN                          │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Detection Rules (Wasm)                  │    │
│  │   - Third-party rules                                │    │
│  │   - Community-contributed rules                      │    │
│  │   - Potentially malicious rules                      │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. System Design

### 3.1 Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         User Space                                │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                    WasmSentinel Host                        │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │  │
│  │  │ Ring Buffer  │  │   Batch      │  │  Wasm Engine     │  │  │
│  │  │   Reader     │──│  Aggregator  │──│  (Wasmtime)      │  │  │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘  │  │
│  │         ▲                                     │             │  │
│  │         │                                     ▼             │  │
│  │  ┌──────────────┐                    ┌──────────────────┐  │  │
│  │  │  Perf Buffer │                    │ Detection Rules  │  │  │
│  │  │   (fallback) │                    │   (Wasm Modules) │  │  │
│  │  └──────────────┘                    └──────────────────┘  │  │
│  └────────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────┤
│                        Kernel Space                               │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                     eBPF Programs                           │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │  │
│  │  │ Syscall  │  │  Sched   │  │ Network  │  │  File    │   │  │
│  │  │ Tracing  │  │ Tracing  │  │ Tracing  │  │ Tracing  │   │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │  │
│  │         │            │            │            │           │  │
│  │         └────────────┴────────────┴────────────┘           │  │
│  │                           │                                 │  │
│  │                    ┌──────▼──────┐                         │  │
│  │                    │ Ring Buffer │                         │  │
│  │                    │   (BPF Map) │                         │  │
│  │                    └─────────────┘                         │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 Key Components

#### 3.2.1 eBPF Event Collector

**Tracepoints**:
- `sys_enter_execve` / `sys_exit_execve`: Process execution
- `sys_enter_openat`: File access
- `sys_enter_connect` / `sys_enter_accept`: Network connections
- `sched_process_fork` / `sched_process_exit`: Process lifecycle

**Data Structure** (in kernel):
```c
struct event {
    u64 timestamp;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 event_type;
    char comm[16];
    char filename[256];
    union {
        struct {
            u32 syscall_nr;
            long ret;
        } syscall;
        struct {
            u32 saddr;
            u32 daddr;
            u16 sport;
            u16 dport;
        } network;
    };
};
```

#### 3.2.2 Zero-Copy Data Transfer

**Innovation**: Use shared memory region between ring buffer and Wasm linear memory.

```
Traditional Approach:
  Ring Buffer → memcpy → Go heap → JSON serialize → Wasm memory
  (4 copies, high overhead)

Our Approach:
  Ring Buffer → Direct mapping → Wasm memory (read-only)
  (1 copy, low overhead)
```

#### 3.2.3 Batch Processing

Adaptive batching based on event rate:

| Event Rate | Batch Size | Latency Target |
|------------|------------|----------------|
| < 100/s    | 1 (immediate) | < 1ms |
| 100-1000/s | 10 | < 10ms |
| 1000-10000/s | 100 | < 50ms |
| > 10000/s | 1000 | < 100ms |

---

## 4. Novel Contributions

### Contribution 1: eBPF-Wasm Zero-Copy Interface
- Design a shared memory protocol for efficient data transfer
- Eliminate JSON serialization overhead in the hot path
- Achieve < 500ns per event overhead

### Contribution 2: Adaptive Event Batching
- Dynamic batch size adjustment based on system load
- Formal analysis of latency-throughput trade-off
- Optimal batching strategy derivation

### Contribution 3: Secure Rule Execution Framework
- Formal verification of Wasm sandbox isolation
- Resource limiting for untrusted rules
- Crash isolation between detection rules

### Contribution 4: Comprehensive Evaluation
- Comparison with Falco, Sysdig, Tetragon
- Evaluation on LID-DS, ADFA-LD datasets
- Real-world attack scenario validation

---

## 5. Evaluation Plan

### 5.1 Datasets

| Dataset | Type | Size | Use Case |
|---------|------|------|----------|
| **LID-DS** | System calls | 10 scenarios | Intrusion detection |
| **ADFA-LD** | Linux attacks | 833 attacks | Attack detection |
| **StreamSpot** | Behavior graphs | 600 graphs | APT detection |
| **Custom** | Real attacks | 50+ samples | Validation |

### 5.2 Baselines

| System | Type | Language | Detection Method |
|--------|------|----------|------------------|
| **Falco** | eBPF-based | C++/Lua | Rule matching |
| **Tetragon** | eBPF-based | Go | Policy enforcement |
| **Sysdig** | Kernel module | C | Syscall tracing |
| **LKRG** | Kernel module | C | Integrity checking |

### 5.3 Metrics

**Performance**:
- Detection latency (p50, p99, p999)
- Throughput (events/second)
- CPU overhead (%)
- Memory footprint (MB)

**Accuracy**:
- True Positive Rate (TPR)
- False Positive Rate (FPR)
- F1 Score
- Detection time

**Security**:
- Rule escape attempts
- Resource exhaustion resistance
- Crash isolation effectiveness

### 5.4 Experiments

1. **Microbenchmark**: Data transfer overhead
2. **Throughput Test**: Maximum sustainable event rate
3. **Latency Test**: End-to-end detection latency
4. **Accuracy Test**: Detection rate on standard datasets
5. **Comparison Test**: Performance vs. Falco, Tetragon
6. **Security Test**: Malicious rule containment

---

## 6. Timeline (Target: CCS 2026 Cycle 2 - April 29)

### Phase 1: Core Implementation (Jan 1 - Feb 15)
- [ ] Week 1-2: eBPF collector implementation
- [ ] Week 3-4: Zero-copy data transfer mechanism
- [ ] Week 5-6: Adaptive batching algorithm

### Phase 2: Evaluation Framework (Feb 15 - Mar 15)
- [ ] Week 7-8: Dataset integration (LID-DS, ADFA-LD)
- [ ] Week 9-10: Baseline setup (Falco, Tetragon)
- [ ] Week 11-12: Experiment execution

### Phase 3: Paper Writing (Mar 15 - Apr 25)
- [ ] Week 13-14: Results analysis and visualization
- [ ] Week 15-16: Paper draft
- [ ] Week 17-18: Internal review and revision

---

## 7. Related Work

### 7.1 eBPF-based Security Systems

- **Falco** (Sysdig, 2016): Rule-based anomaly detection using eBPF
- **Tetragon** (Cilium, 2022): Security observability with eBPF
- **Tracee** (Aqua, 2020): Runtime security using eBPF
- **bpftrace** (Gregg, 2019): Dynamic tracing tool

### 7.2 WebAssembly for Security

- **ERIM** (USENIX Security 2019): Memory isolation using MPK + Wasm
- **Sledge** (ASPLOS 2020): Serverless Wasm runtime
- **WasmBoxC** (USENIX Security 2022): Sandboxing C with Wasm

### 7.3 Intrusion Detection Systems

- **Xu et al.** (CCS 2016): High-fidelity attack provenance
- **Liu et al.** (S&P 2018): Syscall-based anomaly detection
- **Han et al.** (NDSS 2020): Behavior-based threat detection

---

## 8. Paper Outline (Draft)

1. **Introduction** (1 page)
   - Motivation: Trade-off in runtime security
   - Our approach: eBPF + Wasm cooperative detection
   - Contributions summary

2. **Background** (1 page)
   - eBPF overview
   - WebAssembly security model
   - Existing detection systems

3. **Threat Model** (0.5 page)
   - Attacker capabilities
   - Security goals

4. **System Design** (3 pages)
   - Architecture overview
   - eBPF event collector
   - Zero-copy data transfer
   - Adaptive batching
   - Wasm rule engine

5. **Implementation** (1 page)
   - eBPF programs (C + libbpf)
   - Host program (Go)
   - Detection rules (Rust → Wasm)

6. **Evaluation** (3 pages)
   - Experimental setup
   - Performance comparison
   - Detection accuracy
   - Security analysis

7. **Discussion** (0.5 page)
   - Limitations
   - Future work

8. **Related Work** (1 page)

9. **Conclusion** (0.5 page)

---

## 9. Key Insights to Emphasize

1. **"First system to combine eBPF kernel tracing with Wasm-sandboxed detection rules"**

2. **"Zero-copy data transfer reduces per-event overhead by 10x compared to JSON serialization"**

3. **"Adaptive batching achieves 95th percentile latency < 10ms at 10,000 events/second"**

4. **"Wasm sandbox provides strong isolation for third-party detection rules with < 5% overhead"**

---

## 10. Potential Venues

| Venue | Fit | Deadline | Notes |
|-------|-----|----------|-------|
| **CCS 2026** | High | Apr 29, 2026 | Systems security track |
| **USENIX Security 2026** | High | Feb 5, 2026 | Tight timeline |
| **NDSS 2027** | Medium | Aug 2026 | More time |
| **EuroSys 2026** | High | Sep 25, 2025 (passed) | Systems focus |
| **ATC 2026** | Medium | TBD | Systems/performance |

**Primary Target**: CCS 2026 Cycle 2 (April 29, 2026)
