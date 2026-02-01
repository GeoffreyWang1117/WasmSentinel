# WasmSentinel Experiment Design

## Target Conference: CCS 2026 Cycle 2 (Deadline: April 29, 2026)

---

## 1. Research Questions

### RQ1: Performance
**"What is the overhead of eBPF-Wasm cooperative architecture compared to native eBPF-based detection?"**

Metrics:
- Event processing latency (p50, p95, p99)
- System throughput (events/second)
- CPU and memory overhead

### RQ2: Detection Accuracy
**"Can Wasm-sandboxed detection rules achieve comparable accuracy to native detection engines?"**

Metrics:
- True Positive Rate (TPR)
- False Positive Rate (FPR)
- F1 Score
- Detection Time

### RQ3: Security Isolation
**"Does the Wasm sandbox effectively isolate potentially malicious detection rules?"**

Metrics:
- Rule escape attempts blocked
- Resource exhaustion protection
- Cross-rule isolation

### RQ4: Scalability
**"How does the system perform under varying event rates and rule counts?"**

Metrics:
- Throughput vs. event rate
- Latency vs. rule count
- Resource usage vs. load

---

## 2. Experimental Setup

### 2.1 Hardware Configuration

| Component | Specification |
|-----------|--------------|
| CPU | AMD EPYC 7763 64-Core or Intel Xeon Gold 6348 |
| Memory | 256 GB DDR4 |
| Storage | NVMe SSD (Samsung 980 Pro or equivalent) |
| Network | 10 Gbps |
| OS | Ubuntu 22.04 LTS (Kernel 5.15+) |

### 2.2 Software Versions

| Software | Version |
|----------|---------|
| Go | 1.21+ |
| Rust | 1.70+ |
| Wasmtime | 17.0.0 |
| Falco | 0.37.0 |
| Tetragon | 1.0.0 |
| Linux Kernel | 5.15+ (BTF enabled) |

### 2.3 Baseline Systems

1. **Falco** - eBPF-based runtime security
   - Configuration: Default ruleset
   - Mode: eBPF probe

2. **Tetragon** - eBPF-based security observability
   - Configuration: Process and network policies
   - Mode: eBPF LSM

3. **Native eBPF** - Direct eBPF without Wasm
   - WasmSentinel with Wasm disabled
   - Direct rule execution in Go

---

## 3. Datasets

### 3.1 LID-DS 2021 (Primary)

| Scenario | Attack Type | Training Runs | Test Runs |
|----------|-------------|---------------|-----------|
| Bruteforce_CWE-307 | Authentication | 100 | 20 |
| CVE-2012-2122 | Auth Bypass | 100 | 20 |
| CVE-2014-0160 | Heartbleed | 100 | 20 |
| CVE-2017-7529 | Buffer Overflow | 100 | 20 |
| CVE-2018-3760 | Path Traversal | 100 | 20 |
| CWE-89-SQL-injection | SQL Injection | 100 | 20 |

### 3.2 ADFA-LD (Secondary)

| Category | Traces | Syscalls (avg) |
|----------|--------|----------------|
| Training (Normal) | 833 | 5,000 |
| Validation (Normal) | 4,372 | 5,000 |
| Hydra FTP Attack | 162 | 8,000 |
| Hydra SSH Attack | 148 | 7,500 |
| Add User Attack | 91 | 3,000 |
| Java Meterpreter | 125 | 12,000 |
| Web Shell | 118 | 6,000 |

### 3.3 Synthetic Workloads

| Workload | Event Rate | Duration | Pattern |
|----------|------------|----------|---------|
| Light | 100 events/s | 5 min | Normal ops |
| Medium | 1,000 events/s | 5 min | Mixed |
| Heavy | 10,000 events/s | 5 min | Stress test |
| Burst | 50,000 events/s | 30 sec | Peak load |

---

## 4. Experiments

### Experiment 1: Latency Microbenchmark

**Objective**: Measure per-event processing latency breakdown

**Method**:
1. Generate controlled event stream (100 events/s)
2. Measure time at each pipeline stage:
   - eBPF event generation
   - Ring buffer transfer
   - Wasm memory copy
   - Detection execution
   - Result handling
3. Repeat for 10,000 events
4. Calculate percentile statistics

**Expected Output**:
```
Pipeline Stage        | P50    | P95    | P99
---------------------|--------|--------|--------
eBPF Collection      | 0.5 us | 1.0 us | 2.0 us
Ring Buffer Read     | 0.3 us | 0.8 us | 1.5 us
Wasm Transfer        | 0.2 us | 0.5 us | 1.0 us
Detection (Wasm)     | 0.5 us | 1.5 us | 3.0 us
Total                | 1.5 us | 3.8 us | 7.5 us
```

### Experiment 2: Throughput Scaling

**Objective**: Measure maximum sustainable event rate

**Method**:
1. Increase event rate: 100, 500, 1K, 5K, 10K, 50K, 100K events/s
2. For each rate:
   - Run for 60 seconds
   - Measure actual processed events
   - Record dropped events
   - Measure CPU/memory usage
3. Identify saturation point

**Expected Output**:
- Throughput curve (events/s vs. target rate)
- Drop rate curve
- Resource usage curves

### Experiment 3: Detection Accuracy

**Objective**: Compare detection accuracy across systems

**Method**:
1. Load LID-DS scenarios
2. Replay syscall traces through each system
3. Compare detections against ground truth
4. Calculate metrics per scenario

**Expected Output**:
```
System        | TPR    | FPR    | F1
--------------|--------|--------|------
WasmSentinel  | 0.95   | 0.02   | 0.94
Falco         | 0.92   | 0.05   | 0.90
Tetragon      | 0.88   | 0.03   | 0.89
```

### Experiment 4: Rule Scalability

**Objective**: Measure impact of rule count on performance

**Method**:
1. Create 1, 5, 10, 50, 100 detection rules
2. For each configuration:
   - Measure baseline latency
   - Measure memory footprint
   - Test with 1000 events/s

**Expected Output**:
- Latency vs. rule count
- Memory vs. rule count
- Throughput vs. rule count

### Experiment 5: Security Isolation

**Objective**: Verify Wasm sandbox effectiveness

**Method**:
1. Create malicious rules that attempt:
   - File system access
   - Network access
   - Infinite loops
   - Memory exhaustion
   - Stack overflow
2. Verify containment
3. Measure overhead of security checks

**Expected Output**:
| Attack Vector | Contained | Overhead |
|---------------|-----------|----------|
| FS Access     | Yes       | 0%       |
| Network       | Yes       | 0%       |
| Infinite Loop | Yes (timeout) | 5%    |
| Memory Bomb   | Yes (limit)   | 2%    |

### Experiment 6: Real-World Attacks

**Objective**: Validate detection on real attack samples

**Method**:
1. Set up vulnerable applications:
   - Apache Struts (CVE-2017-5638)
   - Log4j (CVE-2021-44228)
   - Spring4Shell (CVE-2022-22965)
2. Execute known exploits
3. Measure detection success
4. Analyze detection timing

---

## 5. Analysis Plan

### 5.1 Statistical Methods

- **Latency**: Percentile analysis, box plots
- **Throughput**: Linear regression, saturation modeling
- **Accuracy**: Confusion matrices, ROC curves
- **Comparison**: Wilcoxon signed-rank test (p < 0.05)

### 5.2 Visualization

1. **Figure 1**: Architecture diagram
2. **Figure 2**: Latency breakdown (stacked bar)
3. **Figure 3**: Throughput scaling (line chart)
4. **Figure 4**: Accuracy comparison (grouped bar)
5. **Figure 5**: ROC curves
6. **Figure 6**: Resource usage (dual y-axis)
7. **Figure 7**: Rule scalability (multi-line)

### 5.3 Key Claims to Support

1. "WasmSentinel achieves < 10us P99 latency at 10,000 events/s"
2. "Wasm sandbox adds < 20% overhead vs. native execution"
3. "Detection accuracy matches or exceeds state-of-the-art"
4. "System scales linearly up to 100 detection rules"

---

## 6. Timeline

### Phase 1: Implementation (Jan 1 - Feb 15, 2026)

| Week | Task | Deliverable |
|------|------|-------------|
| 1-2 | Complete eBPF collector | Working eBPF programs |
| 3-4 | Implement zero-copy bridge | Optimized data transfer |
| 5-6 | Integrate with Wasm engine | Full pipeline working |

### Phase 2: Evaluation (Feb 15 - Mar 31, 2026)

| Week | Task | Deliverable |
|------|------|-------------|
| 7-8 | Dataset preparation | LID-DS, ADFA-LD ready |
| 9-10 | Baseline setup | Falco, Tetragon configured |
| 11-12 | Run experiments | Raw results |
| 13-14 | Analysis | Processed results, figures |

### Phase 3: Writing (Apr 1 - Apr 28, 2026)

| Week | Task | Deliverable |
|------|------|-------------|
| 15-16 | Draft paper | Complete manuscript |
| 17-18 | Internal review | Revised manuscript |
| 19 | Final polish | Camera-ready |
| 20 | Submit | CCS submission |

---

## 7. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| eBPF complexity | Medium | High | Use cilium/ebpf library |
| Wasm overhead too high | Low | High | Optimize critical path |
| Dataset unavailable | Low | Medium | Use synthetic data |
| Baseline setup issues | Medium | Medium | Docker containers |
| Time constraints | Medium | High | Prioritize core experiments |

---

## 8. Artifact Checklist

For reproducibility (CCS artifact evaluation):

- [ ] Source code (GitHub)
- [ ] Build instructions
- [ ] Docker images
- [ ] Dataset download scripts
- [ ] Experiment automation
- [ ] Result analysis scripts
- [ ] Pre-computed results
- [ ] Documentation

---

## 9. References

1. Grimmer et al., "LID-DS: A Dataset for Host-Based Intrusion Detection," RAID 2021
2. Creech and Hu, "ADFA IDS Datasets," ACSW 2013
3. Falco: Cloud-Native Runtime Security, https://falco.org
4. Tetragon: eBPF-based Security Observability, https://tetragon.io
5. Wasmtime: A fast and secure runtime for WebAssembly, https://wasmtime.dev
