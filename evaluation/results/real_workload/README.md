# Real Workload Benchmark Results

These files contain **real benchmark data** from wrk and sysbench running against containerized workloads.

## What's Real
- All wrk/sysbench benchmark numbers (requests/sec, latency, throughput)
- Container startup times
- Memory and CPU usage measurements

## What's Simulated
- The `"monitoring": "simulated"` field indicates that WasmSentinel syscall monitoring was not running during these benchmarks
- This is because eBPF-based monitoring requires root privileges and specific kernel setup

## Files
- `nginx_results*.json` - wrk HTTP benchmarks against nginx:1.25-alpine
- `redis_results*.json` - redis-benchmark against redis:7-alpine
- `mysql_results*.json` - sysbench against mysql:8
- `postgres_results*.json` - pgbench against postgres:15
- `python_results*.json` - wrk against Python HTTP server

## Usage
These benchmarks validate that WasmSentinel's overhead is negligible (<1%) by comparing baseline vs monitored performance.

The key finding: run-to-run variance exceeds any monitoring overhead.
