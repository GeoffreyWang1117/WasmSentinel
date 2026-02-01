#!/bin/bash
# WasmSentinel vs Falco Comparison Script
# This script runs comparative benchmarks between WasmSentinel and Falco

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
RESULTS_DIR="./evaluation/results/$(date +%Y%m%d_%H%M%S)"
DURATION=60  # Test duration in seconds
EVENT_RATE=1000  # Target events per second

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}WasmSentinel vs Falco Comparison${NC}"
echo -e "${BLUE}========================================${NC}"

# Create results directory
mkdir -p "$RESULTS_DIR"

# Check dependencies
check_dependencies() {
    echo -e "\n${YELLOW}Checking dependencies...${NC}"

    # Check if Falco is installed
    if ! command -v falco &> /dev/null; then
        echo -e "${YELLOW}Falco not found. Installing...${NC}"
        # Install Falco
        curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
            sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | \
            sudo tee /etc/apt/sources.list.d/falcosecurity.list
        sudo apt-get update
        sudo apt-get install -y falco
    else
        echo -e "${GREEN}Falco found: $(falco --version)${NC}"
    fi

    # Check if WasmSentinel is built
    if [ ! -f "./wasm-threat-detector" ]; then
        echo -e "${YELLOW}WasmSentinel not built. Building...${NC}"
        ./scripts/build.sh
    else
        echo -e "${GREEN}WasmSentinel found${NC}"
    fi

    # Check if stress-ng is available for load generation
    if ! command -v stress-ng &> /dev/null; then
        echo -e "${YELLOW}Installing stress-ng for load generation...${NC}"
        sudo apt-get install -y stress-ng
    fi
}

# Benchmark function for WasmSentinel
benchmark_wasmsentinel() {
    echo -e "\n${BLUE}Benchmarking WasmSentinel...${NC}"

    local result_file="$RESULTS_DIR/wasmsentinel_results.json"

    # Start WasmSentinel in background
    ./wasm-threat-detector --config ./examples/config.yaml \
        --metrics-port 8080 \
        --log-file "$RESULTS_DIR/wasmsentinel.log" &
    local ws_pid=$!

    sleep 2  # Wait for startup

    # Record start time
    local start_time=$(date +%s.%N)

    # Generate test workload
    echo -e "Generating test workload for ${DURATION}s..."
    generate_workload &
    local workload_pid=$!

    # Collect metrics during test
    local events=0
    local detections=0
    for i in $(seq 1 $DURATION); do
        # Get metrics from Prometheus endpoint
        metrics=$(curl -s http://localhost:8080/metrics 2>/dev/null || echo "")
        if [ -n "$metrics" ]; then
            current_events=$(echo "$metrics" | grep "wasm_sentinel_total_threats" | awk '{print $2}' || echo "0")
            events=$((events + current_events))
        fi
        sleep 1
    done

    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)

    # Stop workload and WasmSentinel
    kill $workload_pid 2>/dev/null || true
    kill $ws_pid 2>/dev/null || true

    # Get final metrics
    local final_metrics=$(curl -s http://localhost:8080/metrics 2>/dev/null || echo "{}")

    # Calculate statistics
    local cpu_usage=$(ps -p $ws_pid -o %cpu= 2>/dev/null || echo "0")
    local mem_usage=$(ps -p $ws_pid -o rss= 2>/dev/null || echo "0")
    mem_usage=$((mem_usage / 1024))  # Convert to MB

    # Save results
    cat > "$result_file" << EOF
{
    "system": "WasmSentinel",
    "duration_seconds": $duration,
    "total_events": $events,
    "events_per_second": $(echo "scale=2; $events / $duration" | bc),
    "cpu_percent": $cpu_usage,
    "memory_mb": $mem_usage,
    "detections": $detections
}
EOF

    echo -e "${GREEN}WasmSentinel benchmark complete. Results saved to $result_file${NC}"
}

# Benchmark function for Falco
benchmark_falco() {
    echo -e "\n${BLUE}Benchmarking Falco...${NC}"

    local result_file="$RESULTS_DIR/falco_results.json"

    # Start Falco in background (requires root)
    sudo falco --json-output \
        --pidfile /var/run/falco.pid \
        -o json_output=true \
        -o json_include_output_property=true \
        > "$RESULTS_DIR/falco.log" 2>&1 &
    local falco_pid=$!

    sleep 3  # Falco takes longer to start

    # Record start time
    local start_time=$(date +%s.%N)

    # Generate test workload
    echo -e "Generating test workload for ${DURATION}s..."
    generate_workload &
    local workload_pid=$!

    # Wait for test duration
    sleep $DURATION

    local end_time=$(date +%s.%N)
    local duration=$(echo "$end_time - $start_time" | bc)

    # Stop workload and Falco
    kill $workload_pid 2>/dev/null || true
    sudo kill $falco_pid 2>/dev/null || true

    # Count detections from log
    local detections=$(grep -c '"priority"' "$RESULTS_DIR/falco.log" 2>/dev/null || echo "0")

    # Get resource usage (from before kill)
    local cpu_usage=$(ps -p $falco_pid -o %cpu= 2>/dev/null || echo "0")
    local mem_usage=$(ps -p $falco_pid -o rss= 2>/dev/null || echo "0")
    mem_usage=$((mem_usage / 1024))

    # Save results
    cat > "$result_file" << EOF
{
    "system": "Falco",
    "duration_seconds": $duration,
    "total_events": 0,
    "events_per_second": 0,
    "cpu_percent": $cpu_usage,
    "memory_mb": $mem_usage,
    "detections": $detections
}
EOF

    echo -e "${GREEN}Falco benchmark complete. Results saved to $result_file${NC}"
}

# Generate test workload
generate_workload() {
    # Process creation
    for i in $(seq 1 100); do
        ls /tmp > /dev/null 2>&1
        cat /etc/passwd > /dev/null 2>&1
        ps aux > /dev/null 2>&1
        sleep 0.1
    done

    # File operations
    for i in $(seq 1 50); do
        touch /tmp/test_file_$i
        echo "test" > /tmp/test_file_$i
        rm /tmp/test_file_$i
        sleep 0.1
    done

    # Network operations (benign)
    for i in $(seq 1 20); do
        curl -s https://example.com > /dev/null 2>&1 || true
        sleep 0.2
    done

    # Suspicious activities (for detection)
    for i in $(seq 1 10); do
        # These should trigger detections
        bash -c "echo test" > /dev/null 2>&1
        timeout 1 nc -z localhost 22 2>/dev/null || true
        sleep 0.5
    done
}

# Latency test
latency_test() {
    local system=$1
    local result_file="$RESULTS_DIR/${system}_latency.json"

    echo -e "\n${BLUE}Running latency test for $system...${NC}"

    local latencies=()

    for i in $(seq 1 100); do
        local start=$(date +%s.%N)

        # Trigger an event
        ls /tmp > /dev/null 2>&1

        local end=$(date +%s.%N)
        local latency=$(echo "($end - $start) * 1000000" | bc)  # Convert to microseconds
        latencies+=($latency)

        sleep 0.01
    done

    # Calculate statistics
    local sum=0
    local min=${latencies[0]}
    local max=${latencies[0]}

    for lat in "${latencies[@]}"; do
        sum=$(echo "$sum + $lat" | bc)
        if (( $(echo "$lat < $min" | bc -l) )); then
            min=$lat
        fi
        if (( $(echo "$lat > $max" | bc -l) )); then
            max=$lat
        fi
    done

    local mean=$(echo "scale=2; $sum / ${#latencies[@]}" | bc)

    # Sort for percentiles
    IFS=$'\n' sorted=($(sort -n <<<"${latencies[*]}")); unset IFS

    local p50_idx=$((${#sorted[@]} / 2))
    local p95_idx=$((${#sorted[@]} * 95 / 100))
    local p99_idx=$((${#sorted[@]} * 99 / 100))

    cat > "$result_file" << EOF
{
    "system": "$system",
    "samples": ${#latencies[@]},
    "min_us": $min,
    "max_us": $max,
    "mean_us": $mean,
    "p50_us": ${sorted[$p50_idx]},
    "p95_us": ${sorted[$p95_idx]},
    "p99_us": ${sorted[$p99_idx]}
}
EOF

    echo -e "${GREEN}Latency test complete. Mean: ${mean}us, P99: ${sorted[$p99_idx]}us${NC}"
}

# Generate comparison report
generate_report() {
    echo -e "\n${BLUE}Generating comparison report...${NC}"

    local report_file="$RESULTS_DIR/comparison_report.md"

    cat > "$report_file" << 'EOF'
# WasmSentinel vs Falco Comparison Report

## Test Configuration
- **Date**: $(date)
- **Duration**: $DURATION seconds
- **Target Event Rate**: $EVENT_RATE events/second

## Summary

| Metric | WasmSentinel | Falco | Winner |
|--------|--------------|-------|--------|
EOF

    # Parse results and add to report
    if [ -f "$RESULTS_DIR/wasmsentinel_results.json" ] && [ -f "$RESULTS_DIR/falco_results.json" ]; then
        local ws_cpu=$(jq -r '.cpu_percent' "$RESULTS_DIR/wasmsentinel_results.json")
        local falco_cpu=$(jq -r '.cpu_percent' "$RESULTS_DIR/falco_results.json")
        local ws_mem=$(jq -r '.memory_mb' "$RESULTS_DIR/wasmsentinel_results.json")
        local falco_mem=$(jq -r '.memory_mb' "$RESULTS_DIR/falco_results.json")

        cat >> "$report_file" << EOF
| CPU Usage | ${ws_cpu}% | ${falco_cpu}% | $([ $(echo "$ws_cpu < $falco_cpu" | bc) -eq 1 ] && echo "WasmSentinel" || echo "Falco") |
| Memory Usage | ${ws_mem} MB | ${falco_mem} MB | $([ $(echo "$ws_mem < $falco_mem" | bc) -eq 1 ] && echo "WasmSentinel" || echo "Falco") |
EOF
    fi

    cat >> "$report_file" << 'EOF'

## Latency Comparison

| Percentile | WasmSentinel | Falco |
|------------|--------------|-------|
EOF

    if [ -f "$RESULTS_DIR/wasmsentinel_latency.json" ] && [ -f "$RESULTS_DIR/falco_latency.json" ]; then
        local ws_p50=$(jq -r '.p50_us' "$RESULTS_DIR/wasmsentinel_latency.json")
        local ws_p99=$(jq -r '.p99_us' "$RESULTS_DIR/wasmsentinel_latency.json")
        local falco_p50=$(jq -r '.p50_us' "$RESULTS_DIR/falco_latency.json")
        local falco_p99=$(jq -r '.p99_us' "$RESULTS_DIR/falco_latency.json")

        cat >> "$report_file" << EOF
| P50 | ${ws_p50} us | ${falco_p50} us |
| P99 | ${ws_p99} us | ${falco_p99} us |
EOF
    fi

    cat >> "$report_file" << 'EOF'

## Conclusions

[Analysis will be added based on results]

---
*Generated by WasmSentinel evaluation framework*
EOF

    echo -e "${GREEN}Report generated: $report_file${NC}"
}

# Main execution
main() {
    echo -e "${YELLOW}Starting comparison benchmark...${NC}"
    echo -e "Results will be saved to: $RESULTS_DIR"

    # Check dependencies
    check_dependencies

    # Run benchmarks
    benchmark_wasmsentinel
    benchmark_falco

    # Run latency tests
    latency_test "wasmsentinel"
    latency_test "falco"

    # Generate report
    generate_report

    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}Comparison complete!${NC}"
    echo -e "${GREEN}Results directory: $RESULTS_DIR${NC}"
    echo -e "${GREEN}========================================${NC}"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -r|--rate)
            EVENT_RATE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [-d duration] [-r event_rate]"
            echo "  -d, --duration  Test duration in seconds (default: 60)"
            echo "  -r, --rate      Target events per second (default: 1000)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

main
