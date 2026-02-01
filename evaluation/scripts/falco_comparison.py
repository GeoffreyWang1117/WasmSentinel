#!/usr/bin/env python3
"""
Falco Performance Comparison

测量Falco的性能指标并与WasmSentinel对比
"""

import subprocess
import time
import json
import os
import sys
from datetime import datetime
import statistics


def run_cmd(cmd, timeout=30):
    """运行命令"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, '', 'Timeout'
    except Exception as e:
        return -1, '', str(e)


def docker_cmd(args):
    """构建docker命令"""
    return ['sudo', 'docker'] + args


def measure_falco_startup():
    """测量Falco启动时间"""
    print("\n[Falco] Measuring startup time...")

    # Clean up any existing container
    run_cmd(docker_cmd(['rm', '-f', 'falco-test']))

    times = []
    for i in range(5):
        start = time.time()

        # Start Falco container
        code, stdout, stderr = run_cmd(docker_cmd([
            'run', '--rm', '--name', 'falco-test',
            '--privileged',
            '-v', '/var/run/docker.sock:/host/var/run/docker.sock',
            '-v', '/proc:/host/proc:ro',
            'falcosecurity/falco-no-driver:latest',
            'falco', '--dry-run'
        ]), timeout=60)

        elapsed = (time.time() - start) * 1000

        if code == 0 or 'Falco initialized' in stdout or 'Falco initialized' in stderr:
            times.append(elapsed)
            print(f"  Iteration {i+1}: {elapsed:.1f} ms")
        else:
            print(f"  Iteration {i+1}: Failed ({stderr[:100]})")

    if times:
        return {
            'mean_ms': statistics.mean(times),
            'stdev_ms': statistics.stdev(times) if len(times) > 1 else 0,
            'min_ms': min(times),
            'max_ms': max(times),
            'samples': len(times)
        }
    return {'error': 'All attempts failed'}


def measure_falco_memory():
    """测量Falco内存占用"""
    print("\n[Falco] Measuring memory usage...")

    # Clean up
    run_cmd(docker_cmd(['rm', '-f', 'falco-mem-test']))

    # Start Falco in background
    code, stdout, stderr = run_cmd(docker_cmd([
        'run', '-d', '--name', 'falco-mem-test',
        '--privileged',
        '-v', '/var/run/docker.sock:/host/var/run/docker.sock',
        '-v', '/proc:/host/proc:ro',
        'falcosecurity/falco-no-driver:latest'
    ]), timeout=30)

    if code != 0:
        print(f"  Failed to start Falco: {stderr}")
        return {'error': stderr}

    container_id = stdout.strip()[:12]
    print(f"  Container ID: {container_id}")

    # Wait for startup
    time.sleep(5)

    # Measure memory over time
    memory_samples = []
    for i in range(10):
        code, stdout, stderr = run_cmd(docker_cmd([
            'stats', '--no-stream', '--format',
            '{{.MemUsage}}', 'falco-mem-test'
        ]))

        if code == 0 and stdout.strip():
            # Parse "123.4MiB / 125.7GiB" format
            mem_str = stdout.strip().split('/')[0].strip()
            try:
                if 'MiB' in mem_str:
                    mem_mb = float(mem_str.replace('MiB', ''))
                elif 'GiB' in mem_str:
                    mem_mb = float(mem_str.replace('GiB', '')) * 1024
                else:
                    mem_mb = float(mem_str)
                memory_samples.append(mem_mb)
                print(f"  Sample {i+1}: {mem_mb:.1f} MiB")
            except:
                pass
        time.sleep(1)

    # Cleanup
    run_cmd(docker_cmd(['rm', '-f', 'falco-mem-test']))

    if memory_samples:
        return {
            'mean_mb': statistics.mean(memory_samples),
            'max_mb': max(memory_samples),
            'min_mb': min(memory_samples),
            'samples': len(memory_samples)
        }
    return {'error': 'No memory samples collected'}


def measure_falco_cpu_overhead():
    """测量Falco对nginx的CPU开销影响"""
    print("\n[Falco] Measuring CPU overhead on nginx workload...")

    # First run nginx without Falco
    print("  Phase 1: Baseline (no monitoring)...")
    run_cmd(docker_cmd(['rm', '-f', 'nginx-baseline']))
    run_cmd(docker_cmd([
        'run', '-d', '--name', 'nginx-baseline',
        '-p', '18081:80', 'nginx:alpine'
    ]))
    time.sleep(2)

    # Benchmark
    code, stdout, stderr = run_cmd([
        'wrk', '-t2', '-c50', '-d10s', 'http://localhost:18081/'
    ], timeout=30)

    baseline_rps = 0
    if 'Requests/sec' in stdout:
        import re
        match = re.search(r'Requests/sec:\s+([\d.]+)', stdout)
        if match:
            baseline_rps = float(match.group(1))
            print(f"    Baseline RPS: {baseline_rps:.0f}")

    run_cmd(docker_cmd(['rm', '-f', 'nginx-baseline']))

    # Now run with Falco monitoring
    print("  Phase 2: With Falco monitoring...")

    # Start Falco
    run_cmd(docker_cmd(['rm', '-f', 'falco-monitor']))
    run_cmd(docker_cmd([
        'run', '-d', '--name', 'falco-monitor',
        '--privileged',
        '-v', '/var/run/docker.sock:/host/var/run/docker.sock',
        '-v', '/proc:/host/proc:ro',
        'falcosecurity/falco-no-driver:latest'
    ]))
    time.sleep(5)

    # Start nginx
    run_cmd(docker_cmd(['rm', '-f', 'nginx-monitored']))
    run_cmd(docker_cmd([
        'run', '-d', '--name', 'nginx-monitored',
        '-p', '18082:80', 'nginx:alpine'
    ]))
    time.sleep(2)

    # Benchmark with monitoring
    code, stdout, stderr = run_cmd([
        'wrk', '-t2', '-c50', '-d10s', 'http://localhost:18082/'
    ], timeout=30)

    monitored_rps = 0
    if 'Requests/sec' in stdout:
        import re
        match = re.search(r'Requests/sec:\s+([\d.]+)', stdout)
        if match:
            monitored_rps = float(match.group(1))
            print(f"    Monitored RPS: {monitored_rps:.0f}")

    # Cleanup
    run_cmd(docker_cmd(['rm', '-f', 'nginx-monitored', 'falco-monitor']))

    if baseline_rps > 0 and monitored_rps > 0:
        overhead = ((baseline_rps - monitored_rps) / baseline_rps) * 100
        print(f"    Overhead: {overhead:.2f}%")
        return {
            'baseline_rps': baseline_rps,
            'monitored_rps': monitored_rps,
            'overhead_percent': overhead
        }

    return {'error': 'Benchmark failed'}


def main():
    results = {
        'timestamp': datetime.now().isoformat(),
        'tool': 'Falco (falcosecurity/falco-no-driver:latest)',
        'tests': {}
    }

    print("=" * 60)
    print("Falco Performance Comparison")
    print("=" * 60)

    # Startup time
    results['tests']['startup'] = measure_falco_startup()

    # Memory usage
    results['tests']['memory'] = measure_falco_memory()

    # CPU overhead
    results['tests']['cpu_overhead'] = measure_falco_cpu_overhead()

    # Save results
    output_file = 'falco_comparison_results.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 60)
    print("COMPARISON COMPLETE")
    print("=" * 60)
    print(f"Results saved to: {output_file}")

    # Summary
    print("\nSummary:")
    if 'startup' in results['tests'] and 'error' not in results['tests']['startup']:
        print(f"  Startup time: {results['tests']['startup']['mean_ms']:.0f} ms")
    if 'memory' in results['tests'] and 'error' not in results['tests']['memory']:
        print(f"  Memory usage: {results['tests']['memory']['mean_mb']:.1f} MiB")
    if 'cpu_overhead' in results['tests'] and 'error' not in results['tests']['cpu_overhead']:
        overhead = results['tests']['cpu_overhead']
        print(f"  Performance overhead: {overhead['overhead_percent']:.2f}%")
        print(f"    (Baseline: {overhead['baseline_rps']:.0f} RPS -> Monitored: {overhead['monitored_rps']:.0f} RPS)")

    return 0


if __name__ == '__main__':
    sys.exit(main())
