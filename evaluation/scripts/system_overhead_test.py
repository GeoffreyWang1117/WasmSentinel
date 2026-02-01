#!/usr/bin/env python3
"""
System Overhead Evaluation for WasmSentinel

测量WasmSentinel对系统性能的影响：
1. Micro-benchmark: syscall延迟测量
2. Macro-benchmark: 应用性能影响
3. 资源消耗对比 (vs Falco/Tetragon)

Usage:
    python system_overhead_test.py --micro          # Run micro-benchmarks
    python system_overhead_test.py --macro          # Run macro-benchmarks
    python system_overhead_test.py --compare-tools  # Compare with other tools
    python system_overhead_test.py --all            # Run all tests
"""

import argparse
import subprocess
import time
import json
import os
import sys
import statistics
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import tempfile
import signal


@dataclass
class BenchmarkResult:
    """基准测试结果"""
    name: str
    baseline_value: float
    monitored_value: float
    overhead_percent: float
    unit: str
    samples: int


@dataclass
class ToolComparison:
    """工具对比结果"""
    tool_name: str
    cpu_percent: float
    memory_mb: float
    startup_time_ms: float
    syscall_latency_us: float


class MicroBenchmark:
    """微基准测试 - 测量单个syscall的延迟"""

    def __init__(self):
        self.results = {}

    def measure_syscall_latency(self, syscall_name: str, iterations: int = 10000) -> Dict:
        """测量特定syscall的延迟"""

        # C程序模板用于精确测量syscall延迟
        c_code = '''
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>

#define ITERATIONS {iterations}

long long get_ns() {{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}}

int main() {{
    long long start, end, total = 0;
    long long min_time = 1000000000LL, max_time = 0;
    long long times[ITERATIONS];

    // Warmup
    for (int i = 0; i < 1000; i++) {{
        {syscall_code}
    }}

    // Measure
    for (int i = 0; i < ITERATIONS; i++) {{
        start = get_ns();
        {syscall_code}
        end = get_ns();
        times[i] = end - start;
        total += times[i];
        if (times[i] < min_time) min_time = times[i];
        if (times[i] > max_time) max_time = times[i];
    }}

    // Calculate statistics
    double mean = (double)total / ITERATIONS;
    double variance = 0;
    for (int i = 0; i < ITERATIONS; i++) {{
        variance += (times[i] - mean) * (times[i] - mean);
    }}
    double stdev = sqrt(variance / ITERATIONS);

    printf("{{\\"syscall\\": \\"{syscall_name}\\", ");
    printf("\\"iterations\\": %d, ", ITERATIONS);
    printf("\\"mean_ns\\": %.2f, ", mean);
    printf("\\"min_ns\\": %lld, ", min_time);
    printf("\\"max_ns\\": %lld, ", max_time);
    printf("\\"stdev_ns\\": %.2f}}", stdev);

    return 0;
}}
'''

        syscall_codes = {
            'getpid': 'getpid();',
            'getuid': 'getuid();',
            'gettimeofday': 'struct timeval tv; gettimeofday(&tv, NULL);',
            'read': 'char buf[1]; read(0, buf, 0);',  # read 0 bytes from stdin
            'write': 'write(1, "", 0);',  # write 0 bytes to stdout
            'open_close': 'int fd = open("/dev/null", O_RDONLY); if(fd >= 0) close(fd);',
            'stat': 'struct stat st; stat("/", &st);',
            'fstat': 'struct stat st; fstat(0, &st);',
            'mmap_munmap': 'void *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0); if(p != MAP_FAILED) munmap(p, 4096);',
        }

        if syscall_name not in syscall_codes:
            return {'error': f'Unknown syscall: {syscall_name}'}

        code = c_code.format(
            iterations=iterations,
            syscall_code=syscall_codes[syscall_name],
            syscall_name=syscall_name
        )

        # Add necessary includes
        if 'mmap' in syscall_name:
            code = '#include <sys/mman.h>\n' + code
        if 'gettimeofday' in syscall_name:
            code = '#include <sys/time.h>\n' + code
        code = '#include <math.h>\n' + code

        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
            f.write(code)
            c_file = f.name

        exe_file = c_file.replace('.c', '')

        try:
            # Compile
            result = subprocess.run(
                ['gcc', '-O2', '-o', exe_file, c_file, '-lm'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                return {'error': f'Compilation failed: {result.stderr}'}

            # Run
            result = subprocess.run(
                [exe_file],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                return {'error': f'Execution failed: {result.stderr}'}

            return json.loads(result.stdout)

        except Exception as e:
            return {'error': str(e)}
        finally:
            # Cleanup
            if os.path.exists(c_file):
                os.unlink(c_file)
            if os.path.exists(exe_file):
                os.unlink(exe_file)

    def run_all_syscall_benchmarks(self) -> Dict:
        """运行所有syscall基准测试"""
        syscalls = ['getpid', 'getuid', 'stat', 'fstat', 'open_close']
        results = {}

        print("\n[Micro-Benchmark] Measuring syscall latencies...")
        print("-" * 60)

        for syscall in syscalls:
            print(f"  Testing {syscall}...", end=' ', flush=True)
            result = self.measure_syscall_latency(syscall, iterations=50000)
            results[syscall] = result

            if 'error' not in result:
                print(f"{result['mean_ns']:.1f} ns (±{result['stdev_ns']:.1f})")
            else:
                print(f"Error: {result['error']}")

        return results


class MacroBenchmark:
    """宏基准测试 - 测量应用级性能影响"""

    def __init__(self, use_sudo: bool = False):
        self.use_sudo = use_sudo
        self.results = {}

    def _docker_cmd(self, args: List[str]) -> List[str]:
        if self.use_sudo:
            return ['sudo', 'docker'] + args
        return ['docker'] + args

    def run_container_startup_benchmark(self, iterations: int = 10) -> Dict:
        """测量容器启动时间"""
        print("\n[Macro-Benchmark] Container startup time...")

        times = []

        for i in range(iterations):
            # Pull image first to avoid network latency
            subprocess.run(
                self._docker_cmd(['pull', 'alpine:latest']),
                capture_output=True, timeout=60
            )

            start = time.time()
            result = subprocess.run(
                self._docker_cmd(['run', '--rm', 'alpine:latest', 'echo', 'hello']),
                capture_output=True, timeout=30
            )
            elapsed = (time.time() - start) * 1000  # ms

            if result.returncode == 0:
                times.append(elapsed)
                print(f"  Iteration {i+1}: {elapsed:.1f} ms")

        if times:
            return {
                'metric': 'container_startup_time',
                'unit': 'ms',
                'iterations': len(times),
                'mean': statistics.mean(times),
                'stdev': statistics.stdev(times) if len(times) > 1 else 0,
                'min': min(times),
                'max': max(times)
            }
        return {'error': 'No successful iterations'}

    def run_file_io_benchmark(self) -> Dict:
        """测量文件I/O性能"""
        print("\n[Macro-Benchmark] File I/O performance...")

        # Use dd for I/O benchmark
        test_file = '/tmp/wasmsentinel_io_test'
        block_size = '1M'
        count = 1000  # 1GB total

        # Write test
        print("  Write test (1GB)...", end=' ', flush=True)
        start = time.time()
        result = subprocess.run(
            ['dd', 'if=/dev/zero', f'of={test_file}', f'bs={block_size}',
             f'count={count}', 'conv=fdatasync'],
            capture_output=True, text=True, timeout=120
        )
        write_time = time.time() - start
        write_speed = count / write_time  # MB/s
        print(f"{write_speed:.1f} MB/s")

        # Read test
        print("  Read test (1GB)...", end=' ', flush=True)
        # Clear cache
        subprocess.run(['sync'], capture_output=True)
        subprocess.run(
            ['sudo', 'sh', '-c', 'echo 3 > /proc/sys/vm/drop_caches'],
            capture_output=True
        )

        start = time.time()
        result = subprocess.run(
            ['dd', f'if={test_file}', 'of=/dev/null', f'bs={block_size}'],
            capture_output=True, text=True, timeout=120
        )
        read_time = time.time() - start
        read_speed = count / read_time  # MB/s
        print(f"{read_speed:.1f} MB/s")

        # Cleanup
        if os.path.exists(test_file):
            os.unlink(test_file)

        return {
            'metric': 'file_io',
            'write_speed_mbps': write_speed,
            'read_speed_mbps': read_speed,
            'test_size_mb': count
        }

    def run_network_benchmark(self) -> Dict:
        """测量网络性能 (使用iperf3)"""
        print("\n[Macro-Benchmark] Network throughput...")

        # Check if iperf3 is available
        result = subprocess.run(['which', 'iperf3'], capture_output=True)
        if result.returncode != 0:
            print("  iperf3 not installed, skipping...")
            return {'error': 'iperf3 not installed'}

        # Start iperf3 server in container
        subprocess.run(
            self._docker_cmd(['rm', '-f', 'iperf-server']),
            capture_output=True
        )

        subprocess.run(
            self._docker_cmd([
                'run', '-d', '--name', 'iperf-server',
                '-p', '15201:5201',
                'networkstatic/iperf3', '-s'
            ]),
            capture_output=True, timeout=30
        )

        time.sleep(2)  # Wait for server to start

        # Run client
        print("  Running iperf3 client...", end=' ', flush=True)
        result = subprocess.run(
            ['iperf3', '-c', 'localhost', '-p', '15201', '-t', '10', '-J'],
            capture_output=True, text=True, timeout=30
        )

        # Cleanup
        subprocess.run(
            self._docker_cmd(['rm', '-f', 'iperf-server']),
            capture_output=True
        )

        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                bandwidth = data['end']['sum_sent']['bits_per_second'] / 1e9  # Gbps
                print(f"{bandwidth:.2f} Gbps")
                return {
                    'metric': 'network_throughput',
                    'bandwidth_gbps': bandwidth,
                    'duration_sec': 10
                }
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Error parsing: {e}")
                return {'error': str(e)}

        print("Failed")
        return {'error': result.stderr}

    def run_cpu_benchmark(self) -> Dict:
        """测量CPU性能"""
        print("\n[Macro-Benchmark] CPU performance (sysbench)...")

        # Check if sysbench is available
        result = subprocess.run(['which', 'sysbench'], capture_output=True)
        if result.returncode != 0:
            # Use simple Python CPU benchmark instead
            print("  sysbench not installed, using Python benchmark...")

            import hashlib
            iterations = 100000

            start = time.time()
            for i in range(iterations):
                hashlib.sha256(str(i).encode()).hexdigest()
            elapsed = time.time() - start

            ops_per_sec = iterations / elapsed
            print(f"  {ops_per_sec:.0f} SHA256 ops/sec")

            return {
                'metric': 'cpu_sha256',
                'ops_per_sec': ops_per_sec,
                'iterations': iterations
            }

        # Use sysbench
        result = subprocess.run(
            ['sysbench', 'cpu', '--cpu-max-prime=20000', '--threads=4', 'run'],
            capture_output=True, text=True, timeout=60
        )

        if result.returncode == 0:
            # Parse sysbench output
            import re
            match = re.search(r'events per second:\s+([\d.]+)', result.stdout)
            if match:
                events_per_sec = float(match.group(1))
                print(f"  {events_per_sec:.0f} events/sec")
                return {
                    'metric': 'cpu_sysbench',
                    'events_per_sec': events_per_sec
                }

        return {'error': 'sysbench failed'}


class ToolComparer:
    """对比不同监控工具的性能"""

    def __init__(self, use_sudo: bool = False):
        self.use_sudo = use_sudo

    def _run_cmd(self, cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        """运行命令"""
        try:
            if self.use_sudo and cmd[0] != 'sudo':
                cmd = ['sudo'] + cmd
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, '', 'Timeout'
        except Exception as e:
            return -1, '', str(e)

    def check_tool_installed(self, tool: str) -> bool:
        """检查工具是否安装"""
        tool_checks = {
            'falco': ['falco', '--version'],
            'tetragon': ['tetragon', 'version'],
            'sysdig': ['sysdig', '--version'],
            'bpftrace': ['bpftrace', '--version'],
        }

        if tool not in tool_checks:
            return False

        code, _, _ = self._run_cmd(tool_checks[tool])
        return code == 0

    def measure_tool_startup(self, tool: str) -> Dict:
        """测量工具启动时间"""
        tool_cmds = {
            'falco': ['falco', '--dry-run'],
            'bpftrace': ['bpftrace', '-e', 'BEGIN { exit(); }'],
        }

        if tool not in tool_cmds:
            return {'error': f'Unknown tool: {tool}'}

        if not self.check_tool_installed(tool):
            return {'error': f'{tool} not installed'}

        times = []
        for _ in range(5):
            start = time.time()
            code, _, _ = self._run_cmd(tool_cmds[tool], timeout=30)
            elapsed = (time.time() - start) * 1000
            if code == 0:
                times.append(elapsed)

        if times:
            return {
                'tool': tool,
                'startup_time_ms': statistics.mean(times),
                'stdev_ms': statistics.stdev(times) if len(times) > 1 else 0
            }
        return {'error': 'All attempts failed'}

    def measure_tool_memory(self, tool: str, duration: int = 10) -> Dict:
        """测量工具运行时的内存占用"""
        tool_cmds = {
            'falco': ['falco'],
            'bpftrace': ['bpftrace', '-e', 'tracepoint:syscalls:sys_enter_* { @ = count(); }'],
        }

        if tool not in tool_cmds:
            return {'error': f'Unknown tool: {tool}'}

        if not self.check_tool_installed(tool):
            return {'error': f'{tool} not installed'}

        # Start tool in background
        cmd = tool_cmds[tool]
        if self.use_sudo:
            cmd = ['sudo'] + cmd

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        try:
            time.sleep(2)  # Let it start

            # Measure memory
            memory_samples = []
            for _ in range(duration):
                try:
                    # Get memory from /proc
                    with open(f'/proc/{proc.pid}/status', 'r') as f:
                        for line in f:
                            if line.startswith('VmRSS:'):
                                mem_kb = int(line.split()[1])
                                memory_samples.append(mem_kb / 1024)  # Convert to MB
                                break
                except:
                    pass
                time.sleep(1)

            if memory_samples:
                return {
                    'tool': tool,
                    'memory_mb_mean': statistics.mean(memory_samples),
                    'memory_mb_max': max(memory_samples),
                    'samples': len(memory_samples)
                }
            return {'error': 'No memory samples collected'}

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except:
                proc.kill()

    def compare_all_tools(self) -> Dict:
        """对比所有可用工具"""
        print("\n[Tool Comparison] Comparing monitoring tools...")
        print("-" * 60)

        tools = ['falco', 'bpftrace']
        results = {}

        for tool in tools:
            print(f"\n  Checking {tool}...")

            if not self.check_tool_installed(tool):
                print(f"    Not installed, skipping")
                results[tool] = {'installed': False}
                continue

            results[tool] = {'installed': True}

            # Startup time
            print(f"    Measuring startup time...", end=' ', flush=True)
            startup = self.measure_tool_startup(tool)
            if 'error' not in startup:
                results[tool]['startup_time_ms'] = startup['startup_time_ms']
                print(f"{startup['startup_time_ms']:.1f} ms")
            else:
                print(f"Error: {startup['error']}")

            # Memory usage
            print(f"    Measuring memory usage...", end=' ', flush=True)
            memory = self.measure_tool_memory(tool, duration=5)
            if 'error' not in memory:
                results[tool]['memory_mb'] = memory['memory_mb_mean']
                print(f"{memory['memory_mb_mean']:.1f} MB")
            else:
                print(f"Error: {memory['error']}")

        return results


def main():
    parser = argparse.ArgumentParser(
        description='WasmSentinel System Overhead Evaluation',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--micro', action='store_true',
                        help='Run micro-benchmarks (syscall latency)')
    parser.add_argument('--macro', action='store_true',
                        help='Run macro-benchmarks (application performance)')
    parser.add_argument('--compare-tools', action='store_true',
                        help='Compare with other monitoring tools')
    parser.add_argument('--all', '-a', action='store_true',
                        help='Run all benchmarks')
    parser.add_argument('--output', '-o', type=str,
                        default='overhead_results.json',
                        help='Output file')
    parser.add_argument('--sudo', action='store_true',
                        help='Use sudo for privileged operations')

    args = parser.parse_args()

    if not any([args.micro, args.macro, args.compare_tools, args.all]):
        parser.print_help()
        return 1

    results = {
        'timestamp': datetime.now().isoformat(),
        'benchmarks': {}
    }

    print("=" * 60)
    print("WasmSentinel System Overhead Evaluation")
    print("=" * 60)

    # Micro-benchmarks
    if args.micro or args.all:
        micro = MicroBenchmark()
        results['benchmarks']['micro'] = micro.run_all_syscall_benchmarks()

    # Macro-benchmarks
    if args.macro or args.all:
        macro = MacroBenchmark(use_sudo=args.sudo)
        results['benchmarks']['macro'] = {}

        # Container startup
        results['benchmarks']['macro']['container_startup'] = \
            macro.run_container_startup_benchmark(iterations=5)

        # File I/O
        results['benchmarks']['macro']['file_io'] = \
            macro.run_file_io_benchmark()

        # CPU
        results['benchmarks']['macro']['cpu'] = \
            macro.run_cpu_benchmark()

    # Tool comparison
    if args.compare_tools or args.all:
        comparer = ToolComparer(use_sudo=args.sudo)
        results['benchmarks']['tool_comparison'] = comparer.compare_all_tools()

    # Save results
    output_path = Path(args.output)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 60)
    print("EVALUATION COMPLETE")
    print("=" * 60)
    print(f"Results saved to: {output_path}")

    # Print summary
    if 'micro' in results['benchmarks']:
        print("\nMicro-benchmark Summary:")
        for syscall, data in results['benchmarks']['micro'].items():
            if 'error' not in data:
                print(f"  {syscall}: {data['mean_ns']:.1f} ns")

    if 'macro' in results['benchmarks']:
        print("\nMacro-benchmark Summary:")
        macro = results['benchmarks']['macro']
        if 'container_startup' in macro and 'error' not in macro['container_startup']:
            print(f"  Container startup: {macro['container_startup']['mean']:.1f} ms")
        if 'file_io' in macro and 'error' not in macro['file_io']:
            print(f"  File write: {macro['file_io']['write_speed_mbps']:.1f} MB/s")
            print(f"  File read: {macro['file_io']['read_speed_mbps']:.1f} MB/s")

    return 0


if __name__ == '__main__':
    sys.exit(main())
