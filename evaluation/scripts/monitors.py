"""Launchers and resource samplers for the monitoring systems compared in E4/E5.

All three run as root with kernel access:
  * WasmSentinel: the host binary, started inside a privileged container that
    chroots back into the host root (no passwordless sudo on the lab machine);
    --collector=ebpf, all hooks, binary encoding, STIDE trained at start
  * Falco: official image, modern eBPF driver, default ruleset
  * Tetragon: official image with evaluation/configs/tetragon-e4-policy.yaml
    (file open + tcp connect on top of the built-in exec/exit)

ResourceSampler reads /proc/<pid>/stat and /status of the monitor's host PID
every interval and /proc/stat for whole-system CPU.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CHROOT_IMAGE = "nvidia/cuda:12.4.1-base-ubuntu22.04"  # any local image with chroot(8)
CLK_TCK = os.sysconf("SC_CLK_TCK")


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def docker_rm(name):
    sh(["docker", "rm", "-f", name])


def docker_pid(name) -> int:
    r = sh(["docker", "inspect", "-f", "{{.State.Pid}}", name])
    return int(r.stdout.strip() or 0)


def wait_log(name, needle, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        logs = sh(["docker", "logs", name]).stdout + sh(["docker", "logs", name]).stderr
        if needle in logs:
            return True
        if sh(["docker", "inspect", "-f", "{{.State.Running}}", name]).stdout.strip() != "true":
            raise RuntimeError(f"{name} exited early:\n{logs[-3000:]}")
        time.sleep(0.5)
    raise RuntimeError(f"{name}: '{needle}' not seen within {timeout}s")


class Monitor:
    name = "none"
    container = None

    def start(self):
        pass

    def stop(self) -> dict:
        return {}

    def pid(self) -> int:
        return 0


class WasmSentinelMonitor(Monitor):
    name = "wasmsentinel"
    container = "e4-wasmsentinel"

    def __init__(self, binary=REPO / "wasmsentinel", rules=REPO / "rules/wasm", train_dir=REPO / "evaluation/datasets/raw/ADFA-LD/ADFA-LD/Training_Data_Master",
                 encoding="binary", hooks="all", log=Path("/tmp/wasmsentinel-e4.log")):
        self.binary, self.rules, self.train_dir, self.encoding, self.hooks, self.log = binary, rules, train_dir, encoding, hooks, log

    def start(self):
        docker_rm(self.container)
        cmd = ["docker", "run", "-d", "--name", self.container, "--privileged", "--pid=host", "-v", "/:/host", CHROOT_IMAGE,
               "chroot", "/host", str(self.binary), "--collector=ebpf", f"--ebpf-hooks={self.hooks}", f"--event-encoding={self.encoding}",
               "--rules", str(self.rules), "--rule-train-dir", str(self.train_dir), "--alert-log=false", "--metrics-port", "0", "--log-level", "info"]
        r = sh(cmd)
        if r.returncode:
            raise RuntimeError(r.stderr)
        wait_log(self.container, "eBPF collector started", 60)

    def pid(self):
        return docker_pid(self.container)

    def stop(self):
        sh(["docker", "kill", "--signal=INT", self.container])
        t0 = time.time()
        while sh(["docker", "inspect", "-f", "{{.State.Running}}", self.container]).stdout.strip() == "true" and time.time() - t0 < 30:
            time.sleep(0.3)
        logs = sh(["docker", "logs", self.container]).stdout + sh(["docker", "logs", self.container]).stderr
        docker_rm(self.container)
        out = {}
        for line in logs.splitlines():
            if '"msg":"Pipeline statistics"' in line:
                j = json.loads(line)
                out.update({"events": j["events"], "alerts": j["alerts"], "events_per_s": float(j["events_per_s"]), "e2e_us": j["e2e_us"], "detect_us": j["detect_us"], "max_rss_kb": j["max_rss_kb"]})
            elif '"msg":"eBPF collector stopped"' in line and "by_type" in line:
                j = json.loads(line)
                out.update({"collector_received": j["received"], "collector_dropped": j["dropped"], "by_type": j["by_type"]})
        return out


class FalcoMonitor(Monitor):
    name = "falco"
    container = "e4-falco"

    def start(self):
        docker_rm(self.container)
        r = sh(["docker", "run", "-d", "--name", self.container, "--privileged", "--pid=host",
                "-v", "/proc:/host/proc:ro", "-v", "/etc:/host/etc:ro",
                "falcosecurity/falco:latest", "falco", "-o", "engine.kind=modern_ebpf", "-o", "json_output=true", "-o", "stdout_output.enabled=true"])
        if r.returncode:
            raise RuntimeError(r.stderr)
        wait_log(self.container, "One ring buffer every", 120)
        time.sleep(2)

    def pid(self):
        return docker_pid(self.container)

    def stop(self):
        logs = sh(["docker", "logs", self.container]).stdout
        alerts = sum(1 for l in logs.splitlines() if l.startswith("{") and '"priority"' in l)
        sh(["docker", "kill", "--signal=TERM", self.container])
        time.sleep(1)
        docker_rm(self.container)
        return {"alerts": alerts}


class TetragonMonitor(Monitor):
    name = "tetragon"
    container = "e4-tetragon"

    def __init__(self, policy=REPO / "evaluation/configs/tetragon-e4-policy.yaml"):
        self.policy = policy

    def start(self):
        docker_rm(self.container)
        r = sh(["docker", "run", "-d", "--name", self.container, "--pid=host", "--cgroupns=host", "--privileged",
                "-v", "/sys/kernel:/sys/kernel", "-v", f"{self.policy}:/etc/tetragon/policy.yaml:ro",
                "quay.io/cilium/tetragon:v1.7.1", "/usr/bin/tetragon", "--tracing-policy", "/etc/tetragon/policy.yaml",
                "--export-filename", "/tmp/tetragon.log", "--metrics-server", "", "--server-address", ""])
        if r.returncode:
            raise RuntimeError(r.stderr)
        wait_log(self.container, "Listening for events", 120)
        time.sleep(2)

    def pid(self):
        return docker_pid(self.container)

    def stop(self):
        size = sh(["docker", "exec", self.container, "sh", "-c", "wc -l < /tmp/tetragon.log 2>/dev/null || echo 0"]).stdout.strip()
        sh(["docker", "kill", "--signal=TERM", self.container])
        time.sleep(1)
        docker_rm(self.container)
        try:
            return {"exported_events": int(size)}
        except ValueError:
            return {"exported_events": -1}


MONITORS = {"none": Monitor, "wasmsentinel": WasmSentinelMonitor, "falco": FalcoMonitor, "tetragon": TetragonMonitor}


def _proc_cpu_ticks(pid):
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return int(fields[11]) + int(fields[12])  # utime + stime


def _proc_rss_kb(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


def _sys_cpu():
    with open("/proc/stat") as f:
        v = list(map(int, f.readline().split()[1:]))
    idle = v[3] + v[4]
    return sum(v), idle


class ResourceSampler:
    """Samples monitor CPU%/RSS and whole-system CPU% until stop()."""

    def __init__(self, pid, interval=0.5):
        self.pid, self.interval = pid, interval
        self.samples = []
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._t.start()
        return self

    def _run(self):
        last_ticks = _proc_cpu_ticks(self.pid) if self.pid else 0
        last_sys = _sys_cpu()
        last_t = time.time()
        while not self._stop.wait(self.interval):
            now = time.time()
            dt = now - last_t
            s = {"t": now}
            if self.pid:
                try:
                    ticks = _proc_cpu_ticks(self.pid)
                    s["cpu_pct"] = (ticks - last_ticks) / CLK_TCK / dt * 100.0
                    s["rss_kb"] = _proc_rss_kb(self.pid)
                    last_ticks = ticks
                except FileNotFoundError:
                    break
            tot, idle = _sys_cpu()
            dtot, didle = tot - last_sys[0], idle - last_sys[1]
            s["sys_cpu_pct"] = (1 - didle / dtot) * 100.0 if dtot else 0.0
            last_sys, last_t = (tot, idle), now
            self.samples.append(s)

    def stop(self):
        self._stop.set()
        self._t.join(timeout=5)
        out = {"samples": len(self.samples)}
        for key in ("cpu_pct", "rss_kb", "sys_cpu_pct"):
            v = [s[key] for s in self.samples if key in s]
            if v:
                out[key + "_mean"] = sum(v) / len(v)
                out[key + "_max"] = max(v)
        return out
