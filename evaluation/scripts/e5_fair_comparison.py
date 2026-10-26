#!/usr/bin/env python3
"""E5: the same three detections in WasmSentinel, Falco and Tetragon.

Scenarios (each run --trials times from an unprivileged shell):
  shadow    open /etc/shadow for reading (fails with EACCES; the open is what counts)
  tmpexec   copy /bin/true under /tmp and execute it
  connect   TCP connect to 127.0.0.1:4444 (the harness listens there and
            closes each connection, like a reverse-shell catcher)
Rules: WasmSentinel suspicious_shell (sensitive path / /tmp executable /
port 4444), Falco evaluation/configs/falco-e5-rules.yaml on top of the
default ruleset, Tetragon evaluation/configs/tetragon-e5-policy.yaml plus
built-in exec events. For every system and scenario: detection rate over the
trials, detection latency (alert timestamp - action timestamp, wall clock,
ms), monitor RSS. WasmSentinel's own event -> alert latency comes from its
alert file (event_time).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
from monitors import CHROOT_IMAGE, FalcoMonitor, ResourceSampler, TetragonMonitor, WasmSentinelMonitor, docker_pid, docker_rm, sh, wait_log  # noqa: E402

# Inside a user-owned directory: the detector runs as root, and a root-owned
# file directly under sticky /tmp could not be removed between runs.
E5_DIR = Path("/tmp/wasmsentinel-e5")
ALERT_FILE = E5_DIR / "alerts.jsonl"
SCENARIOS = ["shadow", "tmpexec", "connect"]


def ts_iso(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat()


def parse_iso(s):
    s = s.replace("Z", "+00:00")
    # trim sub-microsecond digits for fromisoformat
    if "." in s:
        head, tail = s.split(".", 1)
        frac = ""
        tz = ""
        for i, ch in enumerate(tail):
            if ch in "+-":
                frac, tz = tail[:i], tail[i:]
                break
        else:
            frac = tail
        s = f"{head}.{frac[:6].ljust(6, '0')}{tz}"
    return datetime.fromisoformat(s).timestamp()


# ----------------------------------------------------------------------------- scenario actions

class Listener(threading.Thread):
    """Accepts and closes connections on 127.0.0.1:4444 so the connect scenario
    completes a handshake."""

    def __init__(self, port=4444):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(16)
        self.sock.settimeout(0.5)
        self.accepted = 0
        self._quit = threading.Event()

    def run(self):
        while not self._quit.is_set():
            try:
                c, _ = self.sock.accept()
                self.accepted += 1
                c.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self._quit.set()
        self.join(timeout=2)
        self.sock.close()

def act(scenario, trial, tmpdir):
    """Perform one attack action; return the wall-clock time just before it."""
    t = time.time()
    if scenario == "shadow":
        subprocess.run(["cat", "/etc/shadow"], capture_output=True)
    elif scenario == "tmpexec":
        d = tmpdir / f"e5-{trial}"
        d.mkdir(parents=True, exist_ok=True)
        exe = d / "e5true"
        shutil.copy("/bin/true", exe)
        exe.chmod(0o755)
        subprocess.run([str(exe)], capture_output=True)
    elif scenario == "connect":
        subprocess.run(["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/4444"], capture_output=True, timeout=5)
    return t


# ----------------------------------------------------------------------------- monitors with E5 config

class WasmSentinelE5(WasmSentinelMonitor):
    def start(self):
        E5_DIR.mkdir(parents=True, exist_ok=True)
        ALERT_FILE.unlink(missing_ok=True)
        docker_rm(self.container)
        cmd = ["docker", "run", "-d", "--name", self.container, "--privileged", "--pid=host", "-v", "/:/host", CHROOT_IMAGE,
               "chroot", "/host", str(self.binary), "--collector=ebpf", "--ebpf-hooks=all", f"--event-encoding={self.encoding}",
               "--rules", str(self.rules), "--rule-train-dir", str(self.train_dir), "--alert-log=false", "--log-file", str(ALERT_FILE),
               "--metrics-port", "0", "--log-level", "info"]
        r = sh(cmd)
        if r.returncode:
            raise RuntimeError(r.stderr)
        # --log-file redirects the program log too, so readiness shows up in the file.
        t0 = time.time()
        while time.time() - t0 < 60:
            if ALERT_FILE.exists() and "eBPF collector started" in ALERT_FILE.read_text(errors="ignore"):
                return
            if sh(["docker", "inspect", "-f", "{{.State.Running}}", self.container]).stdout.strip() != "true":
                raise RuntimeError("wasmsentinel exited early:\n" + sh(["docker", "logs", self.container]).stderr[-2000:] + (ALERT_FILE.read_text(errors="ignore")[-2000:] if ALERT_FILE.exists() else ""))
            time.sleep(0.5)
        raise RuntimeError("wasmsentinel: eBPF collector did not start within 60s")

    def alerts(self):
        out = []
        if ALERT_FILE.exists():
            buf = ""
            for line in ALERT_FILE.read_text().splitlines():
                buf += line
                try:
                    out.append(json.loads(buf))
                    buf = ""
                except json.JSONDecodeError:
                    buf += "\n"
        return out


class FalcoE5(FalcoMonitor):
    def start(self):
        docker_rm(self.container)
        r = sh(["docker", "run", "-d", "--name", self.container, "--privileged", "--pid=host",
                "-v", "/proc:/host/proc:ro", "-v", "/etc:/host/etc:ro",
                "-v", f"{REPO / 'evaluation/configs/falco-e5-rules.yaml'}:/etc/falco/rules.d/e5.yaml:ro",
                "falcosecurity/falco:latest", "falco", "-U", "-o", "engine.kind=modern_ebpf", "-o", "json_output=true", "-o", "stdout_output.enabled=true",
                "-o", "time_format_iso_8601=true"])
        if r.returncode:
            raise RuntimeError(r.stderr)
        # "Falco initialized" comes before the probe is attached; the event
        # source line is the real readiness signal.
        wait_log(self.container, "One ring buffer every", 120)
        time.sleep(2)

    def alerts(self):
        out = []
        for line in sh(["docker", "logs", self.container]).stdout.splitlines():
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return out


class TetragonE5(TetragonMonitor):
    def __init__(self):
        super().__init__(policy=REPO / "evaluation/configs/tetragon-e5-policy.yaml")

    def alerts(self):
        raw = sh(["docker", "exec", self.container, "cat", "/tmp/tetragon.log"]).stdout
        out = []
        for line in raw.splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return out


# ----------------------------------------------------------------------------- matching

def match_wasmsentinel(alert, scenario):
    ev = alert
    if scenario == "shadow":
        return ev.get("event_type") == "file" and ev.get("file", {}).get("path") == "/etc/shadow"
    if scenario == "tmpexec":
        return ev.get("event_type") == "process" and str(ev.get("process", {}).get("executable", "")).startswith("/tmp/")
    if scenario == "connect":
        return ev.get("event_type") == "network" and ev.get("network", {}).get("dest_port") == 4444
    return False


def match_falco(alert, scenario):
    out = alert.get("output", "")
    return {"shadow": "E5_SHADOW" in out, "tmpexec": "E5_TMPEXEC" in out, "connect": "E5_CONNECT4444" in out}[scenario]


def match_tetragon(ev, scenario):
    if scenario == "shadow":
        k = ev.get("process_kprobe", {})
        return k.get("function_name") in ("__x64_sys_openat", "security_file_open") and any(
            a.get("string_arg") == "/etc/shadow" or a.get("file_arg", {}).get("path") == "/etc/shadow" for a in k.get("args", []))
    if scenario == "tmpexec":
        return str(ev.get("process_exec", {}).get("process", {}).get("binary", "")).startswith("/tmp/")
    if scenario == "connect":
        k = ev.get("process_kprobe", {})
        return k.get("function_name") == "tcp_connect" and any(a.get("sock_arg", {}).get("dport") == 4444 for a in k.get("args", []))
    return False


def alert_time(system, alert):
    if system == "wasmsentinel":
        return parse_iso(alert["timestamp"]), parse_iso(alert["event_time"]) if "event_time" in alert else None
    if system == "falco":
        return parse_iso(alert["time"]), None
    if system == "tetragon":
        return parse_iso(alert["time"]), None
    return None, None


SYSTEMS = {"wasmsentinel": (WasmSentinelE5, match_wasmsentinel), "falco": (FalcoE5, match_falco), "tetragon": (TetragonE5, match_tetragon)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--systems", default="wasmsentinel,falco,tetragon")
    ap.add_argument("--trials", type=int, default=20)
    ap.add_argument("--gap", type=float, default=0.5, help="seconds between actions")
    ap.add_argument("--settle", type=float, default=3.0, help="seconds to wait for late alerts")
    ap.add_argument("--out", type=Path, default=REPO / "evaluation/results/2026-11/e5")
    ap.add_argument("--dump-alerts", action="store_true", help="also write every raw alert per system into --out")
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    if args.quick:
        args.trials = 3
    tmpdir = E5_DIR / "payloads"
    args.out.mkdir(parents=True, exist_ok=True)
    listener = Listener()
    listener.start()
    results = {}
    for system in args.systems.split(","):
        cls, matcher = SYSTEMS[system]
        mon = cls()
        print(f"== {system}", flush=True)
        mon.start()
        time.sleep(2)
        sampler = ResourceSampler(mon.pid(), interval=0.25).start()
        actions = {sc: [] for sc in SCENARIOS}
        for trial in range(args.trials):
            for sc in SCENARIOS:
                actions[sc].append(act(sc, trial, tmpdir))
                time.sleep(args.gap)
        time.sleep(args.settle)
        res = sampler.stop()
        alerts = mon.alerts()
        mstats = mon.stop()
        if args.dump_alerts:
            (args.out / f"raw_{system}.json").write_text(json.dumps({"actions": {sc: [ts_iso(t) for t in v] for sc, v in actions.items()}, "alerts": alerts}, indent=1, default=str))
        per = {}
        for sc in SCENARIOS:
            matched = [a for a in alerts if matcher(a, sc)]
            times = sorted(alert_time(system, a)[0] for a in matched)
            # Assign every alert to the latest action that precedes it; an action
            # counts as detected when at least one alert was assigned to it, and
            # its latency is the first such alert.
            acts = actions[sc]
            first_alert = {}
            for t in times:
                prev = [i for i, t_act in enumerate(acts) if t_act <= t]
                if prev:
                    i = prev[-1]
                    first_alert.setdefault(i, t)
            detected = len(first_alert)
            latencies = [(first_alert[i] - acts[i]) * 1000 for i in sorted(first_alert)]
            internal = [(parse_iso(a["timestamp"]) - parse_iso(a["event_time"])) * 1000 for a in matched if system == "wasmsentinel" and a.get("event_time")]
            per[sc] = {"trials": args.trials, "detected": detected, "rate": detected / args.trials, "alerts_matching": len(matched),
                       "latency_ms": {"median": statistics.median(latencies), "p90": sorted(latencies)[int(0.9 * (len(latencies) - 1))], "max": max(latencies)} if latencies else None,
                       "event_to_alert_ms_median": statistics.median(internal) if internal else None}
            print(f"  {sc:8s} detected {detected}/{args.trials}  alerts {len(matched):4d}  latency ms {per[sc]['latency_ms']}", flush=True)
        results[system] = {"scenarios": per, "total_alerts": len(alerts), "resources": res, "monitor": mstats}
        shutil.rmtree(tmpdir, ignore_errors=True)
        ALERT_FILE.unlink(missing_ok=True)
        time.sleep(1)

    listener.stop()
    cpu = ""
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    out = {"experiment": "E5 same detections in WasmSentinel, Falco, Tetragon",
           "provenance": {"git_commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip(),
                          "kernel": platform.release(), "cpu": cpu, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          "falco_image": sh(["docker", "inspect", "-f", "{{.Id}}", "falcosecurity/falco:latest"]).stdout.strip()[:19],
                          "wasm_sha256": {q.name: hashlib.sha256(q.read_bytes()).hexdigest() for q in sorted((REPO / "rules" / "wasm").glob("*.wasm"))},
                          "tetragon_image": "quay.io/cilium/tetragon:v1.7.1", "args": {k: str(v) for k, v in vars(args).items()}},
           "scenarios": {"shadow": "open /etc/shadow (EACCES)", "tmpexec": "copy /bin/true under /tmp and run it", "connect": "TCP connect to 127.0.0.1:4444"},
           "results": results,
           "notes": ["Detection latency is wall clock from just before the action to the first matching alert; Falco/Tetragon timestamps are their own, WasmSentinel's is the alert-file write time.",
                     "WasmSentinel event_to_alert is kernel event timestamp -> alert written, from its own records.",
                     "Tetragon exports every exec; exec-from-/tmp is a filter on that export, not a policy rule."]}
    (args.out / "e5_results.json").write_text(json.dumps(out, indent=1))
    md = ["# E5 same detections, three systems", "", f"commit {out['provenance']['git_commit'][:12]}, {out['provenance']['timestamp']}, {args.trials} trials per scenario", "",
          "| system | scenario | detected | latency median (ms) | latency p90 | RSS max (MiB) | CPU % during trials |", "|---|---|---|---|---|---|---|"]
    for system, r in results.items():
        for sc, p in r["scenarios"].items():
            lat = p["latency_ms"]
            md.append(f"| {system} | {sc} | {p['detected']}/{p['trials']} | {lat['median']:.1f} | {lat['p90']:.1f} | {r['resources'].get('rss_kb_max', 0) / 1024:.0f} | {r['resources'].get('cpu_pct_mean', 0):.1f} |" if lat else
                      f"| {system} | {sc} | {p['detected']}/{p['trials']} | — | — | {r['resources'].get('rss_kb_max', 0) / 1024:.0f} | {r['resources'].get('cpu_pct_mean', 0):.1f} |")
    (args.out / "e5_summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))
    return 0


if __name__ == "__main__":
    sys.exit(main())
