#!/usr/bin/env python3
"""E4: what monitoring costs the monitored application.

Workloads (containers published on 127.0.0.1 only):
  nginx   static page, wrk -t8 -c128 for --seconds           -> requests/s, latency
  redis   redis-benchmark SET/GET, pipeline 16, -n requests   -> requests/s
  postgres pgbench scale 10, -c 16 -j 8 -T --seconds (client in the
          postgres container)                                  -> tps
Arms: none, wasmsentinel (eBPF, all hooks, binary encoding, both rules,
STIDE trained), falco (modern eBPF, default rules), tetragon (exec + file
open + tcp connect policy). Every (workload, arm) cell is repeated --reps
times in interleaved order; the monitor is started fresh for each run and
its CPU %, RSS and the whole-system CPU % are sampled every 0.5 s while the
load runs. The previous draft's "monitored" arm was simulated; here every
number comes from a run.
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
from monitors import MONITORS, ResourceSampler, docker_rm, sh  # noqa: E402

PORTS = {"nginx": 18080, "redis": 16379, "postgres": 15432}


# ----------------------------------------------------------------------------- workloads

def start_workload(name):
    docker_rm(f"e4-{name}")
    if name == "nginx":
        r = sh(["docker", "run", "-d", "--name", "e4-nginx", "-p", f"127.0.0.1:{PORTS['nginx']}:80", "nginx:1.27-alpine"])
        wait_port(PORTS["nginx"])
    elif name == "redis":
        r = sh(["docker", "run", "-d", "--name", "e4-redis", "-p", f"127.0.0.1:{PORTS['redis']}:6379", "redis:7-alpine", "redis-server", "--save", "", "--appendonly", "no"])
        wait_port(PORTS["redis"])
    elif name == "postgres":
        r = sh(["docker", "run", "-d", "--name", "e4-postgres", "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-p", f"127.0.0.1:{PORTS['postgres']}:5432",
                "postgres:16-alpine", "-c", "fsync=off", "-c", "synchronous_commit=off"])
        # pgbench and pg_isready run inside the container (the host has only the
        # Debian wrapper without a client package); the load is local either way.
        t0 = time.time()
        while time.time() - t0 < 90:
            if sh(["docker", "exec", "e4-postgres", "pg_isready", "-U", "postgres"]).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("postgres not ready")
        time.sleep(2)
        init = sh(["docker", "exec", "e4-postgres", "pgbench", "-i", "-s", "10", "-U", "postgres", "postgres"])
        if init.returncode:
            raise RuntimeError(init.stderr)
    else:
        raise ValueError(name)
    if r.returncode:
        raise RuntimeError(r.stderr)


def wait_port(port, timeout=60):
    import socket
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.5)
    raise RuntimeError(f"port {port} not ready")


def stop_workload(name):
    docker_rm(f"e4-{name}")


def run_load(name, seconds, redis_requests):
    if name == "nginx":
        r = sh(["wrk", "-t8", "-c128", f"-d{int(seconds)}s", "--latency", f"http://127.0.0.1:{PORTS['nginx']}/"])
        out = r.stdout
        m = re.search(r"Requests/sec:\s+([\d.]+)", out)
        lat = {}
        for q in ("50%", "99%"):
            mm = re.search(rf"\s{re.escape(q)}\s+([\d.]+)(us|ms|s)", out)
            if mm:
                v = float(mm.group(1)) * {"us": 1e-3, "ms": 1, "s": 1e3}[mm.group(2)]
                lat[q] = v
        return {"throughput": float(m.group(1)) if m else 0.0, "unit": "req/s", "latency_ms": lat}
    if name == "redis":
        r = sh(["redis-benchmark", "-h", "127.0.0.1", "-p", str(PORTS["redis"]), "-t", "set,get", "-n", str(redis_requests), "-P", "16", "-q", "--csv"])
        rps = {}
        for line in r.stdout.splitlines():
            m = re.match(r'"(\w+)","([\d.]+)"', line)
            if m:
                rps[m.group(1)] = float(m.group(2))
        tput = statistics.mean(rps.values()) if rps else 0.0
        return {"throughput": tput, "unit": "req/s (mean of SET,GET)", "per_test": rps}
    if name == "postgres":
        r = sh(["docker", "exec", "e4-postgres", "pgbench", "-U", "postgres", "-c", "16", "-j", "8", "-T", str(int(seconds)), "postgres"])
        m = re.search(r"tps = ([\d.]+) \(without initial connection time\)", r.stdout) or re.search(r"tps = ([\d.]+)", r.stdout)
        lat = re.search(r"latency average = ([\d.]+) ms", r.stdout)
        return {"throughput": float(m.group(1)) if m else 0.0, "unit": "tps", "latency_ms": {"avg": float(lat.group(1))} if lat else {}}
    raise ValueError(name)


# ----------------------------------------------------------------------------- driver

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workloads", default="nginx,redis,postgres")
    ap.add_argument("--arms", default="none,wasmsentinel,falco,tetragon")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--seconds", type=float, default=20.0)
    ap.add_argument("--redis-requests", type=int, default=4000000, help="redis-benchmark -n; ~300k req/s here, so 4M lasts about 13 s")
    ap.add_argument("--warmup", type=float, default=3.0)
    ap.add_argument("--out", type=Path, default=REPO / "evaluation/results/2026-11/e4")
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    if args.quick:
        args.reps, args.seconds, args.redis_requests = 1, 5.0, 500000
    workloads = args.workloads.split(",")
    arms = args.arms.split(",")

    runs = []
    try:
        for wl in workloads:
            print(f"== workload {wl}", flush=True)
            start_workload(wl)
            # a short untimed warm-up of the workload itself
            run_load(wl, min(3.0, args.seconds), min(100000, args.redis_requests))
            for rep in range(args.reps):
                for arm in arms:
                    mon = MONITORS[arm]()
                    t0 = time.time()
                    mon.start()
                    time.sleep(args.warmup)
                    sampler = ResourceSampler(mon.pid(), interval=0.25).start()
                    load = run_load(wl, args.seconds, args.redis_requests)
                    res = sampler.stop()
                    mstats = mon.stop()
                    time.sleep(1.0)
                    run = {"workload": wl, "arm": arm, "rep": rep, "load": load, "resources": res, "monitor": mstats, "wall_s": round(time.time() - t0, 1)}
                    runs.append(run)
                    print(f"{wl:8s} {arm:12s} rep {rep}: {load['throughput']:10.0f} {load['unit']:28s} mon cpu {res.get('cpu_pct_mean', 0):6.1f}% rss {res.get('rss_kb_max', 0) // 1024:5d} MiB sys cpu {res.get('sys_cpu_pct_mean', 0):5.1f}%", flush=True)
            stop_workload(wl)
    finally:
        for wl in workloads:
            docker_rm(f"e4-{wl}")
        for name in ("e4-wasmsentinel", "e4-falco", "e4-tetragon"):
            docker_rm(name)

    # aggregate: per workload x arm, throughput mean/std, delta vs none with 95% CI (t on differences paired by rep)
    from scipy import stats
    summary = {}
    for wl in workloads:
        base = {r["rep"]: r["load"]["throughput"] for r in runs if r["workload"] == wl and r["arm"] == "none"}
        summary[wl] = {}
        for arm in arms:
            rs = [r for r in runs if r["workload"] == wl and r["arm"] == arm]
            tp = [r["load"]["throughput"] for r in rs]
            cell = {"n": len(rs), "throughput_mean": statistics.mean(tp), "throughput_std": statistics.stdev(tp) if len(tp) > 1 else 0.0,
                    "monitor_cpu_pct_mean": statistics.mean(r["resources"].get("cpu_pct_mean", 0.0) for r in rs),
                    "monitor_rss_mib_max": max(r["resources"].get("rss_kb_max", 0) for r in rs) / 1024,
                    "sys_cpu_pct_mean": statistics.mean(r["resources"].get("sys_cpu_pct_mean", 0.0) for r in rs)}
            if arm != "none" and base:
                d = [(r["load"]["throughput"] - base[r["rep"]]) / base[r["rep"]] * 100 for r in rs if r["rep"] in base]
                cell["throughput_delta_pct_mean"] = statistics.mean(d)
                if len(d) > 1:
                    ci = stats.t.interval(0.95, len(d) - 1, loc=statistics.mean(d), scale=stats.sem(d))
                    cell["throughput_delta_pct_ci95"] = [float(ci[0]), float(ci[1])]
            if arm == "wasmsentinel":
                ev = [r["monitor"].get("events", 0) for r in rs]
                cell["events_mean"] = statistics.mean(ev) if ev else 0
                cell["collector_dropped_mean"] = statistics.mean(r["monitor"].get("collector_dropped", 0) for r in rs)
            summary[wl][arm] = cell

    cpu = ""
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    result = {"experiment": "E4 application overhead under monitoring",
              "provenance": {"git_commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip(),
                             "kernel": platform.release(), "cpu": cpu, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                             "images": {k: sh(["docker", "inspect", "-f", "{{.Id}}", k]).stdout.strip()[:19] for k in ("nginx:1.27-alpine", "redis:7-alpine", "postgres:16-alpine", "falcosecurity/falco:latest", "quay.io/cilium/tetragon:v1.7.1")},
                             "args": {k: str(v) for k, v in vars(args).items()}},
              "summary": summary, "runs": runs}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "e4_results.json").write_text(json.dumps(result, indent=1))
    md = ["# E4 application overhead under monitoring", "", f"commit {result['provenance']['git_commit'][:12]}, {result['provenance']['timestamp']}, reps {args.reps}, {args.seconds:.0f} s per run", "",
          "| workload | arm | throughput (mean ± std) | Δ vs none | 95% CI | monitor CPU % | monitor RSS (MiB) | system CPU % |", "|---|---|---|---|---|---|---|---|"]
    for wl in workloads:
        for arm in arms:
            c = summary[wl][arm]
            delta = f"{c['throughput_delta_pct_mean']:+.1f}%" if "throughput_delta_pct_mean" in c else "—"
            ci = f"[{c['throughput_delta_pct_ci95'][0]:+.1f}, {c['throughput_delta_pct_ci95'][1]:+.1f}]" if "throughput_delta_pct_ci95" in c else "—"
            md.append(f"| {wl} | {arm} | {c['throughput_mean']:.0f} ± {c['throughput_std']:.0f} | {delta} | {ci} | {c['monitor_cpu_pct_mean']:.1f} | {c['monitor_rss_mib_max']:.0f} | {c['sys_cpu_pct_mean']:.1f} |")
    (args.out / "e4_summary.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))
    return 0


if __name__ == "__main__":
    sys.exit(main())
