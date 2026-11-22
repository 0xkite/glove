#!/usr/bin/env python3
"""Measure how glove behaves with many concurrent launches on one host.

    tools/scale/scale.py --glove build/release/src/glove --count 200 --out run1

Starts COUNT `glove exec` launches of a small agent, waits until each agent
is running, samples host and per-launch resources while they hold, then stops
them all at the same moment with SIGTERM and, with --resume, starts them all
again. Writes <out>/summary.json and <out>/samples.csv. Standard library only.

What each phase measures:

  start    time from spawning glove until the agent inside writes its ready
           file, per launch (p50, p90, p99, max) and how many never got there
  hold     resident memory, threads and descriptors of the glove processes,
           host available memory and load, once per second
  stop     time from SIGTERM until each glove exits, its exit status, and
           whether its audit journal has the agent_exit record
  resume   the start phase again, against the same workspaces

Each launch gets its own workspace and audit journal under <out>, so
launches do not share the default journal. The agent is a shell loop that
exits on TERM, HUP or INT and otherwise does nothing; network, model and MCP
traffic are not part of this measurement.

Process-level pause and resume (freezing a running agent and restoring it
later) are not measured: glove has no such operation. --resume measures a
fresh launch of every instance at once, which is what restarting from stored
state costs at the glove layer.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path

AGENT = (
    "trap 'exit 0' TERM HUP INT; "
    "echo ready > ready; "
    "while :; do /bin/sleep 1 & wait $!; done"
)


def percentiles(values: list[float]) -> dict:
    if not values:
        return {"count": 0}
    ordered = sorted(values)

    def at(fraction: float) -> float:
        return round(ordered[min(len(ordered) - 1, int(fraction * len(ordered)))], 1)

    return {"count": len(ordered), "p50": at(0.5), "p90": at(0.9), "p99": at(0.99),
            "max": round(ordered[-1], 1), "mean": round(statistics.fmean(ordered), 1)}


def raise_descriptor_limit() -> int:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = hard if hard != resource.RLIM_INFINITY else 1 << 20
    if sys.platform == "darwin":
        target = min(target, 10240)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except (ValueError, OSError):
        target = soft
    return target


def process_stats(pids: list[int]) -> dict:
    """Summed resident memory (KiB), threads and descriptors of PIDS."""
    rss = threads = fds = 0
    if sys.platform.startswith("linux"):
        for pid in pids:
            try:
                for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        rss += int(line.split()[1])
                    elif line.startswith("Threads:"):
                        threads += int(line.split()[1])
                fds += len(os.listdir(f"/proc/{pid}/fd"))
            except OSError:
                continue
        return {"rss_kib": rss, "threads": threads, "fds": fds}
    if pids:
        result = subprocess.run(["ps", "-o", "rss=", "-p", ",".join(map(str, pids))],
                                capture_output=True, text=True, check=False)
        rss = sum(int(value) for value in result.stdout.split() if value.isdigit())
    return {"rss_kib": rss, "threads": None, "fds": None}


def host_stats() -> dict:
    load = os.getloadavg()[0]
    available = None
    if sys.platform.startswith("linux"):
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                available = int(line.split()[1])
    return {"load1": round(load, 2), "mem_available_kib": available}


class Launch:
    def __init__(self, index: int, root: Path):
        self.index = index
        self.workspace = root / "ws" / f"{index:05d}"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.process: subprocess.Popen | None = None
        self.spawned = 0.0
        self.ready_at: float | None = None
        self.audit: Path | None = None

    def start(self, glove: str, root: Path, round_name: str) -> None:
        ready = self.workspace / "ready"
        if ready.exists():
            ready.unlink()
        self.audit = root / "audit" / f"{round_name}-{self.index:05d}.jsonl"
        self.ready_at = None
        # Wall clock, so it compares with the ready file's mtime: the harness
        # polls only after it has spawned every launch, which at thousands of
        # launches is tens of seconds after the first one was ready.
        self.spawned = time.time()
        self.process = subprocess.Popen(
            [glove, "exec", "--workspace", str(self.workspace), "--audit-log", str(self.audit),
             "--", "/bin/sh", "-c", AGENT],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=open(root / "stderr" / f"{round_name}-{self.index:05d}.txt", "wb"),
            cwd=self.workspace, start_new_session=True)

    def poll_ready(self) -> None:
        if self.ready_at is None:
            try:
                self.ready_at = (self.workspace / "ready").stat().st_mtime
            except OSError:
                pass


def start_round(launches, glove, root, round_name, per_second, deadline_s) -> dict:
    gap = 1.0 / per_second if per_second > 0 else 0.0
    began = time.monotonic()
    for launch in launches:
        launch.start(glove, root, round_name)
        if gap:
            time.sleep(gap)
    spawn_s = time.monotonic() - began
    limit = time.monotonic() + deadline_s
    while time.monotonic() < limit:
        pending = 0
        for launch in launches:
            launch.poll_ready()
            if launch.ready_at is None and launch.process.poll() is None:
                pending += 1
        if pending == 0:
            break
        time.sleep(0.05)
    latencies = [(l.ready_at - l.spawned) * 1000 for l in launches if l.ready_at is not None]
    exited = [l.process.returncode for l in launches
              if l.ready_at is None and l.process.poll() is not None]
    return {"spawn_seconds": round(spawn_s, 2),
            "ready_ms": percentiles(latencies),
            "not_ready_still_running": sum(1 for l in launches
                                           if l.ready_at is None and l.process.poll() is None),
            "exited_before_ready": len(exited),
            "exited_before_ready_codes": sorted(set(exited))}


def hold(launches, seconds, samples, phase) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        pids = [l.process.pid for l in launches if l.process.poll() is None]
        row = {"t": round(time.time(), 1), "phase": phase, "alive": len(pids)}
        row.update(process_stats(pids))
        row.update(host_stats())
        samples.append(row)
        time.sleep(1.0)


def stop_round(launches, deadline_s) -> dict:
    sent = time.monotonic()
    for launch in launches:
        if launch.process.poll() is None:
            try:
                launch.process.send_signal(signal.SIGTERM)
            except OSError:
                pass
    took = {}
    limit = sent + deadline_s
    while time.monotonic() < limit and len(took) < len(launches):
        for launch in launches:
            if launch.index not in took and launch.process.poll() is not None:
                took[launch.index] = (time.monotonic() - sent) * 1000
        time.sleep(0.02)
    stuck = [l for l in launches if l.process.poll() is None]
    for launch in stuck:
        launch.process.kill()
        launch.process.wait()
    codes: dict[int, int] = {}
    with_exit_record = 0
    for launch in launches:
        codes[launch.process.returncode] = codes.get(launch.process.returncode, 0) + 1
        try:
            if '"action":"agent_exit"' in launch.audit.read_text(errors="replace"):
                with_exit_record += 1
        except OSError:
            pass
    return {"exit_ms": percentiles(list(took.values())), "killed_after_deadline": len(stuck),
            "exit_codes": {str(k): v for k, v in sorted(codes.items())},
            "with_exit_record": with_exit_record}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--glove", required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--per-second", type=float, default=0,
                        help="spawn rate; 0 starts all at once (default)")
    parser.add_argument("--hold", type=float, default=10, help="seconds to sample (default 10)")
    parser.add_argument("--deadline", type=float, default=120,
                        help="seconds to wait for start and for stop (default 120)")
    parser.add_argument("--resume", action="store_true",
                        help="after stopping, start every launch again and stop it again")
    args = parser.parse_args()

    glove = os.path.realpath(args.glove)
    if not os.access(glove, os.X_OK):
        sys.exit(f"not an executable: {args.glove}")
    root = Path(args.out).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    for sub in ("ws", "audit", "stderr"):
        (root / sub).mkdir(mode=0o700)
    descriptors = raise_descriptor_limit()
    launches = [Launch(index, root) for index in range(args.count)]
    samples: list[dict] = []
    summary = {"count": args.count, "platform": sys.platform, "glove": glove,
               "per_second": args.per_second, "harness_fd_limit": descriptors,
               "host_before": host_stats()}
    try:
        summary["start"] = start_round(launches, glove, root, "start", args.per_second,
                                       args.deadline)
        hold(launches, args.hold, samples, "hold")
        summary["stop"] = stop_round(launches, args.deadline)
        if args.resume:
            summary["resume"] = start_round(launches, glove, root, "resume", args.per_second,
                                            args.deadline)
            hold(launches, args.hold, samples, "resumed")
            summary["resume_stop"] = stop_round(launches, args.deadline)
    finally:
        for launch in launches:
            if launch.process is not None and launch.process.poll() is None:
                launch.process.kill()
                launch.process.wait()
    held = [row for row in samples if row["phase"] == "hold" and row["alive"]]
    if held:
        peak = max(held, key=lambda row: row["rss_kib"])
        summary["hold_peak"] = {
            "alive": peak["alive"],
            "glove_rss_mib_total": round(peak["rss_kib"] / 1024, 1),
            "glove_rss_kib_per_launch": round(peak["rss_kib"] / peak["alive"]),
            "glove_threads_per_launch": (round(peak["threads"] / peak["alive"], 1)
                                         if peak["threads"] is not None else None),
            "glove_fds_per_launch": (round(peak["fds"] / peak["alive"], 1)
                                     if peak["fds"] is not None else None),
            "load1": peak["load1"], "mem_available_kib": peak["mem_available_kib"]}
    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    with open(root / "samples.csv", "w", encoding="ascii") as stream:
        keys = ["t", "phase", "alive", "rss_kib", "threads", "fds", "load1", "mem_available_kib"]
        stream.write(",".join(keys) + "\n")
        for row in samples:
            stream.write(",".join("" if row.get(k) is None else str(row[k]) for k in keys) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
