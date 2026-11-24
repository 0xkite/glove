#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Firecracker evaluation harness for Glove (RQ1 CVE matrix & RQ3 cold-start)."""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
DEFAULT_TEMPLATE = HERE / "vm-config.template.json"
DEFAULT_BOOT_ARGS = "console=ttyS0 reboot=k panic=1 pci=off quiet"


def percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return sorted_values[lo]
    frac = rank - lo
    return sorted_values[lo] + frac * (sorted_values[hi] - sorted_values[lo])


def summarize_ms(samples_ms: list[float]) -> dict[str, Any]:
    ordered = sorted(samples_ms)
    return {
        "n": len(ordered),
        "min_ms": round(ordered[0], 3) if ordered else 0.0,
        "p50_ms": round(percentile(ordered, 50.0), 3),
        "p95_ms": round(percentile(ordered, 95.0), 3),
        "p99_ms": round(percentile(ordered, 99.0), 3),
        "max_ms": round(ordered[-1], 3) if ordered else 0.0,
        "mean_ms": round(statistics.fmean(ordered), 3) if ordered else 0.0,
    }


def render_vm_config(
    template_path: Path,
    kernel_path: Path,
    rootfs_path: Path,
    vcpu_count: int,
    mem_size_mib: int,
    boot_args: str,
) -> dict[str, Any]:
    raw = template_path.read_text(encoding="utf-8")
    rendered = (
        raw.replace("__KERNEL_PATH__", str(kernel_path))
        .replace("__ROOTFS_PATH__", str(rootfs_path))
        .replace("__VCPU_COUNT__", str(vcpu_count))
        .replace("__MEM_SIZE_MIB__", str(mem_size_mib))
        .replace("__BOOT_ARGS__", boot_args)
    )
    return json.loads(rendered)


def check_kvm_and_binary(firecracker_bin: str) -> list[str]:
    problems: list[str] = []
    if platform.system() != "Linux":
        problems.append(
            f"Firecracker requires Linux KVM (current host: {platform.system()}); "
            "use --dry-run on macOS or run on a Linux KVM host."
        )
    elif not Path("/dev/kvm").exists():
        problems.append("/dev/kvm not found (enable KVM or nested virtualization).")
    if shutil.which(firecracker_bin) is None:
        problems.append(f"firecracker binary not found on PATH: {firecracker_bin}")
    return problems


def run_single_firecracker_vm(
    firecracker_bin: str,
    vm_config: dict[str, Any],
    timeout_s: float,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="glove-fc-") as tmp:
        tmp_dir = Path(tmp)
        cfg_path = tmp_dir / "vm-config.json"
        # Copy rootfs into ephemeral scratch so each run starts clean.
        src_rootfs = Path(vm_config["drives"][0]["path_on_host"])
        scratch_rootfs = tmp_dir / "rootfs.ext4"
        shutil.copyfile(src_rootfs, scratch_rootfs)

        run_cfg = json.loads(json.dumps(vm_config))
        run_cfg["drives"][0]["path_on_host"] = str(scratch_rootfs)
        cfg_path.write_text(json.dumps(run_cfg, indent=2), encoding="utf-8")

        t0 = time.perf_counter()
        proc = subprocess.run(
            [firecracker_bin, "--no-api", "--config-file", str(cfg_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "returncode": proc.returncode,
            "elapsed_ms": round(elapsed_ms, 3),
            "stdout_tail": proc.stdout[-2000:],
            "stderr_tail": proc.stderr[-1000:],
        }


def run_cold_start(args: argparse.Namespace) -> int:
    vm_config = render_vm_config(
        template_path=Path(args.template),
        kernel_path=Path(args.kernel),
        rootfs_path=Path(args.rootfs),
        vcpu_count=args.vcpus,
        mem_size_mib=args.mem_mib,
        boot_args=args.boot_args,
    )

    if args.dry_run:
        report = {
            "mode": "cold-start",
            "dry_run": True,
            "host": {"system": platform.system(), "machine": platform.machine()},
            "preflight_warnings": check_kvm_and_binary(args.firecracker),
            "iterations": args.iterations,
            "rendered_config": vm_config,
        }
        print(json.dumps(report, indent=2))
        return 0

    problems = check_kvm_and_binary(args.firecracker)
    if problems:
        for p in problems:
            print(f"error: {p}", file=sys.stderr)
        return 2

    fc_samples: list[float] = []
    for _ in range(args.iterations):
        res = run_single_firecracker_vm(args.firecracker, vm_config, args.timeout_s)
        fc_samples.append(res["elapsed_ms"])

    report: dict[str, Any] = {
        "mode": "cold-start",
        "host": {"system": platform.system(), "machine": platform.machine()},
        "firecracker": summarize_ms(fc_samples),
    }

    if args.compare_glove:
        glove_samples: list[float] = []
        for _ in range(args.iterations):
            t0 = time.perf_counter()
            subprocess.run(
                [args.compare_glove, "exec", "--", "/bin/true"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=args.timeout_s,
                check=False,
            )
            glove_samples.append((time.perf_counter() - t0) * 1000.0)
        report["glove_os_primitives"] = summarize_ms(glove_samples)

    out_text = json.dumps(report, indent=2)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out_text + "\n", encoding="utf-8")
    print(out_text)
    return 0


def run_cve_matrix(args: argparse.Namespace) -> int:
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    cases = manifest.get("cases", [])
    if not isinstance(cases, list) or not cases:
        print("error: manifest contains no cases", file=sys.stderr)
        return 2

    if args.dry_run:
        preview = []
        for case in cases:
            boot_args = f"{DEFAULT_BOOT_ARGS} init={case['guest_cmd']}"
            cfg = render_vm_config(
                template_path=Path(args.template),
                kernel_path=Path(case["vmlinux"]),
                rootfs_path=Path(case["rootfs"]),
                vcpu_count=args.vcpus,
                mem_size_mib=args.mem_mib,
                boot_args=boot_args,
            )
            preview.append(
                {
                    "id": case["id"],
                    "cve": case.get("cve", "N/A"),
                    "kernel_label": case["kernel_label"],
                    "expected": case.get("expected", {}),
                    "config": cfg,
                }
            )
        report = {
            "mode": "cve-matrix",
            "dry_run": True,
            "host": {"system": platform.system(), "machine": platform.machine()},
            "preflight_warnings": check_kvm_and_binary(args.firecracker),
            "case_count": len(preview),
            "cases": preview,
        }
        print(json.dumps(report, indent=2))
        return 0

    problems = check_kvm_and_binary(args.firecracker)
    if problems:
        for p in problems:
            print(f"error: {p}", file=sys.stderr)
        return 2

    results = []
    for case in cases:
        boot_args = f"{DEFAULT_BOOT_ARGS} init={case['guest_cmd']}"
        cfg = render_vm_config(
            template_path=Path(args.template),
            kernel_path=Path(case["vmlinux"]),
            rootfs_path=Path(case["rootfs"]),
            vcpu_count=args.vcpus,
            mem_size_mib=args.mem_mib,
            boot_args=boot_args,
        )
        run_res = run_single_firecracker_vm(args.firecracker, cfg, args.timeout_s)
        results.append(
            {
                "id": case["id"],
                "cve": case.get("cve", "N/A"),
                "category": case.get("category", "unknown"),
                "kernel_label": case["kernel_label"],
                "expected": case.get("expected", {}),
                "result": run_res,
            }
        )

    report = {
        "mode": "cve-matrix",
        "host": {"system": platform.system(), "machine": platform.machine()},
        "results": results,
    }
    out_text = json.dumps(report, indent=2)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out_text + "\n", encoding="utf-8")
    print(out_text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--firecracker", default="firecracker", help="Firecracker binary path")
    common.add_argument("--template", default=str(DEFAULT_TEMPLATE), help="VM config JSON template")
    common.add_argument("--vcpus", type=int, default=1, help="vCPU count per microVM")
    common.add_argument("--mem-mib", type=int, default=256, help="Memory in MiB per microVM")
    common.add_argument("--timeout-s", type=float, default=30.0, help="Per-run timeout in seconds")
    common.add_argument("--out", default="", help="Write JSON report to this path")
    common.add_argument("--dry-run", action="store_true", help="Render configs without booting VMs")

    p_cs = sub.add_parser("cold-start", parents=[common], help="Measure cold-start latency")
    p_cs.add_argument("--kernel", required=True, help="Uncompressed vmlinux path")
    p_cs.add_argument("--rootfs", required=True, help="Ext4 rootfs image path")
    p_cs.add_argument("--boot-args", default=DEFAULT_BOOT_ARGS, help="Kernel boot arguments")
    p_cs.add_argument("--iterations", type=int, default=20, help="Number of iterations")
    p_cs.add_argument("--compare-glove", default="", help="Optional glove binary for comparison")
    p_cs.set_defaults(func=run_cold_start)

    p_cve = sub.add_parser("cve-matrix", parents=[common], help="Run vulnerable-kernel CVE matrix")
    p_cve.add_argument("--manifest", required=True, help="JSON manifest of CVE cases")
    p_cve.set_defaults(func=run_cve_matrix)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
