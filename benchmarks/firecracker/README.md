# Firecracker Evaluation Harness (RQ1 & RQ3)

Reproducible harness for evaluating Glove across two axes:

1. **RQ1 — Vulnerable-Kernel Escape & Authority Matrix:** Boot pinned historical
   Linux `vmlinux` kernels inside disposable Firecracker microVMs (isolated via
   KVM from the host) and run escape/authority probes under:
   - a stock container / unconfined namespace (control),
   - Glove (`isolation_tier::os_primitives`: namespaces + Landlock ABI v6 +
     `seccomp_user_notif` active escape trapping + credentialed canary proxy),
   - Glove inside Firecracker (`microvm` tenant boundary + Glove authority boundary).
2. **RQ3 — Cold-Start Latency Comparison:** Measure p50 / p95 / p99 startup
   latency of Firecracker microVMs vs. `glove exec` (`os_primitives`) on the
   same Linux KVM host, outputting structured JSON for paper tables and plots.

> **Safety:** Vulnerable kernels must only run inside disposable microVMs with
> no host network bridge and ephemeral scratch rootfs copies. Never boot a
> vulnerable kernel on your host or attach production credentials.

## Prerequisites

- **Linux host with `/dev/kvm`** (bare metal or nested-KVM cloud VM).
  - On macOS, use `--dry-run` to validate configs locally, or develop inside a
    Lima/QEMU Linux VM; run final KVM/Firecracker timing measurements on Linux.
- `firecracker` binary on `PATH` (or pass `--firecracker /path/to/firecracker`).
- Python 3.11+ (stdlib only, no third-party dependencies).
- One or more uncompressed Linux `vmlinux` images and an ext4 `rootfs.ext4`
  containing `glove` and your probe binaries.

## Quick Start

Validate the harness and rendered Firecracker configs on any host (including macOS):

```sh
python3 benchmarks/firecracker/run_firecracker_bench.py \
  cold-start --kernel /path/to/vmlinux --rootfs /path/to/rootfs.ext4 \
  --iterations 5 --dry-run

python3 benchmarks/firecracker/run_firecracker_bench.py \
  cve-matrix --manifest benchmarks/firecracker/cve_matrix.example.json --dry-run
```

Run cold-start latency comparison on a Linux KVM host:

```sh
python3 benchmarks/firecracker/run_firecracker_bench.py \
  cold-start \
  --kernel ./kernels/vmlinux-6.1 \
  --rootfs ./images/glove-bench.ext4 \
  --iterations 50 \
  --compare-glove ./build/release/src/glove \
  --out results/cold-start.json
```

Run the vulnerable-kernel CVE & authority matrix:

```sh
python3 benchmarks/firecracker/run_firecracker_bench.py \
  cve-matrix \
  --manifest benchmarks/firecracker/cve_matrix.example.json \
  --out results/cve-matrix.json
```
