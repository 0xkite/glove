# Verification surface

[`future-work.md`](future-work.md) is the single list of incomplete engineering
work. This document defines which checks produce acceptable evidence.

## Repository gate

```sh
./scripts/preflight.sh
```

Preflight runs actionlint, formatting, clang-tidy analysis, ASan/UBSan tests,
fuzz targets, and TSan tests. A completed clang-tidy stage means analysis ran;
it does not claim the diagnostic backlog is zero.

## Shipping lanes

| Lane | Required evidence |
|---|---|
| macOS | Native preflight plus `scripts/macos-shipping-lane.sh` on a physical Apple Silicon host. The Apple VM probe must prove network denial, read-only root, private workspace, environment scrubbing, and requested/effective resource observations. |
| Linux | Warning-clean build plus installed user-service probes for namespaces, seccomp, delegated cgroups, terminal receipts, process-tree termination, and cleanup. Ordinary-shell skips are not enforcement evidence. |

Platform-specific kernel controls are reported as capabilities. A skipped or
unavailable control never counts as a pass for another platform's boundary.

## Real harness evidence

Codex, Claude Code, Pi, Copilot, and OpenCode must run through the same
programmatic Glove adapter path and shared invariant manifest. Test images do
not bundle vendor clients or credentials. Synthetic probes remain useful for
fault isolation but cannot replace an installed-client lane.

## Performance evidence

Benchmarks are opt-in and emit schema-versioned JSON Lines. Retain raw results
and compare identical workloads and platform metadata; correctness gates do not
use timing thresholds.
