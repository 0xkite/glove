# Security audit: containment boundary and untrusted-input parsers

Date: 2026-09-07. Target: HEAD `7b09022` (`main`). Method: static review of the whole
tree, cross-checked against `infer-out/` and `docs/threat-model.md`, plus dynamic
verification on a Linux host (Debian 13, kernel 6.12, clang 19.1.7) for the Linux-only
containment code. Scope chosen by the operator: both the containment-escape surface and the
untrusted-input parsers.

## Verdict

Glove's memory-safety posture is strong and its design is sound: a rootless clone3 sandbox,
an unprivileged owner-only control plane, fail-closed trust edges, and the remote path
hard-gated off at runtime. The untrusted-input parsers are memory-safe. The one materially
new security issue is a seccomp **denylist bypass** (the filter blocked `mount` but not the
modern mount API), which is fixed in this change and verified on a live kernel. The remaining
items are hardening recommendations, most of which the threat model already documents as v0.1
residual risk.

## Findings

| # | Severity | Area | Status |
|---|---|---|---|
| 1 | Medium | seccomp denylist bypass: modern mount API (`fsopen`/`fsconfig`/`fsmount`/`fspick`/`move_mount`/`open_tree`) reachable while `mount`/`pivot_root`/`chroot` are denied | **Fixed** |
| 2 | Medium | `io_uring` fully reachable inside the sandbox (large async-syscall LPE surface) | **Fixed** (flagged for compat review) |
| 3 | Low–Med | `open_by_handle_at`, `pidfd_getfd`, `userfaultfd`, `fanotify_init` reachable | **Fixed** |
| 4 | Low | Egress proxy `authenticated()` compared the proxy credential with `==` (non-constant-time) | **Fixed** |
| 5 | Low | `apple_container_stats` fuzzer built but never run in CI | **Fixed** |
| 6 | Info | Seccomp is a default-ALLOW denylist (v0.1); production wants default-deny allowlist | Recommendation |
| 7 | Low | No explicit `PR_SET_NO_NEW_PRIVS`; relies on libseccomp's default | Recommendation |
| 8 | Low–Med | No capability bounding-set drop; agent execs as mapped-root with full in-userns caps | Recommendation |
| 9 | Low | `bind_path` (`clone_spawner.cpp:578`) `::stat`+`::mount` by name, no `O_NOFOLLOW`, on operator-granted paths | Recommendation |
| 10 | Low | No `cpu.max` hard cap; CPU is polled + kill, not a scheduler cap | Recommendation |
| — | — | Infer's three "production" findings (`receipt_producer.cpp:54`, `receipt_audit_unix_server.cpp:287`, `egress_proxy.cpp:310`) | **False positives** |

### Fixed in this change (verified on Ghost)

**1–3. Seccomp escape-surface gaps.** The filter (`setup_seccomp`, `clone_spawner.cpp:968`) is
a default-`SCMP_ACT_ALLOW` denylist. A static probe run inside a live `glove exec` sandbox
confirmed that the filter is active (`unshare`, `setns`, `mount`, `ptrace`, `bpf`, `keyctl`
all return `EPERM`) but that `io_uring_setup`, `pidfd_open`, `open_by_handle_at`, `open_tree`,
`fsopen`, `move_mount`, `memfd_create`, and `perf_event_open` were all reachable. The mount-API
case is a true bypass: the filter's own comment says "an already-contained agent has no
legitimate need to mount things", yet only the classic `mount(2)` was denied while its
successor syscalls were open. The change adds a deny group covering the mount API, io_uring,
`open_by_handle_at`, `pidfd_getfd`, `userfaultfd`, and `fanotify_init`. After the fix the probe
shows all of these `BLOCKED` while the controls stay blocked and a normal command still runs.
`pidfd_open` and `memfd_create` are deliberately left reachable (benign / needed by language
runtimes). `io_uring` is the one entry with a real compatibility tradeoff — blocking it is the
conservative sandbox default, but a runtime that needs it can drop the three io_uring lines.

**4. Constant-time proxy auth.** `egress_proxy.cpp` now compares the `proxy-authorization`
credential with `constant_time_equal`, matching the control-plane servers. Severity is low: the
credential is deliberately shared with the sole loopback client, so this is
consistency/defense-in-depth, not a key-recovery path.

**5. Idle fuzzer.** `scripts/preflight.sh` now runs `apple_container_stats_fuzzer` when the
binary is present (macOS), so the target stops being built-but-never-run.

### Memory-safety review (no defects)

All seven untrusted-input parsers were traced from entry through every length/bounds/integer
operation. Every frame decoder bounds the declared length before allocation and uses glaze
strict decode with no manual memory operations; the only manual integer accumulation (the
CONNECT port, `egress_proxy.cpp:201`) is clamped to 65535. Reviewed and found safe:
`egress_proxy.cpp` (CONNECT/host/dial), `receipt_wire.cpp` + the audit-server framing,
`observation_intent_unix_server.cpp`, `guest_channel_transport.cpp`, `mcp/codec.cpp`,
`mcp/stdio_transport.cpp`, and `session_registry_wire.cpp` + `session_registry_recovery.cpp`
(length prefix+suffix matched, payload bounded by both 1 MiB and remaining file bytes before
allocation, underflow-guarded offset arithmetic, full hash commitment). No out-of-bounds,
integer-overflow-into-allocation, use-after-free, or bound-bypass defects were found.

### Infer false positives

All three of Infer's ERROR-severity "production" findings are false positives:
`receipt_producer.cpp:54` is the empty-string-guarded `wipe()` loop whose body never runs when
the pointer is null; the two "FD leak" sites are `::socket()` descriptors handed to the caller,
which moves one into an RAII guard and closes the other on every path. Infer is not run in CI;
the `infer-out/` tree is a stale local artifact.

## Recommendations (not applied here; Linux-tested, owner decision)

- **6. Move to a default-deny seccomp allowlist** for production, as the v0.1 comment already
  plans. The denylist added here is interim; an allowlist is the durable posture.
- **7. Set `PR_SET_NO_NEW_PRIVS` explicitly** before `seccomp_load`. It is functionally on
  today (libseccomp sets it, and unprivileged `seccomp_load` requires it), but relying on the
  default is fragile.
- **8. Drop the capability bounding set** (`PR_CAPBSET_DROP` / a `capset` to empty) before
  `execv`. The agent runs as root in its user namespace with the full in-userns capability set;
  dropping it removes escape primitives that need caps, as defense in depth behind the userns.
- **9. Harden `bind_path`** to the fd-based pattern the newer `bind_program_descriptor` /
  `bind_session_mount` already use (`open(O_NOFOLLOW|O_PATH)` + `move_mount`, re-verify
  `st_dev`/`st_ino`), removing the `::stat`-then-`::mount`-by-name symlink/TOCTOU window on
  operator-granted paths.
- **10. Add a `cpu.max` hard cap** alongside `memory.max`/`pids.max` so CPU is scheduler-bounded
  rather than polled-then-killed.
- Expose the egress CONNECT parser (or a thin wrapper) so it can be added as a fuzz target; it
  is the only hand-rolled, network-facing parser and is currently unfuzzed (reviewed safe).

## Dynamic evidence (Ghost, kernel 6.12)

Before the fix, inside `glove exec`: `REACHABLE io_uring_setup, open_by_handle_at, open_tree,
fsopen, move_mount` (plus `pidfd_open` succeeding). After the fix: those show `BLOCKED`, the
controls (`unshare`/`setns`/`mount`/`ptrace`/`bpf`/`keyctl`) stay `BLOCKED`, and a normal
`glove exec ... -- /usr/bin/echo` still runs. The 23-test asan net/container suite passes.
