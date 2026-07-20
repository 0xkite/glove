# Glove future work

This file lists unresolved engineering work. Implemented history belongs in
version control, tests, and architecture documentation.

## P0: remote-launch gates

| Work | Completion condition |
|---|---|
| Direct-write approval | A distinct authenticated local-consent record is persisted with approval class, actor identity, plan/session digests, scope, and expiry; start verifies it before any retained host write. |
| Prompt-library expansion | A verified Sage bundle is parsed and projected into a bounded harness-native directory; launch binding and receipts commit every derived input. |
| Runtime adapter integration | A private session home, harness-native Codex/Pi bundle projection, and exact initial context are committed to the launch profile and receipt; capability schema v1 is advertised only then. |
| Service ownership | Sage can activate the same-UID user-service templates. Production is complete when `gloved` uses a dedicated least-privilege identity, protected key rotation, and documented upgrade/recovery procedures. |
| macOS resource contract | CPU, memory, PID, wall-time, disk, and terminal-output limits are enforced and represented in authenticated receipts, or managed remote launch remains unavailable on macOS. |
| Exposure lifecycle hardening | Owner-local programmatic enrollment is implemented; production completion adds explicit renewal, revocation CLI/UX, and lifecycle receipts without accepting remote host paths. |

## P1: protocol and integrity hardening

| Work | Completion condition |
|---|---|
| JSON-RPC correlation | Duplicate and unknown IDs cannot replace pending requests or disconnect the original caller; concurrent response routing has regression tests. |
| Transport deadlines | Partial frames and stalled peers have bounded receive deadlines; newline framing is asserted on every write path. |
| Capability change notification | Long-lived clients can detect effective capability changes without reconnect races. |
| Durable-state authentication | Session state and general activity logs are keyed or asymmetrically signed, with explicit recovery and key-rotation rules. |
| Immutable dependency pinning | Glaze and CI actions are pinned to immutable revisions with recorded provenance and verification. |
| Upstream containment | MCP upstream processes receive a separate sandbox profile or a documented isolated service boundary. |
| Linux egress | An authenticated proxy crosses the isolated namespace without exposing a general host socket or DNS bypass. |

## P2: validation evidence

| Work | Completion condition |
|---|---|
| Parser fuzzing | JSON-RPC, policy, plan, journal, and bundle inputs have sanitizer-backed fuzz targets and a checked adversarial corpus. |
| Fault injection | Tests cover short writes, disk-full behavior, journal truncation, process crashes at each lifecycle transition, and recovery idempotence. |
| Multi-agent matrix | Supported Codex, Pi, Claude, and other adapters are tested against the same filesystem, environment, tool, terminal, and recovery invariants. |
| Performance characterization | Startup cost, request latency, throughput, and memory overhead are measured with reproducible workloads and confidence intervals. |
| Comparative evaluation | Claims are evaluated against comparable containment and gateway designs using the same threat model and workload. |

## P3: packaging and extensibility

- Add exported CMake package targets and a stable `find_package(glove)` surface.
- Add SPDX headers and contributor/release documentation.
- Track MCP protocol changes, including HTTP transport and authentication,
  without weakening stdio framing or policy behavior.
- Revisit compile-time reflection when the required C++ support is available.
- Add optional content-addressed audit export without making it part of the
  enforcement path.

Public readiness requires the P0 gates and a security review of their composed
behavior. P1–P3 items may independently block a deployment based on its threat
model.
