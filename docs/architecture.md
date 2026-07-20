# Glove architecture

## Scope

Glove provides three execution surfaces:

| Surface | Purpose | Current boundary |
|---|---|---|
| `glove run` | Contain an agent and mediate MCP tool calls | Public CLI |
| `glove exec` | Contain a direct agent process | Public CLI |
| `gloved` | Validate Sage plans, persist sessions, and deliver receipts | Owner-local control service |

The public CLI is usable for local containment. The distributed Sage session
surface is incomplete and must not advertise remote-launch readiness.

## Process model

```text
operator or Sage controller
          │
          ▼
  Glove control plane ───────► audit and receipt journals
          │
          ├── policy engine
          ├── MCP extensions ─► upstream tool servers
          │
          ▼
  OS sandbox
          └── agent process
```

The control plane remains outside the sandbox. It owns policy evaluation,
upstream transport, audit output, protected filesystem descriptors, and session
state. The agent receives only the endpoints and paths required by its selected
mode.

MCP upstreams are separate host processes. Glove filters requests to them, but
does not sandbox the upstream processes themselves.

## Platform isolation

| Property | Linux | macOS |
|---|---|---|
| Process visibility | PID namespace | SBPL process policy |
| Filesystem | mount namespace, `pivot_root`, read-only binds, private writable mounts | deny-default SBPL path rules |
| Network | network namespace plus seccomp socket denial | deny-default SBPL network rules |
| Identity | user namespace and UID/GID mapping | invoking user |
| IPC and hostname | IPC and UTS namespaces | SBPL policy |
| Resource limits | private cgroup/quota/watchdog implementation | incomplete for the Sage six-limit contract |

Linux launches the child through `clone3`, configures the namespace and mount
perimeter, applies seccomp, then releases the child to execute. Writable
materializations are quota-backed; retained copies use persistent hard-sized
ext4 loop images while ephemeral copies use tmpfs. Read-only inputs are
descriptor-pinned.
macOS constructs a deny-default sandbox profile and applies it before executing
the child.

## Components

| Namespace | Responsibility |
|---|---|
| `container` | sandbox creation, mounts, limits, output accounting, terminal receipts |
| `control` | Unix control protocol, authentication, session registry, receipt delivery |
| `supervisor` | canonical plan validation, local alias resolution, bundle resolution |
| `mcp` | bounded JSON-RPC framing and upstream clients |
| `policy` | tool and argument authorization |
| `kernel` | extension registration and dispatch |
| `audit` | structured local activity records |
| `run` | CLI orchestration for `run` and `exec` |
| `host` | strict XDG configuration, machine setup, diagnostics, and local project enrollment |
| `reflect` | compile-time extension metadata experiments |

Public headers live under `include/glove/`. Implementations mirror that layout in
`src/`. Tests are separated by concern under `tests/`.

## MCP request flow

For `glove run`:

1. Glove starts the configured upstream servers and completes MCP initialization.
2. The contained agent sends a bounded JSON-RPC request.
3. The kernel resolves the extension and tool name.
4. The policy engine validates tool access and configured argument rules.
5. The extension forwards an allowed request to the selected upstream.
6. Glove returns the response and appends the audit event.

Malformed frames, unknown tools, policy failures, transport errors, and audit
append failures fail closed.

`glove exec` bypasses the MCP kernel. It is intended for agents that manage
their own tool protocol, so its security boundary is the OS sandbox and explicit
filesystem/environment exposure.

## Sage session flow

`gloved` uses an owner-only Unix socket and a per-start bootstrap secret. Its
public control methods provide capability discovery, canonical plan validation,
durable create/status operations, bounded receipt pages, and exact
acknowledgement.

`glove setup` creates owner-only XDG configuration, runtime/state directories,
key material, and an optional protected-root policy. `glove init` then creates
a generation-bound exposure through the authenticated local control socket.
Project files are never configuration input, and raw paths never cross P2P.

When Sage configures `glove_activation_mode = "user_service"`, `saged` first
asks the platform user service manager to start the fixed local Glove unit. It
waits for `gloved.sock` and `bootstrap-secret` before health and capability
negotiation. The service label comes only from local Sage configuration and is
restricted to a bounded identifier; remote requests cannot select a process,
unit, or executable. `connect_only` preserves externally managed deployments.

When the Linux runtime is configured, the control service executes this
lifecycle:

1. Validate the canonical identifier-only plan against local policy.
2. Persist the plan and both the controller BLAKE3 digest and Glove SHA-256
   content digest.
3. Reserve a session for preparation; live host writes are never eligible.
4. Resolve generation-bound exposures and library bundles through pinned descriptors.
5. Compose mounts, cgroup limits, output accounting, and an immutable launch
   binding.
6. Start and recover the child through the executor and reconciler.
7. Append an authenticated terminal receipt before projecting terminal state.

The local protocol exposes attach, input, resize, signal, detach, stop, and
cleanup only when the runtime is constructed. Sage now wires that lifecycle and
receipt reconciliation. Exposure create/revoke remains owner-local; peers may
receive only the redacted catalog. Retained-change inspection and independently
authorized apply remain separate launch gates.

## Library projection

Sage plans refer to bundle digests and destination aliases, never arbitrary host
paths. Local policy maps each alias to a protected sandbox target. Glove opens a
digest-named bundle beneath an owner-only root without following links, verifies
its type, ownership, link count, size, identity, and SHA-256 digest, then mounts
the descriptor as a read-only sandbox file.

The launch binding and terminal receipt commit the projection identifier,
destination, target, and digest. Bundle expansion into harness-native prompt
directories is not implemented; `prompt_ref` remains rejected.

## Persistence

Session and receipt journals are append-only and bounded. Recovery rejects
corrupt, reordered, duplicated, truncated, or externally resized records.
Authenticated terminal receipts form an HMAC chain anchored by Sage. The
general JSONL activity log and session-state journal are not protected against a
same-user host process that can rewrite them.

Detailed policy and file invariants are defined in
[session-policy.md](session-policy.md).
