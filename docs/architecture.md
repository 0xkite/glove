# Glove architecture

## Scope

Glove provides three execution surfaces:

| Surface      | Purpose                                                     | Current boundary            |
| ------------ | ----------------------------------------------------------- | --------------------------- |
| `glove run`  | Contain an agent and mediate MCP tool calls                 | Public CLI                  |
| `glove exec` | Contain a direct agent process                              | Public CLI                  |
| `gloved`     | Validate Sage plans, persist sessions, and deliver receipts | Owner-local control service |

The public CLI is usable for local containment. The distributed Sage session
surface is incomplete and must not advertise remote-launch readiness. A
`remote_linux_container` runtime can be constructed from validated operator
configuration, but it is deliberately non-operational and advertises no
lifecycle, runtime-adapter, resource-enforcement, or receipt capability.

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

| Property           | Linux                                                                                                                                                          | macOS                                      |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| Process visibility | PID namespace                                                                                                                                                  | SBPL process policy                        |
| Filesystem         | mount namespace, `pivot_root`, read-only binds, private writable mounts                                                                                        | deny-default SBPL path rules               |
| Network            | route-less network namespace; offline socket denial or private-loopback access to the authenticated audited proxy through an inherited Unix descriptor channel | deny-default SBPL network rules            |
| Identity           | user namespace and UID/GID mapping                                                                                                                             | invoking user                              |
| IPC and hostname   | IPC and UTS namespaces                                                                                                                                         | SBPL policy                                |
| Resource limits    | private cgroup/quota/watchdog implementation                                                                                                                   | incomplete for the Sage six-limit contract |

Linux launches the child through `clone3`, configures the namespace and mount
perimeter, applies seccomp, then releases the child to execute. Writable
materializations are quota-backed; retained copies use persistent hard-sized
ext4 loop images while ephemeral copies use tmpfs. Read-only inputs are
descriptor-pinned.
For approved egress, a namespace-local helper passes accepted loopback sockets
to a host relay with `SCM_RIGHTS`. The relay can connect only to the per-run
authenticated proxy; it never exposes a host-network socket or DNS service to
the agent. The namespace-local helper consumes one PID within the configured
session PID limit.
macOS constructs a deny-default sandbox profile and applies it before executing
the child.

## Components

| Namespace    | Responsibility                                                                     |
| ------------ | ---------------------------------------------------------------------------------- |
| `container`  | sandbox creation, mounts, limits, output accounting, terminal receipts             |
| `control`    | Unix control protocol, authentication, session registry, receipt delivery          |
| `supervisor` | canonical plan validation, local alias resolution, bundle resolution               |
| `mcp`        | bounded JSON-RPC framing and upstream clients                                      |
| `policy`     | tool and argument authorization                                                    |
| `kernel`     | extension registration and dispatch                                                |
| `audit`      | structured local activity records                                                  |
| `run`        | CLI orchestration for `run` and `exec`                                             |
| `host`       | strict XDG configuration, machine setup, diagnostics, and local project enrollment |
| `reflect`    | compile-time extension metadata experiments                                        |

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

`glove daemon` installs and controls a fixed per-user service through systemd
on Linux or launchd on macOS. The CLI resolves the local `gloved` executable,
binds it to the protected config, writes the service definition atomically, and
invokes the service manager without a shell. It never accepts service labels,
extra arguments, environment, or lifecycle requests from P2P.
The Linux unit enters an unprivileged user namespace and a private mount
namespace before executing `gloved`; that gives the current user namespace only
the mount authority needed for quota-backed private session filesystems.
Systemd separately delegates the `cpu`, `memory`, and `pids` controllers to the
unit. Neither mechanism grants host-root authority.

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

`refinement-eval-v1` is a Glove-owned declarative evaluator on the shipping
Linux managed-session backend. The model and harness receive no evidence writer.
Before launch, Glove reads the exact fixture projection through its pinned
read-only bundle descriptor, strictly decodes a non-executable fixture DSL, and
removes that supervisor-only projection from the child mount set. The selected
base or candidate skill projection remains an ordinary immutable read-only
projection.

The PTY drain worker feeds every raw byte to the evaluator before circular
transcript eviction. After clean drain and resource finalization, Glove checks
the trusted termination, exit code, wall latency, UTF-8 stream state, and
required/forbidden transcript literals, then synthesizes the canonical outcome.
PTY JSON is only text and cannot become evidence. An incomplete stream or
invalid UTF-8 produces authenticated invalid evidence; resource termination
overrides otherwise satisfied transcript assertions.

The distinct refinement envelope shares the receipt journal's global sequence
and HMAC head but uses its own receipt and envelope domains. Recovery and audit
paging preserve the receipt kind, and the session registry refuses a resource
V1 envelope for a refinement plan. Capability discovery reports schema version
`1` only when the Linux runtime and protected library projection store were
both constructed.

The local protocol exposes attach, input, resize, signal, detach, stop, and
cleanup only when the constructed runtime reports `lifecycle_operational()`.
Pointer presence is not capability evidence. The remote runtime currently
reports false, schema version `0`, an empty managed-runtime set, and unavailable
resource mechanisms; every lifecycle dispatch returns `method_not_found`
without starting SSH. Sage wires only operational lifecycle and receipt
reconciliation. Exposure create/revoke remains owner-local; peers may
receive only the redacted catalog. Retained-change inspection and independently
authorized apply remain separate launch gates.

## Construction-only remote backend

When `remote_backend` is present, `gloved` validates it as mutually exclusive
with local materialization and Apple Container configuration. It requires the
container identity as an untagged canonical `name@sha256:<64 lowercase hex>`
reference whose suffix exactly equals `container_image_digest`, retains both
values in the runtime composition, and rejects tags or mismatches. It writes an
isolated OpenSSH config and pinned `known_hosts` beneath the already verified
owner-only runtime directory, then constructs the non-operational runtime. This
step performs no DNS lookup, network probe, authentication, SSH process launch,
or Docker operation.

The generated SSH configuration ignores global known-hosts files, accepts only
`ssh-ed25519` host keys, disables host-key learning, and disables connection
sharing with `GlobalKnownHostsFile none`, `HostKeyAlgorithms ssh-ed25519`,
`UpdateHostKeys no`, `ControlMaster no`, `ControlPath none`, and
`ControlPersist no`. The forced remote executable accepts exactly `--stdio`,
sets umask `077`, and reads its expected executable and image SHA-256 digests
only from the administrator-owned `/etc/glove/remote-executor.identity` source.
It measures its opened executable and fails closed on missing, empty, malformed,
writable, or mismatched identity. Before each frame read, it captures the
monotonic receive start and channel deadline. Request-TTL conversion subtracts
all frame-receive time and rejects a frame that consumed its TTL; response writes
use only the resulting request deadline. Only `remote_health` is available and
it always reports `not_operational`;
lifecycle methods return `method_not_found`. This is construction evidence, not
remote-launch readiness.

## Library projection

Sage plans refer to bundle digests and destination aliases, never arbitrary host
paths. Local policy maps each alias to a protected sandbox target. Glove opens a
digest-named bundle beneath an owner-only root without following links, verifies
its type, ownership, link count, size, identity, and SHA-256 digest, then mounts
the descriptor as a read-only sandbox file.

The launch binding and terminal receipt commit the projection identifier,
destination, target, and digest. Bundle expansion into harness-native prompt
directories is not implemented; `prompt_ref` remains rejected.

## Sage guest proposal channel

The authenticated per-session queue accepts two closed logical schemas. The
existing observation schema carries bounded non-signing observations. The
`sage.glove-sxxx-self-delegation-proposal.v1` schema carries only a proposal
identifier, the fixed `sxxx-self-delegation` kind, one constant value digest,
and `item_count = 1`. It carries no wallet, profile, chain, token, calldata,
fee, nonce, Remote Procedure Call endpoint, credential, or operator proof.

Both schemas use the same channel token and authoritative session context, but
their body contracts are distinct. Glove commits either body with the same
length-prefixed digest algorithm and preserves its exact schema in the durable
queue. Sage decides whether to build a final host intent. Glove never signs or
broadcasts a transaction.

## Persistence

Session and receipt journals are append-only and bounded. Recovery rejects
corrupt, reordered, duplicated, truncated, or externally resized records.
Authenticated terminal receipts form an HMAC chain anchored by Sage. The
general JSONL activity log and session-state journal are not protected against a
same-user host process that can rewrite them.

Detailed policy and file invariants are defined in
[session-policy.md](session-policy.md).
