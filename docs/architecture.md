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

## Historical synthetic status milestone

The former construction-only synthetic status stack and harness-shaped adapter were
removed because they had no production composition or child descriptor mapping. Any
future ephemeral query service must be built at a live composition seam and may share
only the harness-neutral bounded guest-channel transport; payload semantics,
persistence, and harness projection remain outside that transport.

The shared `guest_channel_transport` owns one connected Unix stream descriptor,
verifies `AF_UNIX`, `SOCK_STREAM`, and the required peer UID, and performs only
bounded four-byte big-endian framed I/O. Each receive or send uses its caller's
absolute steady-clock deadline and stop token. The transport is single-thread
confined and has no handler, exchange, or public close API; its owner stops and
joins the worker before destruction closes the descriptor, avoiding concurrent
close and descriptor-reuse races.

The observation server carries one absolute accept deadline through every retry
and stop-aware transient backoff. After accept, receive and response send share
one absolute I/O deadline. Stop/deadline checks immediately surround registry
handling, but registry persistence is trusted synchronous local work and cannot
be forcibly interrupted once started. The hard bound therefore covers accept,
framed I/O, and cooperative cancellation—not arbitrary handler execution.

The Linux local-service proxy remains schema-generic. The compatibility
transport, selected when an adapter omits `transport_id`, mounts only
runtime-allowed alias sockets from a private owner-only directory and forwards
one bounded G2 request/response without parsing the payload. Upstream parents
are descriptor-pinned and endpoint identities are drift-checked around connect.
Because portable pathname Unix sockets cannot prevent same-UID ABA replacement,
the operator and service-UID processes are trusted endpoint authority; the
checks do not authenticate an application process. Resolved path grants are
compared by descriptor identity against every endpoint parent ancestor before
filesystem materialization, preventing a grant from exposing the host socket
directly.

An adapter may instead select `inherited-stream-v1`. Glove creates one
owner-`0600` connected `AF_UNIX`/`SOCK_STREAM` socketpair for the exact
adapter-bound alias and keeps the supervisor peer outside the sandbox. Clone
setup loads seccomp with the committed contiguous child-descriptor range, then
installs the guest peer at descriptor 3 after internal setup descriptors close.
Offline `socket`, `connect`, `setsockopt`, and peer inspection remain denied;
only `getsockname` and `getsockopt(SOL_SOCKET, SO_TYPE)` are permitted on the
exact committed inherited descriptors so Node/libuv can classify the already
connected stream. The child receives only the compact one-entry
`GLOVE_LOCAL_SERVICE_FDS_V1` alias-to-descriptor map; no proxy path, other
configured local service, or host endpoint metadata is projected. Clone setup
preserves exactly that descriptor and closes every gap and all undeclared
descriptors. The persistent stream accepts sequential existing G2 frames,
rejects empty, oversized, trailing, or queued input at the request boundary and
immediately before and after response release, uses one absolute deadline per
exchange, and is poisoned on transport, identity, upstream, framing, timeout,
or cancellation failure. The managed-launch binding commits the selector,
alias and child descriptor, both socket identities, and manifest digest.
User-supplied `GLOVE_LOCAL_SERVICE_*` variables and mixed pathname/inherited
authority fail closed.

Guest-channel semantics enter only through an opaque adapter binding resolved
in `src/adapters/`. A generic or arbitrarily named `pi` endpoint does not imply
a Sage schema. The sealed capability requires `inherited-stream-v1` plus the
exact adapter binding, registry catalog, factory, concrete Linux runtime, and
adapter/runtime endpoint intersection. Endpoint checks are construction and
drift evidence, not process-authentication evidence.

Proxy audit uses a conservative three-phase sequence: durable non-success
`delivery_pending` before release, a clean post-audit request boundary before
send, `delivered` only after successful guest send plus an immediate clean
post-send boundary, and best-effort `delivery_failed` after failure. Synchronous
audit persistence checks the exchange deadline before and after the append, but
a kernel-blocked `fsync(2)` is not cooperatively preemptible. A late append
cannot release the response. Stream scheduling cannot prove whether a byte that
arrives after the final post-send peek was written before or after the peer
observed the response; that byte is never processed concurrently and the next
request boundary still applies. A protocol that needs causal no-pipelining proof
must add an explicit versioned credit or acknowledgement.

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
unit. On systemd 254 or newer the generated unit places `gloved` in the fixed
`glove-host` delegate subgroup. Glove pins that subgroup and its parent cgroup,
requires owner identity and process exclusivity, enables the three controllers
only on the empty delegated parent, and creates session cgroups as siblings of
the supervisor subgroup. This avoids moving the supervisor during service
startup while preserving a process-free controller node. When the supervisor
itself has a non-identity UID map, the kernel cannot combine nested UID mapping
with `CLONE_INTO_CGROUP`; Glove instead creates a child whose first operation is
a blocking read on a private sync pipe, writes the nested UID/GID maps, attaches
the blocked child to its sealed session cgroup, and releases it only after the
durable start gate succeeds. No child setup or agent instruction executes
before cgroup attachment. Neither mechanism grants host-root authority.

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

## Guest specialized-channel admission

The durable per-session queue is schema-generic: Glove core enforces only
structural invariants (identifier charset, digest hex, TTL/skew arithmetic,
capacity, idempotency) and delegates body semantics to a host-registered
admission table (`channel_descriptor{schema_id, body_validator, bounds}`). A
host must register every payload contract, propagate registration failures, and
freeze the nonempty `channel_host` before registry construction. Schema strings
never appear in core. Current admission rejects enqueue for every unregistered
schema. Only an authentic intent already present in durable history may recover
after its schema retires, and then solely as non-actionable quarantine metadata
that cannot be enqueued again or launched.

The explicit Sage harness adapter under `src/adapters/sage/` registers only the
bounded, non-signing `sage.glove-observation.v1` schema currently required for
registry admission. Dormant proposal or mutation schemas are not registered, so
current enqueue rejects them. Authentic historical records using a subsequently
retired schema recover only as non-actionable quarantine metadata.

Glove commits admitted bodies with the shared length-prefixed digest algorithm
and preserves the exact schema in the durable queue. Intents bind to the
session's parsed `runtime_id`, so any managed guest runtime can carry a
registered payload.

Capability discovery does not infer observation ingress from registry storage.
On Linux, schema version `1` requires an opaque capability produced only by
sealing the concrete lifecycle runtime against the exact registry, frozen
catalog, preparer-owned proxy factory, managed runtime intersection, complete
resource mechanisms, descriptor-pinned endpoint parents, and current rechecked
socket identities. The opaque capability owns the runtime, which owns its
preparer and registry; the preparer owns the factory, and the factory owns the
same registry. No edge points back to the capability or runtime. Generic,
remote, Apple, mismatched, unsealed, absent-config, and drifted compositions
report `0`.

The optional local-service proxy descriptor-pins each configured owner-`0700`
parent and records and rechecks the owner-only Unix socket's exact
`dev/ino/uid/mode/nlink` before and after every connect. An allowed session gets
one fresh owner-only directory mounted read-only at
`/run/glove-services/local` and the fixed `GLOVE_LOCAL_SERVICE_DIR` environment.
Alias listeners forward one bounded G2-framed opaque request and response under
one absolute deadline with peer-UID checks on both sides. A fixed worker set is
joined before inode-safe socket and directory cleanup. The launch digest commits
the sorted runtime-filtered aliases, descriptor-pinned parent identities,
recorded socket identities, and factory generation; no durable registry or
receipt schema changes.

## Persistence

Session and receipt journals are append-only and bounded. Recovery rejects
corrupt, reordered, duplicated, truncated, or externally resized records.
Authenticated terminal receipts form an HMAC chain anchored by Sage. The
general JSONL activity log and session-state journal are not protected against a
same-user host process that can rewrite them.

Detailed policy and file invariants are defined in
[session-policy.md](session-policy.md).
