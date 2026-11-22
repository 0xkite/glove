# Glove architecture

## Scope

Glove provides these execution surfaces:

| Surface       | Purpose                                                     | Current boundary            |
| ------------- | ----------------------------------------------------------- | --------------------------- |
| `glove run`   | Contain an agent and mediate MCP tool calls                 | Public CLI                  |
| `glove exec`  | Contain a direct agent process                              | Public CLI                  |
| `glove shell` | Interactive sandboxed agent prompt TUI inside the workspace | Public CLI                  |
| `glove loop`  | Seeded agent feedback loop with offline `--verify`          | Public CLI                  |
| `glove pi`    | Native macOS Pi with host-only provider credentials         | Prototype CLI; unqualified installed compatibility |
| `gloved`      | Validate Sage plans, persist sessions, and deliver receipts | Owner-local control service |

The `run` and `exec` CLI surfaces support local containment. Native Pi has
synthetic fixture coverage, not installed-harness or live-provider acceptance.
The distributed Sage session surface is incomplete and must not advertise
remote-launch readiness. A
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
| `run`        | CLI orchestration for `run`, `exec`, and native Pi                                 |
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

## Mediated credential proxy and upstream containment

Glove mediates external network requests through an object-capability model that
unbundles credentials from the agent sandbox (detailed in
[`docs/credentialed-proxy-architecture.md`](credentialed-proxy-architecture.md)).
This section separates what is constructed today from what is planned, because a
capability must never be described as active before it exists.

**Constructed:**

1. **Credentialed loopback endpoint**: Linux uses a private-loopback bridge.
   macOS permits one exact AF_INET loopback TCP port through SBPL. Legacy
   presets use base-URL variables (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`);
   native Pi writes the selected provider URL into private configuration.
2. **Session nonce swap**: The agent receives an ephemeral session token
   (`glove-session-...`). The host endpoint validates it and substitutes the
   real provider credential. The nonce authorizes only the bound live endpoint;
   it is not a durable provider credential.
3. **Mutual exclusion**: A profile may carry either a raw CONNECT egress proxy or
   a bridged reverse endpoint, never both, so a credentialed upstream is not
   also reachable over an uninspected tunnel.
4. **Strict request admission**: The endpoint accepts origin-form HTTP/1.1 only,
   rejects bare CR/LF framing and invalid tokens, requires a single
   `Content-Length` or none, refuses `Transfer-Encoding`, rejects dot-segment
   traversal, and enforces the rule's method and path allowlist. Forwarded
   headers and the request target are validated; hop-by-hop, routing, and
   credential fields are stripped before the transport sees them.
   Every decision is one `egress` audit record, written before the request is
   forwarded or the refusal is sent; its `error` field is `allowed` or the
   reason. A forwarded request gets a second `egress` record when the exchange
   with the provider ends, before any of the response is served: `error` is
   `completed` or `upstream_error`, `latency_ns` is how long the exchange
   took, and `arguments` holds `upstream_status`, `request_bytes` and
   `response_bytes`. So a journal has two records per forwarded request, and
   only the second has a non-zero `latency_ns`. If either record cannot be
   written the client gets 503 and nothing else.

5. **Provider transport**: Legacy `glove exec --agent` presets and the native
   Pi adapter install `make_tls_forwarder` (`src/net/tls_forwarder.cpp`). Each allowed request is
   one HTTP/1.1 exchange over a fresh TLS 1.2+ connection using the platform's
   native stack and trust store: Network.framework on macOS, the system OpenSSL
   on Linux. The peer must chain to a system anchor and match the upstream host
   (also sent as SNI). There is no plaintext fallback and no knob to relax
   verification. The forwarder carries its own `(host, port)` allowlist, set to
   the preset's provider and checked before resolution, and it injects the
   credential in the provider's field (`x-api-key` for Anthropic,
   `Authorization: Bearer` for OpenAI and GitHub). It never follows redirects,
   and it de-frames chunked and length-framed bodies under the endpoint's
   32 MiB cap, refusing unframed (close-delimited) bodies because they cannot
   be told apart from truncated ones. The provider exchange has a 10-minute
   deadline because the whole response is buffered. Responses are not streamed;
   native Pi's installed-harness SSE compatibility remains unqualified.

Both backends admit the per-run credentialed endpoint. Linux uses its namespace
bridge; macOS admits only the exact host-loopback port, not neighboring ports,
UDP, IPv6, or direct upstream access. Name resolution on Linux uses blocking
`getaddrinfo` and is not bounded by the request deadline.
The endpoint serves one connection at a time, so concurrent agent requests
queue behind a long generation.

**Not constructed yet.** The following are design intent, not enforcement:

- Aho-Corasick canary detection and Rabin-Karp rolling-hash checks against known
  secret digests;
- structural JSON schema validation and token-budget enforcement derived from
  provider response metadata;
- **partially isolated MCP upstreams** (`contained_launcher` is not yet constructed). On Linux, `glove run` launches stdio upstreams under `CLONE_NEWUSER | CLONE_NEWNET`, `PR_SET_NO_NEW_PRIVS`, and `PR_SET_PDEATHSIG` (`src/mcp/stdio_transport.cpp`), while full mount/PID/cgroup containment remains unbuilt.

## Native macOS Pi

CLI usage and limits: [Native macOS Pi](native-pi.md).

`glove pi setup` copies an approved Pi/Node runtime and records a builtin
provider/model selection. `refresh` replaces that protected runtime and
selection with explicit consent. Launch does not perform automatic setup.
Only OpenAI Responses and Anthropic Messages API-key authentication are in
scope; Codex CLI and Claude Code remain proposed peer adapters.

Launch validates the workspace, protected runtime, copied builtin catalog and
private operator configuration before creating a per-run home. Generated
configuration uses a nonce, preserves builtin model metadata, and disables
external resource discovery. The child receives captured terminal stdio and
an owned original process group. Cleanup follows endpoint revocation and
checked lifecycle handling; uncertain ownership retains private state.

The default private audit sink retains at most 1,024 events and 1 MiB of logical
event/string charge. Refusal is an error, not eviction or accepted event loss.
The charge is not an allocator or RSS limit. This path does not provide the
managed Linux six-limit contract or authenticated terminal receipts.

Synthetic containment and lifecycle tests do not establish installed Pi startup,
request/edit behavior, buffered-response compatibility, or live-provider access.
Same-UID namespace mutation and detached descendants are not covered by an
atomic snapshot or general process-tree death guarantee.

## Native session continuity

A host supervisor can own successive native generations of one logical
conversation with host-side durable checkpoints, a protected host-only
management transport and retained finalization before private-run cleanup.
See [Native session continuity](native-session-continuity.md). Constructed
for the Claude Code harness in an offline fixture composition; it adds no
public CLI, no provider rail and no managed-session capability.

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

`glove exec`, `glove shell`, and `glove loop` bypass the MCP kernel. They are
intended for interactive inspection or self-driving agents that manage their own
tool protocol, so their security boundary is the OS sandbox and explicit
filesystem/environment exposure. Passing `--allow-loopback-listen` brings up
the private `lo` interface and permits `127.0.0.1` `bind`/`listen`/`accept`
inside `CLONE_NEWNET` without granting external network egress.

On macOS these commands launch the agent through the owned passthrough
(`exec_contained_owned`). While the agent runs, glove holds the SIGINT,
SIGQUIT, SIGTERM and SIGHUP dispositions: a signal sent to glove is passed to
the agent's process group, the group is killed if it has not exited after 1.5
seconds, and glove then returns through its normal exit path. So a supervisor
that stops glove with SIGTERM still gets the `agent_exit` record, the denial
summary and trace end record, and decoy removal, and glove exits with the
agent's code or 128 plus the signal. SIGKILL of glove leaves none of these. A
launch whose stdin is a terminal that glove is not in the foreground of is
refused. On Linux glove does not handle these signals yet: the default action
ends glove without those records, and `PR_SET_PDEATHSIG` ends the agent.

When `--herdr` is passed inside an outer Herdr terminal pane (`HERDR_ENV=1`, `HERDR_PANE_ID`),
Glove's host runner reports lifecycle states (`working`, `done`) and releases authority
via Herdr's CLI strictly from the host side using `posix_spawnp`. The contained child process
receives neither `HERDR_SOCKET_PATH` nor `HERDR_BIN_PATH`, preserving fail-closed containment.
Seccomp explicitly denies `TIOCSTI` and `TIOCLINUX` ioctl calls on the shared terminal descriptor
to prevent synthetic keystroke injection into the host pane buffer, and installs `PR_SET_PDEATHSIG`
to terminate the child if the supervisor dies.

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

`glove run`, `exec`, `shell` and `loop` record to
`<XDG_STATE_HOME>/glove/logs/session.jsonl` unless `--audit-log` names a
journal. A journal has one writer for as long as its launch lives, held by an
exclusive lock, so records of two launches never interleave. A launch that
finds the default journal held by another live launch records to its own
`session.<16 hex>.jsonl` beside it (same directory, mode 0600, same 10 MiB
bound) and prints one stderr line with a fixed prefix, `glove: another launch
holds the default audit journal; this launch records to `, followed by the
path to the end of the line. At most 64 such journals are kept: creating
another removes journals that no live launch holds, oldest modification time
first, and never one whose lock is held. Only a held lock
is worked around; a default journal that is not this user's owner-only
single-link regular file is still an error, and so is an `--audit-log` path
that another launch is using.

### Where configuration and state live

Configuration is files. The `glove` CLI reads them itself; `run`, `exec`,
`shell` and `loop` never contact `gloved`, and the control protocol has no
method that reads or changes configuration. `gloved` loads its own
`config.json` and the state files that file names.

`<config>` is `$XDG_CONFIG_HOME/glove` (default `~/.config/glove`), `<state>`
is `$XDG_STATE_HOME/glove` (default `~/.local/state/glove`) and `<data>` is
`$XDG_DATA_HOME/glove` (default `~/.local/share/glove`). The runtime directory
is `<state>/runtime`; `XDG_RUNTIME_DIR` is not used for it.

| Path | What | Read by | Written by |
|---|---|---|---|
| `<config>/config.json` | service configuration | `gloved`, `glove status`, `doctor`, `session` | `glove setup` |
| `<config>/policies/<name>.json` | session policies | `glove setup`, `glove policy` | `glove policy install` |
| `<config>/path-exposure-policy.json` | path exposure policy | `gloved` | `glove setup` |
| `<config>/profiles/<name>.yaml` | launch profiles | `--profile` | `glove profile new`, `edit` |
| `<config>/envs/<name>.json` | saved shell environments | `glove shell --load`, `--list` | `glove shell --save`, and `last` after each launch |
| `<state>/logs/session*.jsonl` | default audit journals | you | `run`, `exec`, `shell`, `loop` |
| `<state>/decoys` | decoy journals | `glove` | `glove` |
| `<state>/audit.key`, `receipts.journal`, `sessions.journal`, `path-exposures.journal`, `materializations/` | service state | `gloved` | `gloved` |
| `<state>/runtime/gloved.sock`, `gloved.lock` | control socket and lock | `glove` | `gloved` |
| `<data>/library-bundles` | library bundles | `gloved` | `gloved` |

Profiles, saved environments and `config.json` are read only when they are a
regular single-link file owned by the invoking user with mode 0600. A denial
trace and a denial model have no default location; `--denial-trace` and
`--denial-model` name them.

Detailed policy and file invariants are defined in
[session-policy.md](session-policy.md).

## System services

A launch exposes no host system service by default. It can opt in to named
entries from a fixed catalog (`include/glove/container/system_services.hpp`)
with `--system-service <name>` (repeatable; `exec`, `shell`, `run`, `loop`), the
launch-profile key `system_services: [names]`, or the saved-environment key
`system_services` (an array of strings). All three feed one list that
`validate()` checks against the catalog.

| Name             | macOS grant                                                 | Exposes                                                              |
|------------------|-------------------------------------------------------------|----------------------------------------------------------------------|
| `network-config` | `mach-lookup` of `com.apple.SystemConfiguration.configd`    | host network and proxy configuration, read through configd          |
| `tls-config`     | read-only `/private/etc/ssl`                                | the system TLS trust configuration for LibreSSL/OpenSSL clients (curl) |

- Unknown names are refused with `unknown system service '<name>'`. Raw
  platform names such as a mach service name are refused by design: only a
  catalog entry can widen the sandbox, and each entry is reviewed for what it
  reveals. Names are 1-64 bytes; duplicates are removed and the list is sorted.
- `network-config` lets the guest learn the host's network and proxy settings,
  and so the host's network layout. It grants no network access by itself:
  `(deny network*)` and the egress rules still decide connections.
- `tls-config` adds a read-only grant, resolved through the same
  canonicalization and symlink-spelling rules as other read grants. Catalog
  paths pass the same Glove-root exposure check as every other grant
  (`filesystem`, `runtime_filesystem` and system-service read paths), so no
  entry can expose Glove's own configuration or state.
- Linux accepts the names and emits no rule for them: the entries carry no
  Linux rules.

## Launch profiles

`glove exec`, `glove run`, and `glove shell` accept `--profile <name>`, read
from `<XDG_CONFIG_HOME>/glove/profiles/<name>.yaml`. A profile names the
workspace, agent preset, read and write grants, environment (a literal
`value` or `from: host`), egress rules, MCP upstreams, tool allow rules, and
bridge port, and service ports. Command-line flags layer on top: a flag
workspace, agent, or bridge port replaces the profile's; list flags append.

### Service ports

`--service-port <port>` (repeatable; profile key `service_ports: [ports]`;
saved-environment key `service_ports`, an array of decimal strings) lets the
guest connect to plain host-loopback TCP services, for example a Sage Worker
or a relay, next to `--share-credential` or the egress proxy. Service ports
carry no credential and are independent of the credentialed bridge endpoint
and of `proxy`. macOS grants each port with the same exact-port SBPL rule the
bridge endpoint uses. A profile refuses port 0, more than 16 ports, and a port
equal to the credential bridge or proxy port; duplicates collapse. Linux
refuses non-empty `service_ports` (`service ports are not supported on Linux
yet`).

A service port is raw TCP to whatever listens on that host port. It bypasses
the egress proxy's allow-list and egress audit, and Glove cannot tell what the
listener is. Grant only ports whose listener you control and trust with the
guest. Never grant another session's credential bridge or egress proxy port,
or a host-side forward proxy: through those, the guest would gain that
credential or unrestricted egress.

`--bridge-port` bridges one port when no credential bridge or egress proxy
takes the endpoint. Combined with `--share-credential` or egress it is
refused (`--bridge-port cannot be used with ...; use --service-port for plain
loopback services`) instead of being ignored.

- Glove reads profiles on the host before any sandbox exists. The profile
  directory must be owner-only (`0700`) with no group- or other-writable
  ancestor; a profile must be a regular, single-link, owner-owned `0600`
  file of at most 64 KiB, opened without following symlinks.
- The text is a strict YAML subset (`src/run/yaml_subset.cpp`), translated
  to JSON and decoded by Glaze's strict JSON reader with unknown and
  missing keys refused. Duplicate keys, anchors, aliases, tags, block
  scalars, multiple documents, directives, tabs, control and invisible
  characters, multi-line scalars, and plain nulls are refused with a line
  number, so the file a reviewer reads is the policy glove applies.
  Glaze's own YAML reader is not used.
- `glove profile show` prints a canonical encoding that parses back to the
  same profile; the profile fuzzer checks that property.
- Every launch refuses a filesystem grant that lies inside, or contains,
  glove's configuration or state directory (XDG and the account's default
  locations, lexical and symlink-resolved). An agent that could read them
  would learn policy and decoy layout; one that could write them would
  choose its next sandbox.
- `glove profile edit` saves only text that validates, restores mode `0600`
  after editors that replace the file, and keeps a rejected edit aside.
- `secrets.provider` names where the agent preset's provider credential
  lives: `env://NAME`, `file:///path` or `file://~/path`, or
  `keychain://service/account` (macOS Keychain generic password). Glove
  resolves it on the host when the credentialed endpoint starts; the value
  goes only to the endpoint, and the sandbox sees the session nonce. A file
  secret must be a regular, single-link, owner-only file holding one token
  and outside every filesystem grant of the launch. Errors name the
  reference, never the value. `glove profile check` resolves it too.
  Without the field, the preset's host environment variable is used as
  before. Password-manager CLIs (`op://` and similar) are not supported:
  they would run a program named by the profile.

### Decoys

`decoys:` in a profile lists host paths where glove plants a canary file for
each `exec` or `run` launch (`src/run/decoys.cpp`). Each file is new
(`O_EXCL`, mode `0600`) and holds one random `glvc_` token. Glove refuses a
decoy inside or containing a filesystem grant, one whose directory is
missing, not owned by the user, a symlink, or group- or other-writable (it
never creates the directory), and one where a non-decoy file exists. On
macOS a sandbox denial whose target is a decoy is written as a separate
`decoy` audit record with its own cap of 32, and the denial summary counts
`decoy_hits`; elsewhere decoys are content canaries only.

The sandbox cannot list a decoy's directory, so a probe is seen only when it
opens a decoy by its exact name: realistic fixed names (a credential file
the user does not have) catch real probing, while a `{nonce}` name is seen
only by a process told it (scripted scenarios). A fixed name already planted
by another live launch is shared, not refused.

Removal uses content, not process identity: glove unlinks a decoy only if it
is still a regular single-link file of the user's holding exactly its
canary. Each launch journals its decoys under
`<XDG_STATE_HOME>/glove/decoys` before creating them and holds an exclusive
lock on the journal while it runs; the next launch removes what a launch
that no longer holds its lock left behind.

The JSON environments `glove shell --save/--load` writes under
`<XDG_CONFIG_HOME>/glove/envs` remain as session state; profiles are the
operator-authored policy.

## macOS denial telemetry

Observation only; no capability is advertised for it and nothing may depend on
it.

- The runner starts one `log stream` child per `glove run` or `glove exec`
  session, filtered to kernel Sandbox messages that end with the session's
  tag. Every deny rule of the session's profile carries that tag.
- The child must not outlive glove. Glove stops it on a normal exit. For any
  other exit, SIGKILL included, a `/bin/sh` watcher in the child's process
  group reads a pipe whose only write end glove holds, and kills that group
  when the pipe closes.
- Liveness is proven with a canary before the agent starts (at most 2 s) and
  once more at exit (at most 1 s). The log is ordered, so the closing canary is
  the flush barrier for the session's own denials.
- Each accepted denial becomes one `sandbox_denial` audit record with kind,
  operation, target, process name and pid, percent-encoded and bounded (target
  512 bytes, 16 records per second, 256 per session). A denial with the same
  kind, operation, target and process name as one already recorded is not
  written again; the summary counts these as `suppressed_repeat`. So the 256
  records are distinct denials, and the time and pid of a repeat are only in a
  `--denial-trace` file. One `telemetry` record is written at start and one
  `summary` record at exit.
- If the stream cannot be started or proven, one `telemetry` record says
  `unavailable` and the session runs sandboxed without telemetry.
- An audit append failure of a telemetry record is returned as an error after
  the agent has exited.
- On a terminal the CLI says on stderr when it starts and stops telemetry. It
  always says when telemetry is unavailable, and at exit when it was
  incomplete.

Measurements are in [sbpl-reference.md](sbpl-reference.md); the limits are the
two "macOS denial telemetry" rows of the [threat model](threat-model.md).

### Denial decisions (shadow only)

`include/glove/container/denial_decision.hpp` defines how a session's denials
become a verdict. `glove run|exec|shell --denial-model <file>` (macOS) evaluates a
trained model on each denial and records its verdict; nothing acts on one.

- `denial_feature_builder` turns the denial stream into 37 features (schema
  version 3): counts by kind and by target class (workspace, home credential
  store, home personal folders, other home, system, temp, device, other,
  none), writes outside the workspace, denied writes to places that make code
  run later (launch items, scheduled jobs, shell startup files), denied
  accesses to this launch's decoys (exact path only),
  distinct targets and process names, rates over 1 s and 10 s, and timing.
  Values are `log1p` scaled. Memory is bounded: the rate window holds 4096
  entries and each distinct set 1024.
- `denial_decider::decide` maps features to `proceed`, `flag` or `terminate`
  with a score in [0, 1]. It is a pure function: no I/O, no blocking.
- The product arm is a model trained offline and loaded with
  `load_denial_model`: logistic regression or gradient-boosted trees in a
  strict JSON file (at most 1 MiB, 512 trees, 255 nodes per tree, children
  after their parent, feature names equal to the schema). A file that fails
  any check does not load.
- `make_heuristic_denial_decider` is a fixed-threshold arm kept only to
  compare against the model.
- `glove run|exec|shell --denial-trace <path>` records the launch's raw denials to
  a new file (JSON lines: a header with the classification context,
  including the launch's decoy paths, one line per denial with its time
  since launch, an end line with the monitor's report). It holds at most 16384 events; the rest are counted as dropped.
  The file is created with `O_EXCL|O_NOFOLLOW` and mode 0600, and a path that
  any profile mount exposes is refused before the agent starts. A trace holds
  host paths the agent tried to reach, so it is opt-in. Write failures are
  reported after the agent exits. `parse_denial_trace` reads a trace back as
  untrusted input; traces store events, not features, so a corpus survives a
  feature schema change. Version 1 traces, which had no decoys, still load.
- `glove-denial-replay` (built, not installed) replays traces into feature
  rows and evaluates arms; `tools/denial_model/` holds the scenario
  collector, the trainer and the cross-validated ablation. See its README.

- Shadow records: the denial audit writer feeds each denial to the model on
  the telemetry thread and appends a `verdict` record (`mode`, `arm`,
  `verdict`, `score`, denial count, time since launch) only when the verdict
  escalates, so at most two per launch, outside the ordinary rate caps. The
  summary carries the highest verdict and score.
- The model file is refused when it is not one regular file, when another
  local user could have written it (not owned by this user or root, or
  group/other-writable), when any grant of the launch reaches it, or when it
  is not a valid model for this feature schema. A refused model never stops
  the launch: glove records a `decider` record with the reason, says so on
  stderr, and runs the agent sandboxed without a decider.

A decider can only escalate. Verdicts are recorded (shadow mode) until the
operator enables termination, which is not built; it would go through the
identity-checked group teardown. A missing or invalid model leaves the session
sandboxed with no reaction. Features come from agent-chosen bytes, so an
agent can steer its own verdict, but not what the sandbox allows.
