# Glove host setup

`glove setup` configures one machine. `glove init` enrolls one project beneath
an operator-approved root. Neither command publishes paths or accepts path
authority from P2P.

## Harness and session policy

Glove recognizes Codex, Claude Code, Pi, Copilot, and OpenCode from its core
adapter catalog. Discovery never trusts inherited `PATH`. Give it one or more
explicit directories:

For the normal guided path, detect every supported client in reviewed
directories, derive each immutable interpreter/package closure, stage
owner-controlled entry points, and generate a complete offline policy in one
operation:

```sh
glove setup policy \
  --search-path /absolute/reviewed/bin \
  --runtime codex \
  --harness-root "$HOME/.local/share/glove/harnesses" \
  --path-root /absolute/project-root \
  --output "$HOME/.config/glove/session-policy.json" \
  --dry-run

glove setup policy \
  --search-path /absolute/reviewed/bin \
  --runtime codex \
  --harness-root "$HOME/.local/share/glove/harnesses" \
  --path-root /absolute/project-root \
  --output "$HOME/.config/glove/session-policy.json" \
  --yes
```

The dry run performs the same detection, selected-runtime closure derivation,
template digest, and complete-policy encoding without changing files. Apply is explicit,
creates the policy as owner-only mode `0600`, refuses changed existing files,
and validates the result through the production loader.

Pi enrollment requires a separate, explicit adoption binding in the same setup
transaction. The settings file is discovery input containing only approved
`npm:` extension identifiers; the package store is copied into an immutable
Glove-owned snapshot. It is never a host-home projection:

```sh
glove setup policy \
  --search-path /absolute/reviewed/pi-bin --runtime pi \
  --harness-root "$HOME/.local/share/glove/harnesses" \
  --pi-settings /absolute/reviewed/pi-adoption-settings.json \
  --pi-package-store /absolute/reviewed/pi-packages \
  --pi-adoption-root "$HOME/.local/share/glove/harness-adoptions/pi" \
  --path-root /absolute/project-root \
  --output "$HOME/.config/glove/session-policy.json" --yes
```

All three `--pi-*` arguments are required together, and they are rejected
unless Pi is selected. The resulting policy carries only the Glove-owned
manifest root plus manifest and snapshot digests. At launch, Glove generates
private `.pi/agent/settings.json` and extension projections; it never imports
host Pi authentication, sessions, provider/model settings, or package-manager
credentials. Missing clients remain
visible in the report and are not errors when at least one supported harness is
ready. Repeat `--runtime` only when the policy should authorize more than one
detected client; omitting it selects all detected clients. The generated
defaults are deny-network and still require review before machine setup.

Online model-backed sessions extend the same local policy explicitly. Repeat
`--egress POLICY HOST PORT` for each reviewed public endpoint, and add one
`--secret RUNTIME HANDLE SOURCE TARGET` for each exact credential file:

```sh
glove setup policy \
  --search-path /absolute/reviewed/bin \
  --runtime codex \
  --harness-root "$HOME/.local/share/glove/harnesses" \
  --path-root /absolute/project-root \
  --output "$HOME/.config/glove/session-policy.json" \
  --egress openai-online api.openai.com 443 \
  --egress openai-online chatgpt.com 443 \
  --egress openai-online auth.openai.com 443 \
  --egress openai-online ab.chatgpt.com 443 \
  --secret codex codex-auth /absolute/protected/auth.json /home/agent/.codex/auth.json \
  --dry-run
```

These are the currently observed Codex CLI model, authentication, and
configuration endpoints. Keep them as exact host/port grants: do not replace
them with wildcard domains, and review denied egress receipts before adding a
new endpoint.

The source must already be a current-user, single-link, non-symlink regular
file with mode `0600`. Sage plans carry only the handle and egress-policy ID,
never the local path or credential bytes. At first launch Glove imports the
identity-pinned source into an owner-only managed credential lease. Only that
lease is mounted writable inside the private managed home, so vendor OAuth
refresh-token rotation persists without modifying or exposing the operator's
credential file. A nonblocking exclusive lease prevents concurrent sessions
from racing the same rotating credential. When the protected source content
changes after an operator re-login, its digest selects a fresh lease. Egress
remains deny-by-default; every allowed or denied CONNECT decision is durably
audited before an allowed connection is released.

The lower-level commands remain available for custom policies. To inspect only:

```sh
glove policy detect --search-path /absolute/protected/harness-bin --json
```

Package-manager and version-manager directories are commonly group-writable.
Setup may inspect them only because the operator supplied the directory
explicitly; that discovery is not launch authority. Preview and explicitly
stage the selected vendor executable into an owner-controlled directory:

```sh
glove policy stage \
  --runtime codex \
  --source /absolute/path/to/codex \
  --directory "$HOME/.glove-harnesses/codex" \
  --dry-run

glove policy stage \
  --runtime codex \
  --source /absolute/path/to/codex \
  --directory "$HOME/.glove-harnesses/codex" \
  --yes
```

For an already trusted closure, staging creates a protected symlink to the
canonical executable. For a group-writable single-root interpreter/package
closure, it copies the closure into a content-addressed, owner-protected,
read-only snapshot, verifies the source and copy digests match, then runs the
normal launch-trust resolver against the snapshot. It never copies or exposes
the operator's credential/config home. The report emits the snapshot digest,
exact launch executable, script argument, and minimal read-only dependency
root. Unsafe multi-root, escaping-symlink, special-file, root-wide, oversized,
or changed-during-copy closures fail closed.

To retain an existing host's audit key, receipt/session journals, runtime
socket, and materialization roots while adopting a newly reviewed session
policy, derive a new config instead of running fresh machine setup:

```sh
glove config derive \
  --config /absolute/current-config.json \
  --session-policy /absolute/new-session-policy.json \
  --output /absolute/derived-config.json \
  --dry-run

glove config derive \
  --config /absolute/current-config.json \
  --session-policy /absolute/new-session-policy.json \
  --output /absolute/derived-config.json \
  --yes
```

Derivation validates both inputs, changes only the session-policy path, writes
exclusively into an existing owner-only directory, and is idempotent only when
the existing output matches exactly.

Generate a strict `runtime_templates[]` entry through the same resolver and
digest algorithm used by managed launch:

```sh
glove policy generate \
  --runtime codex \
  --template-id codex-safe \
  --executable /absolute/canonical/codex \
  --argument --version \
  --read-only-path /absolute/immutable/harness/dependencies \
  --path-alias workspace \
  --projection-destination libraries
```

Use `--search-path "$HOME/.glove-harnesses/codex"` instead of `--executable`
only when the service sees the same UID ownership mapping as the setup CLI.
Linux services running in an unprivileged user namespace see unmapped
host-root ancestors such as `/home` as UID `65534`; discovery deliberately
rejects that ambiguity. A pinned executable remains adapter-generic and is
identity-pinned again at launch. Interpreter-based clients can instead pin the
interpreter and pass the stage report's detected script as a digest-bound
`--argument`, with its emitted dependency roots supplied by
`--read-only-path`.

The JSON template is written to stdout; the resolved executable and canonical
`adapter_command_digest` are reported separately on stderr. Add the template to
an owner-authored session policy, protect that file with mode `0600`, then use
the production loader directly:

```sh
glove policy explain --file /absolute/owner-only/session-policy.json --json
glove policy validate --file /absolute/owner-only/session-policy.json
```

Validation names the exact schema, runtime-template, digest, launch field, or
host-path trust failure. It does not start the daemon or advertise execution
capability.

## Machine configuration

Start with the guided view:

```sh
glove setup guide
glove setup guide --json
```

Both forms describe the same operator paths. The human form explains
isolation, startup/storage cost, receipt coverage, and the remaining boundary.
The JSON form is stable input for an agent or provisioning tool. On macOS,
Apple Containers plus native runtime tests form the default shipping lane;
native sandboxing alone is the faster local-development mode. On a suitable
Linux host, the default shipping path requires namespaces, seccomp, mounts,
and delegated cgroups and fails closed when those prerequisites are absent.
Capability differences are reported without making either platform secondary.

After choosing the host path, preview and apply the machine configuration:

```sh
glove setup \
  --path-root "$HOME/work" \
  --session-policy /absolute/owner-only/session-policy.json \
  --dry-run

glove setup \
  --path-root "$HOME/work" \
  --session-policy /absolute/owner-only/session-policy.json \
  --yes
```

Omit `--session-policy` for exposure-catalog testing without managed launches.
Setup is idempotent for the same inputs and never overwrites changed protected
files. The policy must already be a current-user, mode-0600 regular file.
`glove setup`, including `--dry-run`, validates it through the same strict
loader as `gloved` before planning machine changes.

Successful setup writes an owner-only `setup-ledger.json` beside the audit
state. The ledger distinguishes resources Glove created from resources it
adopted and content-binds owned files. Cleanup is always a separate,
digest-confirmed operation:

```sh
glove setup cleanup --dry-run
glove setup cleanup --yes --confirm-ledger <sha256-from-preview>
```

Cleanup retains adopted resources, refuses changed files, and stops when an
owned directory contains durable or unmanaged state. It does not infer
deletion authority from a path alone.

For a manually staged or older installation, create a fail-safe ledger without
claiming cleanup ownership:

```sh
glove setup adopt --config /absolute/existing/config.json --dry-run
glove setup adopt --config /absolute/existing/config.json --yes
```

Adoption validates the existing configuration, protected files, session
policy, and managed directories, then records every discovered resource as
retained.

By default Glove uses:

| Purpose                   | Path                                                         |
| ------------------------- | ------------------------------------------------------------ |
| Configuration             | `${XDG_CONFIG_HOME:-~/.config}/glove/config.json`            |
| Persistent state          | `${XDG_STATE_HOME:-~/.local/state}/glove`                    |
| Bundles                   | `${XDG_DATA_HOME:-~/.local/share}/glove`                     |
| Runtime socket and secret | `$XDG_RUNTIME_DIR/glove`, or owner-only local state fallback |

Override the configuration file with `--config /absolute/file`. Runtime and
state paths remain host configuration; they are never placed in a project.

Inspect and validate without mutation:

```sh
glove config path
glove config show
glove config validate
glove doctor
glove doctor --json
```

## Service

Install and start the fixed per-user service after machine setup:

```sh
glove daemon start
glove daemon status
```

`start` idempotently installs the service definition before starting it.
`install`, `stop`, and `restart` are also available. Glove uses
`sage-gloved.service` with the systemd user manager on Linux and
`org.sage-protocol.gloved` with the launchd GUI domain on macOS. The service
definition fixes the resolved local `gloved` binary and protected config path;
no remote request can alter them. On Linux the fixed service enters an
unprivileged user and private mount namespace before starting `gloved`, while
systemd delegates the `cpu`, `memory`, and `pids` cgroup controllers. Both are
required for quota-backed session filesystems and managed resource limits. Do
not replace this service with a bare `gloved` launch from a normal login cgroup.

A systemd restart is a host-supervisor recovery boundary, not an interactive
terminal continuity guarantee: systemd may terminate remaining service-cgroup
processes before restarting `gloved`. Glove can reconcile authenticated durable
state and receipts after restart, but operators must explicitly create or resume
a managed session; do not promise that an interrupted Pi TUI survives a daemon
crash.

Use `--config <absolute-file>` for a non-default machine configuration and
`--gloved <absolute-file>` only when the daemon binary is not installed beside
the `glove` CLI.

## Project enrollment

With the daemon running:

```sh
glove init /absolute/project
```

The default purpose is `inspect`, which is read-only. Choose a human-readable
purpose instead of assembling access, quota, and cleanup options:

| Purpose      | Access          | Writable scope             | Cleanup               | Default TTL |
| ------------ | --------------- | -------------------------- | --------------------- | ----------- |
| `inspect`    | Read-only       | None                       | No copy               | 1 hour      |
| `experiment` | Ephemeral write | Isolated copy, up to 1 GiB | Removed               | 1 hour      |
| `retain`     | Retained write  | Isolated copy, up to 1 GiB | Kept for review/apply | 24 hours    |

```sh
glove init /absolute/project --purpose experiment
```

The CLI prints the effective access, writable scope, cleanup behavior, and TTL
before enrollment. Existing `--access`, `--max-bytes`, and `--ttl-secs` flags
remain advanced overrides for automation and unusual policies; using any of
them is called out in the output. Copy-backed modes never grant direct host
writes.

`glove init` sends the canonical local path over the authenticated owner-local
socket. Fleet peers receive only the exposure identifier, generation, scope
digest, label, modes, expiry, and runtime-template identifiers.

## Sage verification

After registering the service and enabling the local execution host:

```sh
sage config set daemon.glove_activation_mode user_service
sage config set daemon.glove_service_name sage-gloved.service
sage config set daemon.glove_runtime_dir /value/from/glove-config-show
sage config set daemon.glove_session_policy_path /value/from/glove-config-show
sage config set daemon.glove_audit_key_path /value/from/glove-config-show
sage config set daemon.fleet_execution_host_enabled true
sage daemon restart
sage doctor --scope glove --include-details
```

Use `org.sage-protocol.gloved` as the launchd service name on macOS. A failed
Glove startup degrades only execution hosting: Sage remains available and
remote launch requests fail closed.
