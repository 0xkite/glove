# Glove host setup

`glove setup` configures one machine. `glove init` enrolls one project beneath
an operator-approved root. Neither command publishes paths or accepts path
authority from P2P.

## Harness and session policy

Glove recognizes Codex, Claude Code, Pi, Copilot, and OpenCode from its core
adapter catalog. Discovery never trusts inherited `PATH`. Give it one or more
explicit directories:

```sh
glove policy detect --search-path /absolute/protected/harness-bin --json
```

Package-manager bin directories are commonly group-writable and will be
rejected with the exact untrusted ancestor. After inspecting the absolute
vendor executable, preview and explicitly create an adapter-named entry point
in an owner-controlled directory:

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

Staging creates only a protected symlink to the canonical executable. It does
not copy or expose the operator's credential/config home. The stage report
automatically resolves native binaries or safe shebang interpreters and emits
the exact launch executable, script argument, and minimal immutable read-only
dependency roots. Homebrew clients are closed over installed formula kegs;
adjacent version-manager interpreters are closed over that one version root.
Unsupported shebangs and root-wide dependency grants fail closed.

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

By default Glove uses:

| Purpose | Path |
|---|---|
| Configuration | `${XDG_CONFIG_HOME:-~/.config}/glove/config.json` |
| Persistent state | `${XDG_STATE_HOME:-~/.local/state}/glove` |
| Bundles | `${XDG_DATA_HOME:-~/.local/share}/glove` |
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
required for quota-backed session filesystems and managed resource limits.

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

| Purpose | Access | Writable scope | Cleanup | Default TTL |
|---|---|---|---|---|
| `inspect` | Read-only | None | No copy | 1 hour |
| `experiment` | Ephemeral write | Isolated copy, up to 1 GiB | Removed | 1 hour |
| `retain` | Retained write | Isolated copy, up to 1 GiB | Kept for review/apply | 24 hours |

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
