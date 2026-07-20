# Glove host setup

`glove setup` configures one machine. `glove init` enrolls one project beneath
an operator-approved root. Neither command publishes paths or accepts path
authority from P2P.

## Machine configuration

Preview, then apply:

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
no remote request can alter them.

Use `--config <absolute-file>` for a non-default machine configuration and
`--gloved <absolute-file>` only when the daemon binary is not installed beside
the `glove` CLI.

## Project enrollment

With the daemon running:

```sh
glove init /absolute/project
```

The default grant is read-only. `--access ephemeral-write` and
`--access retained-write` request isolated copy-backed modes bounded by local
root policy; they do not grant direct host writes. Use `glove init --help` for
TTL, quota, runtime-template, and identifier options.

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
