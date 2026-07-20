# Glove quickstart

## Prerequisites

| Platform | Requirements |
|---|---|
| macOS | Xcode Command Line Tools; CMake 3.28+; Ninja; Clang 18+; optional `yams` integration tests |
| Linux | CMake 3.28+; Ninja; Clang 18+; libseccomp headers, or Docker |

CMake fetches Glaze during configuration.

## Build and verify

Configure, build, test, and install a Release build to
`${GLOVE_INSTALL_PREFIX:-$HOME/.local}`:

```sh
./setup.sh
```

Use `./setup.sh Debug` for an unoptimized development build or
`./setup.sh Release` explicitly for the default. The script supports macOS and
Linux and requires an absolute `GLOVE_INSTALL_PREFIX` when overriding the
user-local default.

For build-only iteration:

```sh
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

Run all repository gates before committing:

```sh
./scripts/preflight.sh
```

The preflight runs actionlint, formatting, clang-tidy, ASan/UBSan tests, and
TSan tests.

To exercise Linux namespace and mount behavior in Docker:

```sh
docker build -f dockerfiles/Dockerfile.linux -t glove-linux .
docker run --rm --privileged --security-opt seccomp=unconfined glove-linux
```

The elevated Docker flags permit nested namespace creation, `clone3`, and
`pivot_root`. They are not required on a suitable bare-metal Linux host.

## Contained MCP agent

The synthetic agent verifies initialization, tool discovery, policy, dispatch,
and response handling:

```sh
./build/dev/src/glove run \
  --upstream yams=yams,serve,--quiet \
  --allow yams.mcp.echo \
  -- ./build/dev/src/container/glove_synthetic_agent --mode=client
```

Multiple stdio MCP servers may be registered:

```sh
./build/dev/src/glove run \
  --upstream yams=yams,serve,--quiet \
  --upstream local=python3,-m,my_mcp_server \
  --allow yams.mcp.echo \
  --allow local.read \
  --audit-log /tmp/glove-audit.jsonl \
  --workspace /tmp/glove-work \
  -- /absolute/path/to/agent
```

The agent sees qualified tool names such as `yams.mcp.echo`. An upstream server
runs as a host process and is not contained by the agent sandbox.

## Direct agent

`glove exec` contains an agent without connecting the MCP kernel:

```sh
mkdir -p /tmp/glove-work
./build/dev/src/glove exec \
  --workspace /tmp/glove-work \
  -- /absolute/path/to/agent --version
```

Exposure is opt-in:

- `--workspace PATH` grants the working tree.
- `--read PATH` grants a read-only file or directory.
- `--write PATH` grants write access.
- `--env NAME` copies one host environment variable.
- `--egress-allow HOST:PORT` permits an exact macOS HTTPS destination.

Without `--workspace`, Glove starts in a private empty directory. Linux direct
execution is offline because proxy transport into the isolated network namespace
is not implemented.

## Audit output

`--audit-log PATH` appends one JSON object per event:

```sh
tail -f /tmp/glove-audit.jsonl | jq .
```

The audit path must be outside every agent-visible path. Glove rejects unsafe
placement. The general JSONL log prevents contained-agent access but is not
authenticated against a same-user host process.

## Gloved control service

Use the host setup workflow instead of assembling daemon flags manually:

```sh
./build/dev/src/glove setup --path-root "$HOME/work" --dry-run
./build/dev/src/glove setup --path-root "$HOME/work" --yes
./build/dev/src/glove daemon start
./build/dev/src/glove daemon status
```

Pass `--session-policy /absolute/owner-only/session-policy.json` to both setup
commands when testing managed sessions. Retained-write preparation on Linux
also requires `mkfs.ext4`, loop devices, and mount capability. See
[host-setup.md](host-setup.md) and [session-policy.md](session-policy.md).

### Sage-triggered user service

`glove daemon start` installs the fixed user-service definition and starts it.
The templates under `packaging/` document the equivalent systemd and launchd
definitions.

Then configure and verify Sage:

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

Use `org.sage-protocol.gloved` as the service name on macOS. Enable
`fleet_execution_host_enabled` only after reviewing the local Sage daemon
policy.

Sage invokes only the platform service manager with a bounded local service
label. P2P cannot select the binary, service, arguments, environment, or path
policy. Authentication or capability failure leaves Sage available while
remote launch remains disabled.

## Troubleshooting

| Error | Cause and action |
|---|---|
| `clone3: Function not implemented` | Use Linux 5.3+ and allow `clone3` in the outer container. |
| `mount: Operation not permitted` | Grant mount capability to the outer test container. |
| `posix_spawnp: No such file or directory` | Check that agent and upstream paths exist and are executable. |
| JSON-RPC version or frame error | Run the upstream directly and verify MCP stdio framing. |
| Missing yams tests | Install `yams` and reconfigure the build directory. |

For security boundaries and deployment assumptions, read
[threat-model.md](threat-model.md).
