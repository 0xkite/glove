# Glove

Glove runs an LLM agent inside an OS-enforced sandbox and mediates its tool
access. Files and inherited environment variables are denied unless the operator
grants them explicitly.

> Status: research prototype. Remote Sage launch remains disabled until the
> public lifecycle, approval, and resource-enforcement contracts are complete.

## Security model

Glove contains the agent process rather than operating only as a network proxy.

```text
host
├── Glove control, policy, and audit
├── sandbox
│   └── agent
└── approved MCP upstreams
```

On Linux, the sandbox combines user, PID, network, mount, IPC, and UTS
namespaces with `pivot_root`, bind mounts, and seccomp. On macOS, Glove applies
a deny-default Sandbox Profile Language policy before launch. The contained
process receives a minimal environment and only configured filesystem grants.

Glove does not prevent prompt injection, misuse of an allowed tool, compromise
of an unsandboxed upstream tool server, same-user host tampering, or kernel
exploitation. See [the threat model](docs/threat-model.md) for assumptions and
residual risks.

## Build and test

Requirements:

- CMake 3.28 or newer
- Ninja
- Clang 18 or newer
- Linux: libseccomp development headers
- macOS integration tests: `yams`

Build, test, and install Release to `${GLOVE_INSTALL_PREFIX:-$HOME/.local}`:

```sh
./setup.sh
```

Use `./setup.sh Debug` for a development build. Run the complete local gate:

```sh
./scripts/preflight.sh
```

For faster development:

```sh
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

Linux isolation tests can run in the provided container:

```sh
docker build -f dockerfiles/Dockerfile.linux -t glove-linux .
docker run --rm --privileged --security-opt seccomp=unconfined glove-linux
```

## Run modes

`glove run` contains an agent and exposes only allow-listed MCP tools:

```sh
./build/dev/src/glove run \
  --upstream yams=yams,serve,--quiet \
  --allow yams.mcp.echo \
  -- ./build/dev/src/container/glove_synthetic_agent --mode=client
```

`glove exec` contains a direct agent process without attaching the MCP kernel:

```sh
mkdir -p /tmp/glove-work
./build/dev/src/glove exec \
  --workspace /tmp/glove-work \
  -- /absolute/path/to/agent --version
```

`gloved` is an owner-local control service for plan validation, durable session
state, authenticated receipt delivery, and a Linux managed-session lifecycle.
Live host writes are unsupported. Dynamic path exposure is owner-local;
write-capable sessions use isolated, quota-backed materializations.

```sh
./build/dev/src/glove setup --path-root "$HOME/work" --dry-run
./build/dev/src/glove setup --path-root "$HOME/work" --yes
./build/dev/src/glove daemon start
./build/dev/src/glove daemon status
```

Add `--session-policy /absolute/owner-only/session-policy.json` during setup to
enable managed-session configuration. Enroll individual projects only while
the local service is running: `glove init /absolute/project`. See
[host setup](docs/host-setup.md).

## Documentation

- [Architecture](docs/architecture.md): process boundaries and request flow
- [Session policy](docs/session-policy.md): canonical plan and local policy contract
- [Threat model](docs/threat-model.md): guarantees, assumptions, and residual risk
- [Quickstart](docs/quickstart.md): build and invocation examples
- [Host setup](docs/host-setup.md): XDG state, service registration, and project enrollment
- [Future work](docs/future-work.md): prioritized launch and hardening gates
- [Credits](CREDITS.md): dependencies and research references

## License

Glove is licensed under [GPL-3.0-only](LICENSE). Dependency licenses are listed
in [CREDITS.md](CREDITS.md).
