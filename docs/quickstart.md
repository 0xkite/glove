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

On Apple Silicon with macOS 26 or newer, the Apple Containers shipping lane
builds the same Linux image and verifies its portable tests plus an outer VM
perimeter:

```sh
container system start
./scripts/macos-shipping-lane.sh
```

Apple's default guest currently rejects mounting procfs from Glove's nested
child user namespace. The script detects that condition and does not treat its
portable Linux or outer-VM results as evidence that the nested
`linux_production` backend passed. The CI workflow therefore targets a
physical self-hosted Apple Silicon runner. Main-branch pushes run this shipping
gate automatically; reviewed revisions may also be dispatched manually.

The macOS shipping script and installed setup flow use the same operator model:

```sh
glove setup guide
glove setup guide --json
```

The guide makes Apple Containers' VM/storage cost and the platform's nested
kernel capability differences explicit. This is the default macOS shipping
lane, just as the delegated-kernel lane is the default Linux shipping path.

## Contained MCP agent

`glove run` contains an MCP-client agent and exposes only allow-listed tools:

```sh
./build/dev/src/glove run \
  --upstream yams=yams,serve,--quiet \
  --allow yams.mcp.echo \
  -- ./build/dev/src/container/glove_synthetic_agent --mode=client
```

Upstream tool servers are separate host processes and require their own
containment boundary.

## Direct agent

`glove exec` contains an agent without connecting the MCP kernel:

```sh
mkdir -p /tmp/glove-work
./build/dev/src/glove exec \
  --workspace /tmp/glove-work \
  -- /absolute/path/to/agent --version
```

Without `--workspace`, Glove starts in a private empty directory. Linux direct
execution is offline because proxy transport into the isolated network
namespace is not implemented. Use `glove exec --help` for explicit filesystem,
environment, egress, and audit grants.

## Gloved control service

Inspect the platform recommendation, then follow the dedicated host guide:

```sh
./build/dev/src/glove setup guide
```

[`host-setup.md`](host-setup.md) owns machine setup, service activation,
purpose-based project enrollment, and Sage verification.
[`session-policy.md`](session-policy.md) owns the managed-session contract.

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
