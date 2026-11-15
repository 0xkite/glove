# Building Glove

Building proves that the local source compiles; it does not prove that a host
can enforce managed-session isolation. The boundary and its motivation are in
[architecture.md](architecture.md) and [threat-model.md](threat-model.md).

## Prerequisites

- macOS or Linux, CMake **3.28+**, Ninja, Git, and a C++23 compiler/toolchain;
- Linux: `pkg-config` and `libseccomp` development headers;
- macOS: Xcode Command Line Tools and a compatible Clang toolchain.

On Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install --yes \
  build-essential clang cmake ninja-build git pkg-config libseccomp-dev
```

`yams` is optional and only enables the macOS integration-test surface.

## Build and test

`setup.sh` configures, builds, tests, and installs to
`${GLOVE_INSTALL_PREFIX:-$HOME/.local}`:

```sh
./setup.sh
```

For iteration:

```sh
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

Run the full local gate before review or release:

```sh
./scripts/preflight.sh
```

`GLOVE_PREFLIGHT_BUILD_ROOT` selects an absolute build root for the gate.
It defaults to this checkout's `build` directory; the gate creates separate
`dev`, `asan`, `tsan`, and `fuzz` trees beneath it. Select a separate reviewed
root to preserve an existing build configured with another compiler. Every
stage uses the selected root, with the same presets and checks. Relative or
empty overrides are rejected. Selecting an override requires CTest 3.30 or
newer for preset directory overrides; the default root retains CMake 3.28
compatibility. The gate does not install toolchains; a locally
provisioned formatter can be selected with `GLOVE_CLANG_FORMAT`.

### Sage consumer interoperability

The Sage Rust consumer test is opt-in via `GLOVE_ENABLE_SAGE_INTEROP_TEST` and
requires Cargo plus a local Sage checkout. `GLOVE_SAGE_MANIFEST` is a CMake
`FILEPATH` cache variable: provide the reviewed checkout's existing absolute
Cargo manifest path when configuring. The historical default is
`${CMAKE_SOURCE_DIR}/../sage/Cargo.toml`; that checkout is not bundled with Glove.
Relative paths, missing files, and directories are rejected.

After configuring with interoperability enabled:

```sh
cmake --build --preset dev
ctest --preset dev -R '^sage_receipt_audit_interop$' --output-on-failure
```

Enabling this test does not enable remote launch or change production
capabilities. The existing characterization suite for later Sage refactors is:

| Contract | CTest coverage |
| --- | --- |
| Configuration and Sage guest DTO round-trips | `host_config` |
| Canonical plans and refinement plans | `supervisor_session_plan`, `supervisor_refinement_session_plan` |
| Adapter IDs, schema IDs, runtime IDs, aliases, and transport selectors | `control_sage_guest_channel_adapter` |
| Control capabilities, idempotency, and observation dispositions | `control_receipt_audit_protocol` |
| Observation admission and recovery | `control_session_registry`, `control_observation_intent_unix_server` |
| Receipt chain, paging, acknowledgement, and torn-tail behavior | `container_receipt_chain`, `container_receipt_journal` |
| Real Sage Rust consumer interoperability | `sage_receipt_audit_interop` (opt-in) |

## Controlled-source builds

Glaze is pinned in `cmake/Dependencies.cmake`. For an offline or controlled
build, provide the reviewed source explicitly instead of accepting an unpinned
local checkout:

```sh
cmake --preset release \
  -DFETCHCONTENT_SOURCE_DIR_GLAZE=/absolute/reviewed/glaze-source
cmake --build --preset release
ctest --preset release
```

## Managed Linux sessions

A managed-session host also needs cgroup v2 (`cpu`, `memory`, `pids`), user and
mount namespaces, mount support, seccomp, and systemd delegation. Systemd 254+
is the tested service topology: `DelegateSubgroup=glove-host` keeps the
supervisor in a systemd-owned leaf while Glove owns session siblings under the
empty delegated parent. Those requirements exist because Glove must enforce
resource and filesystem limits, not merely start a process. See [host-setup.md](host-setup.md) for the
owner-local workflow and [session-policy.md](session-policy.md) for the policy
contract.

## Containerized development environment

A fast, cached devcontainer environment is provided via Docker Compose and
`dockerfiles/Dockerfile.dev`. It uses targeted capabilities (`SYS_ADMIN`, `SETUID`,
`SETGID`) with persistent ccache storage instead of monolithic `--privileged` rebuilds:

```sh
# Start interactive dev shell
docker compose run --rm dev

# Inside container:
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

The Docker environment is for development and iteration; it is not production
isolation evidence:

```sh
docker build -f dockerfiles/Dockerfile.linux -t glove-linux .
docker run --rm --privileged --security-opt seccomp=unconfined glove-linux
```
