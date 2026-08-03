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
mount namespaces, mount support, seccomp, and systemd delegation. Those
requirements exist because Glove must enforce resource and filesystem limits,
not merely start a process. See [host-setup.md](host-setup.md) for the
owner-local workflow and [session-policy.md](session-policy.md) for the policy
contract.

The privileged Docker command is only a test environment; it is not production
isolation evidence:

```sh
docker build -f dockerfiles/Dockerfile.linux -t glove-linux .
docker run --rm --privileged --security-opt seccomp=unconfined glove-linux
```
