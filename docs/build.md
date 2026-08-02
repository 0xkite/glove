# Building Glove

## Supported build hosts

Glove builds on macOS and Linux. Linux is required for the managed-session
runtime and its cgroup, namespace, mount, and seccomp integration tests.

## Required tools

Every build host needs:

- CMake **3.28+**;
- Ninja;
- Git, because CMake FetchContent retrieves the pinned Glaze source unless an
  operator provides it locally;
- a C++23-capable compiler and standard library. `setup.sh` selects `clang` and
  `clang++` by default, but honors operator-supplied `CC`, `CXX`, and
  `CXXFLAGS`;
- a working linker and standard C/C++ runtime headers.

Linux additionally needs:

- `pkg-config`;
- the `libseccomp` development package (headers and pkg-config metadata).

`yams` is only needed for the macOS integration-test surface, not for a normal
Linux build.

## Debian/Ubuntu example

Install the distribution packages before configuring. The exact CMake and
compiler package versions must meet the requirements above; use a supported
repository/toolchain when the distribution's defaults are older.

```sh
sudo apt-get update
sudo apt-get install --yes \
  build-essential clang cmake ninja-build git pkg-config libseccomp-dev
```

Confirm the Linux-specific dependency before a full configure:

```sh
pkg-config --modversion libseccomp
cmake --version
clang++ --version
ninja --version
```

## macOS example

Install CMake, Ninja, Git, and a compatible Clang toolchain using the
operator's approved package manager. Do not install Linux `libseccomp` on
macOS: the Apple sandbox implementation does not link it.

## Offline or controlled-source builds

Glaze is pinned in `cmake/Dependencies.cmake`. On a build host without approved
network access, stage a reviewed Glaze source tree first and point CMake at it:

```sh
cmake --preset release \
  -DFETCHCONTENT_SOURCE_DIR_GLAZE=/absolute/reviewed/glaze-source
cmake --build --preset release
ctest --preset release
```

The directory must contain the exact reviewed Glaze source corresponding to the
repository pin. Do not silently fall back to an unpinned local checkout.

If `libseccomp-dev` cannot be installed system-wide, extract a reviewed,
version-pinned Debian development package into an owner-controlled prefix. Set
all three variables so both CMake's pkg-config probe and the final static-library
link resolve that prefix:

```sh
export GLOVE_SECCOMP_PREFIX=/absolute/glove-owned/libseccomp-root
export PKG_CONFIG_PATH="$GLOVE_SECCOMP_PREFIX/usr/lib/x86_64-linux-gnu/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$GLOVE_SECCOMP_PREFIX"
export LIBRARY_PATH="$GLOVE_SECCOMP_PREFIX/usr/lib/x86_64-linux-gnu"
```

Record the package version and SHA-256 with the validation evidence. The prefix
is a build input, not a sandbox mount or agent-visible dependency.

## Build and test

`setup.sh` configures, builds, tests, and installs to
`${GLOVE_INSTALL_PREFIX:-$HOME/.local}`:

```sh
./setup.sh
```

For iterative work:

```sh
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

For Linux isolation tests, the provided container requires the privilege shown
below; this is a test environment only, not a production isolation claim:

```sh
docker build -f dockerfiles/Dockerfile.linux -t glove-linux .
docker run --rm --privileged --security-opt seccomp=unconfined glove-linux
```

## Linux managed-session host prerequisites

Building is distinct from running `gloved` managed sessions. A launch host
must also provide cgroup v2 with `cpu`, `memory`, and `pids` controllers, Linux
namespaces, mount support, and seccomp. Run the daemon inside a systemd scope
or service delegated with `Delegate=yes`; a normal user login cgroup is not
writable enough for Glove to create bounded child cgroups. If the account lacks
`CAP_SYS_ADMIN` in the initial namespace, start the disposable validation daemon
inside a private user and mount namespace as well:

```sh
systemd-run --user --unit=glove-validation --collect --property=Delegate=yes \
  unshare --user --map-root-user --mount --propagation private \
  /absolute/path/to/gloved --config /absolute/owner-only-config.json
```

This is a Linux launch-host prerequisite, not a claim that a QEMU VM is in use.
