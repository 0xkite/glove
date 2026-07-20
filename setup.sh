#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$script_dir"

usage() {
    printf '%s\n' "usage: ./setup.sh [Debug|Release]" >&2
    printf '%s\n' "       GLOVE_INSTALL_PREFIX=/absolute/prefix ./setup.sh [Debug|Release]" >&2
}

build_type=${1:-Release}
if [ "$#" -gt 1 ]; then
    usage
    exit 2
fi

case "$build_type" in
    Debug)
        preset=dev
        ;;
    Release)
        preset=release
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage
        exit 2
        ;;
esac

case "$(uname -s)" in
    Darwin|Linux)
        ;;
    *)
        printf '%s\n' "setup.sh supports macOS and Linux only" >&2
        exit 1
        ;;
esac

for command_name in cmake ninja; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'missing required command: %s\n' "$command_name" >&2
        exit 1
    fi
done

if [ -z "${CC:-}" ]; then
    CC=clang
    export CC
fi
if [ -z "${CXX:-}" ]; then
    CXX=clang++
    export CXX
fi
for compiler in "$CC" "$CXX"; do
    if ! command -v "$compiler" >/dev/null 2>&1; then
        printf 'missing required compiler: %s\n' "$compiler" >&2
        exit 1
    fi
done

if [ -z "${GLOVE_INSTALL_PREFIX:-}" ] && [ -z "${HOME:-}" ]; then
    printf '%s\n' "HOME or GLOVE_INSTALL_PREFIX is required" >&2
    exit 1
fi
install_prefix=${GLOVE_INSTALL_PREFIX:-${HOME}/.local}
case "$install_prefix" in
    /*)
        ;;
    *)
        printf '%s\n' "GLOVE_INSTALL_PREFIX must be an absolute path" >&2
        exit 2
        ;;
esac

printf 'Configuring Glove (%s)...\n' "$build_type"
cmake --preset "$preset"
cmake --build --preset "$preset"
ctest --preset "$preset"
cmake --install "build/$preset" --prefix "$install_prefix"

printf '\nInstalled Glove to %s\n' "$install_prefix"
printf '%s\n' "Next:"
printf '  %s/bin/glove setup --dry-run\n' "$install_prefix"
printf '  %s/bin/glove setup --yes\n' "$install_prefix"
printf '  %s/bin/glove daemon start\n' "$install_prefix"
printf '  %s/bin/glove doctor\n' "$install_prefix"
