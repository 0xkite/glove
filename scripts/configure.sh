#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
usage: scripts/configure.sh [preset] [cmake-options...]

Selects a working C++23 toolchain, adding libc++ automatically when the
selected Clang needs it, then configures the requested CMake preset.
The default preset is dev.
EOF
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
esac

preset="${1:-dev}"
if [[ $# -gt 0 ]]; then
    shift
fi

if [[ -z "${CC:-}" && -z "${CXX:-}" ]] && command -v clang++ >/dev/null 2>&1; then
    export CC="${GLOVE_CLANG_C:-$(command -v clang)}"
    export CXX="${GLOVE_CLANG_CXX:-$(command -v clang++)}"
fi

probe_dir="$(mktemp -d "${TMPDIR:-/tmp}/glove-toolchain-probe.XXXXXX")"
cleanup() {
    find "$probe_dir" -mindepth 1 -delete
    rmdir "$probe_dir"
}
trap cleanup EXIT

printf '%s\n' \
    '#include <expected>' \
    'int main() { std::expected<int, int> value{1}; return *value == 1 ? 0 : 1; }' \
    >"$probe_dir/expected.cpp"

compiler="${CXX:-c++}"
if ! "$compiler" -std=c++23 "$probe_dir/expected.cpp" -o "$probe_dir/probe" >/dev/null 2>&1; then
    if [[ "$(basename "$compiler")" == clang++* ]] &&
        "$compiler" -std=c++23 -stdlib=libc++ "$probe_dir/expected.cpp" \
            -o "$probe_dir/probe" >/dev/null 2>&1
    then
        export CXXFLAGS="${CXXFLAGS:+${CXXFLAGS} }-stdlib=libc++"
        export LDFLAGS="${LDFLAGS:+${LDFLAGS} }-stdlib=libc++"
    else
        printf '%s\n' \
            "No supported C++23 std::expected toolchain was found." \
            "Install Clang plus libc++ (recommended), or provide CC/CXX/CXXFLAGS explicitly." >&2
        exit 1
    fi
fi

cmake --preset "$preset" "$@"
