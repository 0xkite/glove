#!/usr/bin/env bash
# preflight.sh — gates that must pass before pushing.
#
# Runs:
#   1. actionlint across GitHub Actions workflows
#   2. clang-format --dry-run -Werror across src/ include/ tests/
#   3. clang-tidy on the dev compile_commands.json (if available)
#   4. asan preset: configure, build, ctest
#   5. tsan preset: configure, build, ctest
#
# Exits non-zero on the first failure. Re-run with --skip-tidy to bypass tidy
# locally if it is not installed.

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

skip_tidy=0
for arg in "$@"; do
    case "${arg}" in
        --skip-tidy) skip_tidy=1 ;;
        *) echo "unknown arg: ${arg}" >&2; exit 2 ;;
    esac
done

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }

run_ctest() {
    if [[ "${GLOVE_PRIVILEGED_TESTS:-0}" == "1" ]]; then
        if [[ "$(uname -s)" != "Linux" ]]; then
            fail "GLOVE_PRIVILEGED_TESTS is supported only on Linux"
        fi
        if ! command -v sudo >/dev/null; then
            fail "GLOVE_PRIVILEGED_TESTS requires sudo"
        fi
        sudo --preserve-env=ASAN_OPTIONS,UBSAN_OPTIONS,TSAN_OPTIONS ctest "$@"
        return
    fi
    ctest "$@"
}

# 1. GitHub Actions ---------------------------------------------------------
bold "[1/5] actionlint"
if ! command -v actionlint >/dev/null; then
    fail "actionlint not on PATH"
fi
actionlint
sh -n setup.sh
ok "GitHub Actions workflows clean"

# 2. format -----------------------------------------------------------------
bold "[2/5] clang-format --dry-run"
if ! command -v clang-format >/dev/null; then
    fail "clang-format not on PATH"
fi
fmt_files=()
while IFS= read -r -d '' f; do
    fmt_files+=("${f}")
done < <(find src include tests -type f \( -name '*.cpp' -o -name '*.hpp' \) -print0 2>/dev/null)
if [[ ${#fmt_files[@]} -eq 0 ]]; then
    ok "no source files yet"
else
    clang-format --dry-run -Werror "${fmt_files[@]}"
    ok "format clean (${#fmt_files[@]} files)"
fi

# 3. tidy -------------------------------------------------------------------
bold "[3/5] clang-tidy"
tidy_bin=""
if [[ ${skip_tidy} -eq 1 ]]; then
    echo "  (skipped via --skip-tidy)"
else
    if command -v clang-tidy >/dev/null; then
        tidy_bin="$(command -v clang-tidy)"
    elif command -v brew >/dev/null && [[ -x "$(brew --prefix llvm 2>/dev/null)/bin/clang-tidy" ]]; then
        tidy_bin="$(brew --prefix llvm)/bin/clang-tidy"
    fi

    if [[ -z "${tidy_bin}" ]]; then
        echo "  clang-tidy not installed; skipping (install via 'brew install llvm' for the gate)"
    else
        if [[ ! -f build/dev/compile_commands.json ]]; then
            cmake --preset dev >/dev/null
        fi
        # Ninja's C++ dependency scanner writes module-map response files that
        # appear in compile_commands.json. A fresh checkout must build once
        # before clang-tidy can consume those generated arguments.
        cmake --build --preset dev
        # Apple clang's compile_commands omits -isysroot because the driver
        # implicitly knows the SDK; homebrew clang-tidy doesn't, so tell it.
        tidy_extra=()
        if [[ "$(uname -s)" == "Darwin" ]] && command -v xcrun >/dev/null; then
            sdk="$(xcrun --show-sdk-path)"
            tidy_extra=(-extra-arg-before="-isysroot${sdk}")
        fi
        # Lint only translation units represented by the active CMake compile
        # database. Headers are still analyzed through their owning sources,
        # while platform-specific files absent from this host build are not
        # parsed with an unrelated fallback command.
        tidy_files=()
        while IFS= read -r -d '' f; do
            tidy_files+=("${f}")
        done < <(
            python3 - "${ROOT}" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
database = json.loads((root / "build/dev/compile_commands.json").read_text())
seen = set()
for entry in database:
    source = pathlib.Path(entry["file"])
    if not source.is_absolute():
        source = pathlib.Path(entry["directory"]) / source
    source = source.resolve()
    try:
        source.relative_to(root)
    except ValueError:
        continue
    if source.suffix != ".cpp" or source in seen:
        continue
    seen.add(source)
    sys.stdout.buffer.write(str(source).encode() + b"\0")
PY
        )
        if [[ ${#tidy_files[@]} -eq 0 ]]; then
            fail "compile database contains no project translation units"
        fi
        tidy_runner="$(dirname "${tidy_bin}")/run-clang-tidy"
        if [[ ! -x "${tidy_runner}" ]]; then
            tidy_runner="$(dirname "${tidy_bin}")/run-clang-tidy.py"
        fi
        if [[ ! -x "${tidy_runner}" ]]; then
            fail "run-clang-tidy not installed alongside ${tidy_bin}"
        fi
        # Two workers keep memory bounded on hosted runners while reducing the
        # full Linux translation-unit pass from timeout-scale wall-clock time.
        "${tidy_runner}" -j 2 -quiet -p build/dev -clang-tidy-binary "${tidy_bin}" \
            "${tidy_extra[@]}" "${tidy_files[@]}"
        ok "tidy clean (${tidy_bin})"
    fi
fi

# 4. asan -------------------------------------------------------------------
bold "[4/5] asan preset"
cmake --preset asan
cmake --build --preset asan
asan_opts="halt_on_error=1:abort_on_error=1"
if [[ "$(uname -s)" != "Darwin" ]]; then
    # LSan ships with ASan on Linux but not on Apple platforms.
    asan_opts="${asan_opts}:detect_leaks=1"
fi
ASAN_OPTIONS="${asan_opts}" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
    run_ctest --preset asan
ok "asan ok"

# 5. tsan -------------------------------------------------------------------
bold "[5/5] tsan preset"
cmake --preset tsan
cmake --build --preset tsan
TSAN_OPTIONS="halt_on_error=1:second_deadlock_stack=1" \
    run_ctest --preset tsan
ok "tsan ok"

bold "all gates passed"
