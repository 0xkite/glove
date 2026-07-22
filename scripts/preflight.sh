#!/usr/bin/env bash
# preflight.sh — gates that must pass before pushing.
#
# Runs:
#   1. actionlint across GitHub Actions workflows
#   2. clang-format --dry-run -Werror across src/ include/ tests/ benchmarks/ fuzz/
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
required_actionlint_version="1.7.12"
required_clang_format_version="22.1.8"
for arg in "$@"; do
    case "${arg}" in
        --skip-tidy) skip_tidy=1 ;;
        *) echo "unknown arg: ${arg}" >&2; exit 2 ;;
    esac
done

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }

prepare_linux_userns_tests() {
    if [[ "${GLOVE_PREPARE_LINUX_USERNS:-0}" == "1" ]]; then
        if [[ "$(uname -s)" != "Linux" ]]; then
            fail "GLOVE_PREPARE_LINUX_USERNS is supported only on Linux"
        fi
        if ! command -v sudo >/dev/null; then
            fail "GLOVE_PREPARE_LINUX_USERNS requires sudo"
        fi
        if [[ ! -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]]; then
            fail "AppArmor unprivileged-userns control is unavailable"
        fi
        sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
    fi
}

find_fuzzer_compiler() {
    local candidate=""
    if [[ "$(uname -s)" == "Darwin" ]] && command -v brew >/dev/null; then
        candidate="$(brew --prefix llvm 2>/dev/null)/bin/clang++"
        if [[ -x "${candidate}" ]]; then
            printf '%s\n' "${candidate}"
            return
        fi
    fi
    for candidate in clang++-22 clang++-21 clang++-20 clang++-19 clang++-18 clang++; do
        if command -v "${candidate}" >/dev/null; then
            command -v "${candidate}"
            return
        fi
    done
    fail "a Clang compiler with libFuzzer support is required"
}

# 1. GitHub Actions ---------------------------------------------------------
bold "[1/5] actionlint"
if ! command -v actionlint >/dev/null; then
    fail "actionlint not on PATH"
fi
actionlint_version="$(actionlint -version | sed -n '1p')"
if [[ "${actionlint_version}" != "${required_actionlint_version}" ]]; then
    fail "actionlint ${required_actionlint_version} required; found ${actionlint_version}"
fi
actionlint
sh -n setup.sh
ok "GitHub Actions workflows clean"

# 2. format -----------------------------------------------------------------
bold "[2/5] clang-format --dry-run"
if ! command -v clang-format >/dev/null; then
    fail "clang-format not on PATH"
fi
clang_format_version="$(clang-format --version)"
if [[ "${clang_format_version}" != *"version ${required_clang_format_version}"* ]]; then
    fail "clang-format ${required_clang_format_version} required; found ${clang_format_version}"
fi
fmt_files=()
while IFS= read -r -d '' f; do
    fmt_files+=("${f}")
done < <(
    find src include tests benchmarks fuzz -type f \( -name '*.cpp' -o -name '*.hpp' \) -print0 \
        2>/dev/null
)
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
        # Benchmarks are opt-in for ordinary builds, but their source remains
        # part of the style gate and must appear in the compilation database.
        cmake --preset dev -DGLOVE_BUILD_BENCHMARKS=ON -DGLOVE_BUILD_FUZZERS=OFF >/dev/null
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
prepare_linux_userns_tests
cmake --preset asan -DGLOVE_BUILD_FUZZERS=OFF
cmake --build --preset asan
asan_opts="halt_on_error=1:abort_on_error=1"
if [[ "$(uname -s)" != "Darwin" ]]; then
    # LSan ships with ASan on Linux but not on Apple platforms.
    asan_opts="${asan_opts}:detect_leaks=1"
fi
ASAN_OPTIONS="${asan_opts}" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
    ctest --preset asan
fuzzer_cxx="$(find_fuzzer_compiler)"
fuzzer_symbolizer="$(dirname "${fuzzer_cxx}")/llvm-symbolizer"
if [[ -x "${fuzzer_symbolizer}" ]]; then
    export ASAN_SYMBOLIZER_PATH="${fuzzer_symbolizer}"
fi
cmake --preset fuzz \
    -DCMAKE_CXX_COMPILER="${fuzzer_cxx}" \
    -DFETCHCONTENT_SOURCE_DIR_GLAZE="${ROOT}/build/dev/_deps/glaze-src"
cmake --build --preset fuzz
fuzz_workspace="$(mktemp -d "${TMPDIR:-/tmp}/glove-fuzz-corpora.XXXXXX")"
trap 'rm -rf -- "${fuzz_workspace}"' EXIT
mcp_fuzz_corpus="${fuzz_workspace}/mcp_codec"
policy_fuzz_corpus="${fuzz_workspace}/policy_jsonpath"
manifest_fuzz_corpus="${fuzz_workspace}/change_manifest"
session_plan_fuzz_corpus="${fuzz_workspace}/session_plan"
journal_fuzz_corpus="${fuzz_workspace}/change_apply_journal"
bundle_fuzz_corpus="${fuzz_workspace}/library_bundle"
cp -R fuzz/corpus/mcp_codec "${mcp_fuzz_corpus}"
cp -R fuzz/corpus/policy_jsonpath "${policy_fuzz_corpus}"
cp -R fuzz/corpus/change_manifest "${manifest_fuzz_corpus}"
cp -R fuzz/corpus/session_plan "${session_plan_fuzz_corpus}"
cp -R fuzz/corpus/change_apply_journal "${journal_fuzz_corpus}"
cp -R fuzz/corpus/library_bundle "${bundle_fuzz_corpus}"
ASAN_OPTIONS="${asan_opts}" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
    build/fuzz/fuzz/glove_mcp_codec_fuzzer \
        -runs=10000 -max_len=65536 -timeout=5 -rss_limit_mb=2048 -verbosity=0 \
        -artifact_prefix="${mcp_fuzz_corpus}/" \
        "${mcp_fuzz_corpus}"
ASAN_OPTIONS="${asan_opts}" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
    build/fuzz/fuzz/glove_policy_jsonpath_fuzzer \
        -runs=10000 -max_len=65536 -timeout=5 -rss_limit_mb=2048 -verbosity=0 \
        -artifact_prefix="${policy_fuzz_corpus}/" \
        "${policy_fuzz_corpus}"
ASAN_OPTIONS="${asan_opts}" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
    build/fuzz/fuzz/glove_change_manifest_fuzzer \
        -runs=10000 -max_len=65536 -timeout=5 -rss_limit_mb=2048 -verbosity=0 \
        -artifact_prefix="${manifest_fuzz_corpus}/" \
        "${manifest_fuzz_corpus}"
ASAN_OPTIONS="${asan_opts}" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
    build/fuzz/fuzz/glove_session_plan_fuzzer \
        -runs=10000 -max_len=65536 -timeout=5 -rss_limit_mb=2048 -verbosity=0 \
        -artifact_prefix="${session_plan_fuzz_corpus}/" \
        "${session_plan_fuzz_corpus}"
ASAN_OPTIONS="${asan_opts}" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
    build/fuzz/fuzz/glove_change_apply_journal_fuzzer \
        -runs=10000 -max_len=65536 -timeout=5 -rss_limit_mb=2048 -verbosity=0 \
        -artifact_prefix="${journal_fuzz_corpus}/" \
        "${journal_fuzz_corpus}"
ASAN_OPTIONS="${asan_opts}" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
    build/fuzz/fuzz/glove_library_bundle_fuzzer \
        -runs=10000 -max_len=65536 -timeout=5 -rss_limit_mb=2048 -verbosity=0 \
        -artifact_prefix="${bundle_fuzz_corpus}/" \
        "${bundle_fuzz_corpus}"
ok "asan ok"

# 5. tsan -------------------------------------------------------------------
bold "[5/5] tsan preset"
cmake --preset tsan -DGLOVE_BUILD_FUZZERS=OFF
cmake --build --preset tsan
TSAN_OPTIONS="halt_on_error=1:second_deadlock_stack=1" \
    ctest --preset tsan
ok "tsan ok"

bold "all gates passed"
