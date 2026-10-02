#!/usr/bin/env bash
# preflight.sh — gates that must pass before pushing.
#
# Runs:
#   1. actionlint across GitHub Actions workflows
#   2. clang-format --dry-run -Werror across src/ include/ tests/ benchmarks/ fuzz/
#   3. clang-tidy over the dev compilation database
#   4. asan preset: configure, build, ctest
#   5. tsan preset: configure, build, ctest
#
# Tool versions: actionlint and clang-tidy must be at or above their minimum.
# clang-format must match the tree's formatted-for version exactly, because
# formatter output is only stable per version. Override a binary with
# GLOVE_ACTIONLINT, GLOVE_CLANG_FORMAT, or GLOVE_CLANG_TIDY. The sanitizer
# presets select clang unless CC/CXX are already set, so a rolling distribution
# whose default compiler is GCC still runs the validated toolchain.
#
# Exits non-zero on the first failure. Stages may be skipped only explicitly:
# --skip-tidy bypasses clang-tidy (a missing clang-tidy is otherwise fatal), and
# GLOVE_ALLOW_NO_LSAN=1 runs ASan/UBSan without leak detection on a host whose
# yama ptrace_scope blocks ptrace. The final banner names any skipped stage.

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

skip_tidy=0
# Two different policies, for two different kinds of tool:
#
#   * clang-format is a *formatter*. Its output is only stable for one exact
#     version — 22.1.8 and 23.1.1 disagree on this tree — so the check requires
#     exactly `formatted_for_clang_format`, which CI also pins. A newer local
#     version can run with GLOVE_ALLOW_NEWER_CLANG_FORMAT=1, but its format
#     result is not authoritative. Bumping this value and the reformat belong in
#     one PR.
#   * Everything else runs on whatever the host provides, at or above a minimum.
#
# Override a binary with GLOVE_ACTIONLINT / GLOVE_CLANG_FORMAT / GLOVE_CLANG_TIDY.
formatted_for_clang_format="23.1.1"
min_actionlint_version="1.7.12"
for arg in "$@"; do
    case "${arg}" in
        --skip-tidy) skip_tidy=1 ;;
        *) echo "unknown arg: ${arg}" >&2; exit 2 ;;
    esac
done

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }

# True when $1 >= $2 for dotted numeric versions such as 23.1.1 vs 22.1.8.
version_ge() {
    local have="$1" want="$2"
    [[ "${have}" == "${want}" ]] && return 0
    local -a h w
    IFS='.' read -r -a h <<<"${have}"
    IFS='.' read -r -a w <<<"${want}"
    local i
    for ((i = 0; i < ${#w[@]} || i < ${#h[@]}; i++)); do
        local a="${h[i]:-0}" b="${w[i]:-0}"
        [[ "${a}" =~ ^[0-9]+$ ]] || a=0
        [[ "${b}" =~ ^[0-9]+$ ]] || b=0
        if ((10#${a} > 10#${b})); then return 0; fi
        if ((10#${a} < 10#${b})); then return 1; fi
    done
    return 0
}

# Resolve a tool from an explicit override, then PATH. Prints the path or
# nothing. Callers decide whether absence is fatal.
resolve_tool() {
    local override="$1" name="$2"
    if [[ -n "${override}" ]]; then
        if [[ ! -x "${override}" ]]; then
            fail "${name} override is not executable: ${override}"
        fi
        printf '%s\n' "${override}"
        return
    fi
    command -v "${name}" 2>/dev/null || true
}

# First word of a possibly launcher-wrapped command, e.g. "ccache clang++".
first_word() { printf '%s\n' "${1%% *}"; }

# Select the compiler the presets and sanitizer builds were validated against.
# The repository requires C++23 with a consistent warning set; the default
# system compiler on rolling distributions is not always clang, and a
# GCC-configured tree emits module flags that clang-tidy rejects.
select_compiler() {
    # Fill CC and CXX together or not at all: clang beside g++ (or the reverse)
    # mixes toolchains in one build. A half-set pair is almost certainly a
    # mistake, and CMake would silently fill the gap with its default.
    if [[ -n "${CC:-}" && -z "${CXX:-}" ]] || [[ -z "${CC:-}" && -n "${CXX:-}" ]]; then
        fail "set both CC and CXX, or neither (CC=${CC:-unset} CXX=${CXX:-unset})"
    fi
    if [[ -z "${CC:-}" && -z "${CXX:-}" ]]; then
        if command -v clang >/dev/null && command -v clang++ >/dev/null; then
            export CC=clang CXX=clang++
            echo "  compiler: none set; selecting clang/clang++"
        fi
    fi

    local cxx_bin cc_bin
    # A launcher wrapper (CXX="ccache clang++") cannot be resolved or compared
    # meaningfully here, and CMake treats it as the compiler rather than a
    # launcher. Point the operator at the supported mechanism instead.
    if [[ "${CC:-}" == *" "* || "${CXX:-}" == *" "* ]]; then
        fail "CC/CXX must name a single compiler, not a launcher (CC='${CC:-}' CXX='${CXX:-}'). Use -DCMAKE_CXX_COMPILER_LAUNCHER=... instead."
    fi
    cc_bin="$(first_word "${CC:-}")"
    cxx_bin="$(first_word "${CXX:-}")"
    if [[ -n "${cc_bin}" ]] && ! command -v "${cc_bin}" >/dev/null; then
        fail "selected C compiler is not on PATH: ${CC}"
    fi
    if [[ -n "${cxx_bin}" ]] && ! command -v "${cxx_bin}" >/dev/null; then
        fail "selected C++ compiler is not on PATH: ${CXX}"
    fi
    if [[ -n "${cxx_bin}" ]]; then
        printf '  compiler: %s\n' "$("${cxx_bin}" --version 2>/dev/null | head -1)"
    fi

    # CMake reads CC/CXX only on a tree's first configure, so an existing build
    # directory keeps whatever compiler it was created with. That silently
    # reproduces the stale-toolchain failures this selection exists to prevent,
    # so refuse to run against a tree built by a different compiler.
    [[ -n "${cxx_bin}" ]] || return 0
    local resolved
    resolved="$(command -v "${cxx_bin}")"
    local cache
    for cache in build/dev/CMakeCache.txt build/asan/CMakeCache.txt build/tsan/CMakeCache.txt; do
        [[ -f "${cache}" ]] || continue
        local cached
        cached="$(sed -n 's/^CMAKE_CXX_COMPILER:[^=]*=//p' "${cache}" | head -1)"
        [[ -n "${cached}" ]] || continue
        local cached_real resolved_real
        cached_real="$(readlink -f "${cached}" 2>/dev/null || printf '%s' "${cached}")"
        resolved_real="$(readlink -f "${resolved}" 2>/dev/null || printf '%s' "${resolved}")"
        if [[ "${cached_real}" != "${resolved_real}" ]]; then
            fail "${cache} was configured with ${cached}, but CXX is ${resolved}. Remove that build tree (rm -rf ${cache%/CMakeCache.txt}) and re-run."
        fi
    done
}

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
        local formula=""
        local prefix=""
        # LLVM 19+ can emit libFuzzer Mach-O relocations rejected by Apple's
        # linker. Prefer the CI-pinned compatible toolchain when available.
        for formula in llvm@18 llvm; do
            if ! prefix="$(brew --prefix "${formula}" 2>/dev/null)"; then
                continue
            fi
            candidate="${prefix}/bin/clang++"
            if [[ -x "${candidate}" ]]; then
                printf '%s\n' "${candidate}"
                return
            fi
        done
    fi
    for candidate in clang++-26 clang++-25 clang++-24 clang++-23 clang++-22 clang++-21 \
                     clang++-20 clang++-19 clang++-18 clang++; do
        if command -v "${candidate}" >/dev/null; then
            command -v "${candidate}"
            return
        fi
    done
    fail "a Clang compiler with libFuzzer support is required"
}

# Select the toolchain before any CMake preset is configured. The clang-tidy
# stage configures the dev preset, and a GCC-configured database emits module
# flags (-fmodules-ts) that clang-tidy rejects, so this must happen first.
select_compiler

# 1. GitHub Actions ---------------------------------------------------------
bold "[1/5] actionlint"
actionlint_bin="$(resolve_tool "${GLOVE_ACTIONLINT:-}" actionlint)"
if [[ -z "${actionlint_bin}" ]]; then
    fail "actionlint not on PATH (set GLOVE_ACTIONLINT to an explicit binary)"
fi
actionlint_version="$("${actionlint_bin}" -version | sed -n '1{s/^v//;p;}')"
if ! version_ge "${actionlint_version}" "${min_actionlint_version}"; then
    fail "actionlint >= ${min_actionlint_version} required; found ${actionlint_version}"
fi
"${actionlint_bin}"
sh -n setup.sh
ok "GitHub Actions workflows clean (actionlint ${actionlint_version})"

# 2. format -----------------------------------------------------------------
bold "[2/5] clang-format --dry-run"
clang_format_bin="$(resolve_tool "${GLOVE_CLANG_FORMAT:-}" clang-format)"
if [[ -z "${clang_format_bin}" ]]; then
    fail "clang-format not on PATH (set GLOVE_CLANG_FORMAT to an explicit binary)"
fi
clang_format_version="$("${clang_format_bin}" --version | sed -n 's/.*version \([0-9][0-9.]*\).*/\1/p')"
if [[ "${clang_format_version}" != "${formatted_for_clang_format}" ]]; then
    if version_ge "${clang_format_version}" "${formatted_for_clang_format}" &&
        [[ "${GLOVE_ALLOW_NEWER_CLANG_FORMAT:-0}" == "1" ]]; then
        echo "  ⚠ clang-format ${clang_format_version} is newer than the formatted-for ${formatted_for_clang_format}."
        echo "    Formatter output can differ between versions; this run's format result is NOT authoritative."
    else
        fail "clang-format ${formatted_for_clang_format} required; found ${clang_format_version:-unknown}. A different version may format this tree differently. Set GLOVE_ALLOW_NEWER_CLANG_FORMAT=1 to proceed with a newer version anyway."
    fi
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
    "${clang_format_bin}" --dry-run -Werror "${fmt_files[@]}"
    ok "format clean (${#fmt_files[@]} files, clang-format ${clang_format_version})"
fi

# 3. tidy -------------------------------------------------------------------
bold "[3/5] clang-tidy"
tidy_bin=""
if [[ ${skip_tidy} -eq 1 ]]; then
    echo "  (skipped via --skip-tidy)"
else
    if [[ -n "${GLOVE_CLANG_TIDY:-}" ]]; then
        tidy_bin="$(resolve_tool "${GLOVE_CLANG_TIDY}" clang-tidy)"
    elif command -v clang-tidy >/dev/null; then
        tidy_bin="$(command -v clang-tidy)"
    elif command -v brew >/dev/null && [[ -x "$(brew --prefix llvm 2>/dev/null)/bin/clang-tidy" ]]; then
        tidy_bin="$(brew --prefix llvm)/bin/clang-tidy"
    fi

    if [[ -z "${tidy_bin}" ]]; then
        # clang-tidy is a required stage. Silently skipping it would let the
        # script end with "all gates passed" while one gate never ran, so make
        # the operator opt out explicitly with --skip-tidy.
        fail "clang-tidy not found; install it, set GLOVE_CLANG_TIDY, or pass --skip-tidy"
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
# Resolve the sanitizer options before building, so a host that cannot provide
# leak evidence fails fast instead of after a full instrumented build.
asan_opts="halt_on_error=1:abort_on_error=1"
lsan_skipped=0
if [[ "$(uname -s)" != "Darwin" ]]; then
    # LSan ships with ASan on Linux but not on Apple platforms, and it needs
    # ptrace. yama ptrace_scope 0 and 1 both work: LSan grants its own tracer
    # thread permission through PR_SET_PTRACER. Scopes 2 and 3 do not, and every
    # instrumented binary then fails at exit instead of reporting a leak.
    #
    # This gate fails closed: a host that cannot produce leak evidence fails the
    # run unless the operator explicitly accepts the gap with
    # GLOVE_ALLOW_NO_LSAN=1. Requiring an opt-in to *strictness* would let the
    # gate pass with silently missing evidence.
    ptrace_scope="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 0)"
    # A non-numeric value would compare as 0 and fail open; require digits.
    if [[ ! "${ptrace_scope}" =~ ^[0-9]+$ ]]; then
        fail "unexpected /proc/sys/kernel/yama/ptrace_scope value: '${ptrace_scope}'"
    fi
    if [[ "${ptrace_scope}" -lt 2 ]]; then
        asan_opts="${asan_opts}:detect_leaks=1"
    elif [[ "${GLOVE_ALLOW_NO_LSAN:-0}" == "1" ]]; then
        lsan_skipped=1
        # Omission is not enough: ASan defaults detect_leaks=1 on Linux, so it
        # must be turned off explicitly.
        asan_opts="${asan_opts}:detect_leaks=0"
        echo "  ⚠ LeakSanitizer disabled by GLOVE_ALLOW_NO_LSAN=1: yama ptrace_scope=${ptrace_scope} blocks ptrace."
        echo "    This run collects NO leak evidence. Do not treat it as an ASan leak pass."
    else
        fail "LeakSanitizer cannot run: yama ptrace_scope=${ptrace_scope} blocks ptrace. Set GLOVE_ALLOW_NO_LSAN=1 to run ASan/UBSan without leak detection, or fix the host sysctl."
    fi
fi
cmake --preset asan -DGLOVE_BUILD_FUZZERS=OFF
cmake --build --preset asan
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
apple_stats_fuzz_corpus="${fuzz_workspace}/apple_container_stats"
cp -R fuzz/corpus/apple_container_stats "${apple_stats_fuzz_corpus}"
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
# The Apple container-stats parser fuzzer is only built on platforms with that
# runtime (macOS); run it when present so the target stops being built-but-idle.
if [[ -x build/fuzz/fuzz/glove_apple_container_stats_fuzzer ]]; then
    ASAN_OPTIONS="${asan_opts}" \
    UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
        build/fuzz/fuzz/glove_apple_container_stats_fuzzer \
            -runs=10000 -max_len=65536 -timeout=5 -rss_limit_mb=2048 -verbosity=0 \
            -artifact_prefix="${apple_stats_fuzz_corpus}/" \
            "${apple_stats_fuzz_corpus}"
fi
if [[ "${lsan_skipped}" == "1" ]]; then
    ok "asan ok (leak detection NOT collected: ptrace restricted)"
else
    ok "asan ok"
fi

# 5. tsan -------------------------------------------------------------------
bold "[5/5] tsan preset"
cmake --preset tsan -DGLOVE_BUILD_FUZZERS=OFF
cmake --build --preset tsan
# Some kernels ship vm.mmap_rnd_bits=32, which makes TSan abort at startup with
# "unexpected memory mapping". Disabling ASLR for the test process keeps the
# sanitizer usable without touching a host sysctl. This does not weaken the
# check: TSan still runs with the same options and the full suite.
tsan_runner=()
if [[ "$(uname -s)" == "Linux" ]] && command -v setarch >/dev/null; then
    tsan_runner=(setarch -R)
fi
TSAN_OPTIONS="halt_on_error=1:second_deadlock_stack=1" \
    "${tsan_runner[@]}" ctest --preset tsan
ok "tsan ok"

if [[ "${skip_tidy}" == "1" || "${lsan_skipped}" == "1" ]]; then
    bold "gates passed with a skipped stage"
    if [[ "${skip_tidy}" == "1" ]]; then
        echo "  ⚠ clang-tidy was skipped; this run is not evidence that tidy is clean."
    fi
    if [[ "${lsan_skipped}" == "1" ]]; then
        echo "  ⚠ LeakSanitizer was skipped; this run is not evidence of leak-freedom."
    fi
else
    bold "all gates passed"
fi
