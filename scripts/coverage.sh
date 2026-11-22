#!/usr/bin/env bash
# coverage.sh — measure which source regions the CTest suite executes.
#
#   scripts/coverage.sh [ctest-args...]
#
# Builds the `coverage` preset (Clang source-based coverage), runs CTest, and
# writes to build/coverage/report/:
#
#   summary.txt   totals and one line per source file
#   lcov.info     the same data in lcov format
#
# Only src/ and include/ are reported. Extra arguments go to ctest, for
# example `scripts/coverage.sh -R '^container_'`.
#
# Limits of the number:
#   * It counts executed regions, not checked behavior.
#   * A process that is killed, or that a sandbox stops from writing its
#     profile, contributes nothing; contained agents are mostly in that group.
#   * Platform code for the other operating system is not compiled and does
#     not appear, so a Linux figure and a macOS figure are not comparable.
#   * Tests that are skipped on this host lower the figure.

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

fail() {
    printf 'coverage.sh: %s\n' "$*" >&2
    exit 1
}

if [[ -z "${CC:-}" && -z "${CXX:-}" ]]; then
    export CC=clang CXX=clang++
fi
command -v "${CXX}" >/dev/null || fail "compiler not found: ${CXX}"

# The profile tools must match the compiler that wrote the profiles.
find_tool() {
    local name="$1" path
    path="$("${CXX}" -print-prog-name="${name}" 2>/dev/null || true)"
    if [[ -n "${path}" && "${path}" != "${name}" && -x "${path}" ]]; then
        printf '%s\n' "${path}"
    elif [[ "$(uname -s)" == "Darwin" ]] && path="$(xcrun --find "${name}" 2>/dev/null)"; then
        printf '%s\n' "${path}"
    elif command -v "${name}" >/dev/null; then
        command -v "${name}"
    else
        fail "${name} not found for ${CXX}"
    fi
}
profdata_bin="$(find_tool llvm-profdata)"
cov_bin="$(find_tool llvm-cov)"

build="${ROOT}/build/coverage"
report="${build}/report"
profiles="${build}/profiles"

cmake --preset coverage
cmake --build --preset coverage

rm -rf -- "${profiles}" "${report}"
mkdir -p "${profiles}" "${report}"

# %p and %m keep concurrent processes and different binaries apart.
ctest_status=0
LLVM_PROFILE_FILE="${profiles}/%p-%m.profraw" \
    ctest --preset coverage "$@" </dev/null || ctest_status=$?

shopt -s nullglob
raw=("${profiles}"/*.profraw)
shopt -u nullglob
[[ ${#raw[@]} -gt 0 ]] || fail "no profiles were written"
# A process killed while writing leaves a truncated profile. Leave those out
# and say how many, rather than lose the whole report.
"${profdata_bin}" merge --sparse --failure-mode=all \
    --output "${report}/merged.profdata" "${raw[@]}" 2>"${report}/merge.log" ||
    fail "no usable profiles; see ${report}/merge.log"
rejected="$(grep -c '^warning: .*\.profraw' "${report}/merge.log" || true)"

# Every instrumented executable the build produced.
objects=()
while IFS= read -r -d '' binary; do
    objects+=(--object "${binary}")
done < <(find "${build}/src" "${build}/tests" -type f -perm -u+x \
    ! -path '*/CMakeFiles/*' ! -name '*.*' -print0 | sort -z)
[[ ${#objects[@]} -gt 0 ]] || fail "no executables found under ${build}"
# llvm-cov takes the first binary positionally and the rest as --object.
first="${objects[1]}"
rest=("${objects[@]:2}")

common=(--instr-profile "${report}/merged.profdata"
    --ignore-filename-regex "^${ROOT}/(tests|benchmarks|fuzz|build)/")
"${cov_bin}" report "${first}" "${rest[@]}" "${common[@]}" >"${report}/summary.txt"
"${cov_bin}" export --format lcov "${first}" "${rest[@]}" "${common[@]}" >"${report}/lcov.info"

printf '\n'
tail -n 1 "${report}/summary.txt"
printf 'report: %s\n' "${report}/summary.txt"
printf 'profiles: %d merged, %d unreadable and left out\n' \
    "$((${#raw[@]} - rejected))" "${rejected}"
if [[ ${ctest_status} -ne 0 ]]; then
    fail "ctest failed (status ${ctest_status}); the figure above excludes what did not run"
fi
