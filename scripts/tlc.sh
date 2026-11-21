#!/usr/bin/env bash
# tlc.sh — model-check the TLA+ specifications under formal/.
#
#   GLOVE_TLA2TOOLS_JAR=/path/to/tla2tools.jar scripts/tlc.sh
#
# For every formal/<Module>.cfg, TLC must find no error. For every
# formal/<Module>.unfixed.cfg, TLC must report an invariant violation: those
# configurations describe the design before a fix, and a model that cannot
# see the defect it was written for proves nothing.
#
# Needs Java 11 or newer and tla2tools.jar (github.com/tlaplus/tlaplus
# releases). This script does not download anything.

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
    printf 'tlc.sh: %s\n' "$*" >&2
    exit 1
}

jar="${GLOVE_TLA2TOOLS_JAR:-}"
[[ -n "${jar}" ]] || fail "set GLOVE_TLA2TOOLS_JAR to tla2tools.jar"
[[ -f "${jar}" ]] || fail "not a file: ${jar}"
command -v java >/dev/null || fail "java not found"

work="$(mktemp -d "${TMPDIR:-/tmp}/glove-tlc.XXXXXX")"
trap 'rm -rf -- "${work}"' EXIT

run_tlc() {
    local config="$1" module="$2" log="$3"
    (cd "${ROOT}/formal" && java -XX:+UseParallelGC -cp "${jar}" tlc2.TLC \
        -workers auto -metadir "${work}/$(basename "${config}")" \
        -config "${config}" "${module}.tla") >"${log}" 2>&1
}

shopt -s nullglob
configs=("${ROOT}"/formal/*.cfg)
shopt -u nullglob
[[ ${#configs[@]} -gt 0 ]] || fail "no models under formal/"

for config in "${configs[@]}"; do
    name="$(basename "${config}")"
    module="${name%%.*}"
    log="${work}/${name}.log"
    status=0
    run_tlc "${name}" "${module}" "${log}" || status=$?
    if [[ "${name}" == *.unfixed.cfg ]]; then
        if grep -q '^Error: Invariant .* is violated' "${log}"; then
            printf 'ok    %s (violation found, as required: %s)\n' "${name}" \
                "$(grep -m1 -o 'Invariant [A-Za-z]*' "${log}")"
        else
            cat "${log}" >&2
            fail "${name}: expected an invariant violation, TLC found none"
        fi
    elif [[ ${status} -eq 0 ]] && grep -q 'Model checking completed. No error has been found.' "${log}"; then
        printf 'ok    %s (%s)\n' "${name}" "$(grep -m1 -o '[0-9]* distinct states found' "${log}")"
    else
        cat "${log}" >&2
        fail "${name}: TLC reported an error"
    fi
done
