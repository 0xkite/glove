#!/usr/bin/env bash
# sbpl-tripwire-matrix.sh — measure which containment tripwires are safe.
#
# A tripwire is (deny <op> (with send-signal SIGKILL)): the sandbox terminates
# the caller at the syscall. Flipping `containment_response` to terminate by
# default is therefore a policy that kills real agents, and it must be decided by
# measurement rather than taste.
#
# This runs each candidate tripwire class against a set of workloads and reports
# survive / killed. A class is only safe to trip by default when every
# representative workload survives it. /usr/bin/true is a trivial control; it is
# NOT sufficient evidence, because a workload can trip a class during startup
# that a real agent also needs (process-info* already does exactly that).
#
# Linux-only translation units aside, this is the measurement gate. Run it on any
# macOS the shipping lane targets, and re-run after an OS upgrade: the grammar is
# unversioned.

set -uo pipefail

work="$(mktemp -d "${TMPDIR:-/private/tmp}/sbpl-tripwire.XXXXXX")"
trap 'rm -rf "${work}"' EXIT

V="(version 1)"
IMPORT="(import \"system.sb\")"
# Grants a contained agent legitimately holds. Deliberately permissive: the
# question is whether the tripwire fires on ordinary work, not whether the
# workload is tightly confined.
GRANTS="${V}${IMPORT}(allow process-exec*)(allow process-fork)(allow sysctl-read)"
GRANTS="${GRANTS}(allow file-read*)(allow file-write* (subpath \"${work}\"))"
GRANTS="${GRANTS}(allow network-outbound (require-all (remote tcp \"localhost:45999\") (socket-domain AF_INET)))"

# Candidate tripwire classes. "none" is the control that must always survive.
classes=(
    "none|"
    "ipc-posix-shm|(deny ipc-posix-shm* (with send-signal SIGKILL))"
    "cores-write|(deny file-write* (subpath \"/cores\") (with send-signal SIGKILL))"
    "syslog-net|(deny network-outbound (subpath \"/private/var/run\") (with send-signal SIGKILL))"
    "mach-lookup|(deny mach-lookup (with send-signal SIGKILL))"
    "process-info|(deny process-info* (with send-signal SIGKILL))"
)

# Workloads. Each is ordinary work a contained agent does at start-up.
workloads=(
    "true|/usr/bin/true"
    "sh-spawn|/bin/sh -c echo-hi"
    "ps-self|/bin/ps -p SELF"
)
if command -v python3 >/dev/null 2>&1; then
    workloads+=("python3|$(command -v python3) -c pass")
fi
if command -v node >/dev/null 2>&1; then
    workloads+=("node|$(command -v node) -e 0")
fi

run_workload() {
    local spec="$1" profile="$2"
    case "${spec}" in
    "/bin/sh -c echo-hi") /usr/bin/sandbox-exec -p "${profile}" /bin/sh -c 'echo hi' ;;
    "/bin/ps -p SELF") /usr/bin/sandbox-exec -p "${profile}" /bin/ps -p $$ ;;
    *)
        # shellcheck disable=SC2086
        /usr/bin/sandbox-exec -p "${profile}" ${spec}
        ;;
    esac
}

printf '%-14s' "class \\ workload"
names=()
for w in "${workloads[@]}"; do
    names+=("${w%%|*}")
    printf '%-12s' "${w%%|*}"
done
printf '\n'

unsafe=()
for entry in "${classes[@]}"; do
    class="${entry%%|*}"
    rule="${entry#*|}"
    printf '%-14s' "${class}"
    for w in "${workloads[@]}"; do
        spec="${w#*|}"
        out="$(run_workload "${spec}" "${GRANTS}${rule}" 2>&1)"
        rc=$?
        if [[ ${rc} -eq 137 ]]; then
            printf '%-12s' "KILLED"
            [[ "${class}" != "none" ]] && unsafe+=("${class}/$(printf '%s' "${w%%|*}")")
        elif [[ ${rc} -eq 0 ]]; then
            printf '%-12s' "ok"
        elif [[ ${rc} -eq 71 ]]; then
            # sandbox-exec could not exec the workload at all under this profile.
            # That measures nothing, and must never be read as "survived".
            printf '%-12s' "invalid"
        else
            # Ordinary denial or workload error: the tripwire did not fire, which
            # is the property under test.
            printf '%-12s' "ok(rc=${rc})"
        fi
    done
    printf '\n'
done

printf '\nclasses that kill a representative workload:\n'
if [[ ${#unsafe[@]} -eq 0 ]]; then
    printf '  none\n'
else
    printf '  %s\n' "${unsafe[@]}"
fi
printf '\nNote: survival here is necessary, not sufficient. A trivial binary must not\n'
printf 'be the only evidence before a class is tripped by default.\n'
