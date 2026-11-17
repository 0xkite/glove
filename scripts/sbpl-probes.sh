#!/usr/bin/env bash
# sbpl-probes.sh — verify the sandbox profile language semantics that
# docs/sbpl-reference.md depends on.
#
# Apple publishes no SBPL reference, so every claim in that document is either
# probed here or marked unverified. Re-run this after a macOS upgrade before
# trusting the reference: the grammar is unversioned and its behaviour is not a
# compatibility guarantee.
#
# The outcome classifier matters. A sandbox denial surfaces as EPERM
# ("Operation not permitted"); a connection the sandbox ALLOWED but that nobody
# is listening for surfaces as ECONNREFUSED. Treating non-zero exit as "denied"
# would misread a permitted connection as a denial.
#
# This is a manual probe harness, not part of scripts/preflight.sh: it needs a
# loopback listener and writes under a temporary directory.

set -uo pipefail

work="$(mktemp -d "${TMPDIR:-/private/tmp}/sbpl-probes.XXXXXX")"
listener_pid=""
cleanup() {
    if [[ -n "${listener_pid}" ]]; then
        kill "${listener_pid}" 2>/dev/null || true
    fi
    rm -rf "${work}"
}
trap cleanup EXIT

# Resolve the work directory the way the sandbox will see it: SBPL matches the
# resolved path, and TMPDIR is /var/folders/... which resolves under /private.
work_real="$(cd "${work}" && pwd -P)"
port=45999

cat >"${work}/connprobe.c" <<'EOF'
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 2) return 2;
    int fd = -1;
    int rc = -1;
    if (strcmp(argv[1], "unixdgram") == 0 && argc == 3) {
        fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        struct sockaddr_un a;
        memset(&a, 0, sizeof a);
        a.sun_family = AF_UNIX;
        strncpy(a.sun_path, argv[2], sizeof(a.sun_path) - 1);
        if (fd >= 0) rc = connect(fd, (struct sockaddr*)&a, sizeof a);
    } else if (argc == 4) {
        int fam = (strcmp(argv[1], "fam6") == 0) ? AF_INET6 : AF_INET;
        int type = SOCK_STREAM;
        if (strcmp(argv[1], "udp4") == 0) {
            fam = AF_INET;
            type = SOCK_DGRAM;
        }
        fd = socket(fam, type, 0);
        if (fd < 0) {
            printf("DENY errno=%d (%s)\n", errno, strerror(errno));
            return 1;
        }
        if (fam == AF_INET) {
            struct sockaddr_in a;
            memset(&a, 0, sizeof a);
            a.sin_family = AF_INET;
            a.sin_port = htons((unsigned short)atoi(argv[3]));
            inet_pton(AF_INET, argv[2], &a.sin_addr);
            rc = connect(fd, (struct sockaddr*)&a, sizeof a);
        } else {
            struct sockaddr_in6 a;
            memset(&a, 0, sizeof a);
            a.sin6_family = AF_INET6;
            a.sin6_port = htons((unsigned short)atoi(argv[3]));
            inet_pton(AF_INET6, argv[2], &a.sin6_addr);
            rc = connect(fd, (struct sockaddr*)&a, sizeof a);
        }
    } else {
        return 2;
    }
    if (rc == 0) {
        printf("ALLOW\n");
        close(fd);
        return 0;
    }
    printf("DENY errno=%d (%s)\n", errno, strerror(errno));
    if (fd >= 0) close(fd);
    return 1;
}
EOF

if ! cc -O1 -o "${work}/connprobe" "${work}/connprobe.c" 2>"${work}/cc.log"; then
    printf 'sbpl-probes: cannot build the connect probe:\n' >&2
    cat "${work}/cc.log" >&2
    exit 1
fi

mkdir -p "${work}/w" "${work}/outside" "${work}/wx" "${work}/real"
printf 'x\n' >"${work}/w/f"
printf 'sibling\n' >"${work}/wx/f"
printf 'secret\n' >"${work}/outside/secret"
printf 'ok\n' >"${work}/real/g"
ln -sfn "${work}/outside" "${work}/w/link"
ln -sfn "${work}/real/g" "${work}/entry"

if command -v nc >/dev/null 2>&1; then
    nc -l 127.0.0.1 "${port}" >/dev/null 2>&1 &
    listener_pid=$!
    sleep 0.3
fi

V="(version 1)"
BASE="${V}(import \"system.sb\")(allow process-exec*)(allow file-read-metadata)(allow sysctl-read)"
BASE="${BASE}(allow file-read* (subpath \"/usr/lib\"))(allow file-read* (subpath \"/System\"))"
BASE="${BASE}(allow file-read* (subpath \"/bin\"))(allow file-read* (subpath \"/usr/bin\"))"
BASE="${BASE}(allow file-read* (subpath \"/dev\"))"

cases=0
unexpected=0

classify() {
    local rc="$1" out="$2"
    if grep -qiE "Operation not permitted|Permission denied|errno=1 \(|errno=13 \(" <<<"${out}"; then
        echo sandbox-deny
    elif [[ "${rc}" -eq 65 ]] && grep -q "^sandbox-exec:" <<<"${out}"; then
        # Compile failure, not a runtime denial. A profile that does not build
        # is a construction failure and must never be read as enforcement.
        echo profile-error
    elif [[ "${rc}" -eq 0 ]] || grep -q "Connection refused\|errno=61" <<<"${out}"; then
        echo allow
    else
        echo "other(rc=${rc})"
    fi
}

# probe <name> <expected: allow|sandbox-deny> <profile> <command...>
probe() {
    local name="$1" expect="$2" profile="$3"
    shift 3
    local out rc got mark
    out="$(/usr/bin/sandbox-exec -p "${profile}" "$@" 2>&1)"
    rc=$?
    got="$(classify "${rc}" "${out}")"
    cases=$((cases + 1))
    mark="ok  "
    if [[ "${got}" != "${expect}" ]]; then
        mark="FAIL"
        unexpected=$((unexpected + 1))
    fi
    printf '%-4s %-4s expect=%-13s got=%-13s %s\n' \
        "${mark}" "${name}" "${expect}" "${got}" "$(head -1 <<<"${out}")"
}

printf '== application model ==\n'
probe V1 profile-error "(deny default)(allow file-read*)" /bin/cat "${work}/w/f"
probe V2 sandbox-deny "${V}" /bin/cat "${work}/w/f"

printf '== path matching: resolved path, rule strings never normalised ==\n'
# $work keeps the caller's spelling (/var/folders/...); $work_real is the path the
# kernel resolves (/private/var/folders/...). A rule using the unresolved
# spelling must never match.
probe T1 sandbox-deny "${BASE}(allow file-read* (literal \"${work_real}/w/f\"))(deny file-read* (literal \"${work_real}/w/f\"))" /bin/cat "${work}/w/f"
probe T2 allow "${BASE}(allow file-read* (literal \"${work_real}/w/f\"))" /bin/cat "${work}/w/f"
probe T3 sandbox-deny "${BASE}(allow file-read* (literal \"${work}/w/f\"))" /bin/cat "${work}/w/f"
probe T4 allow "${BASE}(allow file-read* (literal \"${work_real}/w/f\"))" /bin/cat "${work_real}/w/f"

printf '== subpath is component-aware ==\n'
probe P1 sandbox-deny "${BASE}(allow file-read* (subpath \"${work_real}/w\"))" /bin/cat "${work}/wx/f"
probe P2 allow "${BASE}(allow file-read* (subpath \"${work_real}/w\"))" /bin/cat "${work}/w/f"

printf '== precedence: specificity first, then source order ==\n'
probe O1 sandbox-deny "${BASE}(allow file-read* (literal \"${work_real}/w/f\"))(deny file-read* (literal \"${work_real}/w/f\"))" /bin/cat "${work}/w/f"
probe O2 allow "${BASE}(deny file-read* (literal \"${work_real}/w/f\"))(allow file-read* (literal \"${work_real}/w/f\"))" /bin/cat "${work}/w/f"
probe U1 allow "${BASE}(deny file-read*)(allow file-read* (literal \"${work_real}/w/f\"))" /bin/cat "${work}/w/f"
probe U2 allow "${BASE}(allow file-read* (literal \"${work_real}/w/f\"))(deny file-read*)" /bin/cat "${work}/w/f"

printf '== symlinks: matching follows the target, never the link name ==\n'
probe L1 allow "${BASE}(allow file-read* (subpath \"${work_real}/outside\"))" /bin/cat "${work}/w/link/secret"
probe L2 sandbox-deny "${BASE}(allow file-read* (literal \"${work_real}/w/link/secret\"))" /bin/cat "${work}/w/link/secret"
probe L3 sandbox-deny "${BASE}(allow file-read* (literal \"${work_real}/entry\"))" /bin/cat "${work}/entry"
probe L4 allow "${BASE}(allow file-read* (subpath \"${work_real}/real\"))" /bin/cat "${work}/entry"

printf '== case-insensitive volumes ==\n'
probe K1 allow "${BASE}(allow file-read* (literal \"${work_real}/w/f\"))" /bin/cat "${work}/W/F"

printf '== network filters ==\n'
probe N1 allow "${BASE}(allow network-outbound (remote ip \"localhost:${port}\"))" "${work}/connprobe" fam4 127.0.0.1 "${port}"
probe N2 sandbox-deny "${BASE}(allow network-outbound (remote ip \"localhost:${port}\"))" "${work}/connprobe" fam4 127.0.0.1 46000
probe N3 sandbox-deny "${BASE}" "${work}/connprobe" fam4 127.0.0.1 "${port}"
probe N4 allow "${BASE}(allow network-outbound (remote ip \"localhost:${port}\"))" "${work}/connprobe" fam6 ::1 "${port}"
probe N5 sandbox-deny "${BASE}(allow network-outbound (require-all (remote tcp \"localhost:${port}\") (socket-domain AF_INET)))" "${work}/connprobe" fam6 ::1 "${port}"
probe N6 allow "${BASE}(allow network-outbound (require-all (remote tcp \"localhost:${port}\") (socket-domain AF_INET)))" "${work}/connprobe" fam4 127.0.0.1 "${port}"
probe N7 sandbox-deny "${BASE}(allow network-outbound (remote tcp \"localhost:${port}\"))" "${work}/connprobe" udp4 127.0.0.1 "${port}"
probe N8 allow "${BASE}(deny network*)(allow network-outbound (remote tcp \"localhost:${port}\"))" "${work}/connprobe" fam4 127.0.0.1 "${port}"
probe N9 sandbox-deny "${BASE}(allow network-outbound (remote ip \"localhost:${port}\"))" "${work}/connprobe" fam4 127.0.0.2 "${port}"
probe N10 sandbox-deny "${BASE}(allow network-outbound (require-all (remote tcp \"localhost:${port}\") (socket-domain AF_INET)))" "${work}/connprobe" udp4 127.0.0.1 "${port}"

printf '== import system.sb grants the syslog datagram socket ==\n'
if [[ -S /private/var/run/syslog ]]; then
    probe Y1 allow "${V}(import \"system.sb\")(allow process-exec*)(allow file-read-metadata)" "${work}/connprobe" unixdgram /private/var/run/syslog
    probe Y2 sandbox-deny "${V}(import \"system.sb\")(allow process-exec*)(allow file-read-metadata)(deny network-outbound (subpath \"/private/var/run\"))" "${work}/connprobe" unixdgram /private/var/run/syslog
else
    printf 'skip  Y1,Y2 /private/var/run/syslog is absent on this host\n'
fi

printf '\ncases=%d unexpected=%d\n' "${cases}" "${unexpected}"
[[ "${unexpected}" -eq 0 ]]
