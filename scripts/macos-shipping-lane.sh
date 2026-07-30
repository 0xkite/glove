#!/usr/bin/env bash
#
# Build Glove's Linux image with Apple's container runtime, run the portable
# Linux test surface, and probe the outer VM perimeter. The nested Glove Linux
# sandbox is tested only when the guest kernel permits procfs mounts from a
# child user namespace.

set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
image="glove-macos-shipping:dev"
build_image=1
start_system=0
cpus="${GLOVE_APPLE_CONTAINER_CPUS:-4}"
memory="${GLOVE_APPLE_CONTAINER_MEMORY:-8G}"

usage() {
    cat <<'EOF'
usage: scripts/macos-shipping-lane.sh [options]

options:
  --image <tag>      image tag (default: glove-macos-shipping:dev)
  --skip-build       use an existing image
  --build-only       build the image without running tests
  --start-system     start Apple container services when they are not running
  -h, --help         show this help
EOF
}

run_tests=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)
            [[ $# -ge 2 ]] || { printf '%s\n' "--image requires a value" >&2; exit 2; }
            image="$2"
            shift 2
            ;;
        --skip-build)
            build_image=0
            shift
            ;;
        --build-only)
            run_tests=0
            shift
            ;;
        --start-system)
            start_system=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
    printf '%s\n' "The macOS shipping lane requires an Apple Silicon Mac" >&2
    exit 1
fi
macos_major="$(sw_vers -productVersion | cut -d. -f1)"
if [[ ! "${macos_major}" =~ ^[0-9]+$ ]] || (( macos_major < 26 )); then
    printf 'The macOS shipping lane requires macOS 26 or newer; found %s\n' \
        "$(sw_vers -productVersion)" >&2
    exit 1
fi
if ! command -v container >/dev/null; then
    printf '%s\n' "Apple container CLI is not installed" >&2
    exit 1
fi
if ! container system status >/dev/null 2>&1; then
    if (( start_system == 0 )); then
        printf '%s\n' \
            "Apple container services are stopped; run 'container system start' or pass --start-system" \
            >&2
        exit 1
    fi
    container system start --disable-kernel-install --timeout 30
fi

printf 'Apple container: %s\n' "$(container --version)"
printf 'macOS: %s (%s)\n' "$(sw_vers -productVersion)" "$(uname -m)"

if (( build_image == 1 )); then
    container build \
        --progress plain \
        --cpus "${cpus}" \
        --memory "${memory}" \
        --file "${root}/dockerfiles/Dockerfile.linux" \
        --tag "${image}" \
        "${root}"
fi
if (( run_tests == 0 )); then
    exit 0
fi

# These tests require an inner user namespace with mountable procfs, delegated
# cgroup controllers, or both. Apple container 1.2.0's default guest permits
# the outer root mount but rejects procfs mounts from a child user namespace.
nested_tests='^(container_spawner|glove_exec_perimeter|container_linux_cgroup_v2|container_linux_resource_lifecycle|container_linux_managed_session|control_linux_session_preparation|control_linux_session_executor|container_linux_exec)$'

container run \
    --rm \
    --network none \
    --cap-add ALL \
    --cpus "${cpus}" \
    --memory "${memory}" \
    "${image}" \
    /bin/bash -lc "ctest --preset asan --output-on-failure -E '${nested_tests}'"

if container run \
    --rm \
    --network none \
    --cap-add ALL \
    --cpus 1 \
    --memory 512M \
    "${image}" \
    /bin/sh -c \
        'mkdir -p /tmp/glove-nested-proc && unshare --user --map-root-user --mount /bin/sh -c "mount -t proc proc /tmp/glove-nested-proc"'
then
    printf '%s\n' "nested_userns_procfs=available"
    container run \
        --rm \
        --network none \
        --cap-add ALL \
        --cpus "${cpus}" \
        --memory "${memory}" \
        "${image}" \
        /bin/bash -lc \
        "ctest --preset asan --output-on-failure -R '^(container_spawner|glove_exec_perimeter|container_linux_exec)$'"
else
    printf '%s\n' \
        "nested_userns_procfs=unavailable (portable Linux tests passed; inner Glove sandbox not claimed)"
fi

# The following variables are intentionally expanded inside the guest.
# shellcheck disable=SC2016
GLOVE_TEST_HOST_SECRET=must-not-cross container run \
    --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --cpus 2 \
    --memory 768M \
    --tmpfs /tmp \
    --tmpfs /workspace \
    "${image}" \
    /bin/bash -lc '
        set -euo pipefail
        if touch /glove-outer-write 2>/dev/null; then
            printf "%s\n" "read_only_root=failed" >&2
            exit 1
        fi
        touch /workspace/write-ok
        if [[ -s /proc/net/route ]]; then
            printf "%s\n" "network_none=failed" >&2
            exit 1
        fi
        if env | grep -q "^GLOVE_TEST_HOST_SECRET="; then
            printf "%s\n" "host_environment_scrub=failed" >&2
            exit 1
        fi
        online_cpus="$(nproc)"
        memory_kib="$(awk "/^MemTotal:/ { print \$2 }" /proc/meminfo)"
        # container 1.2.0 exposes one guest-management vCPU in addition to the
        # requested workload count.
        (( online_cpus <= 3 ))
        (( memory_kib <= 900000 ))
        printf "outer_vm_perimeter=passed cpus=%s memory_kib=%s\n" \
            "${online_cpus}" "${memory_kib}"
    '

# Exercise the shipping executor itself, not only ad hoc container commands.
# The receipt intentionally excludes command arguments and terminal content.
image_digest="$(
    container image inspect "${image}" |
        sed -n 's/^[[:space:]]*"digest"[[:space:]]*:[[:space:]]*"\(sha256:[0-9a-f]\{64\}\)",*$/\1/p' |
        head -n 1
)"
[[ "$image_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    printf '%s\n' "built image has no exact OCI index digest" >&2
    exit 1
}
session_artifacts="$(mktemp -d "${TMPDIR:-/tmp}/glove-apple-live.XXXXXX")"
cleanup_session_artifacts() {
    find "$session_artifacts" -mindepth 1 -delete
    rmdir "$session_artifacts"
}
trap cleanup_session_artifacts EXIT
"${root}/scripts/apple-container-session.sh" \
    --session-id shipping-probe \
    --image "${image}" \
    --image-digest "${image_digest}" \
    --receipt "${session_artifacts}/receipt.json" \
    --cpus 1 \
    --memory 512M \
    --pids 32 \
    --wall-seconds 30 \
    --terminal-bytes 4096 \
    -- /bin/sh -c 'printf GLOVE_APPLE_CONTAINER_LIVE_OK'
grep -q '"backend": "apple_container"' "${session_artifacts}/receipt.json"
grep -q '"cleanup_verified": true' "${session_artifacts}/receipt.json"
grep -q '"termination_reason": "exit"' "${session_artifacts}/receipt.json"
printf '%s\n' "apple_container_live_session=passed"
