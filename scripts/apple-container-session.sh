#!/usr/bin/env bash

set -euo pipefail
umask 077

session_id=""
image=""
image_digest=""
workspace=""
receipt=""
cpus=2
memory="1G"
pids=256
wall_seconds=120
terminal_bytes=16777216

usage() {
    cat <<'EOF'
usage: scripts/apple-container-session.sh [options] -- <command> [args...]

options:
  --session-id <id>       bounded receipt/container identity
  --image <reference>     reviewed local image reference
  --image-digest <digest> exact reviewed OCI index digest (sha256:<64 hex>)
  --workspace <path>      optional writable workspace mounted at /workspace
  --receipt <file>        new owner-only JSON receipt
  --cpus <count>          Apple Container CPU limit (default: 2)
  --memory <size>         Apple Container memory limit (default: 1G)
  --pids <count>          guest nproc limit (default: 256)
  --wall-seconds <count>  host watchdog (default: 120)
  --terminal-bytes <n>    aggregate stdout/stderr limit (default: 16777216)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --session-id) session_id="${2:-}"; shift 2 ;;
        --image) image="${2:-}"; shift 2 ;;
        --image-digest) image_digest="${2:-}"; shift 2 ;;
        --workspace) workspace="${2:-}"; shift 2 ;;
        --receipt) receipt="${2:-}"; shift 2 ;;
        --cpus) cpus="${2:-}"; shift 2 ;;
        --memory) memory="${2:-}"; shift 2 ;;
        --pids) pids="${2:-}"; shift 2 ;;
        --wall-seconds) wall_seconds="${2:-}"; shift 2 ;;
        --terminal-bytes) terminal_bytes="${2:-}"; shift 2 ;;
        --) shift; break ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] || {
    printf '%s\n' "Apple Container sessions require Apple Silicon macOS" >&2
    exit 1
}
command -v container >/dev/null 2>&1 || {
    printf '%s\n' "Apple container CLI is unavailable" >&2
    exit 1
}
[[ "$session_id" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$ ]] || {
    printf '%s\n' "invalid session identity" >&2
    exit 2
}
[[ -n "$image" && ${#image} -le 256 && "$image" != *[[:space:]]* ]] || {
    printf '%s\n' "invalid image reference" >&2
    exit 2
}
[[ "$image_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    printf '%s\n' "an exact reviewed OCI image digest is required" >&2
    exit 2
}
[[ "$receipt" == /* && ! -e "$receipt" ]] || {
    printf '%s\n' "receipt must be a new absolute path" >&2
    exit 2
}
[[ "$cpus" =~ ^[1-9][0-9]*([.][0-9]+)?$ ]] || {
    printf '%s\n' "invalid CPU limit" >&2
    exit 2
}
[[ "$memory" =~ ^[1-9][0-9]*([KMGTPE]i?[Bb]?|[kmgptpe])?$ ]] || {
    printf '%s\n' "invalid memory limit" >&2
    exit 2
}
for numeric in "$pids" "$wall_seconds" "$terminal_bytes"; do
    [[ "$numeric" =~ ^[1-9][0-9]*$ ]] || {
        printf '%s\n' "limits must be positive integers" >&2
        exit 2
    }
done
(( pids <= 4096 && wall_seconds <= 3600 && terminal_bytes <= 1073741824 )) || {
    printf '%s\n' "session limit exceeds the built-in safety ceiling" >&2
    exit 2
}
(( $# > 0 )) || {
    printf '%s\n' "a container command is required" >&2
    exit 2
}

if [[ -n "$workspace" ]]; then
    [[ "$workspace" == /* && "$workspace" != *","* && -d "$workspace" ]] || {
        printf '%s\n' "workspace must be an existing absolute directory without commas" >&2
        exit 2
    }
    workspace="$(cd -- "$workspace" && pwd -P)"
fi

image_inspect="$(container image inspect "$image")" || {
    printf '%s\n' "reviewed image is unavailable" >&2
    exit 1
}
resolved_image_digest="$(
    printf '%s\n' "$image_inspect" |
        sed -n 's/^[[:space:]]*"digest"[[:space:]]*:[[:space:]]*"\(sha256:[0-9a-f]\{64\}\)",*$/\1/p' |
        head -n 1
)"
unset image_inspect
[[ "$resolved_image_digest" == "$image_digest" ]] || {
    printf '%s\n' "reviewed image digest does not match the local image" >&2
    exit 1
}

scratch="$(mktemp -d "${TMPDIR:-/tmp}/glove-apple-session.XXXXXX")"
container_name="glove-$session_id"
runner_pid=""
limiter_pid=""
cleanup() {
    if [[ -n "$runner_pid" ]] && kill -0 "$runner_pid" 2>/dev/null; then
        container kill "$container_name" >/dev/null 2>&1 || true
        wait "$runner_pid" 2>/dev/null || true
    fi
    if [[ -n "$limiter_pid" ]] && kill -0 "$limiter_pid" 2>/dev/null; then
        kill "$limiter_pid" >/dev/null 2>&1 || true
        wait "$limiter_pid" 2>/dev/null || true
    fi
    container delete --force "$container_name" >/dev/null 2>&1 || true
    find "$scratch" -mindepth 1 -delete
    rmdir "$scratch"
}
trap cleanup EXIT INT TERM

started_ms=$(( $(date +%s) * 1000 ))
mkfifo "$scratch/terminal.pipe"
touch "$scratch/terminal"
head -c "$terminal_bytes" <"$scratch/terminal.pipe" >"$scratch/terminal" &
limiter_pid=$!
container_args=(
    create
    --name "$container_name"
    --init
    --network none
    --no-dns
    --read-only
    --cap-drop ALL
    --cpus "$cpus"
    --memory "$memory"
    --ulimit "nproc=$pids:$pids"
    --tmpfs /tmp
)
if [[ -n "$workspace" ]]; then
    container_args+=(--mount "type=bind,source=$workspace,target=/workspace")
fi
container_args+=("$image" "$@")
container "${container_args[@]}" >/dev/null
container_inspect="$(container inspect "$container_name")"
image_identity="$(
    printf '%s\n' "$container_inspect" |
        sed -n 's/^[[:space:]]*"digest"[[:space:]]*:[[:space:]]*"sha256:\([0-9a-f]\{64\}\)",*$/\1/p' |
        head -n 1
)"
unset container_inspect
[[ "$image_identity" =~ ^[0-9a-f]{64}$ ]] || {
    printf '%s\n' "created container has no bounded OCI image digest" >&2
    exit 1
}
set +e
container start --attach "$container_name" >"$scratch/terminal.pipe" 2>&1 &
runner_pid=$!
set -e

reason="exit"
deadline=$((SECONDS + wall_seconds))
while kill -0 "$runner_pid" 2>/dev/null; do
    output_size=$(wc -c <"$scratch/terminal")
    if ! kill -0 "$limiter_pid" 2>/dev/null && (( output_size >= terminal_bytes )); then
        reason="terminal_output_limit"
        container kill "$container_name" >/dev/null 2>&1 || true
        break
    fi
    if (( SECONDS >= deadline )); then
        reason="wall_time_limit"
        container kill "$container_name" >/dev/null 2>&1 || true
        break
    fi
    sleep 0.1
done

set +e
wait "$runner_pid"
exit_code=$?
wait "$limiter_pid" 2>/dev/null
limiter_pid=""
set -e
runner_pid=""
finished_ms=$(( $(date +%s) * 1000 ))
output_size=$(wc -c <"$scratch/terminal")
if (( output_size >= terminal_bytes )) && [[ "$reason" == "exit" ]]; then
    reason="terminal_output_limit"
fi

container delete --force "$container_name" >/dev/null 2>&1 || true
cleanup_verified=true
if container inspect "$container_name" >/dev/null 2>&1; then
    cleanup_verified=false
fi
if [[ "$cleanup_verified" != true && "$reason" == "exit" ]]; then
    reason="cleanup_failed"
fi

temporary_receipt="$receipt.tmp.$$"
{
    printf '{\n'
    printf '  "schema_version": 1,\n'
    printf '  "backend": "apple_container",\n'
    printf '  "session_id": "%s",\n' "$session_id"
    printf '  "image_oci_index_digest": "%s",\n' "$image_digest"
    printf '  "image_oci_digest": "sha256:%s",\n' "$image_identity"
    printf '  "network_mode": "none",\n'
    printf '  "root_read_only": true,\n'
    printf '  "limits": {"cpus": "%s", "memory": "%s", "pids": %s, "wall_seconds": %s, "terminal_bytes": %s},\n' \
        "$cpus" "$memory" "$pids" "$wall_seconds" "$terminal_bytes"
    printf '  "started_at_ms": %s,\n' "$started_ms"
    printf '  "finished_at_ms": %s,\n' "$finished_ms"
    printf '  "exit_code": %s,\n' "$exit_code"
    printf '  "terminal_bytes_observed": %s,\n' "$output_size"
    printf '  "termination_reason": "%s",\n' "$reason"
    printf '  "cleanup_verified": %s\n' "$cleanup_verified"
    printf '}\n'
} >"$temporary_receipt"
chmod 0600 "$temporary_receipt"
mv "$temporary_receipt" "$receipt"

[[ "$reason" == "exit" && "$cleanup_verified" == true ]] || exit 1
exit "$exit_code"
