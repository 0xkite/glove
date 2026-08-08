#!/bin/sh
set -eu

if [ "${GLOVE_REMOTE_WORKERD_VALIDATE:-}" != "1" ]; then
    echo "refusing: set GLOVE_REMOTE_WORKERD_VALIDATE=1 for this validation-only run" >&2
    exit 2
fi
if [ "$#" -ne 2 ]; then
    echo "usage: GLOVE_REMOTE_WORKERD_VALIDATE=1 $0 /absolute/glove-remote-exec /absolute/schema-2-config" >&2
    exit 2
fi

executor=$1
config=$2
case "$executor:$config" in
    /*:/*) ;;
    *) echo "executor and config must be absolute paths" >&2; exit 2 ;;
esac
if [ ! -f "$executor" ] || [ -L "$executor" ] || [ ! -x "$executor" ]; then
    echo "executor must be a preverified regular executable, not a symlink" >&2
    exit 2
fi
if [ ! -f "$config" ] || [ -L "$config" ]; then
    echo "config must be a preverified regular file, not a symlink" >&2
    exit 2
fi
for required in \
    GLOVE_REMOTE_EXECUTOR_SHA256 \
    GLOVE_REMOTE_IMAGE \
    GLOVE_REMOTE_WORKERD_SHA256 \
    GLOVE_REMOTE_DESCRIPTOR_SHA256
do
    eval "value=\${$required:-}"
    if [ -z "$value" ]; then
        echo "refusing: $required must be supplied from preverified operator input" >&2
        exit 2
    fi
done

# Python is used only from the local standard library. This script never
# installs, fetches, logs in, mounts host paths, or supplies Docker options.
exec /usr/bin/env -i \
    GLOVE_REMOTE_EXECUTOR_SHA256="$GLOVE_REMOTE_EXECUTOR_SHA256" \
    GLOVE_REMOTE_IMAGE="$GLOVE_REMOTE_IMAGE" \
    GLOVE_REMOTE_WORKERD_SHA256="$GLOVE_REMOTE_WORKERD_SHA256" \
    GLOVE_REMOTE_DESCRIPTOR_SHA256="$GLOVE_REMOTE_DESCRIPTOR_SHA256" \
    /usr/bin/python3 - "$executor" "$config" <<'PY'
import hashlib
import json
import os
import re
import secrets
import struct
import subprocess
import sys
import time
from pathlib import Path

executor = Path(sys.argv[1])
config_path = Path(sys.argv[2])
expected_keys = [
    "schema_version",
    "executor_digest",
    "container_image",
    "container_image_digest",
    "workerd_digest",
    "descriptor_digest",
    "staging_root",
    "max_sessions",
    "max_ttl_ms",
    "docker_executable",
    "docker_executable_digest",
]

raw = config_path.read_text(encoding="ascii")
if not raw.endswith("\n") or "\r" in raw or "\x00" in raw:
    raise SystemExit("invalid canonical executor config")
lines = raw.splitlines()
if len(lines) != len(expected_keys):
    raise SystemExit("invalid canonical executor config field count")
config = {}
for key, line in zip(expected_keys, lines):
    prefix = key + "="
    if not line.startswith(prefix) or not line[len(prefix):]:
        raise SystemExit("invalid canonical executor config ordering")
    config[key] = line[len(prefix):]

sha = lambda path: "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()
digest_re = re.compile(r"sha256:[0-9a-f]{64}\Z")
image_re = re.compile(r"[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)+@sha256:[0-9a-f]{64}\Z")
if config["schema_version"] != "2":
    raise SystemExit("validation requires schema_version=2")
if config["executor_digest"] != os.environ["GLOVE_REMOTE_EXECUTOR_SHA256"]:
    raise SystemExit("operator executor digest does not match config")
if sha(executor) != config["executor_digest"]:
    raise SystemExit("executor binary digest mismatch")
if config["container_image"] != os.environ["GLOVE_REMOTE_IMAGE"]:
    raise SystemExit("operator image identity does not match config")
if not image_re.fullmatch(config["container_image"]):
    raise SystemExit("image must be a canonical digest-qualified name")
if not config["container_image"].endswith("@" + config["container_image_digest"]):
    raise SystemExit("image digest suffix mismatch")
if config["workerd_digest"] != os.environ["GLOVE_REMOTE_WORKERD_SHA256"]:
    raise SystemExit("operator workerd digest does not match config")
if config["descriptor_digest"] != os.environ["GLOVE_REMOTE_DESCRIPTOR_SHA256"]:
    raise SystemExit("operator descriptor digest does not match config")
if not digest_re.fullmatch(config["workerd_digest"]) or not digest_re.fullmatch(config["descriptor_digest"]):
    raise SystemExit("invalid fixed descriptor identity")
if config["docker_executable"] != "/usr/bin/docker":
    raise SystemExit("validation executor requires /usr/bin/docker")
if sha("/usr/bin/docker") != config["docker_executable_digest"]:
    raise SystemExit("Docker executable digest mismatch")

# `image inspect` is local and read-only. `run --pull never` is also hardcoded
# inside the checked executor, so a missing image fails instead of fetching.
subprocess.run(
    ["/usr/bin/docker", "image", "inspect", config["container_image"]],
    env={}, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL, check=True, timeout=10,
)

process = subprocess.Popen(
    [str(executor), "--local-validation-stdio", str(config_path)],
    env={}, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None,
)
assert process.stdin is not None and process.stdout is not None
session_id = "local-workerd-validation"
epoch = secrets.token_hex(16)
descriptor = config["descriptor_digest"]
ttl = min(int(config["max_ttl_ms"]), 60_000)
request_number = 0

def canonical(method, payload):
    value = (
        "glove-remote-validation-v1\n"
        f"method={method}\n"
        f"session_id={payload['session_id']}\n"
        f"session_epoch={payload['session_epoch']}\n"
        f"descriptor_digest={payload['descriptor_digest']}\n"
        f"idempotency_key={payload['idempotency_key']}"
    )
    if method == "remote_read":
        value += f"\ncursor={payload['cursor']}\nmax_bytes={payload['max_bytes']}"
    return value + "\n"

def call(method, key, **specific):
    global request_number
    request_number += 1
    payload = {
        "schema_version": 1,
        "session_id": session_id,
        "session_epoch": epoch,
        "descriptor_digest": descriptor,
        "idempotency_key": key,
        "payload_digest": "sha256:" + "0" * 64,
        **specific,
    }
    payload["payload_digest"] = "sha256:" + hashlib.sha256(
        canonical(method, payload).encode("ascii")
    ).hexdigest()
    request = json.dumps({
        "jsonrpc": "2.0",
        "id": f"local-{request_number}",
        "method": method,
        "deadline_remaining_ms": ttl,
        "payload": payload,
    }, separators=(",", ":")).encode("utf-8")
    process.stdin.write(struct.pack(">I", len(request)) + request)
    process.stdin.flush()
    header = process.stdout.read(4)
    if len(header) != 4:
        raise RuntimeError("executor closed before response")
    size = struct.unpack(">I", header)[0]
    if size == 0 or size > 1024 * 1024:
        raise RuntimeError("invalid executor response frame")
    response = json.loads(process.stdout.read(size))
    if response.get("error"):
        raise RuntimeError(response["error"]["code"] + ": " + response["error"]["message"])
    return response["result"]

try:
    print(json.dumps(call("remote_prepare", "prepare"), sort_keys=True))
    print(json.dumps(call("remote_start", "start"), sort_keys=True))
    cursor = 0
    for attempt in range(600):
        chunk = call("remote_read", f"read-{attempt}", cursor=cursor, max_bytes=16384)
        if chunk["bytes"]:
            sys.stdout.write(chunk["bytes"])
            sys.stdout.flush()
        cursor = chunk["next_cursor"]
        terminal = call("remote_wait", f"wait-{attempt}")
        if terminal["state"] != "running":
            print(json.dumps(terminal, sort_keys=True))
            break
        time.sleep(0.05)
    else:
        raise RuntimeError("validator did not terminate within the bounded polling window")
    print(json.dumps(call("remote_cleanup", "cleanup"), sort_keys=True))
finally:
    process.stdin.close()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
if process.returncode != 0:
    raise SystemExit(process.returncode)
PY
