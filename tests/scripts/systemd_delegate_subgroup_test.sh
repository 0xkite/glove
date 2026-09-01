#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
  echo "usage: $0 MANAGED_SESSION_TEST CAPABILITY_PROBE GLOVED" >&2
  exit 2
fi
for executable in "$@"; do
  if [[ ! -x "$executable" ]]; then
    echo "test executable is unavailable: $executable" >&2
    exit 2
  fi
done
if [[ ! -x /usr/bin/unshare ]] || ! command -v systemctl >/dev/null 2>&1 ||
   ! command -v systemd-run >/dev/null 2>&1; then
  echo "SKIP: systemd-run or unshare is unavailable" >&2
  exit 77
fi
if ! systemctl --user show-environment >/dev/null 2>&1; then
  echo "SKIP: user systemd manager is unavailable" >&2
  exit 77
fi
systemd_version="$(systemd-run --version | awk 'NR == 1 { print $2 }')"
if [[ ! "$systemd_version" =~ ^[0-9]+$ ]] || (( systemd_version < 254 )); then
  echo "SKIP: systemd 254+ is required for DelegateSubgroup" >&2
  exit 77
fi
# The single-quoted probe must expand only inside the transient service.
# shellcheck disable=SC2016
if ! systemd-run --user --quiet --wait --pipe --expand-environment=no \
  -p Type=oneshot \
  -p 'Delegate=cpu memory pids' \
  -p 'DelegateSubgroup=glove-host' \
  /bin/sh -eu -c '
    current="$(cut -d: -f3 /proc/self/cgroup)"
    test "${current##*/}" = glove-host
    parent="/sys/fs/cgroup${current%/*}"
    test -z "$(cat "$parent/cgroup.procs")"
    for controller in cpu memory pids; do
      grep -qw "$controller" "$parent/cgroup.controllers"
    done
  '; then
  echo "SKIP: user manager does not provide the delegated subgroup topology" >&2
  exit 77
fi

root="$(mktemp -d /tmp/glove-systemd-subgroup-test-XXXXXX)"
service_unit="glove-subgroup-service-${BASHPID}"
session_unit="glove-subgroup-session-${BASHPID}"
# Invoked indirectly by trap.
# shellcheck disable=SC2329
cleanup() {
  systemctl --user stop "$service_unit.service" >/dev/null 2>&1 || true
  systemctl --user reset-failed "$service_unit.service" >/dev/null 2>&1 || true
  rm -rf -- "$root"
}
trap cleanup EXIT HUP INT TERM
chmod 0700 "$root"
mkdir -m 0700 "$root/runtime" "$root/materializations" "$root/source"
printf 'seed\n' >"$root/source/input.txt"
printf '%064d\n' 0 >"$root/audit.key"
chmod 0600 "$root/audit.key"
cat >"$root/session-policy.json" <<EOF
{"schema_version":1,"revision":7,"max_plan_ttl_ms":120000,"runtime_templates":[{"runtime_template_id":"pi-safe","runtime_id":"pi","adapter_command_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sandbox_backend":"linux_production","allowed_path_aliases":["workspace"],"allowed_projection_destinations":[]}],"path_aliases":[{"alias":"workspace","host_path":"$root/source","target_path":"/workspace","max_ttl_secs":120,"access":[{"access":"ephemeral_write","materialization":"copy","create_policy":"empty_directory","cleanup_policy":"remove","max_bytes":2097152}]}],"library_projection_destinations":[],"resource_profiles":[{"profile_id":"small","cpu_time_ms":1000,"memory_bytes":67108864,"pids":16,"wall_time_ms":2000,"disk_bytes":2097152,"terminal_output_bytes":1048576}],"egress_policy_ids":["no-network"],"tool_policy_ids":["sage-readonly"],"secret_handles":[]}
EOF
chmod 0600 "$root/session-policy.json"

systemd-run \
  --user \
  --quiet \
  --collect \
  --unit "$service_unit" \
  -p Type=simple \
  -p 'Delegate=cpu memory pids' \
  -p 'DelegateSubgroup=glove-host' \
  -p Restart=on-failure \
  -p RestartSec=100ms \
  -p TimeoutStopSec=15s \
  /usr/bin/unshare \
  --user \
  --map-root-user \
  --mount \
  --propagation private \
  -- \
  "$3" \
  --runtime-dir "$root/runtime" \
  --audit-key "$root/audit.key" \
  --journal "$root/receipts.journal" \
  --session-policy "$root/session-policy.json" \
  --session-store "$root/sessions.journal" \
  --materialization-root "$root/materializations"

"$2" --probe-managed-capabilities "$root/runtime"
previous_secret="$(<"$root/runtime/bootstrap-secret")"
systemctl --user kill --kill-whom=main --signal=SIGKILL "$service_unit.service"
restarted=false
for _ in {1..200}; do
  current_secret="$(cat "$root/runtime/bootstrap-secret" 2>/dev/null || true)"
  if [[ "$current_secret" != "$previous_secret" ]] &&
     systemctl --user is-active --quiet "$service_unit.service"; then
    restarted=true
    break
  fi
  sleep 0.05
done
if [[ "$restarted" != true ]]; then
  echo "gloved did not recover under the delegated subgroup" >&2
  exit 1
fi
"$2" --probe-managed-capabilities "$root/runtime"
systemctl --user stop "$service_unit.service"
if systemctl --user is-active --quiet "$service_unit.service"; then
  echo "gloved service remained active after stop" >&2
  exit 1
fi

node_binary="${GLOVE_TEST_NODE_BINARY:-}"
if [[ -z "$node_binary" ]]; then
  node_binary="$(command -v node || true)"
fi
if [[ -z "$node_binary" || ! -x "$node_binary" ]]; then
  echo "SKIP: Node.js is unavailable for the inherited-stream probe" >&2
  exit 77
fi
set +e
systemd-run \
  --user \
  --collect \
  --wait \
  --pipe \
  --unit "$session_unit" \
  -p Type=oneshot \
  -p 'Delegate=cpu memory pids' \
  -p 'DelegateSubgroup=glove-host' \
  -E "GLOVE_TEST_NODE_BINARY=$node_binary" \
  /usr/bin/unshare \
  --user \
  --map-root-user \
  --mount \
  --propagation private \
  -- \
  "$1" --systemd-service-only
status=$?
set -e
if (( status == 77 )); then
  echo "delegated-subgroup topology was available but Glove rejected it" >&2
  exit 1
fi
exit "$status"
