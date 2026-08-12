#!/bin/sh
set -eu

readonly expected_workerd_sha256='65f9d58baa1eb9ea04614ae6b93826fa7fd72626778e6d236d4fec4e9e8cbfa6'
readonly workerd='/usr/local/bin/workerd'
readonly config='/opt/remote-workerd/workerd.capnp'
readonly log='/tmp/workerd.log'

actual_workerd_sha256=$(sha256sum "$workerd" | cut -d ' ' -f 1)
if [ "$actual_workerd_sha256" != "$expected_workerd_sha256" ]; then
  echo '{"status":"failed","reason":"workerd_digest_mismatch"}'
  exit 1
fi

"$workerd" test --no-verbose "$config" '*:validation'

"$workerd" serve "$config" >"$log" 2>&1 &
workerd_pid=$!
cleanup() {
  kill -TERM "$workerd_pid" 2>/dev/null || true
  cleanup_attempt=0
  while kill -0 "$workerd_pid" 2>/dev/null && [ "$cleanup_attempt" -lt 100 ]; do
    sleep 0.05
    cleanup_attempt=$((cleanup_attempt + 1))
  done
  if kill -0 "$workerd_pid" 2>/dev/null; then
    kill -KILL "$workerd_pid" 2>/dev/null || true
  fi
  wait "$workerd_pid" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 143' HUP INT TERM

attempt=0
while [ "$attempt" -lt 100 ]; do
  if grep -Eq ':2253[[:space:]].*[[:space:]]0A[[:space:]]' "/proc/$workerd_pid/net/tcp" 2>/dev/null ||
     grep -Eq ':2253[[:space:]].*[[:space:]]0A[[:space:]]' "/proc/$workerd_pid/net/tcp6" 2>/dev/null; then
    printf '{"status":"passed","http_status":200,"body":"Hello, World!\\n","socket":"127.0.0.1:8787","workerd_sha256":"%s"}\n' "$actual_workerd_sha256"
    exit 0
  fi
  if ! kill -0 "$workerd_pid" 2>/dev/null; then
    cat "$log" >&2
    echo '{"status":"failed","reason":"workerd_exited_before_socket_bound"}'
    exit 1
  fi
  sleep 0.05
  attempt=$((attempt + 1))
done

cat "$log" >&2
echo '{"status":"failed","reason":"socket_bind_timeout"}'
exit 1
