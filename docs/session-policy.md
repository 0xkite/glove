# Gloved session policy

`gloved` validates remote identifier-only plans against operator-owned local
policy. Remote requests cannot supply executable paths, host paths, environment
variables, or raw secrets.

## Capability activation

| Configuration | Advertised session methods |
|---|---|
| Base service | authenticated receipt paging and acknowledgement |
| `--session-policy` | `validate_plan` |
| plus `--session-store` | `create_session`, `session_status` |
| Linux plus `--materialization-root` | `start_session`, `attach`, `write_stdin`, `resize`, `signal`, `detach`, `stop_session`, `cleanup_session` |
| plus `--library-bundle-root` | digest-bound read-only bundle projection |

Capabilities are derived from successfully constructed components. macOS does
not advertise managed-session resource enforcement.

`agent_runtime_adapter_schema_version` is independent of the raw process/PTY
lifecycle. It remains `0` until Glove creates a private agent home, expands an
exact Sage bundle into Codex/Pi-native locations, and commits the derived
context to the launch profile and receipt. Sage requires version `1` before
remote launch.

Direct-write plans are rejected at start because Glove does not yet have a
separate authenticated local-consent record. Harness bundle expansion is an
independent gate for every remotely managed agent session.

## Protected files

| Object | Required properties | Bound |
|---|---|---|
| Runtime and materialization directories | absolute, current-user owned, mode `0700` | dedicated paths |
| Policy | regular file, current-user owned, mode `0600`, one hard link, no final symlink | 1 MiB |
| Session store | parent mode `0700`; regular file mode `0600`; one hard link; exclusive writer | 64 MiB and 10,000 records |
| Bundle root | directory mode `0700`, identity-pinned | digest filenames only |
| Bundle | regular file mode `0600`, one hard link, no symlink | 16 MiB |

Policy and bundle reads use one descriptor and reject metadata or identity
changes during validation. Policy is frozen for the process lifetime; replace
it atomically and restart `gloved` to change it.

## Policy schema

The decoder rejects unknown fields. This example defines one runtime, one
ephemeral workspace grant, one library destination, and one mandatory resource
profile:

```json
{
  "schema_version": 1,
  "revision": 7,
  "max_plan_ttl_ms": 120000,
  "runtime_templates": [
    {
      "runtime_template_id": "codex-safe",
      "runtime_id": "codex",
      "adapter_command_digest": "05a49649e7973f6f8d6b119c9d525472517e6021fb38f8b191e0b40c8c4741d0",
      "sandbox_backend": "linux_production",
      "allowed_path_aliases": ["workspace"],
      "allowed_projection_destinations": ["libraries"],
      "launch": {
        "executable_path": "/usr/bin/true",
        "arguments": ["--version"],
        "environment": ["PATH=/usr/bin:/bin", "TERM=xterm-256color"]
      }
    }
  ],
  "path_aliases": [
    {
      "alias": "workspace",
      "host_path": "/srv/work/sage-protocol",
      "target_path": "/workspace",
      "max_ttl_secs": 120,
      "access": [
        {
          "access": "ephemeral_write",
          "materialization": "copy",
          "create_policy": "empty_directory",
          "cleanup_policy": "remove",
          "max_bytes": 2097152
        }
      ]
    }
  ],
  "library_projection_destinations": [
    {
      "alias": "libraries",
      "target_path": "/opt/sage/library-bundles"
    }
  ],
  "resource_profiles": [
    {
      "profile_id": "small",
      "cpu_time_ms": 1000,
      "memory_bytes": 67108864,
      "pids": 16,
      "wall_time_ms": 2000,
      "disk_bytes": 2097152,
      "terminal_output_bytes": 1048576
    }
  ],
  "egress_policy_ids": ["no-network"],
  "tool_policy_ids": ["sage-readonly"],
  "secret_handles": ["codex-token"]
}
```

A submitted plan must match:

- policy revision, expiry window, runtime and adapter digest;
- sandbox backend and all six numeric resource limits;
- egress, tool-policy, and secret identifiers;
- path aliases, access modes, materialization, cleanup, TTL, and byte quotas;
- library digests and configured destination aliases.

Arrays must be canonical and unique. Host paths and sandbox targets remain local
to the policy.

## Durable identity

Session creation stores the canonical plan and two digests:

- `controller_plan_digest`: Sage's 64-hex BLAKE3 correlation digest;
- `plan_content_digest`: Glove's SHA-256 digest of the exact canonical JSON.

A byte-identical retry with the same idempotency key returns the original
record. Reusing a session identity or key with different content fails closed.
Recovery rejects incomplete, corrupt, reordered, duplicate, or externally
resized records.

The lifecycle is:

```text
created → preparing → starting → running → stopping → exited
                         └──────────────────────────→ failed
```

Transitions are append-only and idempotent. Start authorization is short-lived
and bound to the session and both plan digests.

## Filesystem and launch binding

Path aliases are opened component-by-component without following links.
Restricted roots, overlapping aliases, non-canonical targets, and unsupported
file types are rejected. Resolved grants retain descriptor identity rather than
exposing a public raw host path.

Bundle requests contain a lowercase SHA-256 digest and destination alias. Glove
opens the digest-named file relative to the pinned root, rehashes it, and mounts
it read-only at the configured target. The launch binding and authenticated
terminal receipt commit each projection's identifier, destination, target, and
digest.

Runtime templates bind an absolute executable, ordered arguments, and canonical
environment to `adapter_command_digest`. Sage and Glove derive that digest
independently. Linux preparation then binds the launch to cgroup identity,
quota-backed filesystems, the six limits, and resolved projections.

## Receipts and recovery

Terminal resource receipts are HMAC-SHA-256 authenticated and chained to Sage's
trusted anchor. The producer reserves journal capacity before launch and
durably appends the terminal envelope before success. Delivery is paged and
acknowledgement must match the exact head; Sage archives before acknowledging.

Recovery identifies processes by boot ID, PID start time, and cgroup identity,
not PID alone. Identity mismatch has no signaling side effect. Orphaned
materializations are removed only after quota and descriptor checks.

## Remaining boundary

Glove projects exact bundle files but does not expand their contents into
agent-specific prompt-library directories or generate initial prompt context.
`prompt_ref` remains rejected. Direct host writes remain unavailable pending a
distinct authenticated local approval mechanism.
