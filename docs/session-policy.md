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
| `--path-exposure-policy` plus `--path-exposure-journal` | local exposure administration and redacted catalog |

Capabilities are derived from successfully constructed components. macOS does
not advertise managed-session resource enforcement.

`agent_runtime_adapter_schema_version` is independent of the raw process/PTY
lifecycle. It remains `0` until Glove creates a private agent home, expands an
exact Sage bundle into Codex/Pi-native locations, and commits the derived
context to the launch profile and receipt. Sage requires version `1` before
remote launch.

`direct_write` remains a legacy parse-only value and is rejected at launch.
New write-capable plans use isolated `retained_write` materializations; applying
their changes to the source is a separate, not-yet-enabled operation.
On Linux, retained copies use a hard-sized ext4 image attached through an
autoclear loop device so the staged filesystem survives daemon and host
restarts. Ephemeral copies and session scratch remain quota-sized tmpfs mounts.
Retained images require a root-owned, non-writable `/usr/sbin/mkfs.ext4` or
`/sbin/mkfs.ext4`, loop-control access, and mount capability.

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

## Dynamic path exposures

Exposure policy defines owner-approved roots, exact mode/quota tuples, maximum
TTL, and runtime templates. The paired journal records local descendant leases.
Both files require owner-only placement; the journal is bounded, hash-chained,
single-writer, and replayed strictly.

On Linux, descendants resolve with `openat2` using `RESOLVE_BENEATH`,
`RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`, and `RESOLVE_NO_XDEV`.
Other platforms use component-wise no-follow descriptor traversal. A catalog
entry exposes only its ID, generation, scope digest, label, allowed modes,
expiry, runtimes, and state. Paths, root IDs, and source identities remain
local. Replacing a live generation requires revocation or expiry.

`glove init <project>` is the owner-local enrollment client. It canonicalizes
the project path and requests one exposure beneath a root created by
`glove setup --path-root`; remote session requests cannot invoke enrollment or
supply a host path.

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

Retained changes are staged and inspected separately from host mutation. The
apply authorization schema, root-controlled Ed25519 trust-policy loader,
durable single-use reservation journal, and Linux whole-entry atomic-exchange
primitive are present. The primitive rejects stale baselines, copies without
following links, recursively syncs the candidate, uses
`renameat2(RENAME_EXCHANGE)`, and retains the old source for recovery. No
production signature backend or privileged signing helper is wired. Receipt
construction, reconstructable durable terminal finalization, prepared-candidate
discard, committed-state recovery, and idempotent baseline cleanup are
implemented locally. Grant IDs, authorization digests, and manifest digests are
each globally single-use. Ambiguous states remain consumed and non-terminal. These
operations are not yet connected to the control server, receipt audit stream,
or startup recovery sweep. Glove therefore advertises apply schema version `0`
and rejects apply operations.

Apply supports only service-owned, single-link, non-sparse regular files and
directories without ACLs, extended attributes, symlinks, special files, or
special mode bits. Contents and child modes come from the frozen stage; the
source-root mode is retained; ownership is normalized to the Glove service
identity; timestamps are intentionally regenerated. A production deployment
must also prevent Sage from mutating the source parent during the final
identity-check/exchange interval. Same-UID access to that parent is not a
sufficient boundary.

The pre-reservation and execution checks also require the full logical staged
tree plus a 64 MiB reserve to fit in the source filesystem's currently
available blocks. Copy bounds and filesystem errors still fail closed if
concurrent disk use consumes that headroom.

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
materializations are removed only after quota and descriptor checks. Retained
images are remounted and frozen before cleanup; volatile materializations lost
across a host restart are removed as empty mountpoints.

Reserved apply transactions can reopen the exact journaled exposure parent by
descriptor after lease revocation or expiry. This recovery-only lookup requires
the exposure ID, generation, scope digest, and original source-identity digest;
the local exposure journal also binds the parent directory identity, so a
replacement at the same path is rejected. The lookup exposes neither a raw path
nor launch authority.

Recovery classifies only four descriptor-proven states: reserved, prepared,
committed, or ambiguous. Reserved and safely discarded prepared transactions
receive durable failed receipts. Committed exchanges receive durable applied
receipts before baseline cleanup. The journal stores the stable failure code
and all receipt bindings, so either terminal receipt can be reconstructed after
restart. Failed terminal receipts require no surviving stage or exposure
locator. Applied terminals resolve those objects only to retry baseline
cleanup. The bounded startup reconciler reports redacted per-record issue
codes. Ambiguous transactions are never retried or terminalized automatically.

## Remaining boundary

Glove projects exact bundle files but does not expand their contents into
agent-specific prompt-library directories or generate initial prompt context.
`prompt_ref` remains rejected. Live direct host writes are outside v2. Applying
a retained stage remains unavailable until Glove verifies an independently
signed, single-use local authorization.
