# Glove host setup

Glove setup is owner-local. It never accepts path authority from a project,
remote peer, or Sage plan. This protects the boundary described in
[architecture.md](architecture.md) and [threat-model.md](threat-model.md).

## 1. Inspect without writing

Choose an existing project root and one or more reviewed harness directories.
Discovery never searches inherited `PATH`, a host-home configuration tree,
credentials, sessions, or provider/model state.

```sh
glove setup plan \
  --path-root /absolute/project-root \
  --search-path /absolute/reviewed/harness-bin \
  --runtime codex \
  --json
```

The default JSON is read-only and summarizes a deny-network, credential-free
policy. It derives Glove-owned config, policy, and harness locations and emits
`runtime_template_ids` for the next step. Use `--show-policy` only when the
local operator needs the complete policy preview.

## 2. Apply reviewed policy and machine setup

Copy the reviewed paths and runtime template IDs from the plan. The two writes
are intentionally separate: the first stages the immutable harness closure and
writes an owner-only policy; the second creates owner-local machine state.

```sh
PROJECT=/absolute/project-root
HARNESS_ROOT=/absolute/glove-owned/harnesses
POLICY=/absolute/glove-owned/session-policy.json

glove setup policy \
  --search-path /absolute/reviewed/harness-bin \
  --runtime codex \
  --harness-root "$HARNESS_ROOT" \
  --path-root "$PROJECT" \
  --output "$POLICY" \
  --dry-run

glove setup policy \
  --search-path /absolute/reviewed/harness-bin \
  --runtime codex \
  --harness-root "$HARNESS_ROOT" \
  --path-root "$PROJECT" \
  --output "$POLICY" \
  --yes

glove setup \
  --path-root "$PROJECT" \
  --session-policy "$POLICY" \
  --runtime codex-safe \
  --dry-run

glove setup \
  --path-root "$PROJECT" \
  --session-policy "$POLICY" \
  --runtime codex-safe \
  --yes
```

Pi adoption additionally requires all of `--pi-settings`, `--pi-package-store`,
and `--pi-adoption-root`; Glove snapshots the selected package closure and
generates a private home. It never imports host Pi authentication, sessions,
provider/model settings, or package-manager credentials. The exact contract is
in [session-policy.md](session-policy.md).

## 3. Start and verify the local service

```sh
glove daemon start
glove doctor --json
glove init /absolute/project --purpose inspect
```

`inspect` is read-only. `experiment` and `retain` use isolated copy-backed
workspaces; they never grant direct host writes. `glove setup cleanup --dry-run`
shows Glove-owned resources, and cleanup requires the preview's ledger digest.

## Platform limits

Linux managed sessions require delegated cgroups, namespaces, mounts, and
seccomp; see [build.md](build.md). macOS does not advertise the managed Linux
resource-enforcement contract. Hostile-content analysis is Linux-only,
deny-network, credential-free, and data-only; see
[hostile-content-analysis.md](hostile-content-analysis.md).

Use [session-policy.md](session-policy.md) for custom egress, credential leases,
advanced policy generation, service recovery, and Sage integration. Those are
security-sensitive exceptions to this minimal owner-local flow.
