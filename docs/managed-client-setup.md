# Managed agent client setup

This runbook turns an operator-installed Codex, Claude Code, Pi, Copilot, or
OpenCode distribution into an explicit Glove runtime. It does not copy the
operator's home or make a client usable merely because it runs in the service
user's shell. Read the authority model and evidence status in
[client-adoption-matrix.md](client-adoption-matrix.md) first.

## Security outcome

A ready runtime has four independently reviewed closures:

1. an immutable executable and dependency closure;
2. a newly created `/home/agent` containing only Glove-owned client state;
3. optional credential leases at exact private-home targets; and
4. an exact egress policy, or `no-network`.

Keep the first deployment credential-free and offline. Provider access is a
separate profile and is never implied by client detection, Pi adoption, or a
successful `--version` probe.

## Prepare protected roots

Use owner-local roots outside client homes and enrolled projects. The examples
assume the Glove service user owns each directory and no other principal can
write it.

```sh
install -d -m 0700 \
  "$HOME/.local/share/glove/harnesses" \
  "$HOME/.local/share/glove/pi-adoption" \
  "$HOME/.local/share/glove/evidence"
install -d -m 0700 "$HOME/.config/glove"
```

Do not use `$HOME/.codex`, `$HOME/.claude`, `$HOME/.pi`, `$HOME/.copilot`,
XDG client-state directories, authentication directories, or package caches as
runtime dependency roots.

## Detect, stage, and pin each distribution

Detection reads only explicitly listed directories and never inherited `PATH`:

```sh
glove policy detect \
  --search-path /absolute/reviewed/client-bin \
  --json
```

For every selected runtime, stage its supported package/interpreter closure
into the protected root. Review the dry run before confirming it.

```sh
glove policy stage \
  --runtime <codex|claude-code|pi|copilot|opencode> \
  --source /absolute/reviewed/client-bin/<executable> \
  --directory "$HOME/.local/share/glove/harnesses" \
  --dry-run --json

# Repeat the identical command with --yes only after reviewing its paths and digest.
```

Generate and inspect the individual runtime entry using only the staged
executable or an explicit protected search directory:

```sh
glove policy generate \
  --runtime <runtime-id> \
  --executable /absolute/protected/staged/<executable> \
  --template-id <runtime-id>-safe
```

The adapter fixes the private home and native skill location:

| Runtime | Executable | Managed skill location | Glove-owned environment |
|---|---|---|---|
| `codex` | `codex` | `/home/agent/.codex/skills` | `CODEX_HOME=/home/agent/.codex` |
| `claude-code` | `claude` | `/home/agent/.claude/skills` | none |
| `pi` | `pi` | `/home/agent/.pi/agent/skills` | none |
| `copilot` | `copilot` | `/home/agent/.copilot/skills` | `COPILOT_HOME=/home/agent/.copilot` |
| `opencode` | `opencode` | `/home/agent/.config/opencode/skills` | `XDG_CONFIG_HOME=/home/agent/.config` |

Arguments, environment, and read-only dependencies are part of the local
runtime digest. A Sage plan can select only the resulting template ID and
digest; it cannot replace those fields.

## Adopt Pi packages without adopting Pi identity

Pi is the only built-in adapter with a package-adoption step. Use an explicitly
reviewed settings file and package store, then inspect the snapshot before
confirming it:

```sh
glove policy adopt-pi \
  --settings /absolute/reviewed/pi/settings.json \
  --package-store /absolute/reviewed/pi/package-store \
  --directory "$HOME/.local/share/glove/pi-adoption" \
  --dry-run --json

# Repeat with --yes only after reviewing selected packages, paths, and digests.
```

The result contains immutable package payloads and generated managed settings.
It excludes host authentication, sessions, provider/model selection, host
settings, package-manager credentials, and arbitrary Pi state. Never place
`auth.json` or a host Pi home in the adoption root.

## Generate the credential-free policy first

Build the full policy from the same reviewed roots. Omit `--secret` and
`--egress` for the baseline so the generated runtime remains credential-free
and uses `no-network`.

```sh
glove setup policy \
  --search-path /absolute/protected/staged/bin \
  --harness-root "$HOME/.local/share/glove/harnesses" \
  --path-root /absolute/enrolled-project-root \
  --output "$HOME/.config/glove/session-policy.json" \
  --backend linux_production \
  --runtime codex \
  --runtime claude-code \
  --runtime pi \
  --runtime copilot \
  --runtime opencode \
  --pi-settings /absolute/reviewed/pi/settings.json \
  --pi-package-store /absolute/reviewed/pi/package-store \
  --pi-adoption-root "$HOME/.local/share/glove/pi-adoption" \
  --dry-run --json

# Review the complete output, then repeat with --yes.

glove policy validate --file "$HOME/.config/glove/session-policy.json"
glove policy explain --file "$HOME/.config/glove/session-policy.json" --json
```

Select only runtime template IDs emitted by that policy when running `glove
setup`. Policy replacement is not live mutation: `gloved` freezes the policy
for its process lifetime, so restart it only after an approved atomic policy
replacement.

## Credential and egress profile

Create a separate online policy only after the offline lifecycle passes. A
credential source must be an owner-protected regular file outside every client
home and enrolled project. The controller receives only the opaque handle.

```sh
install -m 0600 /secure/input/client-credential \
  "$HOME/.config/glove/<runtime>-credential.next"

glove setup policy \
  <the reviewed baseline arguments> \
  --secret <runtime-id> <opaque-handle> \
    "$HOME/.config/glove/<runtime>-credential.next" \
    /home/agent/<exact-client-private-target> \
  --egress <policy-id> <exact-provider-host> 443 \
  --dry-run --json
```

Repeat `--egress` only for additional exact hosts required by the reviewed
client flow. Do not use wildcards, broad private-network access, a host
credential directory, or a provider's entire domain family. A credential does
not authorize egress, and egress does not authorize a secret handle.

Repository-tested credential targets are deliberately narrow:

| Runtime | Repository-approved target | Status |
|---|---|---|
| `codex` | `/home/agent/.codex/auth.json` | Covered by secret-policy, lease, launch-binding, and lifecycle tests |
| `claude-code` | none | Operator must verify the exact target for the pinned distribution before enabling a secret |
| `pi` | none | Host Pi auth is explicitly excluded; a future model profile must separately approve an exact managed target |
| `copilot` | none | Operator must verify the exact target for the pinned distribution before enabling a secret |
| `opencode` | none | Operator must verify the exact target for the pinned distribution before enabling a secret |

"None" is not permission to mount a directory. Until an exact target gains
executable review evidence, that client remains credential-free.

## Rotation and revocation

1. Write a new owner-only source file under a new filename.
2. Generate a dry-run policy with a new handle or content lease.
3. Validate and atomically install the reviewed policy.
4. Restart only `gloved`; do not restart unrelated services.
5. Run one bounded session and verify its plan/profile/receipt digests.
6. Revoke the old provider credential.
7. Remove the old policy handle in the next reviewed policy revision.
8. Retain redacted evidence; never copy credential bytes into logs or receipts.

Do not overwrite a live source file in place. Content-versioned leases and an
exclusive lock serialize use, but policy revision and provider revocation are
still explicit operator actions.

## Validation lanes

### Repository enforcement

Run the normal suite plus the Linux managed-session cases. These use synthetic
executables and real Glove filesystem, cgroup, terminal, receipt, stop, and
cleanup paths. A topology skip is a limitation, not passing enforcement
evidence.

### Installed distributions

Prepare one immutable test root with this reviewed shape:

```text
<harness-root>/
  node_modules/.bin/{codex,claude,pi,copilot,opencode}
  node-runtime/bin/
```

Then run the dedicated credential-free lane:

```sh
GLOVE_TEST_NATIVE_HARNESS_ROOT=/absolute/protected/harness-root \
  ctest --test-dir build/dev --output-on-failure \
  -R '^container_linux_native_harness_matrix$'
```

The lane invokes only `--version`, uses a fresh managed home, binds a verified
skill projection, enforces limits, verifies terminal/profile receipts, and
requires an empty materialization root after every client. If the variable or
a real distribution is absent, the lane must report a skip; synthetic clients
must not be substituted.

### Private model smoke

For each client, use a dedicated least-privilege credential and exact provider
egress. Submit one bounded non-sensitive prompt, disable wallet authority and
retained host writes, record plan/session/profile/receipt digests, stop the
session, and verify cleanup. This is private deployment evidence, not public CI.
Never claim model access from a successful `--version` probe.

## Recovery and evidence checklist

Record, without credential contents:

- client version and distribution/source digest;
- staged closure and Pi-adoption manifest digests;
- policy revision, runtime-template ID, and adapter digest;
- allowed secret handles and egress policy IDs;
- plan, profile, projection, terminal, and resource-receipt digests;
- stop/cancellation outcome and empty materialization root; and
- skip reasons for missing distributions or unavailable kernel enforcement.

After daemon or host recovery, require the same session identity and profile
digest before reconciling terminal state. A changed executable, dependency,
policy, Pi package snapshot, credential handle, or egress target requires a new
reviewed policy revision. Do not resume a session from host client state.

## Current limitations

- Repository tests prove shared Glove enforcement; they do not prove every
  vendor distribution remains compatible.
- Missing installed clients are explicit skips, not passes.
- Model-backed smoke requires private operator credentials and exact provider
  egress and is intentionally absent from public CI.
- Tool-policy identifiers are plan-bound, but harness-native tool enforcement
  is not yet a supported claim.
- Managed Pi does not gain Sage adapter connectivity until a policy-enforced
  Sage bridge exists.
- Linux resource claims require delegated cgroups and the required mount,
  namespace, and seccomp capabilities.
