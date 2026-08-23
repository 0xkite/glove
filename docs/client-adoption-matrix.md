# Managed client adoption and containment matrix

This document defines how an operator-installed agent client becomes launchable
inside Glove and which evidence is required before the multi-agent matrix in
[`future-work.md`](future-work.md) is complete. Follow the operational sequence
in [managed-client-setup.md](managed-client-setup.md) without broadening these
authority boundaries.

## Host configuration is discovery input, not authority

Installing or configuring a client as the Glove service user is not sufficient
for managed launch. Glove deliberately does not inherit the service user's
`PATH`, home, authentication, sessions, provider/model selection, package-manager
credentials, or arbitrary client settings.

The operator must separately authorize four closures:

1. **Executable closure** — detect the client in an explicit search directory,
   then pin a canonical executable and any immutable dependencies in a runtime
   template. Package-manager trees that are not safe launch authority must first
   be copied with `glove policy stage` into a protected snapshot.
2. **Managed home closure** — Glove creates a fresh `/home/agent` and projects
   only adapter-owned configuration and verified Sage skills into the client's
   native locations.
3. **Credential closure** — an owner-protected source file is named only by an
   opaque secret handle in the controller plan. Linux copies it into a
   content-versioned lease and mounts the lease at an exact path below the
   managed home. The original host file and broader host home are never mounted.
4. **Egress closure** — a separate local policy names the exact allowed network
   targets. A credential does not imply network access, and network access does
   not imply a credential.

A client configured under user `bm` therefore becomes usable only after its
executable closure, private-home adapter, credential lease (when needed), and
egress policy have each been reviewed and bound into the Glove policy. This is
intentional: "works on the host" must never mean "inherits host authority."

## Supported adapter inventory

All built-in adapters use `/home/agent`, receive verified Agent Skills bundles,
and are bound to the same Linux managed-session filesystem and resource
lifecycle.

| Runtime | Executable | Native skill root | Adapter-owned environment | Managed configuration | Host-state adoption |
|---|---|---|---|---|---|
| `codex` | `codex` | `.codex/skills` | `CODEX_HOME=/home/agent/.codex` | Glove writes a minimal trusted-project `config.toml`; Glove remains the sandbox authority | None; credentials require an explicit secret mount |
| `claude-code` | `claude` | `.claude/skills` | None | None | None; credentials require an explicit secret mount |
| `pi` | `pi` | `.pi/agent/skills` | None | Glove generates `settings.json` from the adopted package snapshot | Explicit package-closure adoption only; auth, sessions, host settings, model state, and package credentials are excluded |
| `copilot` | `copilot` | `.copilot/skills` | `COPILOT_HOME=/home/agent/.copilot` | None | None; credentials require an explicit secret mount |
| `opencode` | `opencode` | `.config/opencode/skills` | `XDG_CONFIG_HOME=/home/agent/.config` | None | None; credentials require an explicit secret mount |

Pi is intentionally different. `glove policy adopt-pi` reads an explicitly named
host settings file only to select package closure members from an explicitly
named package store. It emits immutable payload snapshots and a generated
managed setting containing relative extension paths plus
`enableSkillCommands=true`. It does not copy the host settings document.

## Operator workflow

For every client:

```sh
glove policy detect --search-path /absolute/reviewed/bin --json

glove policy stage \
  --runtime <runtime-id> \
  --source /absolute/reviewed/bin/<executable> \
  --directory /absolute/protected/runtime-root \
  --dry-run

# Review, then repeat with --yes.

glove policy generate \
  --runtime <runtime-id> \
  --executable /absolute/protected/runtime-root/<executable> \
  --template-id <runtime-id>-safe
```

Pi additionally requires a separate adoption preview and confirmed snapshot:

```sh
glove policy adopt-pi \
  --settings /absolute/reviewed/pi/settings.json \
  --package-store /absolute/reviewed/pi/package-store \
  --directory /absolute/protected/pi-adoption \
  --dry-run

# Review, then repeat with --yes.
```

Credential source files and egress targets are added only through a separately
reviewed policy generation step. Client homes or authentication directories are
never valid runtime dependency roots.

## Containment evidence matrix

`Required` means the repository must provide executable evidence for every
supported adapter. Shared lifecycle evidence may be parameterized by runtime ID
when the enforcement code is client-independent. An installed-client probe is
still required to prove the pinned distribution starts through the same path.

| Invariant | Current evidence | Required completion evidence | Status |
|---|---|---|---|
| Explicit executable authority | Runtime-template validation rejects inherited `PATH`; detection and staging tests cover canonical protected paths | Keep one shared denial suite and one successful staged closure per distribution shape | Partial |
| Fresh private home | Synthetic Linux managed-session cases cover all five native roots | Parameterized assertion for every adapter that host homes and unrelated client state are absent | Partial |
| Native skill projection | Synthetic Linux cases cover all five skill roots and receipt-bound bundle digests | Retain shared projection assertions for every adapter | Covered |
| Managed environment | Synthetic cases cover Codex, Copilot, and OpenCode variables | Assert exact environment allowlist and absence of representative inherited variables for all five | Partial |
| Managed client configuration | Codex and Pi generated files have focused tests | Assert no unmanaged configuration appears for Claude Code, Copilot, or OpenCode | Partial |
| Pi package adoption | Dedicated snapshot, mutation, ownership, link-count, auth/session exclusion, and generated-settings tests | Keep Pi-specific adoption evidence; do not generalize it into host-home copying | Covered |
| Credential isolation | Generic secret-lease and launch-binding tests cover owner files, private-home targets, and runtime binding | Add a table of reviewed client credential target paths and a no-secret startup probe; real credentials remain outside CI | Partial |
| Egress isolation | Linux no-network lifecycle tests are client-independent | Run the same deny-network probe under every adapter identity; online provider access requires a separate opt-in lane | Partial |
| Tool-policy binding | Session-plan validation binds an allowed tool-policy identifier into the canonical plan | Prove the identifier reaches the Sage/controller authorization boundary; do not claim harness-native tool enforcement that does not exist | Gap |
| Terminal limits | PTY, transcript, input, output, resize, signal, and stop tests cover the shared lifecycle | Parameterize adapter identity in terminal receipt assertions or document the shared binding proof | Partial |
| Cancellation and cleanup | Shared Linux process-tree, cgroup, materialization, and cleanup tests exist | Parameterize each adapter identity and require empty materialization roots after exit/stop | Partial |
| Crash recovery | Session/process identity and journal recovery tests cover the shared lifecycle | Demonstrate that every adapter launch uses the same recoverable session identity and profile digest | Partial |
| Installed client startup | Dedicated `container_linux_native_harness_matrix` runs `--version` for Codex, Claude Code, Pi, Copilot, and OpenCode through managed PTYs; a missing harness root is an explicit CTest skip | Run this lane against a protected root containing every reviewed distribution and retain its receipts/output as deployment evidence | Partial |
| Model-backed smoke | No credentialed provider call is claimed | Optional operator-run lane with dedicated credentials, exact egress, bounded prompt, receipts, rotation, and cleanup; never a required public CI secret | Gap |

## Required test lanes

### Repository lane

The ordinary test suite remains credential-free. It must cover all five adapter
identities with synthetic executables while exercising real Glove enforcement:
filesystem projection, private home, environment scrubbing, no-network policy,
resource limits, terminal behavior, cancellation, receipts, and cleanup.

### Installed-client lane

A dedicated Linux CTest lane receives a protected, prebuilt harness root through
`GLOVE_TEST_NATIVE_HARNESS_ROOT`. It runs the real installed executables only
through the normal adapter and managed-session path:

```sh
GLOVE_TEST_NATIVE_HARNESS_ROOT=/absolute/protected/harness-root \
  ctest --test-dir build/dev --output-on-failure \
  -R '^container_linux_native_harness_matrix$'
```

It must:

- include Codex, Claude Code, Pi, Copilot, and OpenCode;
- verify immutable executable/dependency mounts;
- invoke a credential-free command such as `--version`;
- bind a verified skill projection and private home;
- produce a terminal receipt tied to the launch profile and projection digest;
- enforce resource and output ceilings;
- leave no materialization behind; and
- emit an explicit skip when a client distribution is unavailable.

This lane proves distribution compatibility, not model-provider access.

### Operator model-access lane

A model-backed smoke is private deployment evidence. Each client gets a
dedicated least-privilege credential, an exact credential target beneath its
private home, and an explicit provider egress allowlist. The test uses a bounded
prompt, no wallet, no host auth, and no retained host write. Rotate by installing
a new owner-protected source, updating the policy to a new handle or content
lease, verifying one session, then revoking the old credential.

## Completion rule

The `future-work.md` multi-agent item is complete only when:

1. every repository-lane row above is `Covered`;
2. the installed-client lane is a separately visible test and includes all five
   adapters without silently substituting synthetic clients;
3. skipped kernel or missing-distribution probes are reported as skips, not
   passes;
4. a review confirms that client-specific code cannot bypass the shared Linux
   filesystem, resource, terminal, receipt, and recovery lifecycle; and
5. documentation preserves the separation between executable, managed-home,
   credential, and egress authority.
