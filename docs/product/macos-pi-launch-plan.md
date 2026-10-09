# Native macOS harness launch plan

Pi has an implemented prototype CLI with synthetic fixture and scoped review
evidence. Installed startup, request/edit behavior and live-provider compatibility
remain unqualified. Current whole-change review and complete gates are still open.
A prior full preflight pass predates the current corrections.

Base: merged TLS-forwarder PR #39, `dd243b6`.
Branch: `feat/macos-pi-launch`.
Usage: [Native macOS Pi](../native-pi.md).
Product rationale: [Native harness launch](macos-pi-launch.md).

Draft PR preparation, normal commit and push are authorized only after current
review, required gates and normal hooks pass. Installed Pi staging/execution,
live providers, OAuth, imports, new dependencies, merge and release are excluded
from that authorization.

## Target

From an admitted repository, launch Pi without a VM or shell wrapper:

```text
glove pi
```

Explicit setup supplies a protected runtime and builtin provider/model selection.
Launch does not perform automatic setup, import host configuration, grant project
trust or substitute another model. Missing prerequisites fail before execution.

| Milestone | Acceptance |
| --- | --- |
| M1 | Installed Pi completes a mediated API-key model request and edits only an admitted workspace; endpoint, host-key isolation and lifecycle negatives pass |
| M2 | Approved resources load and Glove-owned session continuity works without host auth exposure or host configuration changes |
| Full harness | Each selected external integration has a reviewed capability and exercised compatibility fixtures |

Synthetic tests do not complete these installed milestones. No launch-funnel
telemetry or measured adoption effect is claimed. M1 does not reproduce the
operator's full harness.

## Implemented interface

```text
glove pi setup --provider openai --model MODEL_ID --yes
glove pi refresh --provider openai --model MODEL_ID --yes
glove pi [--provider openai|anthropic] [--model MODEL_ID] [--workspace DIR]
glove pi -- [--print|-p] [--thinking LEVEL] [--mode text|json] PROMPT
```

The current directory is the default workspace. Setup/refresh need explicit
consent before discovery, dependency inspection, protected copying or replacement.
Noninteractive setup requires provider, model and `--yes`. `MODEL_ID` must match
an exact builtin catalog entry; no availability or account entitlement is implied.

Forwarded arguments use a closed allowlist. `--continue`, `--resume`, `--verbose`,
`@file`, arbitrary runtime/config/endpoint/environment overrides and automatic
resource import are unsupported. Detailed grammar and paths are in the usage
reference. Existing `run`/`exec` behavior remains; legacy `exec --agent pi` still
selects Anthropic rather than this native frontend.

## M1 contracts

### Selection and runtime

- Owner-private canonical records contain runtime provenance and provider/model
  identity, not credentials. Replacement requires consent.
- Discovery is a seed, not launch authority. Recurring launch validates the
  protected copied runtime, source provenance, topology, content and bounds.
- Resolve Node, package, libraries, opaque resources and safe relative links.
  No ambient PATH or broad Homebrew/home grant repairs an unsupported closure.
- Exclude known operator auth/control authority before hashing/copy and during
  read-only validation. Exclusions remove authority; they are not guest grants
  or global secret-filename filtering. Native setup and launch propagate bounded
  roots from admitted machine configuration. Synthetic producer/consumer checks
  pass; fresh whole-change gates remain required. Config is admitted once per
  operation, not held as an atomic snapshot against same-UID mutation.
- Unsafe existing objects are refused before mutation, not repaired. Exclusive
  creation, descriptor identity, ancestry, ACL and name/version checks govern
  publication and reuse. Darwin ACL evidence does not imply Linux ACL parity.

### Provider and configuration

| Provider | API | Host credential |
| --- | --- | --- |
| OpenAI | Responses | `OPENAI_API_KEY` |
| Anthropic | Messages | `ANTHROPIC_API_KEY` |

Only API-key authentication is in scope. Do not execute command-valued credentials,
model discovery, extensions or package installers to acquire authority.

The copied builtin catalog is model authority. Generated private configuration
changes only the selected provider URL and literal per-run nonce, preserving
builtin metadata. No host overlays, model upserts or imported auth/settings are
used. Extensions, MCP, skills, templates, themes and context-file discovery are
disabled for this prototype.

The host endpoint substitutes the real provider key after nonce admission. Guest
argv, environment, files, errors and audit must not receive the injected host key.
Fixed provider routes use verified TLS with no redirect, plaintext, raw-key or
verification-relaxation fallback. Responses are buffered; installed Pi's streaming
and cancellation behavior require separate qualification.

### Perimeter and lifecycle

macOS admits one exact AF_INET loopback TCP endpoint, not general localhost,
neighboring ports, UDP, IPv6 or direct upstream access. Endpoint and raw CONNECT
proxy authority are mutually exclusive. Linux's namespace relay is a different
mechanism; native Pi launch on Linux remains unsupported.

The workspace is owner-private and disjoint from admitted host/runtime authority.
A `.pi` entry or case alias is refused. Copied runtime and generated authority are
immutable; writable private state does not permit their replacement.

Admit open stdio before internal descriptors. Check spawn configuration, preserve
captured terminal behavior, and retain original-group ownership through bounded
inspection. Reap, ESRCH, a dead leader or an absent lease is not proof that all
descendants died. Unknown ownership stops signaling authority.

Revoke/stop/join the endpoint before private cleanup, including creation rollback.
Only eligible constructing or checked-quiescent state is removable; uncertain or
launching state remains. Complete read-only tree admission precedes permission
narrowing and deletion. Preserve earlier siblings when a pre-existing later object
is unsafe; do not claim an atomic same-UID namespace snapshot.

The private default audit sink refuses instead of dropping or evicting events at
1,024 retained events or 1 MiB logical event/string charge. This is not an allocator
or RSS limit. Audit allocation errors remain failed results; persistent allocation
failure during cleanup is not a whole-launch no-throw guarantee.

No detached-process-tree death, hard kernel-reap/syscall deadline, all-thread
FD/signal identity, or managed Linux six-limit/terminal-receipt parity is claimed.

## Remaining delivery work

1. Verify the configured source-authority correction in fresh required gates:
   producer/consumer refusals before hashing/copy and positive disjoint resources.
   Keep the stable-control-input scope explicit.
2. Finish whole-current-change review, exact scope/hash ledgers and outstanding
   static-analysis triage. Incomplete analysis is not clean evidence.
3. Review correction/module/documentation deltas. Keep focused ownership,
   filesystem and reusable fixture modules below the configured hook limit;
   no exemptions, compression, threshold changes or hook bypass.
4. Refresh the complete tracked/untracked inventory and test registrations.
   Check for secrets, unrelated artifacts and unsupported claims.
5. Run all required `scripts/preflight.sh` stages with the pinned formatter:
   actionlint, format, configured tidy, ASan/UBSan tests/fuzz and TSan tests.
   Report warnings and platform skips; neither is erased by an outer exit code.
6. Commit through normal hooks, push normally, create/read back a draft PR.
   Draft publication is not installed acceptance or release approval.
7. Obtain separate authorization for installed Pi staging/execution, a scoped
   request/edit acceptance test and opt-in live-provider checks. Stop on secret
   exposure or unexpected authority; never widen grants to make startup pass.

Keep deterministic, installed and live lanes separate. Childless endpoint/owned
callbacks model contracts, not real worker joins or process-group death. Source
inspection of an installed package is not execution compatibility evidence.

## Peer harness qualification

Pi, Codex CLI and Claude Code are first-class harness candidates, not provider
aliases. `glove codex` and `glove claude` are proposed, unimplemented and
unqualified. Pi fixtures do not certify them.

Each peer needs its own version/source identity and qualification of:

- Executable, interpreter, package, library and resource closure.
- API-key-only provider interface, endpoint replacement and nonce authentication.
- Actual paths, buffering/streaming, retries, cancellation and errors.
- Protected model identity/metadata and closed configuration/argv/environment.
- Startup user/project config, trust, hooks/plugins/MCP, telemetry and network.
- Immutable authority, reserved namespaces, private state and builtin tools.
- Stdio/TTY, subprocesses, signals, endpoint revocation and retained uncertainty.

Share tested containment, staging and checked teardown only where contracts match.
Do not assume Pi's catalog, settings or session formats. Extract common adapter
code only when a second tested consumer needs it.

Existing legacy discovery/projections are seeds, not native acceptance.
Codex's managed trusted-project config and
`--dangerously-bypass-approvals-and-sandbox` must not be copied into a native
frontend without qualification. Claude's lack of a managed config/adoption
manifest is not a safe-startup result. See
[client adoption matrix](../client-adoption-matrix.md) for separate Linux evidence.

## M2 and external services

Resource projection, session retention/resume/import, subagents, language servers,
Sage MCP/daemon, GitHub/web services and intercom need separate decisions and
capability designs. Extensions are executable authority. Never mount an entire
credential-bearing host harness directory or launch host helpers implicitly to
bypass containment.

Approved snapshots and owned sessions require bounds, path/ACL/identity checks,
explicit retention and import consent, and host-configuration preservation tests.
A general broker, OAuth/subscriptions and streaming transport are not M1 work.
The formative study in the product note remains proposed, not measured.
