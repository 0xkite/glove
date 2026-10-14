# Native macOS harness launch plan

Refactor the Pi prototype into a harness-neutral native launch core and a
concrete Pi adapter. Preserve the implemented security checks and fixtures;
do not restart the containment work or wrap the existing Pi pipeline in a class
without separating ownership.

Prototype baseline: `5bcfac4`, based on merged TLS PR #39 (`dd243b6`).
Draft PR #40 is closed and unmerged. Its 98-file review and complete macOS
preflight passed before this refactor: exact clang-format 23.1.1, actionlint,
configured tidy, ASan/UBSan and TSan (110 passed and one existing Apple-container
integration skip each), and seven fuzz lanes. Tidy advisories and linker warnings
remain. This evidence characterizes the baseline, not the refactored code.
Installed startup, request/edit behavior and live-provider compatibility remain
unqualified.

Branch: `feat/macos-pi-launch`.
Usage: [Native macOS Pi](../native-pi.md).
Product rationale: [Native harness launch](macos-pi-launch.md).

The current continuation authorizes plan changes, local refactoring, synthetic
tests and required review/gates. It does not authorize another commit, push, PR,
installed Pi staging/execution, live providers, OAuth, imports, new dependencies,
host-configuration changes, merge or release.

## Architecture direction

Keep one containment/enforcement core. Separate four concerns:

| Layer | Owns | Must not own |
| --- | --- | --- |
| Native launch core | Host authority admission, workspace witnesses, bounded projection validation, nonce/endpoint ownership, private run lifecycle, audit and cleanup | Pi catalog/config semantics or harness-specific CLI parsing |
| Harness adapter | Harness-specific runtime layout interpretation, builtin catalog/configuration encoding, closed argv/environment and reserved namespace requirements | Selection/catalog authorization, raw host credentials, endpoint creation, arbitrary grants, process launch or cleanup authority |
| Provider integration | Closed API routes, host credential selection/substitution, verified TLS and transport bounds | Harness identity, package layout or managed capability advertising |
| Platform backend | Constructed OS sandbox and process mechanisms | Invented resource/receipt parity or harness-specific model choices |

The local working tree uses the host-only `native_harness_adapter` contract and
`src/adapters/pi/native_harness.cpp`. The class encodes bounded startup recipes;
it owns no spawn, cleanup or capability interface. `src/run/pi_launch.cpp` admits
Pi records/catalogs and delegates to `src/run/native_launch.cpp`.
`native_private_state.cpp` and `native_audit.cpp` own shared storage and audit;
Pi facades preserve their existing APIs and persisted lease format. Current
validation is incomplete. These changes do not inherit the baseline's gates.

Adapters are compiled trusted implementations, not dynamic plugins or objects
selected by project files. They return bounded typed requirements and projections;
the host core admits them before effects and rechecks authority before launch.
Malformed or unsupported requirements fail before credentials, endpoint creation
or child execution. An adapter receives the bound endpoint URL/nonce, not the real
provider key. Returned strings/spans must have explicit ownership; no temporary
catalog or callback lifetime may escape its synchronous owner.

Keep managed-session capabilities distinct. The existing Sage guest-schema and
managed skill-projection adapters do not, by themselves, implement native harness
startup. Do not repurpose their schema versions, receipt bindings or resource
claims. Native launch and managed sessions may share mechanisms without becoming
identical contracts. The existing `run` MCP mediation versus `exec` direct-tool
split also remains unchanged.

Migrate private-state and audit enforcement behind harness-neutral ownership
without changing Pi's persisted selection, private paths, marker format, bounds
or recovery semantics. Harness-specific configuration bytes and relative filenames
belong to Pi; descriptor admission, immutable publication and removal belong to
the core. A generic filename or environment field is not an arbitrary authority
escape hatch.

Host composition selects a closed startup policy independently of encoder output.
Require exact environment `(name, private-location)` pairs, configuration leaves,
workspace reservations and ordered arguments. Typed argument slots bind provider,
model, private sessions and the approved forwarded suffix; deny-name checks are
only defense in depth. The compiled encoder retains configuration-format
semantics. Generic shape checks do not prove the URL encoded inside opaque bytes.

The core separately admits runtime-library projection: zero entries or one
`DYLD_LIBRARY_PATH`, at most 32 KiB, 64 components and 4,096 bytes per component.
The ordered values must match copied `payload/root-N/lib` directories. Regular
file leaves are not library directories. Internal aliases require bounded,
snapshot-confined descriptor resolution with inode ACL and name/version checks.
No supplied environment path becomes a grant. Source/digest admission remains
mandatory; metadata unit fixtures do not qualify installed library layouts.

Only Pi is a production adapter in this refactor. Use a bounded synthetic adapter
to test the common contract, not to claim Codex/Claude support. No public plugin
registry, new CLI, provider feature, backend capability or installed acceptance
is required to demonstrate the separation.

## Target

From an admitted repository, launch Pi through the shared core without a VM or shell wrapper:

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
  pass in the prototype baseline; fresh refactor gates remain required. Config
  is admitted once per operation, not held as an atomic snapshot against same-UID
  mutation.
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

## Refactor sequence

1. Record the ownership map and compare existing managed adapters with native
   startup needs. Keep the common contract free of `pi_*` types. Read affected
   interfaces and complete callers before editing. Retain `5bcfac4` as the
   reversible baseline; do not reset, rebase or discard it.
2. Characterize the current synthetic launch, setup/refresh and refusal behavior.
   Add adapter-boundary tests before implementation: valid projection, malformed
   or excessive requirements, unsupported backend/provider, immutable authority,
   and refusal before credential/endpoint/executor callbacks. Test a synthetic
   adapter through the same core, not an alternate mock lifecycle pipeline.
3. Introduce the typed startup adapter class and implement Pi-specific
   catalog/configuration encoding, runtime layout and closed arguments using
   the existing helpers. Keep protected selection/catalog authorization in the
   host composition, separate from startup encoding. Keep public Pi APIs and CLI
   semantics unchanged. Return owned values or explicitly synchronous borrows,
   with `std::expected` failure boundaries.
4. Extract the common native launch orchestration, private-state enforcement and
   audit ownership. Preserve early stdio admission, every source exclusion before
   hashing/copy, final runtime/catalog/library/workspace revalidation, nonce-only
   guest configuration, endpoint revocation before rollback/removal and retained
   uncertainty. The adapter cannot bypass these checks or supply a ready-made
   unrestricted sandbox profile.
5. Run focused producer/consumer, CLI/runtime/catalog, private configuration,
   ACL/alias, closed-stdio, endpoint, owned lifecycle, audit/allocation and cleanup
   regressions after each extraction. Preserve legacy `run`/`exec`, including
   Anthropic selection for `exec --agent pi`. Do not manufacture a second
   production adapter or weaken a check to make reuse appear complete.
6. Freeze the refactor and independently review complete changed source, helpers,
   tests and callers. Verify ownership, projection validation, failure ordering
   and unchanged authority. Update architecture claims only when constructed.
   Keep source modules below the unchanged hook limit; no exemptions, compression,
   threshold changes or bypass. Inventory tracked and untracked work explicitly.
7. Run the entire current `scripts/preflight.sh` with exact clang-format 23.1.1:
   actionlint, configured tidy, ASan/UBSan tests/fuzz and TSan tests. Keep `tee`
   inside `set -euo pipefail`. Read actual stage results, warnings, skips and
   sanitizer reports. Any subsequent source correction invalidates this gate.
8. Save the reviewed local result and report implemented boundaries and limits.
   A new commit/push/PR and installed/live qualification need separate approval;
   closing PR #40 does not discard the branch or authorize republication.

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
Extract the existing host enforcement into the common native core now; keep Pi's
catalog, settings and session formats in its adapter. Extend the contract for a
peer only after its requirements and negative fixtures are understood. A synthetic
contract consumer demonstrates separation, not installed compatibility.

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
