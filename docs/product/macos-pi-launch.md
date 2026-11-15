# Native macOS harness launch

Research date: 2026-10-07. Pi M1 composition has scoped local review/fixture
coverage. Release and installed request/edit acceptance remain unproved. Codex CLI and Claude Code are first-class
support candidates. Their native adapters are unqualified.
Decision owner: operator and Glove maintainer.

## Decision

Should Glove let a macOS developer launch an installed Pi harness in the current
repository without a VM, a shell wrapper, or manual provider configuration,
while keeping provider credentials outside the agent?

Segment: macOS developers using Pi, Codex CLI or Claude Code. Pi is the initial
implementation; Codex/Claude need separate qualification, not provider aliases.
Job: continue coding with the existing harness under an OS-enforced perimeter.
Workaround: Linux container, manual runtime grants, and generated models.json.
Observed failure: the operator rejected that workaround as too verbose and
required native macOS. One operator report; no adoption-rate denominator.
Hypothesis: native launch and an owned Pi adapter reduce setup failures without
widening filesystem or network authority.

Pi dev invocation; not yet accepted for operator use:

```text
glove pi
```

Use the current directory as the proposed workspace. Resolve the installed
runtime and the selected provider/model from trusted operator configuration.
Require explicit setup when selection is absent or ambiguous. Do not infer
permissions or credentials from repository files.

## Harness scope

Proposed peer interfaces are `glove codex` and `glove claude`; neither is claimed
available. Each adapter must qualify runtime closure, API-key mediation, private
configuration, trust/automatic-network behavior, builtin tools and checked
lifecycle. Reuse the containment core; do not assume another harness follows Pi's
catalog, settings or session format. OAuth/subscription support, host-state import
and external services require separate decisions. No broad filesystem/network
fallback is allowed to make a candidate pass.

## Evidence

This table records the pre-implementation baseline at `dd243b6` (except the
separately inspected installed Pi source). Current implementation and
gate status are in [macos-pi-launch-plan.md](macos-pi-launch-plan.md).

| Source | Grade | Finding and applicability |
| --- | --- | --- |
| Operator feedback in this session | D | Native macOS and a shorter launch are required. Direct need, unknown prevalence. |
| dd243b6:src/container/macos/sandbox_spawner.cpp:275-295,369-373 | Code fact | SBPL already restricts raw proxy access to one loopback port; bridged reverse endpoints are explicitly refused. This locates the missing native launch capability, not its implementation difficulty. |
| dd243b6:src/run/runner.cpp:386-407 | Code fact | Pi's preset selects Anthropic; OpenAI is a separate preset. Harness identity and provider selection are coupled. |
| Installed Pi openai-responses.js:218 and docs/models.md | Code fact | OpenAI uses model.baseUrl. Merely injecting OPENAI_BASE_URL does not configure this installed Pi version. |
| dd243b6:docs/architecture.md:140-144 | Code fact | Provider responses are buffered; macOS refuses bridge_endpoint. Native TLS alone does not make the launch work. |
| [Command Line Interface Guidelines](https://clig.dev/) | C | Expert guidance favors useful defaults, concise output, and consent before changing another program's configuration. Direct CLI applicability; no Glove outcome data. |
| [Whitten and Tygar, USENIX Security 1999](https://www.usenix.org/legacy/events/sec99/full_papers/whitten/whitten.pdf), sections 2.1,2.2,6.3 | C | Security usability includes avoiding dangerous errors and remaining comfortable enough to continue. Small laboratory PGP study; informs guardrails, not predicted effects for coding-agent users. |
| [Claude Code sandbox documentation](https://code.claude.com/docs/en/sandboxing) | C | Advertises native macOS sandboxing. Its shell-only boundary differs from Glove's whole-process target. Its broad localhost exception is not a design to copy. |

Code facts are verified implementation observations, not evidence of user
prevalence or a causal UX effect. No launch-funnel telemetry or product research
ledger was found in docs. No production success-rate estimate is available.

## Ranked recommendations and hypothesis ledger

### 1. Native launch with an owned Pi adapter

Owner: container, run, and Pi integration maintainers. Cost: medium/high,
engineering estimate pending design. Affected population: macOS Pi users;
size unknown. Expected impact: removes the launch blocker. Evidence: operator
report D; verified code blocker; CLI guidance C.

Add exact per-run endpoint access on macOS. Generate private Pi configuration
inside the run's private home. Separate provider selection from harness identity.
Resolve the Node/package runtime closure rather than requiring user-written
read grants. Keep existing low-level exec syntax available.

Acceptance: a packaged native macOS smoke fixture launches installed Pi,
completes a provider request, and edits a workspace file using one recurring
command. No manual JSON, read grants, Docker, or raw provider secret in the
child. Test unrelated localhost ports, direct upstream access, outside-workspace
writes, and host auth files for denial. All security fixtures must pass.

Reversibility: additive launcher/adapter. Risk: runtime closure or endpoint
grants could overexpose the host. Do not advertise managed Linux six-limit
parity; that is a different contract.

### 2. Preserve approved harness state without importing host authority

Owner: Pi adapter and policy maintainers. Cost: medium, provisional.
Affected population: existing Pi users; size unknown. Expected impact: makes
contained launch useful for current workflows. Evidence: this session's harness
configuration and operator request D; CLI configuration guidance C.

Selectively project approved settings, skills, extensions, and optional session
state. Never mount the entire credential-bearing ~/.pi/agent directory. Define
supported services and auth methods explicitly; do not promise all current MCP,
subagent, web, or intercom integrations work automatically.

Acceptance: restart a fixture session with its approved model and resources;
verify host configuration is unchanged and host auth remains unreadable. An
unsupported service produces a specific diagnostic before launch, not an
uncontained retry. Denominator: every supported compatibility fixture.

Reversibility: opt-in projection. Risk: extension dependencies, service access,
and stored session content can introduce additional authority or sensitive data.

### 3. Concise launch status and actionable failure messages

Owner: CLI maintainer. Cost: low/medium, provisional. Population: launch users;
size unknown. Expected impact: reduces recovery effort. Evidence: operator
feedback D; CLI guidance C; security-usability principles C.

Show effective workspace, provider, credential isolation, and active restrictions.
A future verbose interface could show technical paths and grants; the current
prototype has no `--verbose` option. Missing credentials,
unsupported auth, and missing runtimes should each name one corrective action.
State that responses are buffered; do not imply token streaming.

Acceptance: every expected setup failure has a fixture asserting a concise,
secret-free diagnostic and nonzero exit. Permission expansion always requires
operator consent. Silent direct-network or secret-bearing fallback is forbidden.

Reversibility: output-only changes. Risk: short wording can overstate enforcement.

## Experiment

First run a formative task study with five macOS Pi developers, including this
operator. Five is a discovery budget, not a powered statistical sample. Use a
matched safe sandbox prototype and the current documented launch as a within-user
comparison; alternate order and record assistance.

Task: launch from a repository, complete one model request, edit a fixture file,
restart the session, and recover from one missing prerequisite.

Metrics: unassisted completion/participants attempting each task; time to first
successful request; manual configuration edits; assistance requests; and correct
identification of workspace/network permissions. Measure over each test session.

Provisional gate: at least four of five complete the launch within two minutes
after prerequisites are satisfied, with no handwritten configuration. Every
security fixture passes. This target is a proposed decision rule, not a measured
result. Stop on secret exposure, unexpected host access, or silent fallback.
Rework repeated task failures before a larger adoption study.

## Do not build

- A Docker-first macOS onboarding flow for this user segment.
- A shorter command that silently switches to raw credentials or direct egress.
- Broad Homebrew, home-directory, or localhost grants to make startup pass.
- A GUI before the native CLI launch and adapter work.
- Automatic public publishing, installation, or host configuration mutation.

## Research queries

- paperbridge: Why Johnny cannot encrypt (Crossref; weak matches).
- paperbridge: Why Johnny Can't Encrypt A Usability Evaluation of PGP 5.0
  (OpenAlex; exact title resolved; read the USENIX full paper).
- Web: command line interface guidelines configuration defaults error messages clig.dev.
- Web: Anthropic Claude Code sandboxing macOS sandbox-exec network proxy.

Implementation sequence: [macos-pi-launch-plan.md](macos-pi-launch-plan.md).
Next: record Pi release-gate gaps and qualify Codex/Claude using the per-harness
worklist. Installed and live acceptance need separate consent. Keep this follow-up separate from the TLS-forwarder review fixes.
