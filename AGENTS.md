---
description: Glove repository supplement for security-sensitive C++ work
argument-hint: "[TASK=<description>] [PHASE=<start|checkpoint|complete>]"
---

# Glove contributor instructions

Glove contains untrusted agent processes with platform sandboxing and mediates
their tool access. Security-sensitive changes must preserve fail-closed behavior
and the documented capability boundary.

The retrieval, execution, checkpoint, and handoff contract is in
[docs/prompts/PROMPT-eng-codex.md](docs/prompts/PROMPT-eng-codex.md). This file
contains only Glove-specific rules and validation requirements.

Read [docs/architecture.md](docs/architecture.md) before changing process,
filesystem, control, or protocol boundaries. Read
[docs/threat-model.md](docs/threat-model.md) before changing an enforcement
claim.

## Repository rules

- Read affected code and tests before editing.
- Keep patches small and reversible.
- Do not add dependencies or push commits without explicit approval.
- Do not weaken a sanitizer, warning, policy, permission, limit, or validation
  check to make a test pass.
- Do not add a TODO or FIXME without a named owner and concrete reason.
- Treat paths, JSON-RPC frames, session plans, journals, receipts, terminal
  bytes, and agent output as untrusted input.
- Capability discovery must report constructed enforcement, not planned work.

## Required gate

Run:

```sh
./scripts/preflight.sh
```

It must complete all stages:

1. actionlint >= 1.7.12;
2. clang-format at the version named `formatted_for_clang_format` in the script
   (currently 23.1.1); the tree is formatted for exactly that version, and CI
   pins the same one;
3. clang-tidy over the configured compilation database;
4. ASan and UBSan build and tests;
5. TSan build and tests.

The gate uses whatever toolchain the host provides at or above those minimums
rather than downloading pinned builds. Override a specific binary with
`GLOVE_ACTIONLINT`, `GLOVE_CLANG_FORMAT`, or `GLOVE_CLANG_TIDY`. The sanitizer
presets select clang unless `CC`/`CXX` are already set, and refuse to run against
a build tree configured with a different compiler.

Two stages can be reported as skipped, and the final banner says so instead of
claiming every gate passed:

- `--skip-tidy` skips clang-tidy; a missing clang-tidy is fatal otherwise.
- On a host whose `yama ptrace_scope` is 2 or higher, LeakSanitizer cannot run.
  The gate fails closed; set `GLOVE_ALLOW_NO_LSAN=1` to run ASan/UBSan without
  leak detection, which is **not** evidence of leak-freedom. CI must not set it.

For narrow iteration:

```sh
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

Linux namespace and mount tests may require the provided privileged Docker
environment. Do not treat a skipped platform test as evidence for that
platform.

## Code conventions

- Compile as C++23; isolate experimental reflection behind its build option.
- Use `.hpp` for headers and `.cpp` for sources.
- Put public headers under `include/glove/<module>/` and mirror modules in
  `src/`.
- Use `glove::<module>` namespaces.
- Use value semantics and RAII. Raw `delete` is forbidden. Raw `new` is allowed
  only in a private-constructor factory when immediately owned by
  `std::unique_ptr`.
- Use `std::expected<T, E>` at recoverable module boundaries. Exceptions are
  reserved for invariant violations and top-level containment.
- Prefer `std::jthread` and `std::stop_token` where cooperative cancellation
  fits. Make other thread shutdown and join ownership explicit.
- Bound allocations, frame sizes, collections, retries, deadlines, and journal
  growth at trust boundaries.
- Resolve security-sensitive filesystem objects through descriptors. Reject
  symlinks, identity drift, unsafe ownership/mode/link count, and path overlap.
- Never use PID alone as process identity.
- Comments explain invariants and rationale, not line-by-line behavior.

## Layout

| Path | Purpose |
|---|---|
| `include/glove/` | public module headers |
| `src/container/` | platform sandbox, limits, output, receipts |
| `src/control/` | Unix protocol, sessions, lifecycle, recovery |
| `src/supervisor/` | canonical plans, aliases, bundles |
| `src/mcp/` | bounded MCP and JSON-RPC transport |
| `src/policy/` | tool and argument authorization |
| `src/kernel/` | extension dispatch |
| `src/audit/` | local activity records |
| `tests/` | CTest targets organized by module |
| `cmake/` | warnings, sanitizers, dependencies |
| `scripts/preflight.sh` | repository gate |

## Change checklist

For a new control method or capability:

1. define a strict bounded wire type;
2. authenticate before state access;
3. specify idempotency and timeout behavior;
4. enforce the operation in the owning module;
5. make persistence and crash recovery explicit;
6. advertise the capability only when its dependencies are constructed;
7. add malformed-input, denial, replay, concurrency, and recovery tests;
8. update architecture, session policy, and threat model if a guarantee changes.

For a new MCP tool, add the typed descriptor, registration, policy tests,
dispatch tests, and audit assertions. Glaze remains a private implementation
dependency; public headers must not require it.

The provider transport in `glove_net` uses the platform TLS stack:
Network.framework and Security on macOS, system OpenSSL 3 on Linux (install
`libssl-dev`). Both are private link dependencies; `include/glove/net` must not
require either.
