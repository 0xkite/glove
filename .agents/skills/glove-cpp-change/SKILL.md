---
name: glove-cpp-change
description: Read before changing or reviewing Glove C++ or CMake code, including PR diffs, lifecycle, receipts, projections, cleanup, and concurrency.
license: MIT
metadata:
  scope: project
  project: 0xkite/glove
  tags: [cpp, cmake, security, review, apple-container]
---

Load one applicable modern C++ implementation skill and one security-focused C++ skill. Use this file only for Glove's local contract and verification delta.

## Preserve these contracts

- Keep ownership in RAII types. Use `std::expected` for fallible boundaries and `std::span` or `std::string_view` for bounded non-owning inputs.
- Treat command exit, timeout, not-found, and outcome-unknown as distinct states. Put a monotonic deadline on every child process and reap the whole process group.
- Require immutable `name@sha256:<digest>` image references. Parse identity fields. Never accept a digest because it appears somewhere in diagnostic output.
- Keep descriptor-first filesystem operations. Pair `openat` with `O_NOFOLLOW`, compare opened identity, and mutate permissions through the descriptor.
- Do not authenticate a receipt for a path, projection, resource limit, or observation that Glove did not enforce and observe. Transformed skill trees need effective guest paths, not source bundle paths.
- Fail closed on unresolved instance ownership. Do not cache incomplete reconciliation or move a possibly running instance into a state excluded from recovery.
- Preflight aggregate host writes before materialization. A per-file limit is not a session or fleet limit.
- Keep Apple managed lifecycle unavailable until its six-limit enforcement and receipt contract is complete. Construction tests are not shipping capability.

## Change workflow

1. Read `docs/threat-model.md`, `docs/session-policy.md`, and the affected public interface before editing.
2. Compare the full merge-base diff. Trace every changed capability producer into Sage's consumer when the wire contract or runtime identifiers change.
3. Add the smallest regression test that would fail for the reported behavior. A skipped Apple test is not evidence for an Apple lifecycle change.
4. Build the narrow targets with the repository warning set. Run focused CTest cases, then the broader suite.
5. Run the pinned formatter. Run AddressSanitizer and UndefinedBehaviorSanitizer through the repository preflight before calling the change ready.
6. Report skipped tests, environment-only failures, and unproved live lanes separately from passes.

## Review focus

For PRs and diffs, check these paths first:

- lifecycle state and recovery identity
- command deadlines and ambiguous outcomes
- image and bundle provenance
- projection mount versus receipt truth
- aggregate host resource bounds
- descriptor and symlink safety
- capability compatibility with Sage

Block merge when any authenticated receipt can overstate enforcement, a live instance can leave recovery, or a new runtime breaks an older closed capability consumer.
