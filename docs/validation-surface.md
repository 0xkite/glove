# Validation surface

This document records the current evidence available for the open research and
validation items in [`future-work.md`](future-work.md). It is an audit map, not
a completion claim: a row remains partial until its stated completion condition
is covered end to end on every supported platform.

## C++ style audit

The codebase has a strong modern-C++ baseline: C++23 is required, warnings and
sanitizers are centralized, ownership is expressed through values and smart
pointers, fallible module boundaries generally use `std::expected`, and the
three direct `new` expressions are private-constructor factories immediately
owned by `std::unique_ptr`.

The highest-value structural follow-ups are:

1. `src/main.cpp` and `src/gloved_main.cpp` are 446 and 633 lines respectively.
   Their parsing, planning, execution, and presentation stages should continue
   moving behind typed functions so the entry points become declarative.
2. Twenty-four translation units carry file-local `unique_fd` implementations.
   They preserve RAII, but the duplication makes close/move semantics difficult
   to audit consistently. A private, well-tested descriptor utility would
   reduce that review surface without exposing a public dependency.
3. String-valued errors remain common across module boundaries. Typed errors
   already exist for the session registry; the same approach should be applied
   where callers need distinct recovery, presentation, or policy decisions.
4. Thread ownership is explicit, but several components use `std::thread`
   because of supported libc++ constraints or non-cooperative shutdown. Those
   exceptions need to retain their documented join and stop invariants.
5. The broad clang-tidy configuration currently reports a substantial backlog,
   especially in test assertion macros, long test functions, unchecked indexed
   access, and POSIX boundary code. Its warnings are diagnostic rather than
   errors, so a completed tidy stage is not evidence that the warning count is
   zero. Establishing a reviewed baseline by check and then ratcheting it down
   would turn the audit into a measurable gate.

The MCP JSON-RPC client now centralizes send/receive/decode behavior, serializes
transport transactions, and rejects responses whose ID does not match the
pending request. This closes the previously untested sequential-correlation
hole while leaving asynchronous multi-request routing as future work.

The preflight script verifies the repository-mandated actionlint 1.7.12 and
clang-format 22.1.8 versions explicitly, and benchmark sources participate in
formatting, compilation, and clang-tidy when the gate constructs its dev build.

## Future-work evidence matrix

| Future-work item | Current evidence | Status and next evidence |
|---|---|---|
| JSON-RPC correlation | `mcp_jsonrpc_client_test` covers unknown and duplicate response IDs plus concurrent callers through the serialized client transaction boundary. | Partial. Add a bounded dispatcher and regression tests with multiple simultaneously pending wire requests and reordered responses. |
| Parser fuzzing | libFuzzer targets cover MCP/JSON-RPC request/response envelopes plus all typed MCP result parsers, the constrained-policy argument parser, retained change-manifest decoder, canonical session-plan validator, change-apply journal recovery parser, and retained library-bundle verifier under ASan/UBSan. Checked corpora cover valid v1/v2 shapes, journal framing, empty, structured, malformed, truncated, non-object, wrong-type, strict-unknown-field, and authority-field inputs; preflight performs 10,000 mutations per target. | Partial. When prompt-library expansion is implemented, add a format-aware bundle decoder target and adversarial corpus for its derived files. |
| Fault injection | Journal truncation, audit append failure, crash adoption, and selected lifecycle recovery paths have tests. The change-apply journal additionally injects a real partial write followed by disk-full and an `fsync` failure; both cases prove rollback, retry, and replay behavior. | Partial. Add the reusable short-write/disk-full seam to the remaining persisted journals and enumerate every persisted lifecycle transition with crash/replay cases. |
| Multi-agent matrix | A synthetic MCP client and the YAMS upstream exercise the generic run path; sandbox and terminal invariants have platform tests. | Missing real Codex/Pi/Claude adapters, a shared invariant manifest, and the cross-adapter matrix. |
| Performance characterization | Optional `glove_mcp_benchmark` reports fixed-workload codec and in-memory request latency, throughput, sample standard deviation, and a 95% normal-approximation interval as JSON Lines. | Partial. Add contained-process startup, real stdio request paths, peak/RSS memory, platform metadata, and repeated-run comparison tooling. |
| Comparative evaluation | The threat model defines Glove's boundary and residual risks. | Missing comparable systems, an identical workload, and normalized threat-model results. |

## Running the benchmark baseline

Benchmarks are opt-in so sanitizer and correctness gates do not acquire timing
assertions or nondeterministic pass criteria.

```sh
cmake --preset relwithdebinfo -DGLOVE_BUILD_BENCHMARKS=ON
cmake --build --preset relwithdebinfo --target glove_mcp_benchmark
./build/relwithdebinfo/benchmarks/glove_mcp_benchmark \
  --samples 20 --iterations 1000
```

Each output line is a self-contained schema-versioned JSON record. Consumers
should retain the raw records and compare like-for-like configurations; the
benchmark deliberately has no performance pass/fail threshold.
