# Fuzzing

Fuzz targets exercise untrusted wire and persistence parsers under libFuzzer,
ASan, and UBSan. The current targets cover the MCP/JSON-RPC codec, the
argument parser that backs constrained policy decisions, and the retained
change-manifest decoder, strict canonical session-plan validation, and
change-apply journal recovery parser, and retained library-bundle verifier.
Checked
corpus files are stable review artifacts; fuzzing must mutate a copy rather
than writing generated units into the repository.

Configure and build the targets with a Clang distribution that includes the
libFuzzer runtime. Apple Clang installations do not always ship that runtime;
Homebrew LLVM is the default used by preflight on macOS.

```sh
cmake --preset fuzz -DCMAKE_CXX_COMPILER=/path/to/clang++
cmake --build --preset fuzz
```

Run the MCP codec target against a disposable corpus copy:

```sh
corpus_copy="$(mktemp -d "${TMPDIR:-/tmp}/glove-mcp-corpus.XXXXXX")"
cp -R fuzz/corpus/mcp_codec/. "${corpus_copy}/"
./build/fuzz/fuzz/glove_mcp_codec_fuzzer \
  -runs=10000 -max_len=65536 -timeout=5 -rss_limit_mb=2048 \
  "${corpus_copy}"
```

Run the policy target the same way, substituting
`fuzz/corpus/policy_jsonpath` and `glove_policy_jsonpath_fuzzer`.

Run the manifest target the same way, substituting
`fuzz/corpus/change_manifest` and `glove_change_manifest_fuzzer`.

Run the session-plan target the same way, substituting
`fuzz/corpus/session_plan` and `glove_session_plan_fuzzer`.

Run the change-apply journal target the same way, substituting
`fuzz/corpus/change_apply_journal` and `glove_change_apply_journal_fuzzer`.

Run the library-bundle target the same way, substituting
`fuzz/corpus/library_bundle` and `glove_library_bundle_fuzzer`.

Crashes, sanitizer findings, or timeouts are failures. Minimize a reproducer
before adding it to the checked corpus, and give each retained input a
descriptive filename tied to the parser invariant it covers.
