# Native session continuity

Host-owned sleep/wake continuity for a native harness generation launched by
the native macOS core. Constructed today for the Claude Code harness in an
offline fixture composition; the production `glove pi` path is unchanged and
no new public CLI is added.

## Topology

```text
stock tmux pane
  └─ host Glove session supervisor (native_session_supervisor)
       ├─ exclusive logical-session lease + append-only journal + checkpoints
       ├─ protected management listener (AF_UNIX, host-only)
       └─ one owned contained generation at a time (native_launch core)
            ├─ fresh credentialed loopback endpoint + fresh guest nonce
            └─ generation-local private run (HOME/TMP/config, writable history copy)
```

The tmux server socket and the management socket are host capabilities. The
guest profile grants neither; its only network grant is the exact loopback
port of its own generation's endpoint.

## Lifecycle model

`src/run/native_session_model.cpp` is a pure state machine with no I/O:

| Phase | Entered by | Mutations admitted |
|---|---|---|
| new / stopped | creation, finalization | start, resume (exact published checkpoint), shutdown |
| preparing | accepted start/resume (generation reserved first) | stop |
| running | durable launching marker | stop |
| stopping | accepted stop | repeated stop |
| finalizing | known owned process outcome | none |
| recovery_required | uncertain outcome, failed publication, interrupted durable record | status, shutdown |

Preparation cancellation is the explicit asynchronous edge
preparing → stopping. The launch thread later reports `prepare_cancelled`
(no launch effect existed; stopped with absent history), `prepare_failed`
(admission refused) or `launched` (the owned process exists; the accepted stop
cancels it through the generation's stop token). Both outcomes are tested.

Replay is epoch-scoped: a mutation is recorded by request id and the SHA-256
of its exact body before any effect; an exact retry returns the recorded or
accepted-progress snapshot and never launches again, a changed body conflicts,
an unknown mutation with a stale observed generation refuses, and 64 records
are retained without eviction (capacity refuses further start/resume/
interrupt; stop and shutdown stay admissible up to 8 further records so a
running generation can always be cancelled). An admitted shutdown closes
mutation admission. Status is read-only and never a historical lookup. Interrupt is advertised as
unsupported for Claude because no qualified turn-abort contract exists.

## Durable store

`src/run/native_session_store.cpp` owns one logical session below
`<state>/<runtime>/sessions/ns-<32hex>/`: an flock-held `lease`, sealed
`meta.json` (harness, runtime content digest, history format, workspace,
semantic startup-policy digest, conversation id), `journal.log` (strict JSON
lines, contiguous sequence, ≤4096 events, ≤4 MiB, ≤16 KiB each) and immutable
`checkpoints/<64hex>/{record.json,history.jsonl}` sealed at 0500/0400.

A checkpoint identity is the SHA-256 of its canonical record, which commits
the history digest, producing epoch/generation and the session bindings.
Publication reads the generation-local history twice through descriptors,
admits it with the harness validator, writes an exclusive staging directory,
fsyncs each file, renames the owner-only directory into place, seals it to
0500 through the retained descriptor (macOS 15 refuses to rename a directory
the caller cannot write), fsyncs the parent and journals
`checkpoint_published`. Any failure leaves the previous checkpoint and the
journal unchanged; an unjournaled or unsealed directory is never admitted for
resume.
Checkpoint count/aggregate exhaustion and journal failure during finalization
are persistence failures: the generation enters recovery_required with its
private run retained, never a silent "invalid history" cleanup.
Resume re-admits the exact identity: record digest, history digest, bytes,
modes, link counts and the validator all run again. Injected faults (copy,
history fsync, record fsync, rename, parent sync, journal append) are covered
by `tests/run/native_session_store_test.cpp`.

## Finalization before cleanup

The launch core gained three synchronous hooks: `materialize` (after
immutable configuration publication, before the launching marker) writes the
admitted history copy into the generation's private agent directory;
`on_launching` fires after the durable launching marker; `finalize` runs after
a known owned process outcome and endpoint revocation and BEFORE
`mark_quiescent`. A publication failure in `finalize` retains the private run
and reports `checkpoint_failed`; the generation enters recovery_required and
automatic resume is blocked. The legacy lease wire format is unchanged.

## Management protocol v1

`src/run/native_management_transport.cpp`: AF_UNIX stream `control/s`
below the owner-private session root, peer UID verified, 4-octet big-endian
length framing (1..65536), closed I-JSON frames with depth ≤8 and no
duplicate keys, 2 s authentication and 5 s request deadlines. The first frame
authenticates the exact session, current supervisor epoch and a per-epoch
256-bit capability kept only in the owner-only `control/cap` file; failure
closes without a byte. One request per connection. A replaced socket name is
refused and never unlinked; a missing name is recreated by the surviving
owner with a fresh socket identity and journaled once per episode. Clients never infer
liveness from the pathname: a leftover socket with no acceptor refuses.

## Claude Code adapter

`src/adapters/claude/native_harness.cpp` encodes the closed policy from
`src/run/claude_native_policy.cpp`: `--bare --print --output-format json
--permission-prompts none --tools "" --strict-mcp-config
--disable-slash-commands --model M (--session-id|--resume) UUID -- PROMPT`.
Environment comes only from typed sources: `CLAUDE_CONFIG_DIR` and
`CLAUDE_CODE_TMPDIR` from private locations, `ANTHROPIC_BASE_URL` and
`ANTHROPIC_API_KEY` from the generation's endpoint and nonce, and fixed
literals that disable telemetry, updates, error reporting and interrupted-turn
resumption. `--bare` makes Anthropic authentication strictly
`ANTHROPIC_API_KEY`, so saved OAuth/keychain state is never read.

History is Claude's `projects/<encoded cwd>/<uuid>.jsonl`. Admission
(`src/run/claude_history.cpp`) binds the observed 2.1.296 shape: one bounded
JSON object per line, `sessionId` equal to the host conversation id on every
identified entry, `version` equal to the admitted runtime version, unique
UUIDs, parent links that resolve within the file and terminate, and at least
one user and one assistant entry. A stopped initial turn is `invalid` and
produces no checkpoint; no new conversation is substituted.

## Evidence boundaries

Fake-owner tests (`native_session_supervisor_test`) prove the lifecycle,
store, transport and ordering with no process. The actual-Claude lane
(`run_native_claude_lane_test`, opt-in through `GLOVE_TEST_CLAUDE_*`) and the
stock-tmux lane (`tests/run/claude_tmux_lane.sh`) prove the contained real
executable against the in-process fixture responder, which never dials. They
do not prove live-provider compatibility, interactive key approval, tool
interruption, exactly-once tool effects, universal descendant death or
host-reboot recovery. Interactive mode starts and stops under supervision but
blocks on Claude's first-use API-key approval prompt, which is not fabricated.
