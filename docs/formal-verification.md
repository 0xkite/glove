# Formal models

TLA+ specifications of Glove protocols whose correctness depends on how
steps of separate processes interleave. TLC, the TLA+ model checker, explores
every interleaving of a small instance and checks the stated invariants.

A model checks a design, not the C++. It is evidence only as far as the
model matches the code, and only for the instance sizes checked. Each model
names the code it describes; change them together.

## Running

Needs Java 11+ and `tla2tools.jar` from the
[TLA+ releases](https://github.com/tlaplus/tlaplus/releases). CI uses v1.7.4.

```sh
GLOVE_TLA2TOOLS_JAR=/path/to/tla2tools.jar scripts/tlc.sh
```

```text
ok    AuditJournal.cfg (3087 distinct states found)
ok    AuditJournal.unfixed.cfg (violation found, as required: Invariant NoSpuriousFailure)
```

The `TLA+ models` CI job runs this on every pull request. It is not part of
`scripts/preflight.sh`.

## Conventions

- `formal/<Module>.tla`: the specification.
- `formal/<Module>.cfg`: an instance TLC must pass.
- `formal/<Module>.unfixed.cfg`: the same instance with a fix switched off.
  TLC must report a violation. This shows the model can see the defect the
  fix removes; a model that passes either way checks nothing.

A new model states, in its header comment, the code it describes and every
abstraction it makes.

## Models

### AuditJournal

Code: `make_jsonl_sink` (`src/audit/jsonl_sink.cpp`),
`open_default_audit_journal` and `remove_old_overflow_journals`
(`src/run/audit_journal.cpp`).

Concurrent launches each choose an audit journal. One gets the shared
journal; the others run a retention pass over per-launch journals and create
their own. Opening a journal is `open(O_CREAT)`, `fstat`, `flock`; retention
is `open`, `flock`, `unlink`. The model interleaves those calls.

Checked for 3 launches and 4 journals:

| Invariant | Meaning |
|---|---|
| `WriterIsNamed` | a launch that is recording writes to a file that still has a name |
| `SingleWriter` | no two launches record to the same journal |
| `WriterHoldsLock` | a journal being recorded to is locked by its writer |
| `NoSpuriousFailure` | retention never makes another launch fail to open its journal |

Found by the model: a retention pass could lock and unlink a journal between
another launch's `open` and `flock`. That launch either failed to start
(`NoSpuriousFailure`) or recorded to a file with no name and lost its records
on exit (`WriterIsNamed`). The fix checks the link count again under the lock
and draws another name; `RecheckAfterLock` switches it in the model.
`run_audit_journal` has a stress test for the same race.

Not modeled: record contents, the size cap and truncation, crashes, name
collisions (names are 64 random bits), and the choice of oldest journals
(the model lets retention pick any).
