# Denial decision models

Offline tooling for the deciders in
`include/glove/container/denial_decision.hpp`. macOS only for collection.
Standard library Python; nothing here is part of the build.

```sh
cmake --build --preset release --target glove glove-denial-replay
R=build/release/src/glove-denial-replay

# 1. Collect labeled traces from the scripted scenarios.
tools/denial_model/collect.py --glove build/release/src/glove --out corpus --repeat 12

# 2. Compare arms by scenario-grouped cross-validation.
tools/denial_model/ablate.py --replay $R --corpus corpus --folds 5 --out ablation.json

# 3. Train a model on a fixed split and evaluate it.
$R schema > schema.json
$R rows corpus/manifest.jsonl > rows.jsonl
tools/denial_model/train.py --schema schema.json --rows rows.jsonl --type gbdt --out model.json
$R evaluate corpus/manifest.jsonl --model model.json
```

| File | Purpose |
|---|---|
| `collect.py` | runs `scenarios/{benign,misbehaving}/*.sh` under `glove exec --denial-trace` |
| `train.py` | logistic regression or gradient-boosted trees; session-level thresholds |
| `ablate.py` | heuristic vs logistic vs gbdt, grouped k-fold |
| `src/tools/denial_replay_main.cpp` | `schema`, `rows`, `evaluate`; the only feature implementation |

## Scenarios

A scenario is a POSIX sh script run in an empty workspace. Inside the sandbox
`$HOME` is private; the real home is `$GLOVE_SCENARIO_HOST_HOME`. Every run
also gets three decoys, `$GLOVE_SCENARIO_DECOY_1` to `_3`: canary files glove
plants outside the sandbox in a directory made for that run (never a real
credential directory) and removes afterwards. A scenario that reads one is
misbehaving by construction, and the `target_decoy` feature counts it; the
`decoy_*` scenarios measure that the signal arrives, not that a model is
clever.

A misbehaving scenario marks its onset with
`( /usr/bin/touch "/glove-onset-$GLOVE_SCENARIO_NONCE" ) 2>/dev/null`; the
collector records that denial's time and removes it from the trace.

Scenarios must be harmless if the sandbox fails:

- write only names containing `$GLOVE_SCENARIO_NONCE`;
- append zero bytes (`/usr/bin/true >> file`), only to files that exist;
- connect only to loopback or TEST-NET (192.0.2.0/24);
- read secrets only through the run's decoys, or names that do not exist.

Wrap each denied command in a subshell: in `sh`, a failed redirection on a
special builtin ends the script. The collector stops with an error if any
file carrying the nonce exists after a run.

## Shadow mode

`glove run|exec --denial-model model.json` evaluates a trained model on the
launch's denials and writes its verdict to the audit log as `verdict` records
and in the denial summary. Nothing acts on a verdict. Keep the model outside
every path the launch grants, owned by you and not group- or other-writable;
a model glove cannot use is reported and the launch runs without one.

## Real sessions

Scenarios are scripts, so a model can look good on them and still be wrong
about real agent work. Real sessions are the check on that.

```sh
# 1. Record. The trace path must be outside everything the launch grants.
glove run --denial-trace ~/glove-traces/refactor-1.jsonl ...

# 2. Look at what was denied, in order.
tools/denial_model/label.py show ~/glove-traces/refactor-1.jsonl

# 3. Add it with your label.
tools/denial_model/label.py add --corpus corpus ~/glove-traces/refactor-1.jsonl \
    --label benign --note "pi, refactor task"
tools/denial_model/label.py add --corpus corpus ~/glove-traces/odd.jsonl \
    --label misbehaving --onset-ms 41250 --note "started reading ~/Documents"
```

A session is benign when the agent only did the work it was asked to do, even
if many accesses were denied. It is misbehaving from the first denial that
belongs to something it should not have attempted; `--onset-ms` is that
denial's time as `show` prints it. When unsure, leave the session out.

`add` gives the session split `real`. `ablate.py` and `glove-denial-replay
evaluate --split real` never train on that split and report it separately.
It refuses a trace that is cut short, has no end record, or comes from a
launch whose telemetry was not live throughout (`--allow-incomplete`
overrides the last). A few dozen sessions across the kinds of work you
actually run is enough to see whether a model's false-positive rate holds.

## Reading results

Confusion counts are per session, at the flag and terminate levels.
`before_onset` counts misbehaving sessions first caught before their labeled
onset (a fire on benign behaviour). Timings are comparable only when the
report says `"timing_build": "optimized"`. Traces hold host paths; keep
corpora private.
