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

## Real sessions

Record real sessions with `glove run|exec --denial-trace <file>`, label them
by hand, and add them to a manifest with `"split":"real"`. `ablate.py` never
trains on them and reports them separately.

## Reading results

Confusion counts are per session, at the flag and terminate levels.
`before_onset` counts misbehaving sessions first caught before their labeled
onset (a fire on benign behaviour). Timings are comparable only when the
report says `"timing_build": "optimized"`. Traces hold host paths; keep
corpora private.
