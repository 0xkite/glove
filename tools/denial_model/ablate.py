#!/usr/bin/env python3
"""Compare denial decider arms by scenario-grouped cross-validation.

Standard library only. For each fold, the fold's scenarios are the test set,
the next fold's are the validation set (thresholds), and the rest train the
models. Every scenario is tested exactly once, by a model that never saw it.
Sessions with split "real" in the manifest are never trained on; they are
scored in every fold and reported separately, as drift evidence.

    tools/denial_model/ablate.py --replay build/release/src/glove-denial-replay \\
        --corpus corpus --folds 5 --out ablation.json

Arms: heuristic (fixed thresholds), logistic, gbdt. Confusion counts are
summed over folds; latency and timing are pooled. Timings are only
comparable from an optimized, unsanitized build of glove-denial-replay.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent


def scenario_of(entry):
    """traces/<group>-<scenario>-<run>.jsonl -> <group>-<scenario>."""
    stem = Path(entry["trace"]).stem
    return stem.rsplit("-", 1)[0] if entry["split"] != "real" else stem


def assign_folds(entries, folds):
    """Stratified by label: deal each label's scenarios over the folds in
    hash order, so each fold holds both labels when there are enough."""
    folds_of = {}
    for label in ("benign", "misbehaving"):
        names = sorted({scenario_of(e) for e in entries
                        if e["label"] == label and e["split"] != "real"},
                       key=lambda n: hashlib.sha256(n.encode()).hexdigest())
        for index, name in enumerate(names):
            folds_of[name] = index % folds
    return folds_of


def run(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def add_confusion(total, level):
    for key in ("true_positive", "false_positive", "true_negative", "false_negative",
                "before_onset"):
        total[key] += level[key]


def rates(total):
    def ratio(num, den):
        return num / den if den else 0.0
    tp, fp = total["true_positive"], total["false_positive"]
    tn, fn = total["true_negative"], total["false_negative"]
    return dict(total, precision=ratio(tp, tp + fp), recall=ratio(tp, tp + fn),
                false_positive_rate=ratio(fp, fp + tn))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--replay", required=True)
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--out", required=True)
    parser.add_argument("--terminate-budget", type=float, default=0.0)
    parser.add_argument("--flag-budget", type=float, default=0.05)
    args = parser.parse_args()

    corpus = Path(args.corpus).resolve()
    entries = [json.loads(line) for line in
               (corpus / "manifest.jsonl").read_text(encoding="ascii").splitlines() if line]
    folds_of = assign_folds(entries, args.folds)
    folds = sorted(set(folds_of.values()))
    if len(folds) < 3:
        sys.exit("need at least three folds' worth of scenarios")

    arms = ("heuristic", "logistic", "gbdt")
    summed = {arm: {level: defaultdict(int) for level in ("flag", "terminate")} for arm in arms}
    real = {arm: {level: defaultdict(int) for level in ("flag", "terminate")} for arm in arms}
    latency = {arm: defaultdict(list) for arm in arms}
    timing = defaultdict(list)
    features_ns = []
    timing_build = None
    per_fold = []

    with tempfile.TemporaryDirectory(prefix="glove-ablate-") as temp:
        temp = Path(temp)
        schema = temp / "schema.json"
        schema.write_text(run([args.replay, "schema"]), encoding="ascii")
        for fold in folds:
            validate_fold = folds[(folds.index(fold) + 1) % len(folds)]
            manifest = temp / f"fold{fold}.jsonl"
            with open(manifest, "w", encoding="ascii") as stream:
                for entry in entries:
                    if entry["split"] == "real":
                        split = "real"
                    elif folds_of[scenario_of(entry)] == fold:
                        split = "test"
                    elif folds_of[scenario_of(entry)] == validate_fold:
                        split = "validate"
                    else:
                        split = "train"
                    trace = str(corpus / entry["trace"])
                    stream.write(json.dumps(dict(entry, split=split, trace=trace)) + "\n")
            rows = temp / f"fold{fold}.rows"
            rows.write_text(run([args.replay, "rows", str(manifest)]), encoding="ascii")
            reports = {}
            for kind in ("logistic", "gbdt"):
                model = temp / f"fold{fold}.{kind}.json"
                run([sys.executable, "-I", str(HERE / "train.py"), "--schema", str(schema),
                     "--rows", str(rows), "--type", kind, "--out", str(model),
                     "--terminate-budget", str(args.terminate_budget),
                     "--flag-budget", str(args.flag_budget)])
                for split, sink in (("test", summed), ("real", real)):
                    report = json.loads(run([args.replay, "evaluate", str(manifest),
                                             "--model", str(model), "--split", split]))
                    timing_build = report["timing_build"]
                    if split == "test":
                        features_ns.append(report["features_ns_mean"])
                    for arm_report in report["arms"]:
                        arm = kind if arm_report["arm"] == "model" else "heuristic"
                        if arm == "heuristic" and kind == "gbdt":
                            continue  # the heuristic is scored once per fold
                        for level in ("flag", "terminate"):
                            add_confusion(sink[arm][level], arm_report[level])
                        if split == "test":
                            for level in ("flag", "terminate"):
                                if arm_report[level]["latency_ms_p50"] >= 0:
                                    latency[arm][level].append(
                                        arm_report[level]["latency_ms_p50"])
                            timing[arm].append((arm_report["decide_ns_mean"],
                                                arm_report["decide_ns_p99"]))
                    if split == "test":
                        reports[kind] = report
            per_fold.append({
                "fold": fold,
                "test_scenarios": sorted(n for n, f in folds_of.items() if f == fold),
                "sessions": reports["logistic"]["sessions"],
            })

    def median(values):
        values = sorted(values)
        return values[len(values) // 2] if values else None

    result = {
        "timing_build": timing_build,
        "folds": per_fold,
        "features_ns_mean": sum(features_ns) / len(features_ns) if features_ns else None,
        "arms": {
            arm: {
                "test": {level: rates(summed[arm][level]) for level in ("flag", "terminate")},
                "real": {level: rates(real[arm][level]) for level in ("flag", "terminate")},
                "latency_ms_median_of_fold_p50": {
                    level: median(latency[arm][level]) for level in ("flag", "terminate")},
                "decide_ns_mean": sum(t[0] for t in timing[arm]) / max(len(timing[arm]), 1),
                "decide_ns_p99_max": max((t[1] for t in timing[arm]), default=None),
            }
            for arm in arms
        },
    }
    Path(args.out).write_text(json.dumps(result, indent=2) + "\n", encoding="ascii")
    if timing_build != "optimized":
        print(f"warning: timings come from a {timing_build} build", file=sys.stderr)
    print(f"{'arm':10} {'level':9} {'prec':>5} {'recall':>6} {'fpr':>5} {'early':>5} "
          f"{'lat50ms':>7} {'ns/dec':>7}")
    for arm in arms:
        for level in ("flag", "terminate"):
            r = result["arms"][arm]["test"][level]
            lat = result["arms"][arm]["latency_ms_median_of_fold_p50"][level]
            print(f"{arm:10} {level:9} {r['precision']:5.2f} {r['recall']:6.2f} "
                  f"{r['false_positive_rate']:5.2f} {r['before_onset']:5d} "
                  f"{lat if lat is not None else '-':>7} "
                  f"{result['arms'][arm]['decide_ns_mean']:7.0f}")


if __name__ == "__main__":
    main()
