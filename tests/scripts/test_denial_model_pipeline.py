#!/usr/bin/env python3
"""The denial model pipeline holds together: replay rows from traces, train
both model types with the standard-library trainer, and evaluate them with
the C++ loader. The corpus is synthetic and trivially separable, so this
checks plumbing and format compatibility, not accuracy on real behaviour.

    test_denial_model_pipeline.py <glove-denial-replay> <train.py>
"""

import json
import os
import random
import subprocess
import sys
import tempfile


def line(obj):
    return json.dumps(obj, separators=(",", ":")) + "\n"


def event(t, kind, op, target, comm):
    return {"type": "event", "t_ms": t, "kind": kind, "operation": op, "target": target,
            "target_truncated": False, "comm": comm, "pid": 10, "duplicate_reports": 0,
            "readings": 1}


def corpus(root):
    rng = random.Random(3)
    manifest = []
    for number in range(120):
        misbehaving = number % 2 == 1
        split = ("train", "train", "validate", "test")[number % 4]
        t = 0
        events = []
        for _ in range(rng.randint(1, 12)):
            t += rng.randint(1, 300)
            events.append(event(t, "file_read", "file-read-data",
                                rng.choice(["/dev/tty", "/w/proj/.git/x", "/usr/share/x"]),
                                rng.choice(["bash", "git"])))
        onset = t + 1
        if misbehaving:
            for _ in range(rng.randint(2, 8)):
                t += rng.randint(1, 40)
                events.append(event(t, "file_write", "file-write-create",
                                    rng.choice(["/h/.zshrc", "/Library/LaunchAgents/x.plist"]),
                                    "sh"))
        header = {"type": "header", "format": "glove-denial-trace", "version": 1,
                  "home": "/h", "workspace_roots": ["/w/proj"]}
        end = {"type": "end", "t_ms": t + 5, "state": "live", "reason": "", "end_proof": True,
               "stream_events": len(events), "stream_rejected": 0, "dropped": 0}
        name = f"s{number}.jsonl"
        with open(os.path.join(root, name), "w", encoding="ascii") as stream:
            stream.write(line(header) + "".join(line(e) for e in events) + line(end))
        manifest.append({"trace": name, "label": "misbehaving" if misbehaving else "benign",
                         "onset_ms": onset if misbehaving else 0, "split": split})
    path = os.path.join(root, "manifest.jsonl")
    with open(path, "w", encoding="ascii") as stream:
        stream.write("".join(line(m) for m in manifest))
    return path


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, text=True, **kwargs).stdout


def main():
    replay, trainer = sys.argv[1], sys.argv[2]
    with tempfile.TemporaryDirectory() as root:
        manifest = corpus(root)
        schema = os.path.join(root, "schema.json")
        rows = os.path.join(root, "rows.jsonl")
        with open(schema, "w", encoding="ascii") as stream:
            stream.write(run([replay, "schema"]))
        with open(rows, "w", encoding="ascii") as stream:
            stream.write(run([replay, "rows", manifest]))
        with open(rows, encoding="ascii") as stream:
            first = json.loads(stream.readline())
        assert len(first["features"]) == len(json.load(open(schema))["features"])

        for kind in ("logistic", "gbdt"):
            model = os.path.join(root, f"{kind}.json")
            run([sys.executable, "-I", trainer, "--schema", schema, "--rows", rows,
                 "--type", kind, "--out", model, "--rounds", "10", "--epochs", "60"])
            report = json.loads(run([replay, "evaluate", manifest, "--model", model]))
            assert report["sessions"] == 30, report["sessions"]
            assert report["timing_build"] in ("optimized", "debug", "sanitized")
            arms = {arm["arm"]: arm for arm in report["arms"]}
            assert set(arms) == {"heuristic", "model"}, arms.keys()
            terminate = arms["model"]["terminate"]
            assert terminate["recall"] >= 0.9, (kind, terminate)
            assert terminate["false_positive_rate"] <= 0.1, (kind, terminate)
            print(f"{kind}: recall={terminate['recall']:.2f} "
                  f"fpr={terminate['false_positive_rate']:.2f}")

        # Malformed manifest and model files are refused.
        bad = os.path.join(root, "bad.jsonl")
        with open(bad, "w", encoding="ascii") as stream:
            stream.write(line({"trace": "s0.jsonl", "label": "maybe", "onset_ms": 0,
                               "split": "test"}))
        assert subprocess.run([replay, "evaluate", bad], capture_output=True).returncode != 0
        broken = os.path.join(root, "broken.json")
        with open(broken, "w", encoding="ascii") as stream:
            stream.write("{}")
        assert subprocess.run([replay, "evaluate", manifest, "--model", broken],
                              capture_output=True).returncode != 0
    print("denial model pipeline ok")


if __name__ == "__main__":
    main()
