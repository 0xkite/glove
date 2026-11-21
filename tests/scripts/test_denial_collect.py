#!/usr/bin/env python3
"""The scenario collector records one benign and two misbehaving runs under
glove exec: the traces parse, the misbehaving ones have an onset, no onset
marker survives in any trace, every trace lists the run's decoys, and only
the scenario that reaches for decoys has decoy hits, which replay counts.
macOS only; exits 77 when denial telemetry is unavailable.

    test_denial_collect.py <glove> <glove-denial-replay> <collect.py>
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    glove, replay, collect = sys.argv[1:4]
    with tempfile.TemporaryDirectory(prefix="glove-collect-test-") as temp:
        out = Path(temp) / "corpus"
        result = subprocess.run(
            [sys.executable, "-I", collect, "--glove", glove, "--out", str(out),
             "--repeat", "1", "--only", "env_probe", "--only", "system_tamper",
             "--only", "decoy_read"],
            capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            sys.exit(f"collect failed:\n{result.stderr}")
        if "telemetry unavailable" in result.stderr:
            print("SKIP denial telemetry unavailable")
            sys.exit(77)
        entries = [json.loads(line) for line in
                   (out / "manifest.jsonl").read_text().splitlines() if line]
        labels = sorted(e["label"] for e in entries)
        assert labels == ["benign", "misbehaving", "misbehaving"], (labels, result.stderr)
        for entry in entries:
            text = (out / entry["trace"]).read_text()
            assert "/glove-onset-" not in text, entry
            records = [json.loads(line) for line in text.splitlines()]
            decoys = records[0]["decoys"]
            assert len(decoys) == 3, records[0]
            assert not any(Path(decoy).exists() for decoy in decoys), decoys
            hits = sum(1 for record in records[1:] if record.get("target") in decoys)
            if "decoy_read" in entry["trace"]:
                assert entry["onset_ms"] > 0, entry
                assert hits >= 3, (entry, hits)
            else:
                assert hits == 0, (entry, hits)
            if "system_tamper" in entry["trace"]:
                assert entry["onset_ms"] > 0, entry
                assert "/usr/local/bin/glove-decoy-" in text, entry
        schema = json.loads(subprocess.run(
            [replay, "schema"], capture_output=True, text=True, check=True).stdout)
        column = schema["features"].index("target_decoy")
        rows = subprocess.run(
            [replay, "rows", str(out / "manifest.jsonl")],
            capture_output=True, text=True, check=True).stdout.splitlines()
        peak = {}
        for row in map(json.loads, rows):
            peak[row["session"]] = max(peak.get(row["session"], 0.0), row["features"][column])
        assert sorted(value > 0 for value in peak.values()) == [False, False, True], peak
        report = json.loads(subprocess.run(
            [replay, "evaluate", str(out / "manifest.jsonl"), "--split", "train",
             "--split", "validate", "--split", "test"],
            capture_output=True, text=True, check=True).stdout)
        assert report["sessions"] == 3, report
    print("denial collect ok")


if __name__ == "__main__":
    main()
