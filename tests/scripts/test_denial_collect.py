#!/usr/bin/env python3
"""The scenario collector records one benign and one misbehaving run under
glove exec: both traces parse, the misbehaving one has an onset, and no
onset marker survives in either trace. macOS only; exits 77 when denial
telemetry is unavailable.

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
             "--repeat", "1", "--only", "env_probe", "--only", "system_tamper"],
            capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL)
        if result.returncode != 0:
            sys.exit(f"collect failed:\n{result.stderr}")
        if "telemetry unavailable" in result.stderr:
            print("SKIP denial telemetry unavailable")
            sys.exit(77)
        entries = [json.loads(line) for line in
                   (out / "manifest.jsonl").read_text().splitlines() if line]
        labels = sorted(e["label"] for e in entries)
        assert labels == ["benign", "misbehaving"], (labels, result.stderr)
        for entry in entries:
            text = (out / entry["trace"]).read_text()
            assert "/glove-onset-" not in text, entry
            if entry["label"] == "misbehaving":
                assert entry["onset_ms"] > 0, entry
                assert "/usr/local/bin/glove-decoy-" in text, entry
        report = json.loads(subprocess.run(
            [replay, "evaluate", str(out / "manifest.jsonl"), "--split", "train",
             "--split", "validate", "--split", "test"],
            capture_output=True, text=True, check=True).stdout)
        assert report["sessions"] == 2, report
    print("denial collect ok")


if __name__ == "__main__":
    main()
