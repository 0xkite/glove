#!/usr/bin/env python3
"""label.py adds only complete denial traces to a corpus as real sessions,
and the manifest it writes is one glove-denial-replay accepts.

    test_denial_label.py <glove-denial-replay> <label.py>
"""

import json
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


def line(obj):
    return json.dumps(obj, separators=(",", ":")) + "\n"


def event(t, target):
    return {"type": "event", "t_ms": t, "kind": "file_read", "operation": "file-read-data",
            "target": target, "target_truncated": False, "comm": "cat", "pid": 10,
            "duplicate_reports": 0, "readings": 1}


HEADER = {"type": "header", "format": "glove-denial-trace", "version": 2, "home": "/Users/u",
          "workspace_roots": ["/Users/u/proj"], "decoys": ["/Users/u/vault/token"]}


def end(state="live"):
    return {"type": "end", "t_ms": 900, "state": state, "reason": "", "end_proof": True,
            "stream_events": 3, "stream_rejected": 0, "dropped": 0}


def main():
    replay, label = sys.argv[1:3]

    def run(*args):
        return subprocess.run([sys.executable, "-I", label, *args], capture_output=True,
                              text=True, check=False, stdin=subprocess.DEVNULL)

    def refused(why, *args):
        result = run(*args)
        assert result.returncode != 0 and why in result.stderr, (why, result)

    with tempfile.TemporaryDirectory(prefix="glove-label-test-") as temp:
        root = Path(temp)
        corpus = root / "corpus"
        body = (line(event(10, "/dev/tty")) + line(event(40, "/Users/u/vault/token"))
                + line(event(700, "/Users/u/Documents/a%0Ab")))
        good = root / "good.jsonl"
        good.write_text(line(HEADER) + body + line(end()), encoding="ascii")

        shown = run("show", str(good))
        assert shown.returncode == 0, shown
        assert "denials    3" in shown.stdout and "decoy" in shown.stdout, shown.stdout
        # Text glove would have percent-encoded is refused, never printed.
        raw = root / "raw.jsonl"
        raw.write_text(line(HEADER) + line(event(1, "/x/\x1b[31mred")) + line(end()),
                       encoding="ascii")
        for command in (("show",), ("add", "--corpus", str(corpus), "--label", "benign")):
            result = run(*command, str(raw))
            assert result.returncode != 0 and "not a denial event" in result.stderr, result
            assert "\x1b" not in result.stdout + result.stderr, result

        # Only a complete trace of a launch whose telemetry stayed live.
        cut = root / "cut.jsonl"
        cut.write_text(line(HEADER) + body + line(end())[:-5], encoding="ascii")
        refused("ends inside a line", "add", "--corpus", str(corpus), str(cut), "--label",
                "benign")
        open_ended = root / "open.jsonl"
        open_ended.write_text(line(HEADER) + body, encoding="ascii")
        refused("no end record", "add", "--corpus", str(corpus), str(open_ended), "--label",
                "benign")
        degraded = root / "degraded.jsonl"
        degraded.write_text(line(HEADER) + body + line(end("degraded")), encoding="ascii")
        refused("denials are missing", "add", "--corpus", str(corpus), str(degraded),
                "--label", "benign")
        foreign = root / "foreign.jsonl"
        foreign.write_text(line({"type": "header", "format": "other", "version": 2}),
                           encoding="ascii")
        refused("denial trace header", "add", "--corpus", str(corpus), str(foreign), "--label",
                "benign")
        extra = root / "extra.jsonl"
        extra.write_text(line(HEADER) + line(dict(event(1, "/x"), run="rm")) + line(end()),
                         encoding="ascii")
        refused("not a denial event", "add", "--corpus", str(corpus), str(extra), "--label",
                "benign")
        assert not corpus.exists(), "a refused trace created the corpus"

        # A misbehaving session needs an onset inside the trace.
        refused("needs --onset-ms", "add", "--corpus", str(corpus), str(good), "--label",
                "misbehaving")
        refused("within the trace", "add", "--corpus", str(corpus), str(good), "--label",
                "misbehaving", "--onset-ms", "5000")
        refused("only applies", "add", "--corpus", str(corpus), str(good), "--label", "benign",
                "--onset-ms", "40")
        added = run("add", "--corpus", str(corpus), str(good), "--label", "misbehaving",
                    "--onset-ms", "40", "--note", "reached for the token")
        assert added.returncode == 0, added
        refused("already in", "add", "--corpus", str(corpus), str(good), "--label", "benign")
        added = run("add", "--corpus", str(corpus), str(degraded), "--label", "benign",
                    "--allow-incomplete")
        assert added.returncode == 0, added

        entries = [json.loads(text) for text in
                   (corpus / "manifest.jsonl").read_text().splitlines()]
        assert [(e["label"], e["onset_ms"], e["split"]) for e in entries] == [
            ("misbehaving", 40, "real"), ("benign", 0, "real")], entries
        for entry in entries:
            copy = corpus / entry["trace"]
            assert stat.S_IMODE(copy.stat().st_mode) == 0o600, entry
        assert (corpus / entries[0]["trace"]).read_bytes() == good.read_bytes()
        notes = [json.loads(text) for text in (corpus / "notes.jsonl").read_text().splitlines()]
        assert notes == [{"trace": entries[0]["trace"], "note": "reached for the token"}], notes

        report = json.loads(subprocess.run(
            [replay, "evaluate", str(corpus / "manifest.jsonl"), "--split", "real"],
            capture_output=True, text=True, check=True).stdout)
        assert report["sessions"] == 2 and report["misbehaving"] == 1, report
    print("denial label ok")


if __name__ == "__main__":
    main()
