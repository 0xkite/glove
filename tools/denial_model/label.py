#!/usr/bin/env python3
"""Label real denial traces and add them to a corpus. Standard library only.

Record a real session:

    glove run|exec --denial-trace ~/glove-traces/2026-11-20-refactor.jsonl ...

Look at it, then add it with the label you decide on:

    tools/denial_model/label.py show ~/glove-traces/2026-11-20-refactor.jsonl
    tools/denial_model/label.py add --corpus corpus \\
        ~/glove-traces/2026-11-20-refactor.jsonl --label benign --note "pi, refactor"
    tools/denial_model/label.py add --corpus corpus bad.jsonl \\
        --label misbehaving --onset-ms 41250 --note "started reading ~/Documents"

`add` copies the trace to <corpus>/traces/real-<sha256 prefix>.jsonl (mode
0600), appends a manifest line with split "real", and keeps the note in
<corpus>/notes.jsonl. `ablate.py` and
`glove-denial-replay evaluate` never train on that split and report it
separately, so real sessions measure a model without teaching it.

A session is benign when the agent only did the work it was asked to do,
even if many accesses were denied. It is misbehaving from the first denial
that belongs to something it should not have attempted; --onset-ms is that
denial's t_ms as `show` prints it. When unsure, do not add the session.

A trace is untrusted input: the agent chose the targets and process names in
it. This tool prints them escaped and never executes or opens a path from a
trace. Traces hold host paths; keep the corpus private.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path

MAX_TRACE_BYTES = 32 << 20
MAX_NOTE_BYTES = 200
TRACE_VERSIONS = (1, 2)
EVENT_KEYS = {"type", "t_ms", "kind", "operation", "target", "target_truncated", "comm", "pid",
              "duplicate_reports", "readings"}


def fail(message: str):
    sys.exit(f"label.py: {message}")


def encoded(value) -> bool:
    """Trace text is percent-encoded, so it is printable ASCII. A file that
    holds anything else is not one glove wrote, and replay would refuse it."""
    return isinstance(value, str) and all(" " <= ch <= "~" for ch in value)


def read_trace(path: Path):
    """Returns (bytes, header, events, end or None). Refuses anything that is
    not a complete trace, so a half-written or foreign file is never labeled."""
    try:
        with open(path, "rb") as stream:
            data = stream.read(MAX_TRACE_BYTES + 1)
    except OSError as error:
        fail(f"cannot read {path}: {error.strerror}")
    if len(data) > MAX_TRACE_BYTES:
        fail(f"{path} is larger than a trace can be")
    if not data.endswith(b"\n"):
        fail(f"{path} ends inside a line; the launch did not finish writing it")
    try:
        records = [json.loads(line) for line in data.decode("ascii").splitlines()]
    except (UnicodeDecodeError, ValueError):
        fail(f"{path} is not a denial trace (not ASCII JSON lines)")
    if not records or not all(isinstance(record, dict) for record in records):
        fail(f"{path} is not a denial trace")
    header = records[0]
    if (header.get("type") != "header" or header.get("format") != "glove-denial-trace"
            or header.get("version") not in TRACE_VERSIONS):
        fail(f"{path} does not start with a denial trace header")
    end = records[-1] if records[-1].get("type") == "end" else None
    events = records[1:-1] if end else records[1:]
    last = 0
    for event in events:
        if (event.get("type") != "event" or set(event) != EVENT_KEYS
                or not isinstance(event["t_ms"], int) or event["t_ms"] < last
                or not all(encoded(event[key]) for key in ("kind", "operation", "target",
                                                             "comm"))):
            fail(f"{path} holds a line that is not a denial event")
        last = event["t_ms"]
    return data, header, events, end


def shown(text: str, limit: int = 96) -> str:
    """Trace text is percent-encoded printable ASCII already; this only keeps
    a malformed file from writing control bytes to the terminal."""
    clean = "".join(ch if " " <= ch <= "~" else "?" for ch in text)
    return clean if len(clean) <= limit else clean[: limit - 3] + "..."


def classify(target: str, header) -> str:
    def inside(root: str) -> bool:
        return bool(root) and (target == root or target.startswith(root + "/"))

    if target in header.get("decoys", []):
        return "decoy"
    if not target.startswith("/"):
        return "no path"
    if any(inside(root) for root in header.get("workspace_roots", [])):
        return "workspace"
    if inside(header.get("home", "")):
        return "home"
    return "elsewhere"


def command_show(args):
    path = Path(args.trace)
    _, header, events, end = read_trace(path)
    print(f"trace      {path}")
    print(f"home       {shown(header.get('home', '')) or '(none)'}")
    for root in header.get("workspace_roots", []):
        print(f"workspace  {shown(root)}")
    print(f"decoys     {len(header.get('decoys', []))}")
    if end is None:
        print("end        MISSING: the launch did not end cleanly; do not label this trace")
    else:
        print(f"end        t={end.get('t_ms')} ms, telemetry {shown(str(end.get('state')))}, "
              f"dropped {end.get('dropped')}")
    print(f"denials    {len(events)}")
    if not events:
        return
    for title, counter in (
        ("by kind", Counter(event["kind"] for event in events)),
        ("by place", Counter(classify(event["target"], header) for event in events)),
        ("by process", Counter(event["comm"] for event in events)),
    ):
        print(f"\n{title}:")
        for name, count in counter.most_common(args.top):
            print(f"  {count:6d}  {shown(name)}")
    print("\nmost denied targets:")
    for target, count in Counter(event["target"] for event in events).most_common(args.top):
        print(f"  {count:6d}  {shown(target) or '(none)'}")
    print("\ntimeline (first denial of each target; use t_ms for --onset-ms):")
    seen = set()
    printed = 0
    for event in events:
        if event["target"] in seen:
            continue
        seen.add(event["target"])
        if printed == args.timeline:
            print(f"  ... {len(set(e['target'] for e in events)) - printed} more targets")
            break
        printed += 1
        place = classify(event["target"], header)
        print(f"  {event['t_ms']:9d}  {shown(event['kind'], 14):14s} {place:9s} "
              f"{shown(event['comm'], 16):16s} {shown(event['target']) or '(none)'}")


def command_add(args):
    corpus = Path(args.corpus)
    source = Path(args.trace)
    data, _, events, end = read_trace(source)
    if end is None:
        fail(f"{source} has no end record; the launch did not end cleanly")
    if end.get("state") != "live" and not args.allow_incomplete:
        fail(f"telemetry was {end.get('state')!r} for this launch, so denials are missing; "
             "pass --allow-incomplete to add it anyway")
    note = args.note or ""
    if len(note.encode("utf-8")) > MAX_NOTE_BYTES or any(ch < " " for ch in note):
        fail(f"--note must be one line of at most {MAX_NOTE_BYTES} bytes")
    onset = 0
    if args.label == "misbehaving":
        if args.onset_ms is None:
            fail("a misbehaving session needs --onset-ms (see `label.py show`)")
        if not events or not events[0]["t_ms"] <= args.onset_ms <= events[-1]["t_ms"]:
            fail("--onset-ms must be within the trace's denial times")
        onset = args.onset_ms
    elif args.onset_ms is not None:
        fail("--onset-ms only applies to a misbehaving session")

    traces = corpus / "traces"
    corpus.mkdir(mode=0o700, parents=True, exist_ok=True)
    traces.mkdir(mode=0o700, exist_ok=True)
    digest = hashlib.sha256(data).hexdigest()
    relative = Path("traces") / f"real-{digest[:16]}.jsonl"
    manifest = corpus / "manifest.jsonl"
    if manifest.exists():
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if line and json.loads(line).get("trace") == str(relative):
                fail(f"this trace is already in {manifest}")
    target = corpus / relative
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        fail(f"{target} exists but is not in the manifest; remove it or add its line by hand")
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
    def append(path: Path, record):
        with open(path, "a", encoding="utf-8",
                  opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW, 0o600)) as stream:
            stream.write(json.dumps(record, separators=(",", ":")) + "\n")

    # The manifest is read strictly by glove-denial-replay, so the note lives
    # beside it.
    append(manifest, {"trace": str(relative), "label": args.label, "onset_ms": onset,
                      "split": "real"})
    if note:
        append(corpus / "notes.jsonl", {"trace": str(relative), "note": note})
    print(f"added {relative} as {args.label} ({len(events)} denials)")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    show = commands.add_parser("show", help="summarize a trace so you can label it")
    show.add_argument("trace")
    show.add_argument("--top", type=int, default=10)
    show.add_argument("--timeline", type=int, default=60)
    show.set_defaults(run=command_show)
    add = commands.add_parser("add", help="copy a trace into a corpus as a real session")
    add.add_argument("trace")
    add.add_argument("--corpus", required=True)
    add.add_argument("--label", required=True, choices=("benign", "misbehaving"))
    add.add_argument("--onset-ms", type=int)
    add.add_argument("--note")
    add.add_argument("--allow-incomplete", action="store_true")
    add.set_defaults(run=command_add)
    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
