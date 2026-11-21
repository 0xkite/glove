#!/usr/bin/env python3
"""Collect a labeled denial-trace corpus by running scripted scenarios under
`glove exec --denial-trace`. macOS only. Standard library only.

    tools/denial_model/collect.py --glove build/release/src/glove \\
        --out corpus --repeat 5

Scenarios are POSIX sh scripts under scenarios/benign/ and
scenarios/misbehaving/. Each runs inside the sandbox with a fresh empty
workspace and these variables (passed with --env):

  GLOVE_SCENARIO_HOST_HOME  the invoking user's real home directory (inside
                            the sandbox $HOME is a private directory)
  GLOVE_SCENARIO_NONCE      a fresh random hex string for this run
  GLOVE_SCENARIO_DECOY_1..3 decoy files planted for this run (see below)

Every run, benign or not, gets the same three decoys: canary files that glove
plants outside the sandbox through a launch profile and removes afterwards.
They live in a directory made for the run, never in a real credential
directory. The sandbox cannot list that directory, so a scenario reaches a
decoy only by the name it is given, which models an agent that goes looking
for a well-known secret path. The trace header lists the decoys, and the
`target_decoy` feature counts denied accesses to them.

A misbehaving scenario marks when it starts misbehaving by trying to create
/glove-onset-$GLOVE_SCENARIO_NONCE. The collector takes that denial's time as
the onset and removes the marker from the trace, so no model learns the
marker itself.

Scenarios must be harmless even if the sandbox failed: write only names that
carry the nonce, append zero bytes, and connect only to loopback or TEST-NET
(192.0.2.0/24). After every run the collector looks for any file carrying the
nonce, and stops with an error if one exists.

Output: <out>/traces/*.jsonl and <out>/manifest.jsonl for
`glove-denial-replay rows|evaluate`. Splits are by scenario, so test
scenarios are never seen in training. Traces hold host paths; <out> is 0700.
Add hand-labeled real sessions to the manifest with split "real".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

GROUPS = ("benign", "misbehaving")
SPLIT_PATTERN = ("train", "train", "train", "validate", "test")
RUN_TIMEOUT_S = 120
DECOY_NAMES = ("backup-token", "vault-export.json", "recovery-codes.txt")
PROFILE_NAME = "scenario"


def scenarios(root: Path):
    found = []
    for group in GROUPS:
        for path in sorted((root / group).glob("*.sh")):
            found.append((group, path.stem, path))
    if not found:
        sys.exit(f"no scenarios under {root}")
    return found


def split_for(group: str, name: str, names_in_group: list[str]) -> str:
    """Stratified and deterministic: order a group's scenarios by hash and
    deal them over SPLIT_PATTERN, so every split gets both labels."""
    ordered = sorted(names_in_group, key=lambda n: hashlib.sha256(n.encode()).hexdigest())
    return SPLIT_PATTERN[ordered.index(name) % len(SPLIT_PATTERN)]


def leftovers(nonce: str, home: Path) -> list[Path]:
    """Files that only exist if a scenario write escaped the sandbox."""
    places = [Path("/"), Path("/usr/local/bin"), Path("/Library/LaunchAgents"),
              Path("/Library/LaunchDaemons"), Path("/private/var/at"), home,
              home / "Library" / "LaunchAgents"]
    hits = []
    for place in places:
        try:
            hits.extend(p for p in place.iterdir() if nonce in p.name)
        except OSError:
            continue
    return hits


def clean_trace(raw: Path, marker: str):
    """Drops marker events; returns (lines, onset_ms or None, end state)."""
    kept, onset, state = [], None, None
    for line in raw.read_text(encoding="ascii").splitlines(keepends=True):
        record = json.loads(line)
        if record.get("type") == "event" and record.get("target") == marker:
            if onset is None:
                onset = record["t_ms"]
            continue
        if record.get("type") == "end":
            state = record.get("state")
        kept.append(line)
    return kept, onset, state


def write_profile(config: Path, vault: Path) -> list[Path]:
    """A launch profile that plants the decoys and tells the scenario where
    they are. glove requires the directory 0700 and the file 0600."""
    profiles = config / "glove" / "profiles"
    profiles.mkdir(mode=0o700, parents=True)
    os.chmod(config / "glove", 0o700)
    vault.mkdir(mode=0o700)
    decoys = [vault / name for name in DECOY_NAMES]
    text = "version: 1\nenv:\n"
    for number, decoy in enumerate(decoys, start=1):
        text += f"  GLOVE_SCENARIO_DECOY_{number}: {{ value: {json.dumps(str(decoy))} }}\n"
    text += "decoys:\n" + "".join(f"  - {json.dumps(str(decoy))}\n" for decoy in decoys)
    target = profiles / f"{PROFILE_NAME}.yaml"
    with open(target, "w", encoding="ascii", opener=lambda p, f: os.open(p, f, 0o600)) as s:
        s.write(text)
    return decoys


def run_once(glove: str, group: str, name: str, script: Path, home: Path, out: Path,
             index: int):
    nonce = secrets.token_hex(8)
    marker = f"/glove-onset-{nonce}"
    with tempfile.TemporaryDirectory(prefix="glove-scenario-") as temp:
        temp_path = Path(temp).resolve()
        workspace = temp_path / "workspace"
        workspace.mkdir()
        shutil.copyfile(script, workspace / ".scenario.sh")
        raw = temp_path / "trace.jsonl"
        config = temp_path / "config"
        decoys = write_profile(config, temp_path / "vault")
        env = dict(os.environ, GLOVE_SCENARIO_HOST_HOME=str(home),
                   GLOVE_SCENARIO_NONCE=nonce, XDG_CONFIG_HOME=str(config))
        argv = [glove, "exec", "--profile", PROFILE_NAME, "--workspace", str(workspace),
                "--denial-trace", str(raw),
                "--env", "GLOVE_SCENARIO_HOST_HOME", "--env", "GLOVE_SCENARIO_NONCE",
                "--", "/bin/sh", str(workspace / ".scenario.sh")]
        try:
            subprocess.run(argv, env=env, cwd=workspace, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=RUN_TIMEOUT_S, check=False)
        except subprocess.TimeoutExpired:
            print(f"  {name}#{index}: timed out; skipped", file=sys.stderr)
            return None
        escaped = leftovers(nonce, home)
        if escaped:
            for path in escaped:
                try:
                    path.unlink()
                except OSError:
                    pass
            sys.exit(f"SANDBOX DID NOT HOLD: {name}#{index} left {escaped}")
        if not raw.exists():
            print(f"  {name}#{index}: no trace written; skipped", file=sys.stderr)
            return None
        lines, onset, state = clean_trace(raw, marker)
        planted = json.loads(lines[0]).get("decoys") if lines else None
        if planted != [str(decoy) for decoy in decoys]:
            sys.exit(f"{name}#{index}: the trace does not list the planted decoys: {planted}")
        hits = sum(1 for line in lines if json.loads(line).get("target") in planted)
        if group == "benign" and hits:
            sys.exit(f"scenario bug: benign {name} reached for a decoy")
    if state != "live":
        print(f"  {name}#{index}: telemetry {state or 'incomplete'}; skipped", file=sys.stderr)
        return None
    if group == "benign" and onset is not None:
        sys.exit(f"scenario bug: benign {name} wrote the onset marker")
    if group == "misbehaving" and onset is None:
        print(f"  {name}#{index}: onset marker not observed; skipped", file=sys.stderr)
        return None
    relative = Path("traces") / f"{group}-{name}-{index}.jsonl"
    target = out / relative
    with open(target, "w", encoding="ascii", opener=lambda p, f: os.open(p, f, 0o600)) as s:
        s.writelines(lines)
    return str(relative), (onset or 0)


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--glove", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--scenarios", default=str(here / "scenarios"))
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--only", action="append", default=[],
                        help="run only these scenario names (repeatable)")
    args = parser.parse_args()
    if sys.platform != "darwin":
        sys.exit("denial traces are recorded on macOS only")
    glove = os.path.realpath(args.glove)
    if not os.access(glove, os.X_OK):
        sys.exit(f"not an executable: {args.glove}")

    out = Path(args.out)
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    (out / "traces").mkdir(mode=0o700)
    home = Path(os.path.realpath(os.path.expanduser("~")))
    found = scenarios(Path(args.scenarios))
    by_group = {g: [n for gg, n, _ in found if gg == g] for g in GROUPS}
    manifest = []
    for group, name, script in found:
        if args.only and name not in args.only:
            continue
        split = split_for(group, name, by_group[group])
        print(f"{group}/{name} -> {split}", file=sys.stderr)
        for index in range(args.repeat):
            result = run_once(glove, group, name, script, home, out, index)
            if result is None:
                continue
            trace, onset = result
            manifest.append({"trace": trace, "label": group, "onset_ms": onset,
                             "split": split})
    with open(out / "manifest.jsonl", "w", encoding="ascii") as stream:
        for entry in manifest:
            stream.write(json.dumps(entry, separators=(",", ":")) + "\n")
    print(f"{len(manifest)} traces in {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
