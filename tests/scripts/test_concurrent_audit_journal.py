#!/usr/bin/env python3
"""Two glove launches at once with the default audit journal both run: the
second records to its own journal beside the shared one, and no record of
one launch lands in the other's journal. An explicit --audit-log that is in
use stays an error. Exits 77 when this host cannot launch a sandbox at all.

    test_concurrent_audit_journal.py <glove>
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def main():
    binary = sys.argv[1]
    with tempfile.TemporaryDirectory(prefix="glove-journal-test-", dir=Path.home()) as temp:
        root = Path(os.path.realpath(temp))
        state = root / "state"
        workspace = root / "workspace"
        state.mkdir(mode=0o700)
        workspace.mkdir()
        env = dict(os.environ, XDG_STATE_HOME=str(state))
        logs = state / "glove" / "logs"
        shared = logs / "session.jsonl"

        def launch(script, *flags):
            return subprocess.Popen(
                [binary, "exec", "--workspace", str(workspace), *flags, "--", "/bin/sh", "-c",
                 script],
                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True)

        probe = launch("exit 0")
        _, probe_err = probe.communicate(timeout=60)
        if probe.returncode != 0:
            print(f"SKIP this host cannot launch a sandbox: {probe_err.strip()[:200]}")
            sys.exit(77)
        before = len(records(shared))

        first = launch(f'while [ ! -e "{workspace}/go" ]; do sleep 0.1; done')
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and len(records(shared)) == before:
            time.sleep(0.05)
        if len(records(shared)) == before:
            first.kill()
            fail("the first launch never wrote to the shared journal")

        second = launch("exit 7")
        _, second_err = second.communicate(timeout=60)
        (workspace / "go").touch()
        _, first_err = first.communicate(timeout=60)
        if second.returncode != 7 or first.returncode != 0:
            fail(f"launches failed: first rc={first.returncode} {first_err!r}; "
                 f"second rc={second.returncode} {second_err!r}")
        own = [p for p in logs.iterdir() if p.name != "session.jsonl"]
        if len(own) != 1 or not own[0].name.startswith("session.") or own[0].suffix != ".jsonl":
            fail(f"expected one per-launch journal beside the shared one, found {own}")
        # The notice is one line with a fixed prefix and the path to the end
        # of the line, so a harness can collect the journal without guessing.
        prefix = "glove: another launch holds the default audit journal; this launch records to "
        noted = [line[len(prefix):] for line in second_err.splitlines()
                 if line.startswith(prefix)]
        if noted != [str(own[0])]:
            fail(f"the second launch did not say where it recorded: {second_err!r}")
        if (own[0].stat().st_mode & 0o777) != 0o600:
            fail("the per-launch journal is not 0600")
        mine = [r["action"] for r in records(own[0])]
        if mine.count("agent_launch") != 1 or mine.count("agent_exit") != 1:
            fail(f"the per-launch journal does not hold exactly one launch: {mine}")
        shared_actions = [r["action"] for r in records(shared)[before:]]
        if shared_actions.count("agent_launch") != 1 or shared_actions.count("agent_exit") != 1:
            fail(f"the shared journal holds another launch's records: {shared_actions}")

        # A journal the operator named is theirs to keep single-writer.
        named = root / "named.jsonl"
        (workspace / "go").unlink()
        holder = launch(f'while [ ! -e "{workspace}/go" ]; do sleep 0.1; done', "--audit-log",
                        str(named))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not (named.exists() and named.stat().st_size):
            time.sleep(0.05)
        clash = launch("exit 0", "--audit-log", str(named))
        _, clash_err = clash.communicate(timeout=60)
        (workspace / "go").touch()
        holder.communicate(timeout=60)
        if clash.returncode == 0 or "in use by another glove launch" not in clash_err:
            fail(f"a named journal in use was not refused: rc={clash.returncode} {clash_err!r}")
    print("concurrent audit journal ok")


if __name__ == "__main__":
    main()
