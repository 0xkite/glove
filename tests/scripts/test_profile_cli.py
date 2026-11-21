#!/usr/bin/env python3
"""End-to-end `glove profile` and `--profile` behaviour.

    test_profile_cli.py <glove>

Profiles live in a private directory under XDG_CONFIG_HOME; `new` creates an
owner-only template; `edit` saves only content that validates and keeps a
rejected edit aside; `check` refuses profiles that expose glove's own
directories or name missing paths. On macOS, `exec --profile` applies the
profile's environment inside the sandbox and refuses a launch that would
expose the configuration directory before the agent runs.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def glove(binary, env, *args, cwd=None):
    return subprocess.run([binary, *args], env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=60, check=False)


def expect(result, code, needle="", where="stderr"):
    text = result.stdout if where == "stdout" else result.stderr
    if result.returncode != code or needle not in text:
        fail(f"expected rc={code} with {needle!r} in {where}; got rc={result.returncode}\n"
             f"stdout: {result.stdout}\nstderr: {result.stderr}")
    return result


def write_editor(directory: Path, name: str, body: str) -> str:
    path = directory / name
    path.write_text("#!/bin/sh\n" + body, encoding="ascii")
    path.chmod(0o700)
    return str(path)


def main():
    binary = os.path.realpath(sys.argv[1])
    with tempfile.TemporaryDirectory(prefix="glove-profile-cli-") as temp:
        root = Path(os.path.realpath(temp))
        # State stays at its default: exec hardens the audit directory's
        # ancestors, which a system temporary directory does not allow.
        env = dict(os.environ, XDG_CONFIG_HOME=str(root / "config"))
        env.pop("VISUAL", None)

        directory = Path(expect(glove(binary, env, "profile", "path"), 0, where="stdout")
                         .stdout.strip())
        if directory != root / "config" / "glove" / "profiles":
            fail(f"unexpected profile directory {directory}")
        if stat.S_IMODE(directory.stat().st_mode) != 0o700:
            fail("profile directory is not 0700")

        expect(glove(binary, env, "profile", "new", "../escape"), 1, "invalid profile name")
        expect(glove(binary, env, "profile", "new", "demo"), 0, "demo.yaml", where="stdout")
        demo = directory / "demo.yaml"
        if stat.S_IMODE(demo.stat().st_mode) != 0o600:
            fail("new profile is not 0600")
        expect(glove(binary, env, "profile", "new", "demo"), 1, "already exists")
        expect(glove(binary, env, "profile", "check", "demo"), 0, "ok", where="stdout")
        expect(glove(binary, env, "profile", "show", "demo"), 0, "version: 1", where="stdout")
        expect(glove(binary, env, "profile", "show", "absent"), 1, "glove profile new absent")

        # An edit that validates is saved, even when the editor replaces the
        # file the way some editors do (new inode, default mode).
        workspace = root / "workspace"
        workspace.mkdir()
        good = (f"version: 1\nworkspace: {workspace}\n"
                "env:\n  GREETING: { value: \"hi # there\" }\n  PORT: { value: 8080 }\n")
        (root / "good.yaml").write_text(good, encoding="ascii")
        editor = write_editor(root, "replace.sh",
                              f'cp "{root}/good.yaml" "$1.new" && chmod 644 "$1.new" '
                              '&& mv "$1.new" "$1"\n')
        expect(glove(binary, dict(env, EDITOR=editor), "profile", "edit", "demo"), 0, "saved",
               where="stdout")
        if demo.read_text(encoding="ascii") != good:
            fail("saved profile differs from the edit")
        if stat.S_IMODE(demo.stat().st_mode) != 0o600:
            fail("saved profile is not 0600")
        expect(glove(binary, dict(env, EDITOR=editor), "profile", "edit", "demo"), 0,
               "unchanged", where="stdout")

        # An edit that does not validate leaves the profile alone and keeps
        # the attempt aside.
        bad_editor = write_editor(root, "bad.sh", 'printf "version: 1\\nread: [/a]\\nread: [/b]\\n" > "$1"\n')
        expect(glove(binary, dict(env, EDITOR=bad_editor), "profile", "edit", "demo"), 1,
               "duplicate key 'read'")
        if demo.read_text(encoding="ascii") != good:
            fail("a rejected edit changed the profile")
        kept = [p for p in directory.iterdir() if p.name.startswith(".demo.yaml.")]
        if len(kept) != 1:
            fail(f"expected one kept edit, found {kept}")
        kept[0].unlink()

        # A profile that would expose glove's configuration, or names a
        # missing path, is refused by check.
        exposing = directory / "exposing.yaml"
        exposing.write_text(f"version: 1\nread: [\"{root / 'config'}\"]\n", encoding="ascii")
        exposing.chmod(0o600)
        expect(glove(binary, env, "profile", "check", "exposing"), 1, "would expose")
        missing = directory / "missing.yaml"
        missing.write_text("version: 1\nread: [/glove-no-such-path]\n", encoding="ascii")
        missing.chmod(0o600)
        expect(glove(binary, env, "profile", "check", "missing"), 1, "does not exist")
        loose = directory / "loose.yaml"
        loose.write_text("version: 1\n", encoding="ascii")
        loose.chmod(0o644)
        listing = expect(glove(binary, env, "profile", "list"), 0, "demo", where="stdout").stdout
        if "loose" not in listing or "mode 0600" not in listing:
            fail(f"list does not report the loose profile:\n{listing}")
        expect(glove(binary, env, "exec", "--profile", "loose", "--", "/usr/bin/true"), 1, "mode 0600")
        expect(glove(binary, env, "exec", "--profile", "demo", "--profile", "demo", "--",
                     "/usr/bin/true"), 2, "may be given once")

        if sys.platform != "darwin":
            print("profile cli ok (sandbox launch checks run on macOS only)")
            return

        # A private audit log keeps this test independent of other launches
        # holding the default journal's lock.
        audit = str(root / "audit" / "audit.jsonl")
        (root / "audit").mkdir(mode=0o700)

        # The profile's literal environment reaches the sandboxed process.
        script = 'printf "%s|%s" "$GREETING" "$PORT" > out.txt'
        result = glove(binary, env, "exec", "--profile", "demo", "--audit-log", audit, "--",
                       "/bin/sh", "-c", script)
        expect(result, 0)
        if (workspace / "out.txt").read_text(encoding="ascii") != "hi # there|8080":
            fail("profile environment did not reach the sandbox")

        # Exposing glove's configuration stops the launch before the agent runs.
        marker = workspace / "ran.txt"
        result = glove(binary, env, "exec", "--profile", "demo", "--audit-log", audit,
                       "--read", str(root / "config"), "--", "/bin/sh", "-c", f"touch {marker}")
        expect(result, 1, "would expose glove's own configuration")
        if marker.exists():
            fail("the agent ran although the launch was refused")
        # A profile secret reaches only the host side of the credentialed
        # endpoint; the sandbox sees a session nonce, never the value.
        keys = root / "keys"
        keys.mkdir(mode=0o700)
        key = keys / "provider"
        key.write_text("sk-ant-profile-secret-must-not-leak\n", encoding="ascii")
        key.chmod(0o600)
        secret_env = {k: v for k, v in env.items()
                      if k not in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")}

        def profile(name, body):
            path = directory / f"{name}.yaml"
            path.write_text(body, encoding="ascii")
            path.chmod(0o600)

        profile("secret", f"version: 1\nworkspace: {workspace}\nagent: claude-code\n"
                          f"secrets:\n  provider: \"file://{key}\"\n")
        expect(glove(binary, env, "profile", "check", "secret"), 0, "ok", where="stdout")
        observed = workspace / "observed.txt"
        script = 'printf "key=%s\\nbase=%s\\n" "$ANTHROPIC_API_KEY" "$ANTHROPIC_BASE_URL" > observed.txt'
        expect(glove(binary, secret_env, "exec", "--profile", "secret", "--audit-log", audit,
                     "--", "/bin/sh", "-c", script), 0)
        seen = observed.read_text(encoding="ascii")
        if "sk-ant-profile-secret" in seen or "key=glove-session-" not in seen \
                or "base=http://127.0.0.1:" not in seen:
            fail(f"profile secret handling is wrong:\n{seen}")

        # A secret file the sandbox could read is refused before launch.
        inner = workspace / "key"
        inner.write_text("sk-ant-inner\n", encoding="ascii")
        inner.chmod(0o600)
        profile("inner", f"version: 1\nworkspace: {workspace}\nagent: claude-code\n"
                         f"secrets:\n  provider: \"file://{inner}\"\n")
        result = expect(glove(binary, secret_env, "exec", "--profile", "inner", "--audit-log",
                              audit, "--", "/usr/bin/true"), 1, "sandbox can reach")
        if "sk-ant-inner" in result.stderr:
            fail("an error message carried the secret value")
        profile("unset", "version: 1\nagent: claude-code\n"
                         "secrets:\n  provider: env://GLOVE_TEST_UNSET_KEY\n")
        expect(glove(binary, secret_env, "profile", "check", "unset"), 1, "unset or empty")
        expect(glove(binary, secret_env, "profile", "check", "inner"), 1, "sandbox can reach")
        expect(glove(binary, secret_env, "exec", "--profile", "unset", "--audit-log", audit,
                     "--", "/usr/bin/true"), 1, "unset or empty")
        profile("noagent", f"version: 1\nsecrets:\n  provider: \"file://{key}\"\n")
        expect(glove(binary, secret_env, "exec", "--profile", "noagent", "--audit-log", audit,
                     "--", "/usr/bin/true"), 1, "needs an agent preset")
        # A decoy is planted outside the sandbox for the launch, a sandboxed
        # read of it is audited as a decoy hit when denial telemetry is live,
        # and it is gone afterwards.
        vault = root / "vault"
        vault.mkdir(mode=0o700)
        decoy = vault / "backup-token"
        profile("decoy", f"version: 1\nworkspace: {workspace}\ndecoys:\n  - \"{decoy}\"\n")
        decoy_audit = root / "audit" / "decoy.jsonl"
        script = f'cat "{decoy}" > /dev/null 2>&1; exit 0'
        decoy_trace = root / "audit" / "decoy.trace.jsonl"
        expect(glove(binary, env, "exec", "--profile", "decoy", "--audit-log", str(decoy_audit),
                     "--denial-trace", str(decoy_trace), "--", "/bin/sh", "-c", script), 0)
        if decoy.exists():
            fail("the decoy outlived its launch")
        # The trace header names the decoy as the kernel reports it, so a
        # replay counts the hit.
        trace = [json.loads(line) for line in
                 decoy_trace.read_text(encoding="utf-8").splitlines() if line]
        named = os.path.realpath(decoy)
        if trace[0].get("decoys") != [named]:
            fail(f"the trace header does not name the decoy: {trace[0]}")
        records = [json.loads(line) for line in
                   decoy_audit.read_text(encoding="utf-8").splitlines() if line]
        if not any(r["tool"] == "decoys_planted:1" for r in records):
            fail("the planted decoy was not audited")
        live = any(r["tool"] == "telemetry" and '"live"' in r["arguments"] for r in records)
        hits = [r for r in records if r["action"] == "sandbox_denial" and r["tool"] == "decoy"]
        if live and not hits:
            fail(f"a sandboxed read of the decoy was not audited:\n{records}")
        if hits and "backup-token" not in hits[0]["arguments"]:
            fail("the decoy record does not name the decoy")
        if hits and not any(r["type"] == "event" and r["target"] == named for r in trace):
            fail(f"the traced denial does not match the header's decoy: {trace}")

        profile("decoy_inside", f"version: 1\nworkspace: {workspace}\n"
                                f"decoys:\n  - \"{workspace / 'canary'}\"\n")
        expect(glove(binary, env, "exec", "--profile", "decoy_inside", "--audit-log",
                     str(decoy_audit), "--", "/usr/bin/true"), 1, "sandbox can reach")
        if (workspace / "canary").exists():
            fail("a refused decoy was planted")
    print("profile cli ok")


if __name__ == "__main__":
    main()
