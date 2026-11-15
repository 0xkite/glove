# Glove quickstart

This page is for local containment experiments. For build prerequisites and
managed-session setup, use [build.md](build.md) and
[host-setup.md](host-setup.md). Read [threat-model.md](threat-model.md) before
grading a local experiment into a security claim.

## Build

```sh
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

## Contain an MCP client

```sh
./build/dev/src/glove run \
  --upstream yams=yams,serve,--quiet \
  --allow yams.mcp.echo \
  -- ./build/dev/src/container/glove_synthetic_agent --mode=client
```

## Contain a direct agent

```sh
mkdir -p /tmp/glove-work
./build/dev/src/glove exec \
  --workspace /tmp/glove-work \
  -- /absolute/path/to/agent --version
```

Pass `--allow-loopback-listen` for runtimes (such as `agy`) that bind a
private `127.0.0.1:0` socket inside the isolated network namespace.

## Interactive workspace shell

```sh
./build/dev/src/glove shell --workspace /tmp/glove-work
```

- When `-- <command argv>...` is omitted, `glove shell` defaults to `/bin/bash`
  (or `/bin/sh`).
- When `--workspace` is omitted, Glove creates an ephemeral private runtime
  directory and removes it on exit. An explicit `--workspace` path must already
  exist.

## Seeded agent feedback loop

```sh
./build/dev/src/glove loop \
  --workspace /tmp/glove-work \
  --agent pi \
  --prompt "Write a findings summary to report.md" \
  --verify "test -s report.md" \
  --max-iterations 5
```

`--verify` runs offline inside the sandbox after each turn and feeds failure
output back into the next iteration until it passes or `--max-iterations` is
reached.

`run`, `exec`, `shell`, and `loop` are explicit local containment surfaces. They
do not make remote Sage launch available, and direct Linux execution remains
offline unless `--egress-allow` or `--agent` is specified.
