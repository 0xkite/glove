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

`run` and `exec` are explicit local containment surfaces. They do not make
remote Sage launch available, and direct Linux execution remains offline.
