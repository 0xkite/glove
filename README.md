# Glove

Glove contains an LLM agent in an OS-enforced sandbox. It denies files,
environment, network, and tool access unless an operator grants them explicitly.

> **Status:** research prototype. Remote Sage launch remains disabled until its
> lifecycle, approval, and resource-enforcement contracts are complete.

## Start here

```sh
./setup.sh
```

For development:

```sh
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

Use [`docs/build.md`](docs/build.md) for prerequisites, controlled/offline
builds, and Linux runtime requirements. Use
[`docs/host-setup.md`](docs/host-setup.md) to plan and apply owner-local managed
session setup.

## Why Glove

Glove is a containment boundary, not a prompt-injection detector or a complete
host-security boundary. The motivation, trust boundaries, and residual risks
are in [`docs/architecture.md`](docs/architecture.md) and
[`docs/threat-model.md`](docs/threat-model.md).

## Documentation

- [`docs/build.md`](docs/build.md) — build and validation
- [`docs/host-setup.md`](docs/host-setup.md) — owner-local machine setup
- [`docs/session-policy.md`](docs/session-policy.md) — managed-session policy
  contract
- [`docs/hostile-content-analysis.md`](docs/hostile-content-analysis.md) —
  offline hostile-content profile
- [`docs/quickstart.md`](docs/quickstart.md) — local containment commands
- [`docs/future-work.md`](docs/future-work.md) — unsupported and planned work

## License

Glove is licensed under [GPL-3.0-only](LICENSE). See [CREDITS.md](CREDITS.md)
for dependency licenses and research references.
