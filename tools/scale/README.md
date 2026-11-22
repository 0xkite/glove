# Scale harness

Many concurrent `glove exec` launches on one host: start them, hold, stop
them all with SIGTERM at the same moment, optionally start them all again.

```sh
cmake --build --preset release --target glove
tools/scale/scale.py --glove build/release/src/glove --count 1000 --resume --out run-1000
```

On macOS each launch also starts a `log stream` process for denial
telemetry; `samples.csv` counts them, and the stop phase reports how each
launch's telemetry started (`live`, `unavailable`, `degraded`) and how many
ended other than live.

`<out>/summary.json` has start latency (spawn to the agent's ready file),
stop latency and exit codes, how many audit journals have the exit record,
and peak glove memory, threads and descriptors; `<out>/samples.csv` has one
row per second. Run it on a machine you can load: thousands of launches use
every core while they start.

The agent is a shell loop. Model traffic, MCP, egress and denial telemetry
are not exercised, and agent memory is not representative: a real harness
(Pi, Claude) is one to two orders of magnitude larger than glove.

## Measured

Linux x86-64, 16 cores, 31 GiB, Clang 23 release build of bd689e4, all
launches spawned at once by one harness process:

| launches | ready p50 / p99 | stop after SIGTERM p50 / p99 | exit 137 | exit records | host memory used |
|---|---|---|---|---|---|
| 100 | 27 / 49 ms | 21 / 21 ms | 0 | 100 | 0.1 GiB |
| 1000 | 20 / 78 ms | 87 / 137 ms | 0 | 1000 | 1.7 GiB |
| 2000 | 21 / 72 ms | 217 / 281 ms | 0 | 2000 | 4.6 GiB |
| 4000 | 44 / 4317 ms | 1378 / 1748 ms | 37 | 4000 | 9.9 GiB |

Ready latency is from spawning glove to the mtime of the agent's ready file.
Host memory is the drop in MemAvailable and includes the shell agents. Each
glove process held 2 threads and 7 descriptors at every size. One run each;
other work shared the host.

At 4000, 37 agents had not exited within glove's default 1.5 s grace after
SIGTERM because the host was saturated, and were killed (exit 137); every
launch still wrote its exit record. `glove exec --stop-grace <seconds>`
raises the grace. One harness process needed 35 s to
spawn 4000 launches.
