# SBPL reference (local, verified)

Apple does not publish a reference for the sandbox profile language. `sandbox.h`
declares `sandbox_init` deprecated as of macOS 10.8, `sandbox-exec(1)` is
deprecated, and the profile grammar exists only in the implementation. Glove
generates SBPL as its entire macOS containment boundary, so this file records
the subset Glove depends on, with each claim marked:

- **[verified]** — observed on this host with `scripts/sbpl-probes.sh`; the probe
  id is given so the claim can be re-checked.
- **[apple-doc]** — stated by Apple documentation or the `sandbox-exec` man page.
- **[inferred]** — follows from the above but was not directly probed; treat as
  a hypothesis to confirm before relying on it.

Verified on: macOS 27.2.1, arm64, Apple clang 21. Re-run the harness after an OS
upgrade before trusting any [verified] line; the grammar is unversioned.

## Application model

Glove does not call `sandbox_init`. It builds the profile text and passes it to
`/usr/bin/sandbox-exec -p <profile> <program> [args...]`
(`src/container/macos/sandbox_spawner.cpp:391-404`), which compiles and applies
the profile, then `exec`s the target. The profile therefore covers the agent from
its first instruction and survives `exec` and `fork`.

- **[verified] (V1)** `(version 1)` is mandatory. A profile without it fails with
  `sandbox-exec: no version specified` and exit 65. Glove emits it
  (`sandbox_spawner.cpp:306`).
- **[verified]** Without an explicit `(deny default)`, `sandbox-exec` still
  applies a restrictive built-in baseline: `(version 1)` alone cannot even
  `exec` a binary. "No deny default" does not mean "allow".
- **[verified]** A malformed or unknown profile construct fails at *apply* time
  with exit 65 and a diagnostic on stderr, after `posix_spawn` has already
  succeeded. The parent sees a normal child exit, not a construction failure.
  Compile-check a profile by running it against `/usr/bin/true` before launch.
- **[apple-doc]** Only `sandbox_init`, `sandbox_free_error`, and
  `sandbox_check` exist in the header; `sandbox_check` is not in the public SDK.

## Rule model

```text
(allow|deny <operation> [<filter> ...])
```

Precedence is **specificity first, then source order**:

- **[verified] (U1, U2)** A *filtered* allow is not overridden by a later
  *unfiltered* deny. `(deny file-read*)(allow file-read* (literal "..."))` allows
  the literal; reversed order also allows it.
- **[verified] (O1, O2)** Among rules of equal specificity, the **later** rule
  wins: `(allow ...)(deny ...)` on the same literal denies, while
  `(deny ...)(allow ...)` allows.
- **[inferred]** This is why `(deny default)` plus targeted filtered allows is a
  coherent model: the blanket deny has zero filters, so every filtered allow
  outranks it. A later *unfiltered* deny cannot retract an earlier filtered
  allow; only an equal-or-more-specific deny can.

## Denial telemetry

A denial is written to the unified log by the kernel, not by the profile:

```text
Sandbox: <comm>(<pid>) deny(<n>) <operation> <target>
```

- **[verified]** A non-root reader can follow these events live with
  `log stream --predicate 'eventMessage CONTAINS "Sandbox:" AND eventMessage CONTAINS "deny"'`,
  and sees the line while the denied process is still running. The workload
  continues afterwards: the denial stays non-fatal.
- **[verified]** `(with no-log)` is accepted on a deny and suppresses logging;
  a profile that wants telemetry must not carry it.
- **[verified, negative]** `(with report)` on an *allow* produced no observable
  record in this test. Treat allow-side reporting as unavailable rather than
  relying on it.

This is what makes a middle response possible at all. The sandbox can only allow
or deny, and `report` is rejected on deny, so "warn" cannot be expressed in
SBPL. It can be expressed *outside* it: the profile denies as usual (the agent
keeps running), and the trusted supervisor tails the log, attributes the event
to a verified child identity, and decides what to do.

Limits, which matter more than the capability:

- Best effort, not enforcement. The log is asynchronous and can lose events
  under load. A signal that the agent can flood is not a control.
- Attribution is by sandbox membership, not by pid. A deny rule can carry
  `(with message "<text>")`, and the kernel appends a newline and that text to
  every denial the rule decides. Glove gives every deny rule of a launch the
  same random 128-bit tag, so a line that ends with the tag came from a process
  under that launch's profile. The pid in the line is informative only: pids
  are recycled, and it must never choose a signal target.
- Host-wide noise is real: a `bash` invocation in this probe also produced
  `/dev/tty` denials from unrelated activity. Filter by verified pid, classify
  by operation, and rate-limit.

### Reading the denial log safely

Measured on macOS 27.2.1 (arm64) with `log stream`, a deny-default profile, and probes that put hostile bytes in
the process name and in the denied target.

- **[verified]** The predicate above is not a provenance check. An unprivileged process, including one inside
  the sandbox, can run `logger "Sandbox: x(4243) deny(1) file-read-data /y"` and the predicate matches it. Real
  denials carry `processID` 0, `processImagePath` `/kernel`, and `senderImagePath`
  `/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox`; the forged record carries the logger's own
  pid and image path. A reader must check those three fields. The predicate
  `processID == 0 AND senderImagePath ENDSWITH "/Sandbox" AND eventMessage CONTAINS "deny("` drops the forgery
  at the source, and the reader checks the fields again.
- **[verified]** The text styles (`default`, `compact`, `syslog`) are not line-safe. A denied target can contain a
  newline (a Mach service name did in the probe), and the text styles print it raw, so one event can forge a
  complete second `Sandbox: ...` line. `--style ndjson` prints one JSON object per line and escapes the newline.
  Use `ndjson` only.
- **[verified]** `ndjson` output starts with one non-JSON banner line (`Filtering the log data using ...`).
  Forward slashes are escaped as `\/`, control bytes as `\u00XX`, and non-ASCII UTF-8 is passed through.
- **[verified]** The message is `Sandbox: <name>(<pid>) deny(<n>) <operation> <target>`. The kernel may also emit
  `<N> duplicate report(s) for Sandbox: ...` for repeats. Some operations append a second line to the message
  (`syscall-unix 186\nsyscall-unix-denied`). The target is unquoted and unescaped.
- **[verified]** `<name>` is the process name, truncated to 32 bytes, and is taken from the executed file's name.
  A file named `x(1) deny(1) file-read-data y` produced
  `Sandbox: x(1) deny(1) file-read-data y(65172) deny(1) mach-lookup ...`. The grammar cannot tell which
  `(<pid>) deny(` is the real one, so a reader must keep every reading and must not attribute an ambiguous event
  to one process on the text alone.
- **[verified, negative]** A denial whose target is not valid UTF-8 did not appear in `log stream` at all, in
  either `ndjson` or `compact` style, while the denials immediately before and after it from the same process
  did. A sandboxed process can therefore hide a `mach-lookup` denial from this channel by choosing the service
  name. Denial counts from the log are a lower bound.
- **[verified]** `log stream` delivered a denial triggered about 0.3 s after the stream process was started, and
  exits on SIGTERM. Host-wide volume during the probe was about 300 matching events per second from unrelated
  system processes.

### Session tag (`with message`)

Measured on macOS 27.2.1 (arm64), Sandbox profiles version 1, with `sandbox-exec` and `log stream --style ndjson`.

- **[verified]** `(deny default (with message "T"))` and a filtered deny such as
  `(deny file-write* (literal "/p") (with message "T"))` compile, and the message of each denial they decide ends
  with a newline and T. This holds for file, network-outbound, mach-lookup and user-preference denials, for the
  `<N> duplicate report for` form, for children, and for a process that called `setsid`.
- **[verified]** A deny rule without the modifier gives no suffix, including when a tagged `(deny default ...)` is
  present and the untagged rule is the one that decides. Every deny rule must carry the tag.
- **[verified]** `system.sb` and `dyld-support.sb` contain no deny rule on this release.
- **[verified]** In a `log stream` predicate, `eventMessage ENDSWITH "\nT"` works when the newline is written as
  backslash-n; a literal newline byte is rejected as a bad predicate. Two tags can be joined with `OR`.
- **[verified]** Only the final line is evidence. A sandboxed process can put a newline and any text, including
  another launch's tag, in a denied path; the kernel still appends its own profile's tag after it.
- **[verified]** The tag is not secret. A process inside a profile that allows `sysctl-read` can read the
  arguments of the `log` child with `KERN_PROCARGS2`, and `sandbox-exec` holds the profile in its arguments until
  it executes the agent. A process outside the launch that knows the tag and can sandbox itself can produce a
  line that ends with it, either with an untagged profile and a path ending in a newline and the tag, or with its
  own profile carrying the same message. A process already inside a sandbox cannot apply a second profile
  (`sandbox_apply: Operation not permitted`).
- **[verified]** Some lines carry no tag, so counts stay a lower bound:
  - A message longer than 1007 bytes is cut to 1008 bytes plus the three characters `<…>` and loses the tag.
    That happens for a path of about 930 bytes or more.
  - A denied `signal` produced no log line at all.
  - `forbidden-exec-sugid` is logged without the tag and has no rule name to attach one to.
  - Platform-policy denials are logged as `System Policy: ...` by the same kernel sender, without the tag and
    with a target the process chooses. A reader must require the `Sandbox: ` prefix as well as the tag.
  - A target that is not valid UTF-8 is still not logged.

## Response modifiers

A rule can carry `(with ...)` modifiers that change what happens when it matches.
These are the only lever SBPL gives for *reacting* to a violation.

| Modifier | Valid on | Effect | Probe |
| --- | --- | --- | --- |
| `(with send-signal SIGKILL)` | allow or deny | terminates the calling process at the syscall | R3, R6 |
| `(with send-signal SIGTERM)` | — | accepted but does **not** terminate; the caller continues and sees the ordinary denial | R5 |
| `(with report)` | **allow only** | logs the allowed operation; rejected on a deny with `sandbox-exec: report modifier does not apply to deny action` | R1 |
| `(with no-log)` | deny | accepted; suppresses logging | — |

Precision holds: the signal fires only when that rule is the one that decides.
A write outside the rule's filter, or a connection to an allowed port, is
unaffected (R4, R7). Specificity still governs, so a filtered tripwire outranks
the unfiltered `(deny default)` and even an unfiltered allow.

This is the only in-kernel "stop the caller" primitive SBPL offers, and it is
the macOS counterpart to the Linux seccomp `SCMP_ACT_NOTIFY` supervisor running
its `terminate_container` policy: it needs no supervisor process and the agent
cannot race it.

It is also the *only* containment-violation signal a parent can observe,
because `report` is rejected on denials. A child killed by a tripwire exits
137; an ordinary denial is invisible to the parent, which sees only the agent's
later exit code. Design consequence: put tripwires on operation classes that are
never legitimate for a contained agent, and leave ordinary capability denials
(an ungranted path or host) as plain `EPERM`, because agents probe those
routinely and must keep running.

## Path filters

`(literal <path>)`, `(subpath <path>)`, `(regex <pattern>)`, `(suffix <s>)`,
`(prefix <s>)` **[inferred from grammar; only literal/subpath probed]**.

Path matching has four properties that decide correctness:

1. **[verified] (T2, T3, T4)** Rules are matched against the **fully resolved
   path**, and rule strings are **never normalized**. A rule written as
   `/tmp/x` does not match an access to `/private/tmp/x`, because `/tmp` is a
   symlink to `/private/tmp`. The same trap applies to `/var` and
   `/etc` (`/private/var`, `/private/etc`). A grant in symlink spelling grants
   nothing: it fails closed, and looks like an agent bug rather than a policy
   bug.
2. **[verified] (L2, L3, L5, L6)** A symlink inside a granted directory cannot
   escape the grant. Accessing `grant/link/target` is matched as the resolved
   target, so the grant applies only if the *target* is granted; a rule naming
   the symlink itself matches nothing. This is stronger than lexical prefix
   matching and is why symlink swaps inside a grant are not an escape.
3. **[verified] (P1)** `subpath` is component-aware: granting `/w` does not
   match `/wx`.
4. **[verified] (K1)** Matching is case-insensitive on a case-insensitive
   volume: a rule on `/w/F` matches an access to `/w/f`. On default APFS this is
   the same object, so it is not an escape; it becomes one if a
   case-sensitive volume is reachable inside a grant.

Residual difference from Landlock: Landlock binds **inodes** when the ruleset is
built; SBPL matches a **resolved path string** at access time. Replace a granted
directory (rename it away and put a different directory at the same path) and
SBPL grants the new object, while a Landlock rule would still protect the
original inode. Glove mitigates the grant-root case
(`append_grant_root_guard`, `sandbox_spawner.cpp:296-303`) but does not, and
cannot, get inode binding.

## Network filters

`(remote ip "host:port")`, `(remote tcp "host:port")`, `(remote udp ...)`,
`(local ...)`, `(socket-domain AF_INET|AF_INET6|AF_UNIX)`.

- **[verified] (N1, N2, N9)** `(remote ip "localhost:PORT")` with a numeric port
  admits `127.0.0.1:PORT` only: not a neighbouring port, not `127.0.0.2`.
- **[verified] (N4)** `localhost` in a `remote ip` filter matches **both**
  loopback families, so that rule also admits `::1:PORT`. Pinning
  `(socket-domain AF_INET)` removes it (N5) — this is the defect class fixed in
  commit `4db3241`.
- **[verified] (N7, N10)** `remote tcp` excludes UDP on the same port;
  `remote ip` does not distinguish transport, so a UDP probe passes it unless a
  `socket-domain` filter excludes it.
- **[verified] (N8)** A filtered network allow outranks `(deny network*)`.
- **[verified] (Y1, Y2)** `(import "system.sb")` grants exactly one network
  endpoint — the host syslog datagram socket at `/private/var/run/syslog` — and a
  filtered `(deny network-outbound (subpath "/private/var/run"))` closes it.
  Without that deny, a profile that advertises deny-default network is false.

## Operations Glove emits

| Operation | Emitted at | Notes |
| --- | --- | --- |
| `process-exec*`, `process-fork`, `sysctl-read` | `sandbox_spawner.cpp:308` | unfiltered allows |
| `file-read*` | `:309-325` via `append_read_rule` | literal + subpath, plus ancestor `file-read-metadata` |
| `network*` (deny) | `:327` | blanket |
| `network-outbound` (deny, path-filtered) | `:334` | closes the imported syslog grant |
| `network-outbound` (allow, `AF_INET`) | `:338-351` | bridge endpoint and egress proxy |
| `file-write*` (deny) | `:352` | blanket |
| `file-write*` (allow) | `:355-360` | per writable grant |
| `file-write-unlink/mode/owner/flags` (deny) | `:296-303` | grant-root guard |

Never emitted, therefore handed to `(deny default)` **unless the import grants
it**: `mach-lookup`, `ipc-posix-shm`, `process-info*`, `signal`, `iokit`,
`device*`, `pseudo-tty`, `nvram`, `file-map-executable`. See the next section:
three of those are in fact granted by the import, so "not emitted" means
"unknown", not "denied". Nothing in the test suite currently asserts any of
them.

## What `(import "system.sb")` actually grants

The import is not limited to dynamic-loader plumbing. Its rules are *filtered*
allows, so they outrank `(deny default)`. Reading
`/System/Library/Sandbox/Profiles/system.sb` (version 3, 12 KB) on this host:

- `(allow mach-lookup (global-name ...))` for around twenty host services
  (`:158`), and, under `(when (sbpl-version-compatible? 1) ...)`, an **empty XPC
  prefix**: `(allow mach-lookup (xpc-service-name-prefix ""))` (`:21-23`).
- `(allow ipc-posix-shm-read* (ipc-posix-name "apple.shm.notification_center")
  (ipc-posix-name-prefix "apple.cfprefs."))` (`:154-156`).
- Filtered write grants: `(allow file-read-data file-test-existence
  file-write-data (subpath "/dev/fd"))` (`:119`) and `(allow file-write-create
  (require-all (prefix "/cores/") (vnode-type REGULAR-FILE)))` (`:135`).
- The syslog datagram socket (probes Y1/Y2).

Consequence for auditing: an operation class the generator never mentions is
*not* necessarily denied. It is denied only where the import grants nothing.
The generator retracts the imported network grant explicitly
(`sandbox_spawner.cpp:334`) and retracts none of the others.

## Reproducing

```sh
./scripts/sbpl-probes.sh          # prints ok/FAIL per case and a total
```

The harness compiles a small connect probe, starts a loopback listener, and runs
each case under `sandbox-exec`, classifying the outcome as `allow`,
`sandbox-deny`, or `profile-error`. All three matter: a sandbox denial surfaces
as `EPERM` (`Operation not permitted`), an *allowed* connection to a closed port
surfaces as `ECONNREFUSED`, and a profile that does not compile exits 65 with a
`sandbox-exec:` diagnostic. Treating any non-zero exit as "denied" would misread
a permitted connection as a denial and hide a compile failure behind it.

## Not covered

`system.sb` contents beyond the syslog grant; `mach-lookup` service matching;
`iokit` and device matching; entitlements interaction; anything requiring a
code-signed bundle. Extend the harness before relying on any of it.
