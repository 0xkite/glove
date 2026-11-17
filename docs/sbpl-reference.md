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

Never emitted, therefore covered only by `(deny default)`:
`mach-lookup`, `ipc-posix-shm`, `process-info*`, `signal`, `iokit`, `device*`,
`pseudo-tty`, `nvram`, `file-map-executable`. Nothing currently asserts these are
denied.

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
