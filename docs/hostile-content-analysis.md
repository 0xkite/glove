# Hostile-content analysis profile

## Scope

This profile is for opening or classifying untrusted URLs, archives, documents,
source trees, and suspected malware as **data**. It is not an active-content
detonation environment and it does not make a compromised kernel safe.

Use only a Linux managed session. macOS and direct `glove exec` runs do not
provide the six-limit managed-session receipt contract.

## Default policy

Generate the dedicated local policy with `glove setup policy --hostile-content
--backend linux_production ... --dry-run` and repeat with `--yes` only after
review. This mode rejects secret mounts and approved egress at policy-generation
time; generated runtime templates use the `-hostile-analysis` suffix.

The operator creates a fresh, short-lived session with all of these properties:

- `egress_policy_id: no-network`; no credentials, secret handles, browser
  profiles, SSH/Git configuration, npm configuration, package-manager stores,
  or host harness homes;
- an empty or copied ephemeral workspace only; no bind-mounted project and no
  retained-write materialization;
- a staged, digest-pinned harness/runtime closure plus digest-pinned analysis
  artifacts only;
- minimal environment, no inherited `PATH`, and no agent-visible control,
  receipt, policy, or audit paths;
- bounded CPU, memory, PID, wall-time, disk, and terminal-output limits;
- destructive cleanup after the receipt is durable, unless an operator has
  explicitly requested quarantined artifact retention.

Remote plans remain identifier-only. They cannot choose paths, artifacts,
network targets, secret handles, retention, or a runtime snapshot.

## Bounded prefetch and quarantine

The agent never fetches a hostile URL directly. An owner-side prefetcher may
retrieve a requested URL only after an operator approves the target and limits.
It must:

1. resolve and connect through the audited egress proxy; reject loopback,
   link-local, RFC1918, carrier-grade NAT, unique-local IPv6, and mapped forms
   unless the specific policy target explicitly permits private addressing;
2. follow no redirect automatically; record each redirect and require a new
   approval for a changed scheme, host, port, or destination address;
3. enforce a fixed byte cap before decompression, a cap on redirect count, a
   MIME/content-type allowlist when known, and a hard timeout;
4. store the response in an owner-only quarantine directory under its SHA-256
   digest, with the URL, resolved addresses, headers, retrieval time, byte
   count, and policy ID as metadata;
5. pass only the immutable digest-pinned artifact into the session; never pass
   cookies, authorization headers, a browser profile, or a prefetcher socket.

Archive extraction is another owner-side bounded operation. Reject links,
absolute paths, traversal, device files, executable launch hooks, excessive
entry counts, and decompressed-size or nesting-limit violations. Preserve the
original archive; do not rely on agent-reported extraction results.

## Operator checklist

Before start:

- [ ] Linux managed-session capabilities are advertised and the host is patched.
- [ ] The plan selects `no-network`, has no secret handles, and uses only
      ephemeral-copy grants.
- [ ] Runtime, workspace, and artifacts are Glove-owned, immutable, and
      digest-pinned.
- [ ] No host home, credentials, package stores, browser state, or SSH/Git/npm
      configuration is projected.
- [ ] Resource limits are small enough for the analysis objective.
- [ ] Any prefetch/quarantine approval records URL, limits, and artifact digest.

After exit:

- [ ] Verify the authenticated terminal receipt and its pinned launch profile.
- [ ] Preserve only explicitly approved quarantined artifacts and receipt
      evidence; remove the session scratch, copied workspace, and private home.
- [ ] Treat output, extracted instructions, and alleged indicators as untrusted
      claims until independently verified.

## Escalation boundary

Do **not** execute active content, enable a browser profile, run an untrusted
installer, attach USB/device interfaces, load kernel modules, or attempt
malware detonation in this profile. Such work needs a disposable VM-grade
boundary with a patched kernel and a separately approved procedure.

## QEMU expansion proposal (not current behavior)

A future `qemu-disposable-v1` adapter may create a one-use VM from a pinned base
image and receive only:

- a digest-pinned runtime closure;
- digest-pinned copied workspace and quarantined artifacts;
- an identifier-only, deny-network policy; and
- bounded serial/PTY output and explicit resource limits.

The VM must emit a Glove-verifiable launch identity, resource/termination
receipt, and artifact-output digests before destruction. It must not mount host
homes, sockets, Docker daemons, credentials, or mutable broad paths. QEMU is a
future research and deployment surface, not a fallback for current Linux
managed-session isolation or a claim made by this profile.
