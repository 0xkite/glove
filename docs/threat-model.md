# Glove threat model

## Security objective

Glove limits the authority of an untrusted agent process to explicitly selected
files, environment variables, network destinations, and MCP tools. It also
records policy decisions and, for managed Linux sessions, produces authenticated
resource-enforcement receipts.

Glove is a containment boundary, not a prompt-injection detector or a complete
host security boundary.

## Trust boundaries

| Component | Trust assumption |
|---|---|
| Agent process and model output | Untrusted |
| Agent-supplied JSON-RPC and terminal input | Untrusted |
| Glove control, policy, and sandbox code | Trusted |
| Local policy, launch templates, and approval records | Trusted operator input |
| Project files, repository configuration, and agent instructions | Untrusted; never machine-setup authority |
| MCP upstream servers | Trusted host processes; not sandboxed by Glove |
| Sage controller | Authenticated peer, but not authority for raw paths, exposure administration, or host mutation |
| Operating-system kernel and platform sandbox | Trusted and patched |
| Other processes under the same host user | Outside the strong integrity boundary |

## Enforced properties

| Area | Enforcement |
|---|---|
| Filesystem | Deny-default sandbox; explicit read/write grants; descriptor-based path resolution; link, ownership, identity, and overlap checks |
| Network | Linux network namespace and seccomp denial; exact macOS egress rules |
| Process surface | Linux PID/user/IPC/UTS namespaces; macOS deny-default SBPL |
| Environment | Minimal environment plus named grants |
| Tool access | Qualified allow-list and configured argument rules before upstream dispatch |
| Protocol | Bounded JSON-RPC frames, strict decoding, initialization checks, and timeouts |
| Resources | Linux cgroup CPU/memory/PID limits, watchdog wall time, filesystem quotas, and aggregate terminal-output accounting |
| Audit | Agent-inaccessible JSONL destination; HMAC-chained managed-session terminal receipts |
| Remote plans | Identifier-only canonical plan matched against owner-local policy and dual digests |
| Recovery | Append-only state, exact replay, process identity beyond PID, and fail-closed reconciliation |

Security-relevant append, policy, setup, and receipt failures terminate or reject
the operation rather than silently reducing enforcement.

## Residual risks

| Risk | Consequence | Required mitigation |
|---|---|---|
| Allowed-tool abuse or prompt injection | An agent can perform malicious operations that remain within an allowed tool's semantics. | Narrow tool and argument policy; upstream semantic authorization. |
| Unsandboxed upstream compromise | A vulnerable MCP server can act with its host-user authority. | Run upstreams in separate sandboxes or move them behind a hardened service boundary. |
| Same-user host tampering | A peer process can rewrite the general JSONL log or unkeyed session state and may read shared local secrets. | Isolate the service identity; use asymmetric signing or protected key storage; authenticate general logs. |
| Linux kernel escape | A kernel vulnerability can cross namespace or seccomp boundaries. | Patch hosts and add an outer VM/container boundary where required. |
| macOS resource exhaustion | The Sage six-limit resource contract is not implemented on macOS. | Add enforceable CPU, memory, PID, wall-time, disk, and output controls with receipts. |
| Linux egress unavailable | Contained direct agents cannot use approved network destinations on Linux. | Implement an authenticated proxy transport into the network namespace. |
| Retained-change apply disabled | The local atomic/recovery primitive is not a production authorization boundary by itself. | Keep capability `0` until the independent Ed25519 helper/verifier, local RPC/audit path, startup sweep, host-space policy, and Sage-to-parent isolation are configured and tested. |
| Bundle expansion absent | A verified bundle file is not yet converted into harness-native prompt context. | Add bounded, format-aware extraction and receipt-bound launch inputs. |
| Dependency or compiler compromise | Build-time code or toolchain compromise can alter enforcement. | Pin dependencies by immutable digest, verify releases, and use reproducible builds. |
| Protocol parser defects | Malformed input may expose untested parser behavior. | Add fuzz targets and a maintained adversarial corpus. |

## Assumptions

The security claims require:

- the operator controls policy, runtime templates, protected directories, and
  the Glove executable;
- the host kernel and platform sandbox behave as documented;
- no agent-visible path contains control secrets, journals, or audit output;
- machine setup and project enrollment are performed by the local operator,
  outside any remote request or project-provided configuration;
- allowed tools and upstream servers are appropriate for the deployment;
- Linux cgroup v2, namespace, mount, seccomp, and quota prerequisites are
  available when managed-session capabilities are advertised;
- callers use capability discovery and do not infer support from source code or
  platform alone.

## Deployment review

Before enabling an agent, record:

1. Which host paths and environment variables are visible?
2. Which MCP tools and argument forms are allowed?
3. Which upstream processes run outside the sandbox?
4. Is network access denied or restricted to exact destinations?
5. Are audit and control files inaccessible to the agent and other principals?
6. Are all advertised resource controls enforced on the selected backend?
7. Are live host writes absent, and is any future change apply independently authorized?
8. Is the host patched and, where needed, enclosed by a stronger VM boundary?

Remote Sage launch should remain gated whenever any mandatory capability or
approval class is unavailable.
