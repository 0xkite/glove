# Mediated Credential Proxy & Upstream Containment Architecture

## 1. Problem Statement & Motivation

Traditional cloud sandboxes and disposable VMs isolate the host machine's filesystem from accidental destruction (`rm -rf /`), but they fail to solve the primary threat in autonomous agent workflows: **credential exfiltration and privilege abuse**.

When an LLM coding agent requires access to external APIs (e.g., Anthropic, OpenAI, GitHub), conventional platforms inject raw API keys or access tokens directly into the container's environment or filesystem. If the agent encounters prompt injection, hostile active content, or dependency-chain malware, the agent has both:
1. **The Credential**: Full access to inspect and read the raw token.
2. **The Egress Route**: Unrestricted outbound internet connectivity to exfiltrate the token to an arbitrary attacker-controlled domain.

Glove addresses this vulnerability through an **object-capability mediated proxy abstraction** that completely unbundles credentials from the agent sandbox.

---

## 2. Core Architecture: Virtual Loopback Reverse Proxy & Nonce Swap

Instead of mounting credential files into `/home/agent` or injecting ambient secrets into the process environment, Glove intercepts provider traffic over its existing private loopback descriptor channel.

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ Contained Agent (Untrusted Sandbox Namespace)                                          │
│                                                                                        │
│   • ANTHROPIC_BASE_URL = http://127.0.0.1:4880/anthropic                               │
│   • ANTHROPIC_API_KEY  = glove-session-a8f3b9c... (ephemeral session nonce)            │
│   • Direct internet egress DENIED (Seccomp denies socket/connect)                      │
│                                                                                        │
│   Request: POST http://127.0.0.1:4880/anthropic/v1/messages                            │
│   Header:  x-api-key: glove-session-a8f3b9c...                                         │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Inherited SCM_RIGHTS Loopback Channel
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ Glove Host Control Plane (credentialed_endpoint & Detection Engine)                    │
│                                                                                        │
│   1. Validate session nonce (fails closed if missing or mismatched)                    │
│   2. Strip dummy key; inject host-held credential from mlocked memory                  │
│   3. Structural validation (HTTP/1.1 only, method allowlist, JSON depth/size caps)     │
│   4. Detection Engine:                                                                 │
│      - Aho-Corasick canary scanner (detects planted decoy tokens: glvc_<base32>)       │
│      - Rabin-Karp rolling hash + SHA-256 confirmation of known project secret digests  │
│      - Token/byte budget accounting (derived from upstream usage metadata)             │
│   5. Terminate outbound TLS session to https://api.anthropic.com:443                   │
│   6. Three-phase audit append (delivery_pending ──► release ──► delivered)             │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │ Outbound TLS Handshake (Host Network)
                                            ▼
                             https://api.anthropic.com:443
```

### 2.1 The Nonce Swap Mechanism
* Most agent clients (Claude Code, Codex, Pi, Aider) refuse to boot if provider API keys are completely empty.
* Glove supplies a cryptographically random, ephemeral session nonce:
  `ANTHROPIC_API_KEY=glove-session-<random-hex>`
* The host-side proxy verifies that the request carries the exact session nonce for that container, strips it, and substitutes the genuine provider secret (`x-api-key` or `Authorization: Bearer <token>`).
* **Security Invariant**: The agent never possesses the real credential. If the agent dumps its environment, logs, or `/proc/self/environ`, the leaked token is completely non-actionable outside that specific sandbox session.

### 2.2 Mutual Exclusion with CONNECT Egress
* Glove's standard network proxy allows raw TCP CONNECT tunneling to explicitly whitelisted domains (e.g. package registries).
* **Hard Rule**: Any domain registered as a `credentialed_endpoint` (e.g. `api.anthropic.com`) is **strictly removed from the raw CONNECT allowlist**.
* An agent cannot bypass the inspection and injection pipeline by dialing the provider directly.

### 2.3 Provider Presets (Zero-Configuration Setup)
Agents are configured via standard base-URL environment overrides:

| Agent Client | Glove Preset Configuration |
|---|---|
| **Claude Code** | `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>/anthropic`, `ANTHROPIC_API_KEY=glove-session-...`, OAuth and keychain readers disabled in sandbox `/home/agent`. |
| **Codex** | `OPENAI_BASE_URL=http://127.0.0.1:<port>/openai`, `OPENAI_API_KEY=glove-session-...`. |
| **Pi** | Provider `baseUrl` in models configuration pointing to local endpoint. |
| **Aider / OpenCode** | `OPENAI_API_BASE` / `ANTHROPIC_BASE_URL` with session nonces. |

---

## 3. Detection & Semantic Validation Pipeline

The host-side proxy processes outbound requests and inbound responses through a deterministic, bounded validation pipeline:

| Tier | Technique | Action on Match | Rationale |
|---|---|---|---|
| **Structural** | Fixed path allowlist (`POST /v1/messages`), JSON array/nesting depth caps, model allowlist, server-side tool blocking | **Block (400/403)** | Denies prompt-injected requests that attempt to invoke provider-side execution or web-fetch tools that circumvent local egress policy. |
| **Canaries** | Decoy tokens (`glvc_<base32>`) planted in fake `.env` or `~/.aws/credentials` in the sandbox | **Block & Poison Session** | Zero false-positive indicator of active exfiltration. Immediate session termination. |
| **Known Secrets** | Rabin-Karp rolling hash (16-byte window) + SHA-256 verification of registered project secret digests | **Block & Poison Session** | Prevents exfiltration of local `.env` keys, database passwords, or private keys even if base64/hex encoded. |
| **Heuristics** | Shannon entropy checks on outbound tokens $\ge 20$ chars; regex patterns for common API keys | **Audit / Annotate** | Logged as advisory events in the JSONL audit trail without blocking legitimate code/hashes. |
| **Budgets** | Session limits on total request count, request bytes, response bytes, and billed model tokens | **Block (429/Limit Exceeded)** | Prevents denial-of-wallet and infinite agent loops at the transport boundary. |
| **Inbound Sanitization** | Response scanner for echoed credentials | **Redact** | Ensures upstream providers do not echo leaked secrets back into the agent's visible context. |

* **Performance Budget**: Target added latency is $< 1\text{ ms}$ at p99 for 200 KB payloads. Hashing and Aho-Corasick matchers operate in a single linear pass over the unescaped buffer.

---

## 4. Sandboxed Upstream MCP Servers

In the existing architecture, `glove run` sandboxes the agent process, while upstream MCP servers run as unsandboxed host processes (`docs/threat-model.md`). 

### 4.1 The `contained_launcher` Pattern
Glove replaces raw `posix_spawn` in `src/mcp/stdio_transport.cpp` with an isolated container spawner:

```cpp
namespace glove::mcp {

struct upstream_launch_options {
    std::vector<std::string> argv;
    container::profile sandbox_profile;
};

// contained_launcher executes the upstream server inside private Linux
// user, mount, pid, and network namespaces with an exclusive cgroup v2.
auto launch_contained_upstream(const upstream_launch_options& options)
    -> std::expected<std::unique_ptr<transport>, std::string>;

} // namespace glove::mcp
```

### 4.2 Upstream Profile Invariants
1. **Filesystem**: Read-only rootfs projection with descriptor-pinned grants (`path_exposure`) and private tmpfs `/tmp`.
2. **Network**: Deny-default. Upstreams that require external API access (such as a GitHub MCP server) connect **through the same credentialed reverse proxy**, holding no raw tokens.
3. **Process Supervision**: Monitored via Linux `pidfd` identities with bounded crash restart backoff. Mid-call crashes fail closed with `JSON-RPC` transport errors.

---

## 5. Phased Implementation Roadmap

* **Phase 0: Baseline & Red-Team Benchmark Harness**:
  Measure latency and token metrics across Claude Code and Pi using the existing CONNECT egress proxy. Establish a benchmark corpus of prompt-injection exfiltration attacks.
* **Phase 1: Credentialed Reverse Endpoint (`glove::net::credentialed_endpoint`)**:
  Implement the HTTP/1.1 parser, session nonce validator, host-side lease store, and SSE streaming proxy for Anthropic. Remove credentialed hosts from the CONNECT allowlist.
* **Phase 2: Detection Engine v1**:
  Implement canary generation and Aho-Corasick matching, Rabin-Karp secret hash scanning, and transport-level token/byte budget enforcement.
* **Phase 3: Multi-Provider Expansion**:
  Add OpenAI and GitHub endpoint presets and compatibility adapters for Codex, Pi, and Aider.
* **Phase 4: Contained MCP Upstreams**:
  Implement `contained_launcher` with per-upstream Glove profiles and pidfd supervision.
