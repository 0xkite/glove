# Native macOS Pi

`glove pi` is a prototype native macOS launcher with host-only provider keys.
Synthetic fixtures cover its admission, containment and lifecycle seams.
Installed Pi startup, provider requests, workspace edits and buffered-response
compatibility remain unqualified. These commands describe the implemented CLI;
they are not an installed-harness acceptance result.

## Synopsis

```text
glove pi setup --provider openai --model MODEL_ID --yes
glove pi refresh --provider openai --model MODEL_ID --yes
glove pi [--provider openai|anthropic] [--model MODEL_ID] [--workspace DIR]
glove pi -- [--print|-p] [--thinking LEVEL] [--mode text|json] PROMPT
glove pi --help
```

Replace `MODEL_ID` with an exact builtin model ID from the selected Pi runtime.
No model availability or account entitlement is implied. Anthropic setup uses
`--provider anthropic` and its corresponding builtin model ID.

## Setup and refresh

Setup discovers Pi at fixed `/opt/homebrew/bin` and `/usr/local/bin` locations,
resolves its Node/package dependencies, copies an admitted runtime into a
protected store, and publishes a credential-free provider/model record.
Dependency inspection may execute bounded host commands during staging.

Interactive setup asks for consent, provider and builtin model ID. Noninteractive
setup requires `--yes`, `--provider` and `--model`. No key prompt is provided.
Refresh requires consent to replace the runtime and selection. Launch never
performs automatic setup, refresh or host-state import.

Provide `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` on the host through your credential
manager before launch. Authentication is API-key-only. OAuth, subscription
credentials and automatic auth-file import are unsupported.

## Launch

Without `--workspace`, launch uses the current directory. The workspace must be
owner-private (`0700`), disjoint from admitted host/runtime authority, and contain
no `.pi` entry or case alias. Unsafe existing objects are rejected, not repaired.
Glove does not grant project trust based on repository files.

The protected record supplies the default provider and model. Switching providers
requires an explicit `--model`; the stored model defaults only for its provider.
Launch overrides must still match the copied builtin catalog. Generated private configuration
changes only the selected provider URL and per-run nonce; it does not persist
host model overlays or modify your Pi configuration.

After `--`, the supported options are `--print`/`-p`, `--thinking` and `--mode`.
Thinking levels are `off`, `minimal`, `low`, `medium`, `high`, `xhigh` and `max`.
Modes are `text` and `json`. Each option is single-use. Prompt text is allowed.
Unknown options before Pi's own second `--` fail closed; tokens after that
terminator are prompt text. `@file` input is rejected everywhere. This is not
arbitrary Pi argument passthrough.

`--continue`, `--resume`, `--verbose`, arbitrary config/runtime/endpoint paths,
environment overrides, extensions, MCP, skills, templates, themes and automatic
context-file discovery are unsupported. No uncontained fallback is attempted.

## Files

Defaults, before XDG directory selection:

| File or directory | Purpose |
| --- | --- |
| `$HOME/.config/glove/pi/selection.json` | Protected runtime and provider/model selection |
| `$HOME/.local/share/glove/pi/runtime` | Protected copied runtime store |
| `$HOME/.local/state/glove/runtime/pi/runs` | Private per-run state |

Each run has its own home, temporary files, agent configuration and sessions.
Glove does not inject the host provider key into guest argv, environment, files
or audit; the guest receives only the bound run nonce. Uncertain lifecycle ownership
retains private state instead of claiming cleanup succeeded.

## Limits

- macOS only. Native Pi launch on Linux fails before execution.
- OpenAI Responses and Anthropic Messages only; responses are buffered, not
  streamed. Installed-harness SSE behavior requires separate qualification.
- One exact authenticated loopback TCP endpoint. No general localhost or direct
  upstream grant.
- The default audit sink refuses after 1,024 retained events or 1 MiB of logical
  event/string charge. This is not an allocator or RSS bound.
- No managed Linux six-limit or authenticated terminal-receipt parity.
- No atomic same-UID namespace snapshot or general detached-process-tree death
  guarantee.
- `glove codex` and `glove claude` are proposed peer adapters, not implemented
  aliases or qualified native launchers.

## See also

[Architecture](architecture.md), [threat model](threat-model.md),
[Pi implementation plan](product/macos-pi-launch-plan.md).
