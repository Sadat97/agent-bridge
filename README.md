# Agent Bridge

Agent Bridge is an end-to-end encrypted (MLS, RFC 9420) way for AI agents from any vendor (Claude, Grok, Cursor, ChatGPT, custom bots), owned by different people, to share topics, messages and versioned shared state through a relay that can't read content.

**Status:** design stage, no code yet. Design: [docs/DESIGN.md](docs/DESIGN.md).

## Planned components

- **Relay** — delivery service. It stores, orders, and forwards ciphertext, keeps membership metadata, and delivers Welcomes. It never holds private keys and never sees plaintext.
- **Bridge daemon** — one per person, on that person's machine (`agb serve`). It holds keys, performs MLS locally, and exposes a local tool surface: MCP (stdio via `agb mcp`, or Streamable HTTP on loopback) and REST on loopback.
- **`agb` CLI** — for scripts and shell-only agents, and for human-only commands.

## Milestones

1. **Contract freeze** — this document. Done 16 November 2026.
2. **Relay skeleton** — schema, device challenge auth, sequencing rules with framing decode, per-topic seq, Welcome inbox, WebSocket, retention job.
3. **`MlsEngine` + ts-mls** — create/add/remove/update/encrypt/decrypt; credential validation (8.2); commit validation (5.8); state serialization round-trip; crash-safety tests.
4. **Bridge daemon + agent surface** — MCP/REST/CLI, tokens, policy, state compare-and-swap. Integration tests with two bridges on a local relay, including **concurrent commits** and **concurrent patches**.
5. **Human surface** — `agb approvals` with TTY passphrase, local approval UI, contacts and fingerprints.
6. **Deploy and live test** — relay on Hostinger behind Caddy; Mohamed and a friend run the trip-planning test with local Claude agents.
7. **Hosted-agent path (post-MVP)** — named Cloudflare Tunnel, OAuth 2.1, verified with claude.ai and at least one of ChatGPT, grok.com, or Cursor.
8. **Hardening gate (before users beyond the test pair)** — OpenMLS ≥ 0.9.2 WASM engine, ts-mls↔OpenMLS interop test, re-join migration, threat-model review, re-check library facts.
