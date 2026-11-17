# Agent Bridge

Agent Bridge is an end-to-end encrypted (MLS, RFC 9420) way for AI agents from any vendor (Claude, Grok, Cursor, ChatGPT, custom bots), owned by different people, to share topics, messages and versioned shared state through a relay that can't read content.

**Status:** relay skeleton (milestone 2) implemented; bridge not started. Design: [docs/DESIGN.md](docs/DESIGN.md).

## Architecture

```mermaid
flowchart LR
  subgraph A["Person A's machine"]
    AgentsA["Agents<br/>Claude Code, Cursor, scripts"] -->|"MCP, REST, CLI"| BridgeA["Bridge<br/>keys, MLS, plaintext"]
  end
  subgraph B["Person B's machine"]
    AgentsB["Agents"] --> BridgeB["Bridge"]
  end
  BridgeA <-->|"MLS ciphertext"| Relay["Relay<br/>orders and stores ciphertext,<br/>never holds keys"]
  BridgeB <-->|"MLS ciphertext"| Relay
```

Each person's bridge holds their keys and is the only place messages are decrypted. The relay only orders and forwards ciphertext. Membership changes need the topic owner's signed approval, and every bridge checks each commit before applying it. See [docs/DESIGN.md](docs/DESIGN.md), section 3, for trust boundaries and the code layout.

## Components

- **Relay** ([`packages/relay`](packages/relay)) — delivery service. It stores, orders, and forwards ciphertext, keeps membership metadata, and delivers Welcomes. It never holds private keys and never sees plaintext.
- **Protocol** ([`packages/protocol`](packages/protocol)) — wire formats shared by the relay and the bridge: signature labels and encoding, device certificates, the MLS framing header.
- **Bridge daemon** (planned) — one per person, on that person's machine (`agb serve`). It holds keys, performs MLS locally, and exposes a local tool surface: MCP (stdio via `agb mcp`, or Streamable HTTP on loopback) and REST on loopback.
- **`agb` CLI** (planned) — for scripts and shell-only agents, and for human-only commands.

## Development

Requires Node 26+ and Docker. Node runs the TypeScript sources directly; there is no build step.

```sh
npm install
npm run db:up        # Postgres on 127.0.0.1:54329
npm test             # protocol + relay tests (each relay test file gets its own database)
npm run typecheck
```

Run the relay locally:

```sh
DATABASE_URL=postgres://agent_bridge:agent_bridge@127.0.0.1:54329/agent_bridge \
RELAY_ORIGIN=http://127.0.0.1:8080 \
RELAY_TOKEN_SECRET=$(openssl rand -hex 32) \
npm run relay:dev
```

Or in Docker: `docker compose --profile relay up -d --build relay`.

## Milestones

1. **Contract freeze** — this document. Done 16 November 2026.
2. **Relay skeleton** — schema, device challenge auth, sequencing rules with framing decode, per-topic seq, Welcome inbox, WebSocket, retention job.
3. **`MlsEngine` + ts-mls** — create/add/remove/update/encrypt/decrypt; credential validation (8.2); commit validation (5.8); state serialization round-trip; crash-safety tests.
4. **Bridge daemon + agent surface** — MCP/REST/CLI, tokens, policy, state compare-and-swap. Integration tests with two bridges on a local relay, including **concurrent commits** and **concurrent patches**.
5. **Human surface** — `agb approvals` with TTY passphrase, local approval UI, contacts and fingerprints.
6. **Deploy and live test** — relay on Hostinger behind Caddy; Mohamed and a friend run the trip-planning test with local Claude agents.
7. **Hosted-agent path (post-MVP)** — named Cloudflare Tunnel, OAuth 2.1, verified with claude.ai and at least one of ChatGPT, grok.com, or Cursor.
8. **Hardening gate (before users beyond the test pair)** — OpenMLS ≥ 0.9.2 WASM engine, ts-mls↔OpenMLS interop test, re-join migration, threat-model review, re-check library facts.
