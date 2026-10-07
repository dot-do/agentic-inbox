<div align="center">
  <h1>Agentic Inbox</h1>
  <p><em>A self-hosted email client with an AI agent, running entirely on Cloudflare Workers</em></p>
</div>

> [!WARNING]
> **Marked for retirement (dot-do fork, emails.do).** The mail store moves to api.sb's email primitive
> (StartupsStudio/sb#337; ADR-0025 Q145: emails.do's fork, `visibility-inbox` and `vis/apps/inbox` retire onto it).
> This store is **kept, never deleted** (ADR-0005): its R2 bucket `agentic-inbox` and every MailboxDO stay as they
> are, read-only for the move.
>
> - **Export, read-only:** `POST /api/v1/_admin/export` (HMAC, `RELAY_SECRET`) answers every mailbox and every row,
>   soft-deleted ones too, for sb's importer (`poc/workers/api-sb-prototype/scripts/import-emails-do.ts`), which checks
>   counts after.
> - **Client of api.sb:** with `MAIL_BACKEND = "api.sb"` (plus `API_SB_STARTUP`, and the `API_SB_TOKEN` secret) the
>   UI's mailbox routes read and send through api.sb (`workers/routes/api-sb-backend.ts`). Unset, nothing changes.
> - **Order:** deploy this branch, import, check the counts, switch Email Routing to api.sb, set `MAIL_BACKEND`.
>   New features go to api.sb, not here.

Agentic Inbox lets you send, receive, and manage emails through a modern web interface -- all powered by your own Cloudflare account. Incoming emails arrive via [Cloudflare Email Routing](https://developers.cloudflare.com/email-routing/), each mailbox is isolated in its own [Durable Object](https://developers.cloudflare.com/durable-objects/) with a SQLite database, and attachments are stored in [R2](https://developers.cloudflare.com/r2/).

An **AI-powered Email Agent** can read your inbox, search conversations, and draft replies -- built with the [Cloudflare Agents SDK](https://developers.cloudflare.com/agents/) and [Workers AI](https://developers.cloudflare.com/workers-ai/).

![Agentic Inbox screenshot](./demo_app.png)


Read the blog post to learn more about Cloudflare Email Service and how to use it with the Agents SDK, MCP, and from the Wrangler CLI: [Email for Agents](https://blog.cloudflare.com/email-for-agents/).

## How to setup

**Important**: Clicking the 'Deploy to Cloudflare' button is only one part of the setup. You must follow the **After deploying** steps as well. For a full step-by-step guide with screenshots, refer to this comment: 
https://github.com/cloudflare/agentic-inbox/issues/4#issuecomment-4269118513

### To set up

1. Deploy to Cloudflare. The deploy flow will automatically provision R2, Durable Objects, and Workers AI. You'll be prompted for **DOMAINS**, which is the domain (yourdomain.com) you want to receive emails for (email@yourdomain.com).

     [![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/cloudflare/agentic-inbox)

2. **Configure Cloudflare Access** -- Enable [one-click Cloudflare Access](https://developers.cloudflare.com/changelog/post/2025-10-03-one-click-access-for-workers/) on your Worker under Settings > Domains & Routes. The modal will show your `POLICY_AUD` and `TEAM_DOMAIN` values. `TEAM_DOMAIN` can be either your Access team URL or the full `.../cdn-cgi/access/certs` URL. **You must set these as secrets for your Worker.**
3. **Set up Email Routing** -- In the Cloudflare dashboard, go to your domain > Email Routing and create a catch-all rule that forwards to this Worker
4. **Enable Email Service** -- The worker needs the `send_email` binding to send outbound emails. See [Email Service docs](https://developers.cloudflare.com/email-routing/email-workers/send-email-workers/)
5. **Create a mailbox** -- Visit your deployed app and create a mailbox for any address on your domain (e.g. `hello@example.com`)

### Troubleshooting Access

1. If you see `Invalid or expired Access token`, that usually means `POLICY_AUD` or `TEAM_DOMAIN` secrets are incorrect.
   * Resolution: [turn Access off and back on for the Worker to get the Access modal again](https://developers.cloudflare.com/changelog/post/2025-10-03-one-click-access-for-workers/), then reset your Worker secrets to the latest `POLICY_AUD` and `TEAM_DOMAIN` values shown there.
2. If you see `Cloudflare Access must be configured in production`, this application is intentionally enforcing Cloudflare Access so your inbox is not exposed to anyone on the internet.
   * Resolution: enable Access using [one-click Cloudflare Access for Workers](https://developers.cloudflare.com/changelog/post/2025-10-03-one-click-access-for-workers/), then set the `POLICY_AUD` and `TEAM_DOMAIN` Worker secrets from the modal values.

## Features

- **Full email client** — Send and receive emails via Cloudflare Email Routing with a rich text composer, reply/forward threading, folder organization, search, and attachments
- **Per-mailbox isolation** — Each mailbox runs in its own Durable Object with SQLite storage and R2 for attachments
- **Built-in AI agent** — Side panel with 9 email tools for reading, searching, drafting, and sending
- **Auto-draft on new email** — Agent automatically reads inbound emails and generates draft replies, always requiring explicit confirmation before sending
- **Configurable and persistent** — Custom system prompts per mailbox, persistent chat history, streaming markdown responses, and tool call visibility

## Stack

- **Frontend:** React 19, React Router v7, Tailwind CSS, Zustand, TipTap, `@cloudflare/kumo`
- **Backend:** Hono, Cloudflare Workers, Durable Objects (SQLite), R2, Email Routing
- **AI Agent:** Cloudflare Agents SDK (`AIChatAgent`), AI SDK v6, Workers AI (`@cf/moonshotai/kimi-k2.5`), `react-markdown` + `remark-gfm`
- **Auth:** Cloudflare Access JWT validation (required outside local development)

## Getting Started

```bash
npm install
npm run dev
```

### Configuration

1. Set your domain in `wrangler.jsonc`
2. Create an R2 bucket named `agentic-inbox`: `wrangler r2 bucket create agentic-inbox`

### Deploy

```bash
npm run deploy
```

## Prerequisites

- Cloudflare account with a domain
- [Email Routing](https://developers.cloudflare.com/email-routing/) enabled for receiving
- [Email Service](https://developers.cloudflare.com/email-service/) enabled for sending
- [Workers AI](https://developers.cloudflare.com/workers-ai/) enabled (for the agent)
- [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/) configured for deployed/shared environments (required in production)

Any user who passes the shared Cloudflare Access policy can access all mailboxes in this app by design. This includes the MCP server at `/mcp` -- external AI tools (Claude Code, Cursor, etc.) connected via MCP can operate on any mailbox by passing a `mailboxId` parameter. There is no per-mailbox authorization; the Cloudflare Access policy is the single trust boundary.

## The estate email ledger (agents@ archive)

Founder ruling 2026-08-20: **the `agents@do.industries` archive is the real
Google Workspace mailbox** — archive copies are DELIVERED there as actual
emails. Every message through the center produces two ledger artifacts
(`workers/lib/archive.ts`, per `EMAIL-CASCADE.md` §(b)):

- **Journal delivery (the archive)**: after every successful outbound send
  (direct `env.EMAIL.send()` *and* relayed `/send`, both via `sendVia`) and
  every stored inbound message (Email Routing and relay `/api/v1/ingest`,
  both via `storeInboundEmail`), the center sends a **real journal email** to
  `ARCHIVE_ADDRESS` via CF Email Service → Google MX. Subject prefixed
  `[ledger:outbound]` / `[ledger:inbound]`; headers `X-Ledger-Copy`,
  `X-Original-Message-Id`, `X-Original-From`, `X-Original-To` (plus
  `X-Delivered-To` inbound); body = original body. Sender is the dedicated
  identity `LEDGER_ADDRESS` (`ledger@emails.do`) so the Google mailbox can
  filter/label cleanly.
- **Ledger DO index**: a queryable center-native MailboxDO record of the same
  message, kept because it is free and agent-searchable. The index DO is
  named `ledger@emails.do` (matching the sender) — **not**
  `agents@do.industries` — eliminating the name collision with the real
  Google mailbox. (The 6 pre-ruling records remain in the old
  `agents@do.industries` DO, un-migrated by design.)
- **Attachments by reference**: journal emails carry authenticated fetch
  links + R2 keys, never re-attached bytes; index records carry the keys in
  `x-archive-attachment-refs`. Refs are pointers — deleting the original
  email deletes the blobs and the refs dangle.
- **Loop guards (paramount)**: never journal a journal — messages bearing
  `X-Ledger-Copy`, mail from the `ledger@` sender, and mail from/to the
  archive or ledger addresses are never ledgered; the journal send also
  bypasses `sendVia` structurally. `do.industries` inbound is Google (not
  the center), so copies cannot re-enter — guarded anyway.
- **Failure isolation**: ledger writes are best-effort (`ctx.waitUntil` /
  caught, detached promises), and the two legs are isolated from each other
  (`Promise.allSettled`). A failed — or arbitrarily slow — ledger write is
  logged and can never fail or delay the real send or delivery.
- **⚠️ Volume ceiling (founder decision deferred)**: journal delivery is one
  real email per message into a single Workspace mailbox. At future migrated
  volume (tens of thousands/day) this hits Workspace receiving limits — the
  DO index is the scale path; the Google-delivery layer may then need
  sampling/batching. See the header of `workers/lib/archive.ts`.
- **Growth posture (DO index)**: unbounded by design; bodies capped
  (`MAX_ARCHIVE_BODY_CHARS`, truncated records tagged `x-archive-truncated`),
  attachment bytes never duplicated — a 10GB SQLite DO gives years of
  headroom. `ARCHIVE_ENABLED=false` is the kill switch.

Configuration (`wrangler.jsonc` vars):

| var               | default                | meaning                                  |
| ----------------- | ---------------------- | ---------------------------------------- |
| `ARCHIVE_ADDRESS` | `agents@do.industries` | the REAL archive mailbox (Google Workspace) journal emails are delivered to |
| `LEDGER_ADDRESS`  | `ledger@emails.do`     | dedicated journal sender identity + name of the internal ledger index DO |
| `ARCHIVE_ENABLED` | `true`                 | set `false` to disable all ledger activity |

## Tests

```bash
npm test        # vitest run — archive + sendVia unit tests (test/)
```

## Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Browser    │────>│  Hono Worker     │────>│  MailboxDO      │
│  React SPA   │     │  (API + SSR)     │     │  (SQLite + R2)  │
│  Agent Panel │     │                  │     └─────────────────┘
└──────┬───────┘     │  /agents/* ──────┼────>┌─────────────────┐
       │             │                  │     │  EmailAgent DO  │
       │ WebSocket   │                  │     │  (AIChatAgent)  │
       └─────────────┤                  │     │  9 email tools  │
                     │                  │────>│  Workers AI     │
                     └──────────────────┘     └─────────────────┘
```

## License

Apache 2.0 -- see [LICENSE](LICENSE).
