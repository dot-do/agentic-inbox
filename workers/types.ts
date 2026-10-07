// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

export interface Env extends Cloudflare.Env {
	POLICY_AUD: string;
	TEAM_DOMAIN: string;
	// Optional: dynamic domain discovery via the Cloudflare API. When set,
	// /api/v1/domains serves the account's zone list (cached in R2) in addition
	// to the static DOMAINS env var, and the UI becomes a searchable combobox.
	CF_API_TOKEN?: string; // needs Zone:Read
	CF_ACCOUNT_ID?: string; // optional: restrict zone listing to one account

	// --- Pluggable auth (workers/lib/auth.ts) ---
	// AUTH_MODE selects the auth implementation ("cf-access" | "id.org.ai");
	// absent/unknown => "cf-access" (the pre-existing Cloudflare Access
	// behavior, unchanged). It is a wrangler var, so it arrives via the
	// generated Cloudflare.Env — not redeclared here because wrangler types
	// renders vars as literal types and a wider redeclaration is a TS2430
	// conflict (same convention as EMAIL_RELAYS and the archive vars below).
	// ID_ORG_AI_ISSUER (OIDC issuer origin, defaults to https://id.org.ai),
	// ID_ORG_AI_CLIENT_ID, and SESSION_SECRET (HS256 key for session/state
	// cookies; required in id.org.ai mode, missing => fail closed with 500)
	// likewise arrive via the generated Cloudflare.Env.
	// Only for confidential clients; also enables opaque-token introspection.
	// (Not in the generated Cloudflare.Env; declared here.)
	ID_ORG_AI_CLIENT_SECRET?: string; // secret

	// --- Email cascade: center <-> per-account relay (workers/lib/relay-hmac.ts) ---
	// Shared HMAC secret with the per-account relay workers. Same 32-byte value
	// set as `wrangler secret put RELAY_SECRET` in BOTH this worker and each
	// relay. Verifies inbound POST /api/v1/ingest and signs outbound /send.
	// (A secret, so it is not in the generated Cloudflare.Env; declared here.)
	//
	// EMAIL_RELAYS (registry-seeded JSON map of send-as domain -> relay base
	// URL) is a wrangler var, so it arrives via Cloudflare.Env — see
	// wrangler.jsonc and email-sender.ts parseEmailRelays().
	RELAY_SECRET?: string; // secret (legacy shared key; see workers/lib/relay-auth.ts)
	// Per-relay keys, JSON {"<relay base URL>": "<secret>"}. Each key is valid
	// only for the EMAIL_RELAYS domains that point at that relay.
	RELAY_KEYS?: string; // secret

	// --- Per-mailbox authorization (workers/lib/access.ts) ---
	// Admin allowlist: emails and/or id.org.ai subs, comma/space separated or a
	// JSON array. Admins can read every mailbox; everyone else only mailboxes
	// they own or were granted. Unset = no admins (deny by default). Set with
	// `wrangler secret put MAILBOX_ADMINS` (kept out of wrangler.jsonc vars so
	// identities are not committed to the repo).
	MAILBOX_ADMINS?: string; // secret

	// --- agents@ archive (workers/lib/archive.ts) ---
	// ARCHIVE_ADDRESS ("agents@do.industries") and ARCHIVE_ENABLED (true) are
	// wrangler vars, so they arrive via the generated Cloudflare.Env (wrangler
	// types renders them as literal types; archive.ts reads them through
	// tolerant accessors). Not redeclared here to avoid literal-type conflicts.
}
