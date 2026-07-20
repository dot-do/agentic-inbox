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
	// Selects the auth implementation. Absent/unknown => "cf-access"
	// (the pre-existing Cloudflare Access behavior, unchanged).
	AUTH_MODE?: "cf-access" | "id.org.ai";
	// OIDC issuer origin; defaults to https://id.org.ai when unset.
	ID_ORG_AI_ISSUER?: string;
	// OAuth client registered with id.org.ai (var or secret).
	ID_ORG_AI_CLIENT_ID?: string;
	// Only for confidential clients; also enables opaque-token introspection.
	ID_ORG_AI_CLIENT_SECRET?: string; // secret
	// HMAC key for signing the session/state cookies (HS256). Required in
	// id.org.ai mode; missing => fail closed with 500.
	SESSION_SECRET?: string; // secret

	// --- Email cascade: center <-> per-account relay (workers/lib/relay-hmac.ts) ---
	// Shared HMAC secret with the per-account relay workers. Same 32-byte value
	// set as `wrangler secret put RELAY_SECRET` in BOTH this worker and each
	// relay. Verifies inbound POST /api/v1/ingest and signs outbound /send.
	// (A secret, so it is not in the generated Cloudflare.Env; declared here.)
	//
	// EMAIL_RELAYS (registry-seeded JSON map of send-as domain -> relay base
	// URL) is a wrangler var, so it arrives via Cloudflare.Env — see
	// wrangler.jsonc and email-sender.ts parseEmailRelays().
	RELAY_SECRET?: string; // secret
}
