// Relay credentials, scoped per relay.
//
// Before: one shared RELAY_SECRET was held by the center AND every relay, and
// it authenticated ingest for ANY recipient, including local .do mailboxes,
// plus an operator read of any mailbox (/_admin/read, now removed). Any relay
// holding that secret could inject mail anywhere or read everything.
//
// Now every credential is bound to the domains its relay serves:
//
//   RELAY_KEYS (secret, JSON): { "<relay base URL>": "<that relay's secret>" }
//     A relay's domains are the EMAIL_RELAYS registry entries that point at
//     its base URL. Its key signs center -> relay /send and verifies
//     relay -> center /ingest, and is valid ONLY for those domains.
//
//   RELAY_SECRET (legacy shared secret): still accepted so existing relays
//     keep working unchanged, but scoped to relay-served domains whose relay
//     has NO key in RELAY_KEYS. It never authorizes a local (.do) domain.
//     Once every relay has its own key, unset RELAY_SECRET.
//
// Relays need no code change: the center identifies the relay by which key
// verifies the HMAC. Rotating a relay onto its own key means setting the same
// value as RELAY_SECRET in that relay and under its base URL in RELAY_KEYS.

import { parseEmailRelays } from "../email-sender";
import type { Env } from "../types";
import { verifyRelayRequest } from "./relay-hmac";

export interface RelayCredential {
	/** Relay base URL, or "legacy" for the shared RELAY_SECRET. */
	relay: string;
	secret: string;
	/** Lower-cased domains this credential may deliver mail for. */
	domains: Set<string>;
}

/** Parse RELAY_KEYS: JSON { relayBaseUrl: secret } (fail closed on bad JSON). */
export function parseRelayKeys(raw: unknown): Record<string, string> {
	if (typeof raw !== "string" || !raw.trim()) return {};
	try {
		const parsed = JSON.parse(raw);
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
		const out: Record<string, string> = {};
		for (const [k, v] of Object.entries(parsed)) {
			if (typeof v === "string" && v) out[k.replace(/\/+$/, "")] = v;
		}
		return out;
	} catch {
		console.error("RELAY_KEYS is not valid JSON; no per-relay keys loaded");
		return {};
	}
}

export function relayCredentials(env: Env): RelayCredential[] {
	const registry = parseEmailRelays(env.EMAIL_RELAYS as string | undefined); // domain -> relay base
	const keys = parseRelayKeys(env.RELAY_KEYS);
	const creds: RelayCredential[] = [];
	for (const [relay, secret] of Object.entries(keys)) {
		const domains = new Set(Object.entries(registry).filter(([, base]) => base === relay).map(([d]) => d));
		creds.push({ relay, secret, domains });
	}
	if (env.RELAY_SECRET) {
		const keyed = new Set(Object.keys(keys));
		const domains = new Set(Object.entries(registry).filter(([, base]) => !keyed.has(base)).map(([d]) => d));
		creds.push({ relay: "legacy", secret: env.RELAY_SECRET, domains });
	}
	return creds;
}

/** The secret used to sign center -> relay requests for this relay. */
export function signingSecretFor(env: Env, relayBase: string): string | undefined {
	return parseRelayKeys(env.RELAY_KEYS)[relayBase.replace(/\/+$/, "")] ?? env.RELAY_SECRET;
}

/**
 * Verify a relay -> center request against every configured credential.
 * Per-relay keys are tried first; the first that verifies identifies the relay.
 */
export async function verifyRelayCaller(
	env: Env,
	rawBody: string,
	sig: string | undefined,
	ts: string | undefined,
): Promise<{ ok: true; credential: RelayCredential } | { ok: false; reason: string }> {
	const creds = relayCredentials(env);
	if (creds.length === 0) return { ok: false, reason: "no relay credentials configured" };
	let reason = "signature mismatch";
	for (const credential of creds) {
		const r = await verifyRelayRequest(credential.secret, rawBody, sig, ts);
		if (r.ok) return { ok: true, credential };
		// Header/timestamp problems are the same for every key; report them.
		if (r.reason !== "signature mismatch") reason = r.reason;
	}
	return { ok: false, reason };
}

/** Domain of an address ("a@b.com" or "Name <a@b.com>"), lower-cased. */
export function domainOf(address: string): string | null {
	const m = address.match(/@([^>\s]+)\s*>?\s*$/);
	return m ? m[1].toLowerCase() : null;
}

export function inScope(credential: RelayCredential, address: string): boolean {
	const d = domainOf(address);
	return !!d && credential.domains.has(d);
}
