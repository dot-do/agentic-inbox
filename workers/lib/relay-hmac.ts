// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Center-side HMAC for the email cascade (center <-> per-account relay).
 *
 * This is the exact counterpart of the contract implemented in the relay worker
 * (~/projects/email-relay/src/index.ts). Both directions use the SAME scheme and
 * the SAME shared secret (RELAY_SECRET):
 *
 *   CANONICAL SIGNING CONTRACT
 *     signed_string     = `${x-relay-timestamp}.${rawRequestBody}`
 *     x-relay-signature = base64( HMAC-SHA256(RELAY_SECRET, signed_string) )
 *     x-relay-timestamp = integer unix SECONDS
 *
 * The timestamp is folded INTO the signed payload so a captured request cannot
 * be replayed with a bumped timestamp. Receivers reject if the skew exceeds
 * SKEW_LIMIT_SECONDS or the signature does not verify.
 *
 * Direction map (who signs / who verifies):
 *   OUTBOUND  center SIGNS  POST <relayBase>/send   -> relay verifies
 *   INBOUND   relay  SIGNS  POST /api/v1/ingest     -> center VERIFIES (here)
 */

export const RELAY_SIG_HEADER = "x-relay-signature";
export const RELAY_TS_HEADER = "x-relay-timestamp";
const SKEW_LIMIT_SECONDS = 300;

const encoder = new TextEncoder();

async function importKey(secret: string): Promise<CryptoKey> {
	return crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign", "verify"],
	);
}

function bufToBase64(buf: ArrayBuffer): string {
	const bytes = new Uint8Array(buf);
	let bin = "";
	for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
	return btoa(bin);
}

/** Constant-time-ish equality over equal-length base64 strings. */
function timingSafeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return diff === 0;
}

/**
 * Sign a raw body for an OUTBOUND request (center -> relay /send).
 * Returns the two headers the relay expects.
 */
export async function signRelayBody(
	secret: string,
	rawBody: string,
): Promise<{ [RELAY_SIG_HEADER]: string; [RELAY_TS_HEADER]: string }> {
	const timestamp = Math.floor(Date.now() / 1000).toString();
	const key = await importKey(secret);
	const digest = await crypto.subtle.sign(
		"HMAC",
		key,
		encoder.encode(`${timestamp}.${rawBody}`),
	);
	return {
		[RELAY_SIG_HEADER]: bufToBase64(digest),
		[RELAY_TS_HEADER]: timestamp,
	};
}

/**
 * Verify an INBOUND request (relay -> center /api/v1/ingest). Mirrors the
 * relay's verifyRequest exactly: presence of both headers, finite timestamp,
 * skew <= 300s, then a constant-time signature comparison.
 */
export async function verifyRelayRequest(
	secret: string,
	rawBody: string,
	sigHeader: string | undefined,
	tsHeader: string | undefined,
): Promise<{ ok: true } | { ok: false; reason: string }> {
	if (!secret) return { ok: false, reason: "RELAY_SECRET not configured" };
	if (!sigHeader) return { ok: false, reason: `missing ${RELAY_SIG_HEADER}` };
	if (!tsHeader) return { ok: false, reason: `missing ${RELAY_TS_HEADER}` };

	const ts = Number(tsHeader);
	if (!Number.isFinite(ts)) return { ok: false, reason: "invalid timestamp" };
	const skew = Math.abs(Math.floor(Date.now() / 1000) - ts);
	if (skew > SKEW_LIMIT_SECONDS) {
		return { ok: false, reason: `timestamp skew ${skew}s > ${SKEW_LIMIT_SECONDS}s` };
	}

	const key = await importKey(secret);
	const expected = bufToBase64(
		await crypto.subtle.sign("HMAC", key, encoder.encode(`${tsHeader}.${rawBody}`)),
	);
	if (!timingSafeEqual(expected, sigHeader)) {
		return { ok: false, reason: "signature mismatch" };
	}
	return { ok: true };
}
