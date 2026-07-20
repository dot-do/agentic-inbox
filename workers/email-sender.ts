// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Email sending via Cloudflare Email Service binding.
 *
 * Uses the `send_email` Worker binding (`env.EMAIL.send()`) to send emails.
 *
 * See: https://developers.cloudflare.com/email-service/api/send-emails/workers-api/
 */

import type { Env } from "./types";
import { signRelayBody } from "./lib/relay-hmac";

export interface SendEmailParams {
	to: string | string[];
	from: string | { email: string; name: string };
	subject: string;
	html?: string;
	text?: string;
	cc?: string | string[];
	bcc?: string | string[];
	replyTo?: string | { email: string; name: string };
	attachments?: {
		content: string; // base64 encoded
		filename: string;
		type: string;
		disposition: "attachment" | "inline";
		contentId?: string;
	}[];
	headers?: Record<string, string>;
}

/**
 * Send an email using the Cloudflare Email Service binding.
 *
 * @param binding  - The `EMAIL` SendEmail binding from env
 * @param params   - Email parameters (to, from, subject, body, etc.)
 * @returns The send result with messageId
 * @throws On validation or delivery errors (error has `.code` property)
 */
export async function sendEmail(
	binding: SendEmail,
	params: SendEmailParams,
): Promise<{ messageId: string }> {
	const message: Record<string, unknown> = {
		to: params.to,
		from: params.from,
		subject: params.subject,
	};

	if (params.html) message.html = params.html;
	if (params.text) message.text = params.text;
	if (params.cc) message.cc = params.cc;
	if (params.bcc) message.bcc = params.bcc;
	if (params.replyTo) message.replyTo = params.replyTo;

	if (params.headers && Object.keys(params.headers).length > 0) {
		message.headers = params.headers;
	}

	if (params.attachments && params.attachments.length > 0) {
		message.attachments = params.attachments.map((att) => ({
			content: att.content,
			filename: att.filename,
			type: att.type,
			disposition: att.disposition,
			...(att.contentId ? { contentId: att.contentId } : {}),
		}));
	}

	const result = await binding.send(message as any);
	return { messageId: result.messageId };
}

// ---------------------------------------------------------------------------
// Registry-aware send delegation (the OUTBOUND cascade)
//
// A send-as domain may live in a DIFFERENT Cloudflare account than the center
// (".do"). Cloudflare Email Service can only send-as domains onboarded in the
// worker's OWN account, so for a remote domain (e.g. domains@longtail.studio,
// a Semantics.dev domain) the center cannot call its local env.EMAIL. Instead
// it POSTs the message, HMAC-signed, to that account's relay worker /send,
// which owns the send-as capability locally.
//
// The registry lives in env.EMAIL_RELAYS: a JSON string mapping a from-domain
// to the relay's base URL, seeded from ~/projects/domains/data/email-zones.tsv,
// e.g. {"longtail.studio":"https://relay.longtail.studio"}. A domain with NO
// entry is LOCAL — the center sends directly via env.EMAIL (unchanged path).
// ---------------------------------------------------------------------------

/** Parse the EMAIL_RELAYS JSON var into a domain -> relayBase map (fail-soft). */
export function parseEmailRelays(raw: string | undefined): Record<string, string> {
	if (!raw) return {};
	try {
		const parsed = JSON.parse(raw);
		if (parsed && typeof parsed === "object") {
			const out: Record<string, string> = {};
			for (const [k, v] of Object.entries(parsed)) {
				if (typeof v === "string") out[k.toLowerCase()] = v.replace(/\/+$/, "");
			}
			return out;
		}
	} catch {
		console.error("EMAIL_RELAYS is not valid JSON; treating all domains as local");
	}
	return {};
}

/** Extract the domain from a `from` value (bare address, or "Name <a@b>" form). */
function fromDomainOf(from: SendEmailParams["from"]): string | null {
	const raw = typeof from === "string" ? from : from.email;
	// Handle both "a@b.com" and "Name <a@b.com>".
	const m = raw.match(/@([^>\s]+)/);
	return m ? m[1].toLowerCase() : null;
}

/**
 * Resolve the relay base URL for a given `from` address, or null if the domain
 * is local (no registry entry) and should be sent via env.EMAIL directly.
 */
export function resolveRelayBase(env: Env, from: SendEmailParams["from"]): string | null {
	const domain = fromDomainOf(from);
	if (!domain) return null;
	const relays = parseEmailRelays(env.EMAIL_RELAYS);
	return relays[domain] ?? null;
}

/**
 * Send an email, delegating to a per-account relay when the from-domain is
 * remote. This is the single send entry point the app should use (reply,
 * forward, compose, agent auto-send). Local domains keep the exact prior
 * behavior: a direct env.EMAIL.send() via sendEmail().
 */
export async function sendVia(
	env: Env,
	params: SendEmailParams,
): Promise<{ messageId: string }> {
	const relayBase = resolveRelayBase(env, params.from);
	if (!relayBase) {
		// LOCAL domain — unchanged direct send.
		return sendEmail(env.EMAIL, params);
	}

	// REMOTE domain — delegate to the account's relay over HMAC-signed HTTPS.
	if (!env.RELAY_SECRET) {
		throw new Error(
			`Cannot delegate send for remote domain to ${relayBase}: RELAY_SECRET is not configured`,
		);
	}

	// The relay's /send accepts the same structured message the Email Service
	// binding takes (to/from/subject/html/text/cc/bcc/replyTo/headers). NOTE:
	// the relay does not currently re-emit attachments, so remote send-as drops
	// attachments in v1; local sends are unaffected.
	const payload: Record<string, unknown> = {
		to: params.to,
		from: params.from,
		subject: params.subject,
	};
	if (params.html) payload.html = params.html;
	if (params.text) payload.text = params.text;
	if (params.cc) payload.cc = params.cc;
	if (params.bcc) payload.bcc = params.bcc;
	if (params.replyTo) payload.replyTo = params.replyTo;
	if (params.headers && Object.keys(params.headers).length > 0) {
		payload.headers = params.headers;
	}

	const rawBody = JSON.stringify(payload);
	const sigHeaders = await signRelayBody(env.RELAY_SECRET, rawBody);

	const res = await fetch(`${relayBase}/send`, {
		method: "POST",
		headers: { "content-type": "application/json", ...sigHeaders },
		body: rawBody,
	});
	if (!res.ok) {
		const detail = await res.text().catch(() => "");
		throw new Error(`relay ${relayBase}/send returned ${res.status}: ${detail.slice(0, 200)}`);
	}
	const result = (await res.json().catch(() => ({}))) as { messageId?: string };
	return { messageId: result.messageId ?? "" };
}
