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
import { archiveOutboundCopy } from "./lib/archive";

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

/** Optional per-send context for sendVia (archive journaling). */
export interface SendViaOptions {
	/**
	 * When provided, the best-effort archive journal write rides
	 * ctx.waitUntil so its completion is guaranteed without delaying the
	 * caller. Without it, the (already caught, never-rejecting) journal
	 * promise is left DETACHED — it is never awaited inline, because a
	 * slow/hung archive DO after a successful send would stall the caller
	 * (e.g. an agent tool call in lib/tools.ts), and a stalled tool call can
	 * trigger a retry → duplicate real send. DO-context callers keep running
	 * detached promises; plain Worker callers should pass ctx to guarantee
	 * the journal completes. Typed structurally so both the workers-types
	 * ExecutionContext and Hono's c.executionCtx satisfy it.
	 */
	ctx?: { waitUntil(promise: Promise<unknown>): void };
	/**
	 * R2 keys of attachment blobs the caller already stored for this message
	 * (attachments/<emailId>/<attId>/<filename>). The archive records these
	 * REFERENCES; attachment bytes are never duplicated.
	 */
	attachmentKeys?: string[];
}

/**
 * Best-effort outbound ledger (EMAIL-CASCADE.md §(b), founder ruling
 * 2026-08-20): a [ledger:outbound] journal email DELIVERED to the real
 * archive mailbox (agents@do.industries, Google Workspace) from the
 * dedicated ledger sender, plus a queryable index record in the ledger DO
 * (ledger@emails.do). Runs only AFTER a successful send. FAILURE-ISOLATED:
 * the returned promise never rejects — ledger errors are logged and
 * swallowed so they can never fail or delay the actual send.
 */
function journalOutbound(
	env: Env,
	params: SendEmailParams,
	sentMessageId: string,
	opts?: SendViaOptions,
): Promise<void> {
	return archiveOutboundCopy(env, params, sentMessageId || null, opts?.attachmentKeys)
		.then((outcome) => {
			// "skipped:disabled" is the steady state when the archive is off —
			// logging it per-send would be pure noise.
			if (outcome !== "archived" && outcome !== "skipped:disabled") {
				console.log(`Outbound archive skipped (${outcome})`);
			}
		})
		.catch((e) => {
			console.error("Outbound archive write failed (send unaffected):", (e as Error).message);
		});
}

/**
 * Dispatch the journal promise without ever blocking the caller: ride
 * ctx.waitUntil when available, otherwise leave it detached (it never
 * rejects — see journalOutbound). The send result must never wait on it.
 */
function scheduleJournal(opts: SendViaOptions | undefined, journal: Promise<void>): void {
	if (opts?.ctx) opts.ctx.waitUntil(journal);
	// else: detached on purpose — see SendViaOptions.ctx.
}

/**
 * Send an email, delegating to a per-account relay when the from-domain is
 * remote. This is the single send entry point the app should use (reply,
 * forward, compose, agent auto-send). Local domains keep the exact prior
 * behavior: a direct env.EMAIL.send() via sendEmail().
 *
 * After every successful send — local AND relayed — a [ledger:outbound]
 * journal email is delivered to the archive mailbox and an index record is
 * written to the ledger DO (see journalOutbound above). The journal is
 * best-effort and can never fail OR delay the send: it is never awaited on
 * the send path (waitUntil with opts.ctx, detached without).
 */
export async function sendVia(
	env: Env,
	params: SendEmailParams,
	opts?: SendViaOptions,
): Promise<{ messageId: string }> {
	const relayBase = resolveRelayBase(env, params.from);
	if (!relayBase) {
		// LOCAL domain — unchanged direct send.
		const result = await sendEmail(env.EMAIL, params);
		scheduleJournal(opts, journalOutbound(env, params, result.messageId, opts));
		return result;
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
	const sent = { messageId: result.messageId ?? "" };
	scheduleJournal(opts, journalOutbound(env, params, sent.messageId, opts));
	return sent;
}
