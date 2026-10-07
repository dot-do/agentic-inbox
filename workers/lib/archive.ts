// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * The estate email ledger (~/projects/domains/docs/EMAIL-CASCADE.md §(b)).
 *
 * FOUNDER RULING (2026-08-20): the agents@do.industries ARCHIVE is the real
 * Google Workspace mailbox. Every outbound send and inbound ingest through
 * the center therefore produces TWO ledger artifacts:
 *
 *  1. JOURNAL DELIVERY — a real email, sent via the normal send path
 *     (Cloudflare Email Service → Google MX), DELIVERED to ARCHIVE_ADDRESS
 *     (agents@do.industries). Subject is prefixed "[ledger:outbound]" /
 *     "[ledger:inbound]"; headers carry X-Ledger-Copy, X-Original-Message-Id,
 *     X-Original-From, X-Original-To (and X-Delivered-To for inbound); the
 *     body is the original body with attachments rendered as R2 REFERENCE
 *     LINKS (never re-attached — messages stay light). The From identity is
 *     the dedicated ledger sender (LEDGER_ADDRESS, ledger@emails.do) so the
 *     Google mailbox can filter/label cleanly.
 *
 *  2. LEDGER DO INDEX — a queryable, center-native MailboxDO record, kept
 *     because it is free and agent-searchable. Its identity is the LEDGER
 *     address (ledger@emails.do) — NOT agents@do.industries — eliminating
 *     the name collision with the real Google mailbox. (The first 6 ledger
 *     records, written 2026-08-20 before this ruling, remain in the old DO
 *     named "agents@do.industries"; deliberately left un-migrated.)
 *
 * ⚠️ VOLUME CEILING — FOUNDER DECISION DEFERRED. Journal delivery sends ONE
 * real email per message through the center to a SINGLE Google Workspace
 * mailbox. At current estate volume this is fine. At future migrated volume
 * (tens of thousands of messages/day, e.g. post-SES migration) this WILL hit
 * Workspace per-mailbox receiving limits. The ledger DO index is the scale
 * path; the Google-delivery layer may then need sampling/batching or a
 * per-class policy. Do not silently raise volume through this path without
 * revisiting [EMAIL-CASCADE.md §(b)].
 *
 * Design points:
 *  - LOOP GUARDS ARE PARAMOUNT. Never journal a journal: skip anything
 *    bearing X-Ledger-Copy, anything from the ledger sender or the archive
 *    address, anything addressed to the archive or ledger address, and
 *    inbound delivered into the archive/ledger mailboxes. (do.industries
 *    inbound is Google, not the center, so journal copies do not re-enter —
 *    these guards hold anyway in case routing ever changes.) The journal
 *    send also bypasses sendVia structurally (direct env.EMAIL.send), so it
 *    cannot recursively journal even without the header guard.
 *  - ATTACHMENTS BY REFERENCE. Neither the journal email nor the DO record
 *    ever duplicates attachment bytes. Both carry the original R2 keys; the
 *    journal email renders them as authenticated fetch links
 *    (https://emails.do/api/v1/...). These are best-effort POINTERS: DELETE
 *    /emails/:id deletes the original blobs, after which refs dangle.
 *  - FAILURE ISOLATION. Callers must treat ledger writes as best-effort:
 *    wrap in ctx.waitUntil()/catch so a failed journal send or DO write
 *    NEVER fails or delays the actual send or inbound delivery. The two
 *    legs (journal email, DO index) are also isolated from EACH OTHER
 *    (Promise.allSettled) — a Google-delivery failure still indexes, and
 *    vice versa. archiveOutboundCopy / archiveInboundCopy may throw; the
 *    sendVia/storeInboundEmail call sites own the isolation.
 *  - GROWTH POSTURE (DO index). Unbounded by design; records are metadata +
 *    body text only, bodies capped at MAX_ARCHIVE_BODY_CHARS (truncated
 *    records carry x-archive-truncated). A SQLite DO holds 10GB — years of
 *    headroom at current volume. ARCHIVE_ENABLED=false is the kill switch.
 *
 * Config (wrangler.jsonc vars):
 *  - ARCHIVE_ADDRESS — the real archive mailbox journal emails are DELIVERED
 *    to (default agents@do.industries, Google Workspace)
 *  - LEDGER_ADDRESS  — the dedicated journal sender identity AND the name of
 *    the internal ledger index DO (default ledger@emails.do)
 *  - ARCHIVE_ENABLED — set false to disable all ledger activity (default true)
 */

import { Folders } from "../../shared/folders";
import type { Env } from "../types";
import type { SendEmailParams } from "../email-sender";

export const LEDGER_HEADER = "X-Ledger-Copy";
const LEDGER_HEADER_LC = "x-ledger-copy";

/** The real archive mailbox (Google Workspace) journal emails are delivered to. */
export const DEFAULT_ARCHIVE_ADDRESS = "agents@do.industries";

/** Dedicated journal sender identity + internal ledger index DO name. */
export const DEFAULT_LEDGER_ADDRESS = "ledger@emails.do";

/**
 * Base URL for attachment reference links in journal emails. Attachment blobs
 * live in the center's R2 bucket; the links point at the center's authed
 * fetch route (viewer must be signed in to emails.do).
 */
const CENTER_BASE_URL = "https://emails.do";

/**
 * Cap on the body text stored per ledger record and journal email (~256K
 * chars). Keeps a single pathological message (huge inline HTML) from
 * bloating the ledger DO or tripping the Email Service message-size cap; the
 * full body still lives in the real mailbox record.
 */
export const MAX_ARCHIVE_BODY_CHARS = 262144;

/** Outcome of a ledger attempt: written, or skipped with a reason. */
export type ArchiveOutcome = "archived" | `skipped:${string}`;

/**
 * Minimal shape of an inbound message for the ledger. Structurally a subset
 * of NormalizedInbound (workers/index.ts); declared here to avoid an import
 * cycle (index.ts → email-sender.ts → archive.ts).
 */
export interface InboundForArchive {
	to: string[];
	from: string;
	subject: string;
	html?: string;
	text?: string;
	messageId?: string | null;
	cc?: string[];
	bcc?: string[];
	rawHeaders?: unknown;
}

// -- Config accessors ------------------------------------------------
// Read via index-cast: wrangler typegen renders vars as literal types (e.g.
// `true`), which would make honest boolean/string comparisons type errors.

export function archiveEnabled(env: Env): boolean {
	const v = (env as unknown as Record<string, unknown>).ARCHIVE_ENABLED;
	if (v === undefined || v === null) return true; // default ON
	if (typeof v === "boolean") return v;
	const s = String(v).trim().toLowerCase();
	return !(s === "false" || s === "0" || s === "off" || s === "no");
}

export function archiveAddress(env: Env): string {
	const v = (env as unknown as Record<string, unknown>).ARCHIVE_ADDRESS;
	const addr = typeof v === "string" && v.includes("@") ? v : DEFAULT_ARCHIVE_ADDRESS;
	return addr.trim().toLowerCase();
}

export function ledgerAddress(env: Env): string {
	const v = (env as unknown as Record<string, unknown>).LEDGER_ADDRESS;
	const addr = typeof v === "string" && v.includes("@") ? v : DEFAULT_LEDGER_ADDRESS;
	return addr.trim().toLowerCase();
}

// -- Address / header helpers ---------------------------------------

/** Extract the bare lowercase email from "a@b" or "Name <a@b>" forms. */
function bareAddress(value: string | { email: string; name?: string } | null | undefined): string | null {
	if (!value) return null;
	const raw = typeof value === "string" ? value : value.email;
	if (!raw) return null;
	const m = raw.match(/<([^>]+)>/);
	return (m ? m[1] : raw).trim().toLowerCase() || null;
}

function toList(value: string | string[] | undefined | null): string[] {
	if (!value) return [];
	const arr = Array.isArray(value) ? value : [value];
	return arr.map((a) => bareAddress(a)).filter(Boolean) as string[];
}

/** True if a headers map (send-params style) carries X-Ledger-Copy. */
function paramsHeadersHaveLedgerTag(headers: Record<string, string> | undefined): boolean {
	if (!headers) return false;
	return Object.keys(headers).some((k) => k.toLowerCase() === LEDGER_HEADER_LC);
}

/** True if PostalMime-style raw headers ([{key,value}, ...]) carry X-Ledger-Copy. */
function rawHeadersHaveLedgerTag(rawHeaders: unknown): boolean {
	if (!Array.isArray(rawHeaders)) return false;
	return rawHeaders.some(
		(h) => h && typeof h === "object" && typeof (h as { key?: unknown }).key === "string" &&
			(h as { key: string }).key.toLowerCase() === LEDGER_HEADER_LC,
	);
}

// -- Ledger index mailbox provisioning -------------------------------

/**
 * Ensure the ledger index mailbox (ledger@emails.do) exists — same machinery
 * as the wildcard auto-provision path in storeInboundEmail / POST
 * /api/v1/mailboxes: an R2 settings object plus a first DO touch (getFolders
 * seeds the folder rows).
 */
async function ensureLedgerMailbox(env: Env, address: string): Promise<void> {
	const key = `mailboxes/${address}.json`;
	if (await env.BUCKET.head(key)) return;
	const defaultSettings = {
		fromName: address,
		forwarding: { enabled: false, email: "" },
		signature: { enabled: false, text: "" },
		autoReply: { enabled: false, subject: "", message: "" },
	};
	await env.BUCKET.put(key, JSON.stringify(defaultSettings));
	const stub = env.MAILBOX.get(env.MAILBOX.idFromName(address));
	await stub.getFolders();
	console.log(`Auto-created ledger index mailbox ${address}`);
}

// -- Shared meta ------------------------------------------------------

interface LedgerMeta {
	direction: "outbound" | "inbound";
	originalMessageId: string | null;
	from: string;
	to: string;
	cc?: string | null;
	bcc?: string | null;
	subject: string;
	body: string;
	/** Whether `body` is HTML (drives journal email html-vs-text). */
	bodyIsHtml: boolean;
	deliveredTo?: string; // inbound only: which mailbox got the real copy
	attachmentKeys?: string[];
	/**
	 * The center mailbox whose attachment fetch route serves the R2 keys
	 * (outbound: the sending mailbox; inbound: the delivered-to mailbox).
	 * Used only to build reference links in the journal email.
	 */
	refMailbox?: string;
}

/** Normalize a Message-ID to its bare form (no surrounding <...>). */
function bareMessageId(id: string | null): string | null {
	if (!id) return null;
	const m = id.match(/<([^<>]+)>/);
	return (m ? m[1] : id).trim() || null;
}

/** Truncate a body at MAX_ARCHIVE_BODY_CHARS with a visible marker. */
function capBody(body: string): { body: string; truncated: boolean; originalLength: number } {
	if (body.length <= MAX_ARCHIVE_BODY_CHARS) return { body, truncated: false, originalLength: body.length };
	return {
		body: `${body.slice(0, MAX_ARCHIVE_BODY_CHARS)}\n[archive: body truncated]`,
		truncated: true,
		originalLength: body.length,
	};
}

// -- Journal email delivery (leg 1: the real archive) ----------------

/**
 * Render attachment R2 keys as reference links. Key shape (set at store
 * time): attachments/<emailId>/<attId>/<filename>. Links target the center's
 * authed attachment fetch route; bytes are NEVER re-attached.
 */
function attachmentRefBlock(meta: LedgerMeta, asHtml: boolean): string {
	const keys = meta.attachmentKeys ?? [];
	if (keys.length === 0) return "";
	const refs = keys.map((key) => {
		const parts = key.split("/");
		const [, emailId, attId] = parts;
		const filename = parts.slice(3).join("/") || key;
		const url = meta.refMailbox && emailId && attId
			? `${CENTER_BASE_URL}/api/v1/mailboxes/${encodeURIComponent(meta.refMailbox)}/emails/${encodeURIComponent(emailId)}/attachments/${encodeURIComponent(attId)}`
			: null;
		return { key, filename, url };
	});
	if (asHtml) {
		const items = refs
			.map((r) => `<li>${r.url ? `<a href="${r.url}">${r.filename}</a>` : r.filename} <span style="color:#888">(r2: ${r.key})</span></li>`)
			.join("");
		return `<hr><p><strong>Ledger:</strong> ${refs.length} attachment(s) by reference — not re-attached.</p><ul>${items}</ul>`;
	}
	const lines = refs.map((r) => ` - ${r.filename}${r.url ? ` — ${r.url}` : ""} (r2: ${r.key})`).join("\n");
	return `\n\n----\nLedger: ${refs.length} attachment(s) by reference — not re-attached:\n${lines}\n`;
}

/**
 * Send the journal email: a REAL message delivered to the archive mailbox
 * (agents@do.industries → Google MX) from the dedicated ledger sender.
 *
 * Deliberately a DIRECT env.EMAIL.send(), not sendVia(): the ledger sender's
 * domain (emails.do) is local to the center's account, and bypassing sendVia
 * makes recursion structurally impossible — a journal send can never journal
 * itself even before the X-Ledger-Copy header guard is consulted.
 *
 * ⚠️ VOLUME CEILING: one Google-delivered email per message through the
 * center — see the file header before scaling traffic through this path.
 */
async function sendJournalEmail(env: Env, ledger: string, archive: string, meta: LedgerMeta): Promise<void> {
	const capped = capBody(meta.body);
	const bodyWithRefs = capped.body + attachmentRefBlock(meta, meta.bodyIsHtml);
	const headers: Record<string, string> = {
		[LEDGER_HEADER]: meta.direction,
		"X-Original-From": meta.from,
		"X-Original-To": meta.to,
	};
	if (meta.originalMessageId) headers["X-Original-Message-Id"] = `<${meta.originalMessageId}>`;
	if (meta.deliveredTo) headers["X-Delivered-To"] = meta.deliveredTo;

	const message: Record<string, unknown> = {
		from: { email: ledger, name: "Estate Ledger" },
		to: archive,
		subject: `[ledger:${meta.direction}] ${meta.subject}`,
		headers,
	};
	if (meta.bodyIsHtml) message.html = bodyWithRefs || "<p>[no body]</p>";
	else message.text = bodyWithRefs || "[no body]";

	await env.EMAIL.send(message as never);
}

// -- Ledger DO index (leg 2: queryable, free) ------------------------

async function writeLedgerRecord(env: Env, address: string, meta: LedgerMeta): Promise<void> {
	await ensureLedgerMailbox(env, address);
	const id = crypto.randomUUID();
	const now = new Date().toISOString();
	const capped = capBody(meta.body);
	const rawHeaders = [
		{ key: LEDGER_HEADER_LC, value: meta.direction },
		...(meta.originalMessageId ? [{ key: "x-original-message-id", value: `<${meta.originalMessageId}>` }] : []),
		...(meta.deliveredTo ? [{ key: "x-delivered-to", value: meta.deliveredTo }] : []),
		{ key: "from", value: meta.from },
		{ key: "to", value: meta.to },
		...(meta.cc ? [{ key: "cc", value: meta.cc }] : []),
		...(meta.bcc ? [{ key: "bcc", value: meta.bcc }] : []),
		{ key: "subject", value: meta.subject },
		{ key: "date", value: now },
		// Attachment REFERENCES only — R2 keys of the original blobs; bytes are
		// never duplicated into the ledger.
		...(meta.attachmentKeys && meta.attachmentKeys.length > 0
			? [{ key: "x-archive-attachment-refs", value: JSON.stringify(meta.attachmentKeys) }]
			: []),
		...(capped.truncated ? [{ key: "x-archive-truncated", value: String(capped.originalLength) }] : []),
	];

	const stub = env.MAILBOX.get(env.MAILBOX.idFromName(address));
	await stub.createEmail(Folders.INBOX, {
		id,
		subject: meta.subject,
		sender: meta.from,
		recipient: meta.to,
		cc: meta.cc ?? null,
		bcc: meta.bcc ?? null,
		date: now,
		body: capped.body,
		in_reply_to: null,
		email_references: null,
		thread_id: id, // ledger records are flat — no thread stitching
		message_id: meta.originalMessageId,
		raw_headers: JSON.stringify(rawHeaders),
	}, []);
}

// -- Both legs, isolated from each other -----------------------------

/**
 * Run journal delivery + DO index write in parallel, isolated from each
 * other: one leg failing never stops the other. Throws (after both settle)
 * if any leg failed, so call sites' catch/waitUntil isolation still sees and
 * logs the error.
 */
async function writeLedger(env: Env, meta: LedgerMeta): Promise<void> {
	const ledger = ledgerAddress(env);
	const archive = archiveAddress(env);
	meta = { ...meta, originalMessageId: bareMessageId(meta.originalMessageId) };
	const results = await Promise.allSettled([
		sendJournalEmail(env, ledger, archive, meta),
		writeLedgerRecord(env, ledger, meta),
	]);
	const failures = results
		.map((r, i) => (r.status === "rejected" ? `${i === 0 ? "journal-delivery" : "do-index"}: ${(r.reason as Error)?.message ?? r.reason}` : null))
		.filter(Boolean);
	if (failures.length > 0) throw new Error(failures.join("; "));
}

// -- Public API ------------------------------------------------------

/**
 * Ledger an OUTBOUND message: deliver a [ledger:outbound] journal email to
 * the archive mailbox AND index it in the ledger DO. Call only AFTER a
 * successful send (local env.EMAIL or relay /send). May throw — call sites
 * must isolate (catch/waitUntil) so ledgering never affects the send.
 */
export async function archiveOutboundCopy(
	env: Env,
	params: SendEmailParams,
	sentMessageId: string | null,
	attachmentKeys?: string[],
): Promise<ArchiveOutcome> {
	if (!archiveEnabled(env)) return "skipped:disabled";
	const archive = archiveAddress(env);
	const ledger = ledgerAddress(env);

	// LOOP GUARDS — never journal a journal.
	if (paramsHeadersHaveLedgerTag(params.headers)) return "skipped:ledger-copy";
	const fromEmail = bareAddress(params.from) ?? "";
	if (fromEmail === archive) return "skipped:from-archive";
	if (fromEmail === ledger) return "skipped:from-ledger";
	const to = toList(params.to);
	const cc = toList(params.cc);
	const bcc = toList(params.bcc);
	const recipients = [...to, ...cc, ...bcc];
	if (recipients.includes(archive)) return "skipped:to-archive";
	if (recipients.includes(ledger)) return "skipped:to-ledger";

	await writeLedger(env, {
		direction: "outbound",
		originalMessageId: sentMessageId || null,
		from: fromEmail,
		to: to.join(", "),
		cc: cc.length ? cc.join(", ") : null,
		bcc: bcc.length ? bcc.join(", ") : null,
		subject: params.subject,
		body: params.html || params.text || "",
		bodyIsHtml: Boolean(params.html),
		attachmentKeys,
		refMailbox: fromEmail || undefined,
	});
	return "archived";
}

/**
 * Ledger an INBOUND message: deliver a [ledger:inbound] journal email to the
 * archive mailbox AND index it in the ledger DO. Call AFTER the real
 * MailboxDO delivery (covers both the direct Email Routing path and the
 * relay /api/v1/ingest path — both flow through storeInboundEmail). May
 * throw — call sites must isolate (catch/waitUntil).
 */
export async function archiveInboundCopy(
	env: Env,
	msg: InboundForArchive,
	deliveredTo: string,
	attachmentKeys?: string[],
): Promise<ArchiveOutcome> {
	if (!archiveEnabled(env)) return "skipped:disabled";
	const archive = archiveAddress(env);
	const ledger = ledgerAddress(env);

	// LOOP GUARDS — do.industries inbound is Google today (journal copies
	// cannot re-enter the center), but guard anyway in case routing changes.
	const delivered = deliveredTo.toLowerCase();
	if (delivered === archive) return "skipped:archive-mailbox";
	if (delivered === ledger) return "skipped:ledger-mailbox";
	if (rawHeadersHaveLedgerTag(msg.rawHeaders)) return "skipped:ledger-copy";
	const fromEmail = bareAddress(msg.from) ?? "";
	if (fromEmail === archive) return "skipped:from-archive";
	if (fromEmail === ledger) return "skipped:from-ledger";
	const to = toList(msg.to);
	const cc = toList(msg.cc);
	const bcc = toList(msg.bcc);
	const recipients = [...to, ...cc, ...bcc];
	if (recipients.includes(archive)) return "skipped:to-archive";
	if (recipients.includes(ledger)) return "skipped:to-ledger";

	const extractMsgId = (s: string) => { const m = s.match(/<([^>]+)>/); return m ? m[1] : s.trim().split(/\s+/)[0]; };

	await writeLedger(env, {
		direction: "inbound",
		originalMessageId: msg.messageId ? extractMsgId(msg.messageId) : null,
		from: fromEmail,
		to: to.join(", "),
		cc: cc.length ? cc.join(", ") : null,
		bcc: bcc.length ? bcc.join(", ") : null,
		subject: msg.subject || "",
		body: msg.html || msg.text || "",
		bodyIsHtml: Boolean(msg.html),
		deliveredTo: delivered,
		attachmentKeys,
		refMailbox: delivered,
	});
	return "archived";
}
