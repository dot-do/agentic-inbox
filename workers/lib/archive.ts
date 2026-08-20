// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * The agents@ archive — a center-native ledger mailbox that receives a stored
 * copy of every outbound and inbound message that passes through the center
 * (~/projects/domains/docs/EMAIL-CASCADE.md, PROPOSAL v2 §(b)).
 *
 * Design points:
 *  - FORWARD-STYLE COPIES, NOT RE-SENDS. Each archived record is a fresh row
 *    in the archive MailboxDO with its OWN id — no second env.EMAIL.send(),
 *    so it costs no send quota, no recipient slots, and cannot loop through
 *    Email Routing. The original Message-ID is preserved as metadata.
 *  - TAGGING. Every record carries an `x-ledger-copy: outbound|inbound`
 *    entry in raw_headers, plus the original message-id, delivered-to, and
 *    attachment R2-key references.
 *  - ATTACHMENTS BY REFERENCE. Attachment bytes are never duplicated; the
 *    archive record lists the original R2 keys in an
 *    `x-archive-attachment-refs` raw_headers entry. These are best-effort
 *    POINTERS, not owned copies: DELETE /emails/:id deletes the original R2
 *    blobs (workers/index.ts), after which the archive's refs dangle. The
 *    ledger keeps the metadata (key names, subject, body) either way.
 *  - GROWTH POSTURE. The archive is UNBOUNDED BY DESIGN — it is the estate's
 *    ledger of record and nothing prunes it. Bounding factors: records are
 *    metadata + body text only (attachments by reference), and bodies are
 *    capped at MAX_ARCHIVE_BODY_CHARS (truncated records carry an
 *    `x-archive-truncated` raw_headers entry with the original length). A
 *    SQLite-backed DO holds 10GB, so at ~10-100KB/record that is years of
 *    headroom at current estate volume. If the archive DO ever becomes hot
 *    or full, ARCHIVE_ENABLED=false is the immediate pressure valve;
 *    retention/rollover is deliberately deferred until volume warrants it.
 *  - LOOP GUARDS. Never archive: (a) a message already bearing X-Ledger-Copy,
 *    (b) mail from the archive address (the archive mailbox's own sends),
 *    (c) mail addressed to the archive address, (d) inbound delivered INTO
 *    the archive mailbox itself.
 *  - FAILURE ISOLATION. Callers must treat archive writes as best-effort:
 *    wrap in ctx.waitUntil()/catch so a failed archive write NEVER fails or
 *    delays the actual send or inbound delivery. archiveOutboundCopy /
 *    archiveInboundCopy may throw; the sendVia/storeInboundEmail call sites
 *    own the isolation.
 *
 * Config (wrangler.jsonc vars):
 *  - ARCHIVE_ADDRESS  — the archive mailbox address (default agents@do.industries)
 *  - ARCHIVE_ENABLED  — set false to disable all archive writes (default true)
 */

import { Folders } from "../../shared/folders";
import type { Env } from "../types";
import type { SendEmailParams } from "../email-sender";

export const LEDGER_HEADER = "X-Ledger-Copy";
const LEDGER_HEADER_LC = "x-ledger-copy";

export const DEFAULT_ARCHIVE_ADDRESS = "agents@do.industries";

/**
 * Cap on the body text stored per ledger record (~256K chars). Keeps a single
 * pathological message (huge inline HTML) from bloating the archive DO; the
 * full body still lives in the real mailbox record. See GROWTH POSTURE above.
 */
export const MAX_ARCHIVE_BODY_CHARS = 262144;

/** Outcome of an archive attempt: written, or skipped with a reason. */
export type ArchiveOutcome = "archived" | `skipped:${string}`;

/**
 * Minimal shape of an inbound message for archiving. Structurally a subset of
 * NormalizedInbound (workers/index.ts); declared here to avoid an import cycle
 * (index.ts → email-sender.ts → archive.ts).
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

// -- Archive mailbox provisioning -----------------------------------

/**
 * Ensure the archive mailbox exists — same machinery as the wildcard
 * auto-provision path in storeInboundEmail / POST /api/v1/mailboxes: an R2
 * settings object plus a first DO touch (getFolders seeds the folder rows).
 */
async function ensureArchiveMailbox(env: Env, address: string): Promise<void> {
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
	console.log(`Auto-created archive mailbox ${address}`);
}

// -- Record writers --------------------------------------------------

interface LedgerMeta {
	direction: "outbound" | "inbound";
	originalMessageId: string | null;
	from: string;
	to: string;
	cc?: string | null;
	bcc?: string | null;
	subject: string;
	body: string;
	deliveredTo?: string; // inbound only: which mailbox got the real copy
	attachmentKeys?: string[];
}

async function writeLedgerRecord(env: Env, address: string, meta: LedgerMeta): Promise<void> {
	await ensureArchiveMailbox(env, address);
	const id = crypto.randomUUID();
	const now = new Date().toISOString();
	const truncated = meta.body.length > MAX_ARCHIVE_BODY_CHARS;
	const body = truncated
		? `${meta.body.slice(0, MAX_ARCHIVE_BODY_CHARS)}\n[archive: body truncated]`
		: meta.body;
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
		// never duplicated into the archive.
		...(meta.attachmentKeys && meta.attachmentKeys.length > 0
			? [{ key: "x-archive-attachment-refs", value: JSON.stringify(meta.attachmentKeys) }]
			: []),
		...(truncated ? [{ key: "x-archive-truncated", value: String(meta.body.length) }] : []),
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
		body,
		in_reply_to: null,
		email_references: null,
		thread_id: id, // ledger records are flat — no thread stitching
		// (body may be truncated — see MAX_ARCHIVE_BODY_CHARS)
		message_id: meta.originalMessageId,
		raw_headers: JSON.stringify(rawHeaders),
	}, []);
}

// -- Public API ------------------------------------------------------

/**
 * File an OUTBOUND journal copy into the archive mailbox. Call only AFTER a
 * successful send (local env.EMAIL or relay /send). May throw — call sites
 * must isolate (catch/waitUntil) so archiving never affects the send.
 */
export async function archiveOutboundCopy(
	env: Env,
	params: SendEmailParams,
	sentMessageId: string | null,
	attachmentKeys?: string[],
): Promise<ArchiveOutcome> {
	if (!archiveEnabled(env)) return "skipped:disabled";
	const archive = archiveAddress(env);

	if (paramsHeadersHaveLedgerTag(params.headers)) return "skipped:ledger-copy";
	const fromEmail = bareAddress(params.from) ?? "";
	if (fromEmail === archive) return "skipped:from-archive";
	const to = toList(params.to);
	const cc = toList(params.cc);
	const bcc = toList(params.bcc);
	if ([...to, ...cc, ...bcc].includes(archive)) return "skipped:to-archive";

	await writeLedgerRecord(env, archive, {
		direction: "outbound",
		originalMessageId: sentMessageId || null,
		from: fromEmail,
		to: to.join(", "),
		cc: cc.length ? cc.join(", ") : null,
		bcc: bcc.length ? bcc.join(", ") : null,
		subject: params.subject,
		body: params.html || params.text || "",
		attachmentKeys,
	});
	return "archived";
}

/**
 * File an INBOUND copy into the archive mailbox. Call AFTER the real
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

	if (deliveredTo.toLowerCase() === archive) return "skipped:archive-mailbox";
	if (rawHeadersHaveLedgerTag(msg.rawHeaders)) return "skipped:ledger-copy";
	const fromEmail = bareAddress(msg.from) ?? "";
	if (fromEmail === archive) return "skipped:from-archive";
	const to = toList(msg.to);
	const cc = toList(msg.cc);
	const bcc = toList(msg.bcc);
	if ([...to, ...cc, ...bcc].includes(archive)) return "skipped:to-archive";

	const extractMsgId = (s: string) => { const m = s.match(/<([^>]+)>/); return m ? m[1] : s.trim().split(/\s+/)[0]; };

	await writeLedgerRecord(env, archive, {
		direction: "inbound",
		originalMessageId: msg.messageId ? extractMsgId(msg.messageId) : null,
		from: fromEmail,
		to: to.join(", "),
		cc: cc.length ? cc.join(", ") : null,
		bcc: bcc.length ? bcc.join(", ") : null,
		subject: msg.subject || "",
		body: msg.html || msg.text || "",
		deliveredTo: deliveredTo.toLowerCase(),
		attachmentKeys,
	});
	return "archived";
}
