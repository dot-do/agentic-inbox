// emails.do as a client of api.sb's email primitive (StartupsStudio/sb#337;
// ADR-0025 Q145-Q146: api.sb holds the mail, emails.do is the host/UI).
//
// api.sb keeps a Mailbox per address, Threads/Conversations, and Messages
// (direction inbound|outbound, status received|sent|draft|…, `labels` for
// archive/spam/trash/custom folders, `deletedAt` for a hidden one: nothing is
// deleted). This module reads and writes them through api.sb's records
// surface, and maps a Message to the emails row shape the UI already renders,
// so the React app does not change.
//
// Where a Mailbox lives (the founder, 2026-10-08): in the namespace of the
// Startup that sends and receives through it, the owner of its address.
// `@startups.studio` addresses are in startups.studio, each Startup's in its
// own. emails.do is the provider: it acts on the owner's namespace through
// api.sb's records and `:verb` paths, and never keeps other Startups' mail in
// a namespace of its own (emails.do's namespace holds only its own business).
//
// Off unless MAIL_BACKEND = "api.sb" (API_SB_URL optional).

export interface ApiSbEnv {
	MAIL_BACKEND?: string;
	/** default https://api.sb */
	API_SB_URL?: string;
	/** JSON {"<address or host>": "<namespace>"}: the owner where the address's name does not say it (a Domain another
	 *  Startup holds, a host under a two-part suffix such as co.uk) */
	API_SB_NAMESPACES?: string;
	/** service token (an id.org.ai access token) used when the caller brought no bearer of its own */
	API_SB_TOKEN?: string;
}

export const apiSbOn = (env: ApiSbEnv) => env.MAIL_BACKEND === "api.sb";

/** The Studio's namespace, and the names that address it (api.sb is its alias). */
const STUDIO_NS = "startups.studio";
const STUDIO_NAMES = new Set([STUDIO_NS, "api.sb"]);

/**
 * The namespace that owns an address: API_SB_NAMESPACES's entry for it or its host, else the Studio's for its names,
 * else the host's Domain (its last two labels; a two-part suffix needs the map). api.sb refuses any namespace that does
 * not own the address (403 not_address_owner), so a wrong guess fails loudly, never lands mail elsewhere.
 */
export function namespaceOf(address: string, env: ApiSbEnv = {}): string {
	const a = address.trim().toLowerCase();
	const host = a.split("@")[1] ?? "";
	let map: Record<string, string> = {};
	try { map = env.API_SB_NAMESPACES ? Object.fromEntries(Object.entries(JSON.parse(env.API_SB_NAMESPACES) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v])) : {}; } catch { /* a bad map is no map */ }
	if (map[a] ?? map[host]) return map[a] ?? map[host]!;
	const domain = host.split(".").slice(-2).join(".");
	return STUDIO_NAMES.has(domain) ? STUDIO_NS : domain;
}

type Rec = Record<string, any>

/** A Mailbox's slug on api.sb (src/email/mail.ts mailboxSlug). */
export const mailboxSlug = (address: string) =>
	address.toLowerCase().replace("@", "-at-").replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 128);

/** The folders the UI shows, as saved queries over Messages. */
export const SYSTEM_FOLDERS = [
	{ id: "inbox", name: "Inbox" },
	{ id: "sent", name: "Sent" },
	{ id: "draft", name: "Drafts" },
	{ id: "archive", name: "Archive" },
	{ id: "spam", name: "Spam" },
	{ id: "trash", name: "Trash" },
] as const;

/** Which folder a Message shows in: its label, else its direction and status. */
export function folderOf(m: Rec): string {
	const label = String(m.labels ?? "").split(/\s*,\s*/).filter(Boolean)[0];
	if (label) return label;
	if (m.status === "draft") return "draft";
	return m.direction === "outbound" ? "sent" : "inbox";
}

/** A Message as the emails row the UI renders (workers/db/schema.ts). */
export function rowOf(m: Rec): Rec {
	const refs = String(m.references ?? "").split(/\s+/).filter(Boolean);
	return {
		id: m.id,
		folder_id: folderOf(m),
		subject: m.subject ?? "",
		sender: m.from ?? "",
		recipient: m.to ?? "",
		cc: m.cc ?? null,
		bcc: m.bcc ?? null,
		date: m.receivedAt ?? m.sentAt ?? m.$createdAt ?? null,
		read: m.read ? 1 : 0,
		starred: m.starred ? 1 : 0,
		body: m.html ?? m.text ?? "",
		in_reply_to: m.inReplyTo ?? null,
		email_references: refs.length ? JSON.stringify(refs) : null,
		thread_id: m.thread ?? null,
		message_id: m.messageId ?? null,
		raw_headers: m.headers ?? null,
		attachments: (() => { try { return JSON.parse(m.files ?? "[]"); } catch { return []; } })(),
	};
}

export class ApiSbError extends Error {
	constructor(readonly status: number, readonly code: string, message: string) { super(message); }
}

/** A Mailbox as api.sb holds it, with the namespace it was read from. */
export type Box = Rec & { $ns: string };

/** api.sb's email primitive, as one caller: each Mailbox in its owner's namespace. */
export class ApiSbMail {
	readonly base: string;
	constructor(
		readonly env: ApiSbEnv,
		readonly token: string,
		readonly fetcher: typeof fetch = fetch,
	) {
		this.base = (env.API_SB_URL ?? "https://api.sb").replace(/\/+$/, "");
	}

	private async call(ns: string, method: string, path: string, body?: unknown): Promise<Rec> {
		const r = await this.fetcher(`${this.base}/${ns}${path}`, {
			method,
			headers: { authorization: `Bearer ${this.token}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
			...(body !== undefined ? { body: JSON.stringify(body) } : {}),
		});
		const j = (await r.json().catch(() => ({}))) as Rec;
		if (!r.ok) throw new ApiSbError(r.status, j.error?.code ?? "api_sb_error", j.error?.message ?? `api.sb answered ${r.status}`);
		return j;
	}

	/** Every page of a list. */
	private async all(ns: string, coll: string, q: Record<string, string>): Promise<Rec[]> {
		const out: Rec[] = [];
		let after: string | null = null;
		for (let i = 0; i < 100; i++) {
			const p = new URLSearchParams({ ...q, limit: "100", ...(after ? { after } : {}) });
			const j = await this.call(ns, "GET", `/${coll}?${p}`);
			const items = (j[coll] ?? []) as Rec[];
			out.push(...items);
			const next = j.links?.next ? new URL(j.links.next, "https://api.sb").searchParams.get("after") : null;
			if (!items.length || !next || next === after) break;
			after = next;
		}
		return out;
	}

	/** The open Mailboxes api.sb holds for these addresses (emails.do's own list of the addresses it serves), each read
	 *  in its owner's namespace. */
	async mailboxes(addresses: string[]): Promise<Box[]> {
		const boxes = await Promise.all(addresses.map((a) => this.mailbox(a)));
		return boxes.filter((m): m is Box => !!m && m.status !== "closed");
	}

	async mailbox(address: string): Promise<Box | null> {
		const ns = namespaceOf(address, this.env);
		try {
			const j = await this.call(ns, "GET", `/mailboxes/${mailboxSlug(address)}`);
			return { ...(j.record ?? j), $ns: ns };
		} catch (e) {
			if (e instanceof ApiSbError && e.status === 404) return null;
			throw e;
		}
	}

	/** A Mailbox's Messages shown in a folder, newest first; hidden (deletedAt) ones never. */
	async messages(box: Box, folder?: string, thread?: string): Promise<Rec[]> {
		const q: Record<string, string> = { mailbox: box.id };
		if (thread) q.thread = thread;
		const all = await this.all(box.$ns, "messages", q);
		return all
			.filter((m) => !m.deletedAt && (!folder || folderOf(m) === folder))
			.sort((a, b) => String(rowOf(b).date ?? "").localeCompare(String(rowOf(a).date ?? "")));
	}

	async message(box: Box, id: string): Promise<Rec | null> {
		try {
			const j = await this.call(box.$ns, "GET", `/messages/${encodeURIComponent(id)}`);
			return j.record ?? j;
		} catch (e) {
			if (e instanceof ApiSbError && e.status === 404) return null;
			throw e;
		}
	}

	async update(box: Box, id: string, data: Rec): Promise<Rec> {
		const j = await this.call(box.$ns, "PATCH", `/messages/${encodeURIComponent(id)}`, data);
		return j.record ?? j;
	}

	async send(box: Box, out: { to: string | string[]; cc?: string | string[]; bcc?: string | string[]; subject: string; text?: string; html?: string }): Promise<Rec> {
		return (await this.call(box.$ns, "POST", `/mailboxes/${mailboxSlug(String(box.address))}:send`, out)).message;
	}

	async reply(box: Box, id: string, out: { text?: string; html?: string; to?: string | string[]; cc?: string | string[] }): Promise<Rec> {
		return (await this.call(box.$ns, "POST", `/messages/${encodeURIComponent(id)}:reply`, out)).message;
	}
}
