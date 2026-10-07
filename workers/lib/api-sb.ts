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
// Off unless MAIL_BACKEND = "api.sb" (with API_SB_URL and API_SB_STARTUP).

export interface ApiSbEnv {
	MAIL_BACKEND?: string;
	/** default https://api.sb */
	API_SB_URL?: string;
	/** the records Startup that holds emails.do's Mailboxes (the import's target) */
	API_SB_STARTUP?: string;
	/** service token (an id.org.ai access token) used when the caller brought no bearer of its own */
	API_SB_TOKEN?: string;
}

export const apiSbOn = (env: ApiSbEnv) => env.MAIL_BACKEND === "api.sb" && !!env.API_SB_STARTUP;

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

/** api.sb's email primitive, for one records Startup, as one caller. */
export class ApiSbMail {
	readonly base: string;
	constructor(
		readonly env: ApiSbEnv,
		readonly token: string,
		readonly fetcher: typeof fetch = fetch,
	) {
		this.base = `${(env.API_SB_URL ?? "https://api.sb").replace(/\/+$/, "")}/${env.API_SB_STARTUP}`;
	}

	private async call(method: string, path: string, body?: unknown): Promise<Rec> {
		const r = await this.fetcher(`${this.base}${path}`, {
			method,
			headers: { authorization: `Bearer ${this.token}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
			...(body !== undefined ? { body: JSON.stringify(body) } : {}),
		});
		const j = (await r.json().catch(() => ({}))) as Rec;
		if (!r.ok) throw new ApiSbError(r.status, j.error?.code ?? "api_sb_error", j.error?.message ?? `api.sb answered ${r.status}`);
		return j;
	}

	/** Every page of a list. */
	private async all(coll: string, q: Record<string, string>): Promise<Rec[]> {
		const out: Rec[] = [];
		let after: string | null = null;
		for (let i = 0; i < 100; i++) {
			const p = new URLSearchParams({ ...q, limit: "100", ...(after ? { after } : {}) });
			const j = await this.call("GET", `/${coll}?${p}`);
			const items = (j[coll] ?? []) as Rec[];
			out.push(...items);
			const next = j.links?.next ? new URL(j.links.next, "https://api.sb").searchParams.get("after") : null;
			if (!items.length || !next || next === after) break;
			after = next;
		}
		return out;
	}

	async mailboxes(): Promise<Rec[]> {
		return (await this.all("mailboxes", {})).filter((m) => m.status !== "closed");
	}

	async mailbox(address: string): Promise<Rec | null> {
		try {
			const j = await this.call("GET", `/mailboxes/${mailboxSlug(address)}`);
			return j.record ?? j;
		} catch (e) {
			if (e instanceof ApiSbError && e.status === 404) return null;
			throw e;
		}
	}

	/** A Mailbox's Messages shown in a folder, newest first; hidden (deletedAt) ones never. */
	async messages(box: Rec, folder?: string, thread?: string): Promise<Rec[]> {
		const q: Record<string, string> = { mailbox: box.id };
		if (thread) q.thread = thread;
		const all = await this.all("messages", q);
		return all
			.filter((m) => !m.deletedAt && (!folder || folderOf(m) === folder))
			.sort((a, b) => String(rowOf(b).date ?? "").localeCompare(String(rowOf(a).date ?? "")));
	}

	async message(id: string): Promise<Rec | null> {
		try {
			const j = await this.call("GET", `/messages/${id}`);
			return j.record ?? j;
		} catch (e) {
			if (e instanceof ApiSbError && e.status === 404) return null;
			throw e;
		}
	}

	async update(id: string, data: Rec): Promise<Rec> {
		const j = await this.call("PATCH", `/messages/${id}`, data);
		return j.record ?? j;
	}

	async send(address: string, out: { to: string | string[]; cc?: string | string[]; bcc?: string | string[]; subject: string; text?: string; html?: string }): Promise<Rec> {
		return (await this.call("POST", `/mailboxes/${mailboxSlug(address)}:send`, out)).message;
	}

	async reply(id: string, out: { text?: string; html?: string; to?: string | string[]; cc?: string | string[] }): Promise<Rec> {
		return (await this.call("POST", `/messages/${id}:reply`, out)).message;
	}
}
