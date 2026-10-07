// Read-only export of a mailbox, for its move to api.sb's email primitive
// (StartupsStudio/sb#337; ADR-0025 Q145: emails.do's fork retires onto api.sb).
//
// Every row, a soft-deleted one too (keep-everything: a deleted row is still
// mail), with its attachment rows; folders; and the counts the importer checks
// api.sb against. Only SELECTs: nothing here writes to the mailbox, its R2
// objects or its ACL. Driven by POST /api/v1/_admin/export (workers/index.ts),
// HMAC-authed like /api/v1/ingest.

/** The slice of SqlStorage this reads (DurableObjectState.storage.sql). */
export interface SqlReader {
	exec(query: string, ...bindings: unknown[]): Iterable<Record<string, unknown>>;
}

export interface ExportAttachment {
	id: string;
	email_id: string;
	filename: string;
	mimetype: string;
	size: number;
	content_id: string | null;
	disposition: string | null;
	/** its R2 key in this worker's BUCKET */
	key: string;
	/** base64 bytes, when asked for */
	content?: string;
}

export interface ExportEmail {
	id: string;
	folder_id: string;
	subject: string | null;
	sender: string | null;
	recipient: string | null;
	cc: string | null;
	bcc: string | null;
	date: string | null;
	read: number | null;
	starred: number | null;
	body: string | null;
	in_reply_to: string | null;
	email_references: string | null;
	thread_id: string | null;
	message_id: string | null;
	raw_headers: string | null;
	deleted_at: string | null;
	attachments: ExportAttachment[];
}

export interface ExportCounts {
	/** every row, deleted ones too */
	emails: number;
	deleted: number;
	attachments: number;
	byFolder: Record<string, number>;
}

export const MAX_EXPORT_PAGE = 200;

const rows = (sql: SqlReader, q: string, ...b: unknown[]) => [...sql.exec(q, ...b)];
const n = (v: unknown) => Number(v ?? 0);

export const attachmentKey = (a: { email_id: string; id: string; filename: string }) =>
	`attachments/${a.email_id}/${a.id}/${a.filename}`;

/** Whether a column exists (a mailbox DO migrated before 9_add_soft_delete has no deleted_at). */
function hasColumn(sql: SqlReader, table: string, column: string): boolean {
	return rows(sql, `SELECT name FROM pragma_table_info(?)`, table).some((r) => r.name === column);
}

/** One page of rows by id, after the cursor; `next` is the last id when more follow. */
export function exportEmails(sql: SqlReader, opts: { after?: string | null; limit?: number } = {}): { emails: ExportEmail[]; next: string | null } {
	const limit = Math.min(Math.max(Math.trunc(opts.limit ?? 50), 1), MAX_EXPORT_PAGE);
	const del = hasColumn(sql, "emails", "deleted_at") ? "deleted_at" : "NULL AS deleted_at";
	const cols = `id, folder_id, subject, sender, recipient, cc, bcc, date, read, starred, body, in_reply_to, email_references, thread_id, message_id, raw_headers, ${del}`;
	const page = opts.after
		? rows(sql, `SELECT ${cols} FROM emails WHERE id > ? ORDER BY id ASC LIMIT ?`, opts.after, limit + 1)
		: rows(sql, `SELECT ${cols} FROM emails ORDER BY id ASC LIMIT ?`, limit + 1);
	const more = page.length > limit;
	const kept = page.slice(0, limit);
	const ids = kept.map((r) => String(r.id));
	const atts = new Map<string, ExportAttachment[]>();
	if (ids.length) {
		const marks = ids.map(() => "?").join(", ");
		for (const a of rows(sql, `SELECT id, email_id, filename, mimetype, size, content_id, disposition FROM attachments WHERE email_id IN (${marks}) ORDER BY id`, ...ids)) {
			const att: ExportAttachment = {
				id: String(a.id), email_id: String(a.email_id), filename: String(a.filename), mimetype: String(a.mimetype), size: n(a.size),
				content_id: (a.content_id as string | null) ?? null, disposition: (a.disposition as string | null) ?? null,
				key: attachmentKey({ email_id: String(a.email_id), id: String(a.id), filename: String(a.filename) }),
			};
			atts.set(att.email_id, [...(atts.get(att.email_id) ?? []), att]);
		}
	}
	const emails = kept.map((r) => ({ ...(r as unknown as Omit<ExportEmail, "attachments">), attachments: atts.get(String(r.id)) ?? [] }));
	return { emails, next: more ? ids.at(-1)! : null };
}

/** The counts the importer holds api.sb to. */
export function exportCounts(sql: SqlReader): ExportCounts {
	const del = hasColumn(sql, "emails", "deleted_at");
	const byFolder: Record<string, number> = {};
	for (const r of rows(sql, `SELECT folder_id, COUNT(*) AS c FROM emails GROUP BY folder_id ORDER BY folder_id`)) byFolder[String(r.folder_id)] = n(r.c);
	return {
		emails: n(rows(sql, `SELECT COUNT(*) AS c FROM emails`)[0]?.c),
		deleted: del ? n(rows(sql, `SELECT COUNT(*) AS c FROM emails WHERE deleted_at IS NOT NULL`)[0]?.c) : 0,
		attachments: n(rows(sql, `SELECT COUNT(*) AS c FROM attachments`)[0]?.c),
		byFolder,
	};
}

/** Folders, deleted ones too. */
export function exportFolders(sql: SqlReader): { id: string; name: string; is_deletable: number; deleted_at: string | null }[] {
	const del = hasColumn(sql, "folders", "deleted_at") ? "deleted_at" : "NULL AS deleted_at";
	return rows(sql, `SELECT id, name, is_deletable, ${del} FROM folders ORDER BY id`).map((r) => ({
		id: String(r.id), name: String(r.name), is_deletable: n(r.is_deletable), deleted_at: (r.deleted_at as string | null) ?? null,
	}));
}
