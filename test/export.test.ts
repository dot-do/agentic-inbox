// The read-only export for the move to api.sb (StartupsStudio/sb#337):
// every row (soft-deleted too) with its attachments, paged by id, and the
// counts the importer checks api.sb against. Runs the mailbox's real
// migrations on node:sqlite; asserts nothing is written.
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import { applyMigrations, mailboxMigrations } from "../workers/durableObject/migrations";
import { exportCounts, exportEmails, exportFolders, type SqlReader } from "../workers/lib/export";

/** SqlStorage's exec over node:sqlite (statements split on ';' outside triggers are not needed here). */
function mailboxDb() {
	const db = new DatabaseSync(":memory:");
	const sql = {
		exec(query: string, ...b: unknown[]) {
			const q = query.trim();
			if (b.length === 0 && /;\s*\S/.test(q.replace(/BEGIN[\s\S]*?END;/gi, ""))) { db.exec(q); return []; }
			const st = db.prepare(q);
			return /^\s*(SELECT|WITH|PRAGMA)/i.test(q) ? (st.all(...(b as never[])) as Record<string, unknown>[]) : (st.run(...(b as never[])), []);
		},
	};
	applyMigrations(sql as never, mailboxMigrations);
	return { db, sql: sql as SqlReader };
}

function seed(db: DatabaseSync) {
	const put = db.prepare(`INSERT INTO emails (id, folder_id, subject, sender, recipient, date, body, thread_id, message_id, deleted_at, read, starred) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
	put.run("e1", "inbox", "Hello", "pat@x.example", "box@acme.example", "2026-09-01T00:00:00Z", "hi", "t1", "m1@x", null, 0, 0);
	put.run("e2", "sent", "Re: Hello", "box@acme.example", "pat@x.example", "2026-09-02T00:00:00Z", "<p>yo</p>", "t1", "m2@acme", null, 1, 0);
	put.run("e3", "trash", "Old", "lee@y.example", "box@acme.example", "2026-08-01T00:00:00Z", "bye", "t3", "m3@y", "2026-09-03T00:00:00Z", 1, 1);
	db.prepare(`INSERT INTO attachments (id, email_id, filename, mimetype, size) VALUES (?, ?, ?, ?, ?)`).run("a1", "e1", "f.pdf", "application/pdf", 4);
}

describe("read-only export of a mailbox", () => {
	it("pages every row by id, soft-deleted ones too, each with its attachments", () => {
		const { db, sql } = mailboxDb();
		seed(db);
		const p1 = exportEmails(sql, { limit: 2 });
		expect(p1.emails.map((e) => e.id)).toEqual(["e1", "e2"]);
		expect(p1.next).toBe("e2");
		expect(p1.emails[0]!.attachments).toEqual([{ id: "a1", email_id: "e1", filename: "f.pdf", mimetype: "application/pdf", size: 4, content_id: null, disposition: null, key: "attachments/e1/a1/f.pdf" }]);
		const p2 = exportEmails(sql, { after: p1.next, limit: 2 });
		expect(p2.emails.map((e) => [e.id, e.deleted_at])).toEqual([["e3", "2026-09-03T00:00:00Z"]]);
		expect(p2.next).toBeNull();
	});

	it("counts every row, the deleted ones, the attachments and each folder's rows", () => {
		const { db, sql } = mailboxDb();
		seed(db);
		expect(exportCounts(sql)).toEqual({ emails: 3, deleted: 1, attachments: 1, byFolder: { inbox: 1, sent: 1, trash: 1 } });
		expect(exportFolders(sql).map((f) => f.id)).toEqual(["archive", "draft", "inbox", "sent", "spam", "trash"]);
	});

	it("writes nothing", () => {
		const { db, sql } = mailboxDb();
		seed(db);
		const before = db.prepare("SELECT total_changes() AS n").get() as { n: number };
		exportEmails(sql, { limit: 10 });
		exportCounts(sql);
		exportFolders(sql);
		expect((db.prepare("SELECT total_changes() AS n").get() as { n: number }).n).toBe(before.n);
	});
});
