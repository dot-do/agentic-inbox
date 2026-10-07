// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Keep-everything (ADR-0005): deleting mail must never remove rows.
 *
 * Runs the REAL MailboxDO (Drizzle + raw SQL + migrations) against SQLite
 * via a node:sqlite stand-in for DO storage (test/helpers/do-sqlite.ts).
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("cloudflare:workers", () => ({
	DurableObject: class {
		ctx: unknown;
		env: unknown;
		constructor(ctx: unknown, env: unknown) {
			this.ctx = ctx;
			this.env = env;
		}
	},
}));

import { MailboxDO } from "../workers/durableObject";
import { applyMigrations, mailboxMigrations } from "../workers/durableObject/migrations";
import { makeDoStorage } from "./helpers/do-sqlite";

type Db = ReturnType<typeof makeDoStorage>["db"];

function count(db: Db, sql: string, ...params: (string | number)[]): number {
	return (db.prepare(sql).get(...params) as { n: number }).n;
}

function email(id: string, extra: Record<string, unknown> = {}) {
	return {
		id,
		subject: `Subject ${id}`,
		sender: "someone@example.com",
		recipient: "box@example.com",
		date: new Date().toISOString(),
		body: `body of ${id} findme`,
		thread_id: "t1",
		...extra,
	};
}

function newMailbox() {
	const { db, storage } = makeDoStorage();
	const mailbox = new MailboxDO({ storage } as never, {} as never);
	return { db, mailbox };
}

describe("MailboxDO soft delete", () => {
	let db: Db;
	let mailbox: MailboxDO;

	beforeEach(async () => {
		({ db, mailbox } = newMailbox());
		await mailbox.createEmail("inbox", email("e1"), [
			{ id: "a1", email_id: "e1", filename: "f.txt", mimetype: "text/plain", size: 3 },
		]);
		await mailbox.createEmail("inbox", email("e2"), []);
	});

	it("deleteEmail keeps the email row and its attachment rows", async () => {
		const result = await mailbox.deleteEmail("e1");
		expect(result).toEqual([{ id: "a1", filename: "f.txt" }]);

		expect(count(db, "SELECT COUNT(*) AS n FROM emails")).toBe(2);
		expect(count(db, "SELECT COUNT(*) AS n FROM attachments")).toBe(1);
		const row = db.prepare("SELECT body, deleted_at FROM emails WHERE id = 'e1'").get() as {
			body: string;
			deleted_at: string | null;
		};
		expect(row.body).toBe("body of e1 findme");
		expect(row.deleted_at).toBeTruthy();
	});

	it("hides a soft-deleted email from every read path", async () => {
		await mailbox.deleteEmail("e1");

		expect(await mailbox.getEmail("e1")).toBeNull();
		expect((await mailbox.getEmails({ folder: "inbox" })).map((e) => e.id)).toEqual(["e2"]);
		expect(await mailbox.countEmails({ folder: "inbox" })).toBe(1);
		expect((await mailbox.getThreadEmails("t1")).map((e: { id: string }) => e.id)).toEqual(["e2"]);
		const threaded = await mailbox.getThreadedEmails({ folder: "inbox" });
		expect(threaded.map((e: { id: string }) => e.id)).toEqual(["e2"]);
		expect(threaded[0].thread_count).toBe(1);
		expect(await mailbox.countThreadedEmails("inbox")).toBe(1);
		expect((await mailbox.searchEmails({ query: "findme" })).map((e) => e.id)).toEqual(["e2"]);
		expect(await mailbox.countSearchResults({ query: "findme" })).toBe(1);
		expect(await mailbox.getAttachment("a1")).toBeNull();
		const inbox = (await mailbox.getFolders()).find((f) => f.id === "inbox");
		expect(inbox?.unreadCount).toBe(1);
	});

	it("a second delete reports not-found and mutations skip deleted rows", async () => {
		await mailbox.deleteEmail("e1");
		expect(await mailbox.deleteEmail("e1")).toBeNull();
		expect(await mailbox.updateEmail("e1", { starred: true })).toBeNull();
		expect(count(db, "SELECT COUNT(*) AS n FROM emails WHERE id = 'e1' AND starred = 1")).toBe(0);
	});

	it("deleteFolder no longer cascades: folder and its emails are kept and hidden", async () => {
		await mailbox.createFolder("projects", "Projects");
		await mailbox.createEmail("projects", email("p1", { thread_id: "tp" }), [
			{ id: "pa", email_id: "p1", filename: "p.pdf", mimetype: "application/pdf", size: 9 },
		]);

		expect(await mailbox.deleteFolder("projects")).toBe(true);

		expect(count(db, "SELECT COUNT(*) AS n FROM folders WHERE id = 'projects'")).toBe(1);
		expect(count(db, "SELECT COUNT(*) AS n FROM emails WHERE id = 'p1'")).toBe(1);
		expect(count(db, "SELECT COUNT(*) AS n FROM attachments WHERE id = 'pa'")).toBe(1);
		expect((await mailbox.getFolders()).map((f) => f.id)).not.toContain("projects");
		expect(await mailbox.getEmail("p1")).toBeNull();
		expect(await mailbox.moveEmail("e2", "projects")).toBe(false);

		// Re-creating the folder revives it; the deleted emails stay deleted.
		const revived = await mailbox.createFolder("projects", "Projects");
		expect(revived?.id).toBe("projects");
		expect(await mailbox.getEmails({ folder: "projects" })).toEqual([]);
	});

	it("the database itself refuses hard deletes, direct or cascaded", () => {
		expect(() => db.exec("DELETE FROM emails WHERE id = 'e1'")).toThrow(/keep-everything/);
		expect(() => db.exec("DELETE FROM attachments")).toThrow(/keep-everything/);
		expect(() => db.exec("DELETE FROM folders WHERE id = 'inbox'")).toThrow(/keep-everything/);
		expect(count(db, "SELECT COUNT(*) AS n FROM emails")).toBe(2);
	});
});

describe("soft-delete migrations are additive", () => {
	it("upgrading a pre-existing mailbox keeps every row visible", async () => {
		const { db, storage } = makeDoStorage();
		// A mailbox as deployed before this change: migrations 1–8 only.
		const before = mailboxMigrations.filter((m) => !/^(9|10)_/.test(m.name));
		applyMigrations(storage.sql as never, before, storage);
		db.exec(`INSERT INTO emails (id, folder_id, subject, body, date, thread_id)
			VALUES ('old1', 'inbox', 'legacy', 'kept', '2026-01-01T00:00:00Z', 'old1')`);
		db.exec(`INSERT INTO attachments (id, email_id, filename, mimetype, size)
			VALUES ('olda', 'old1', 'x.bin', 'application/octet-stream', 1)`);

		// Constructing the DO applies 9_add_soft_delete and 10_forbid_hard_deletes.
		const mailbox = new MailboxDO({ storage } as never, {} as never);

		expect(count(db, "SELECT COUNT(*) AS n FROM emails")).toBe(1);
		expect(count(db, "SELECT COUNT(*) AS n FROM attachments")).toBe(1);
		expect(count(db, "SELECT COUNT(*) AS n FROM folders")).toBe(6);
		expect((await mailbox.getEmail("old1"))?.body).toBe("kept");
		expect((await mailbox.getAttachment("olda"))?.filename).toBe("x.bin");
		const applied = (db.prepare("SELECT name FROM d1_migrations ORDER BY id").all() as { name: string }[]).map((r) => r.name);
		expect(applied.slice(-2)).toEqual(["9_add_soft_delete", "10_forbid_hard_deletes"]);
	});
});
