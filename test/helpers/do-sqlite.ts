// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * A minimal stand-in for DurableObjectState.storage (the SQLite-backed DO
 * storage API) over node:sqlite, so MailboxDO's real SQL — Drizzle and raw
 * queries, migrations included — can run in plain vitest/node.
 *
 * Covers what this codebase and drizzle-orm/durable-sqlite use:
 * storage.sql.exec(query, ...params) returning a cursor with toArray(),
 * raw().toArray(), next(), one() and iteration; and transactionSync().
 */
import { DatabaseSync } from "node:sqlite";

type Row = Record<string, unknown>;

function cursor(rows: Row[], rawRows: unknown[][]) {
	let i = 0;
	return {
		toArray: () => rows,
		raw: () => ({ toArray: () => rawRows, [Symbol.iterator]: () => rawRows[Symbol.iterator]() }),
		next: () => (i < rows.length ? { done: false, value: rows[i++] } : { done: true, value: undefined }),
		one: () => {
			if (rows.length !== 1) throw new Error(`Expected exactly one row, got ${rows.length}`);
			return rows[0];
		},
		[Symbol.iterator]: () => rows[Symbol.iterator](),
	};
}

export function makeDoStorage() {
	const db = new DatabaseSync(":memory:");
	db.exec("PRAGMA foreign_keys = ON");

	const exec = (query: string, ...params: unknown[]) => {
		const body = query.trim().replace(/;\s*$/, "");
		// Multi-statement scripts (migrations) carry no params and return no rows.
		if (params.length === 0 && body.includes(";")) {
			db.exec(query);
			return cursor([], []);
		}
		const stmt = db.prepare(query);
		// Arrays keep duplicate column names (joins) distinct for raw().
		stmt.setReturnArrays(true);
		const rawRows = stmt.all(...(params as never[])) as unknown as unknown[][];
		const names = stmt.columns().map((c) => c.name);
		const rows = rawRows.map((arr) => Object.fromEntries(names.map((n, i) => [n, arr[i]])) as Row);
		return cursor(rows, rawRows);
	};

	const storage = {
		sql: { exec },
		transactionSync<T>(fn: () => T): T {
			db.exec("SAVEPOINT tx");
			try {
				const out = fn();
				db.exec("RELEASE tx");
				return out;
			} catch (e) {
				db.exec("ROLLBACK TO tx");
				db.exec("RELEASE tx");
				throw e;
			}
		},
	};
	return { db, storage };
}
