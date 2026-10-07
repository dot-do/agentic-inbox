// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Per-mailbox authorization: a signed-in user may read only mailboxes they
 * own, were granted, or administer (MAILBOX_ADMINS). Deny by default.
 *
 * Drives the real API app (workers/index.ts) with mocked bindings, plus the
 * /mcp and /agents/* gates (workers/lib/gates.ts).
 */

import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("agents", () => ({ getAgentByName: vi.fn() }));

import { app as apiApp } from "../workers/index";
import { PRINCIPAL_HEADER, type Principal } from "../workers/lib/access";
import { principalFromClaims } from "../workers/lib/auth";
import { gateAgentRequest, gateMcpRequest } from "../workers/lib/gates";

// -- Mock bindings ----------------------------------------------------

function makeBucket(initial: Record<string, unknown>) {
	const store = new Map<string, string>(
		Object.entries(initial).map(([k, v]) => [k, typeof v === "string" ? v : JSON.stringify(v)]),
	);
	const bucket = {
		store,
		get: vi.fn(async (key: string) => {
			const v = store.get(key);
			if (v === undefined) return null;
			return { json: async () => JSON.parse(v), text: async () => v, body: v };
		}),
		head: vi.fn(async (key: string) => (store.has(key) ? { key } : null)),
		put: vi.fn(async (key: string, value: string) => {
			store.set(key, value);
		}),
		list: vi.fn(async ({ prefix }: { prefix: string }) => ({
			objects: [...store.keys()].filter((k) => k.startsWith(prefix)).map((key) => ({ key })),
		})),
		// Keep-everything: nothing in these flows may hard-delete from R2.
		delete: vi.fn(async () => {
			throw new Error("BUCKET.delete must never be called");
		}),
	};
	return bucket;
}

function makeStub(mailbox: string) {
	return {
		getEmails: vi.fn(async () => [{ id: `${mailbox}-e1` }]),
		countEmails: vi.fn(async () => 1),
		getEmail: vi.fn(async (id: string) => ({ id, body: `secret of ${mailbox}` })),
		getThreadEmails: vi.fn(async () => [{ id: `${mailbox}-e1` }]),
		searchEmails: vi.fn(async () => [{ id: `${mailbox}-e1` }]),
		countSearchResults: vi.fn(async () => 1),
		getAttachment: vi.fn(async (id: string) => ({ id, email_id: "e1", filename: "f.txt", mimetype: "text/plain" })),
		getFolders: vi.fn(async () => []),
		deleteEmail: vi.fn(async () => []),
	};
}

const ALICE: Principal = { sub: "sub-alice", email: "alice@x.com" };
const BOB: Principal = { sub: "sub-bob", email: "bob@x.com" };
const CAROL: Principal = { sub: "sub-carol" }; // bearer token without an email claim
const ADMIN: Principal = { sub: "sub-admin", email: "ops@x.com" };

const settings = { fromName: "x" };

function setup() {
	const bucket = makeBucket({
		"mailboxes/alice@x.com.json": settings,
		"mailboxes/bob@x.com.json": settings,
		"mailboxes/shared@x.com.json": settings,
		"mailboxes/legacy@x.com.json": settings, // no ACL: admins + address holder only
		"mailbox-acl/alice@x.com.json": { owner: "alice@x.com", members: [] },
		"mailbox-acl/bob@x.com.json": { owner: "bob@x.com", members: [] },
		"mailbox-acl/shared@x.com.json": { owner: "alice@x.com", members: ["sub-carol"] },
		"attachments/e1/a1/f.txt": "file",
	});
	const stubs = new Map<string, ReturnType<typeof makeStub>>();
	const env = {
		BUCKET: bucket,
		MAILBOX: {
			idFromName: (name: string) => name,
			get: (id: string) => {
				if (!stubs.has(id)) stubs.set(id, makeStub(id));
				return stubs.get(id)!;
			},
		},
		MAILBOX_ADMINS: "ops@x.com",
		EMAIL_ADDRESSES: [],
	};
	// Stand-in for the auth middleware in workers/app.ts: it sets the verified
	// principal on the context before the API routes run.
	const outer = new Hono<{ Variables: { principal: Principal } }>();
	outer.use("*", async (c, next) => {
		const who = c.req.header("x-test-principal");
		if (who) c.set("principal", JSON.parse(who));
		await next();
	});
	outer.route("/", apiApp as never);
	const call = (who: Principal | null, path: string, init: RequestInit = {}) =>
		outer.request(
			path,
			{
				...init,
				headers: {
					"Content-Type": "application/json",
					...(who ? { "x-test-principal": JSON.stringify(who) } : {}),
					...(init.headers as Record<string, string> | undefined),
				},
			},
			env as never,
		);
	return { env, bucket, stubs, call };
}

const READ_PATHS = (box: string) => [
	`/api/v1/mailboxes/${box}`,
	`/api/v1/mailboxes/${box}/emails?folder=inbox`,
	`/api/v1/mailboxes/${box}/emails/e1`,
	`/api/v1/mailboxes/${box}/threads/t1`,
	`/api/v1/mailboxes/${box}/search?query=secret`,
	`/api/v1/mailboxes/${box}/emails/e1/attachments/a1`,
	`/api/v1/mailboxes/${box}/folders`,
	`/api/v1/mailboxes/${box}/members`,
];

describe("mailbox read access (REST API)", () => {
	let t: ReturnType<typeof setup>;
	beforeEach(() => {
		t = setup();
	});

	it("user A cannot read user B's mailbox on any read path", async () => {
		for (const path of READ_PATHS("bob@x.com")) {
			const res = await t.call(ALICE, path);
			expect(res.status, path).toBe(404);
			expect(await res.text(), path).not.toContain("secret");
		}
		// Bob's Durable Object was never even reached.
		expect(t.stubs.has("bob@x.com")).toBe(false);
	});

	it("user A cannot write to, delete from, or delete user B's mailbox", async () => {
		const attempts: [string, string, unknown?][] = [
			["PUT", "/api/v1/mailboxes/bob@x.com", { settings: {} }],
			["DELETE", "/api/v1/mailboxes/bob@x.com"],
			["DELETE", "/api/v1/mailboxes/bob@x.com/emails/e1"],
			["PUT", "/api/v1/mailboxes/bob@x.com/members", { members: ["alice@x.com"] }],
			["POST", "/api/v1/mailboxes/bob@x.com/drafts", { body: "x" }],
		];
		for (const [method, path, body] of attempts) {
			const res = await t.call(ALICE, path, { method, body: body ? JSON.stringify(body) : undefined });
			expect(res.status, `${method} ${path}`).toBe(404);
		}
		expect(t.stubs.has("bob@x.com")).toBe(false);
		expect(t.bucket.store.has("mailbox-deleted/bob@x.com.json")).toBe(false);
	});

	it("the owner can read their own mailbox", async () => {
		for (const path of READ_PATHS("bob@x.com")) {
			const res = await t.call(BOB, path);
			expect(res.status, path).toBe(200);
		}
	});

	it("an unauthenticated request is denied", async () => {
		const res = await t.call(null, "/api/v1/mailboxes/bob@x.com/emails?folder=inbox");
		expect(res.status).toBe(404);
		expect(await (await t.call(null, "/api/v1/mailboxes")).json()).toEqual([]);
	});

	it("explicitly granted members (matched by sub) can read; nothing else", async () => {
		expect((await t.call(CAROL, "/api/v1/mailboxes/shared@x.com/emails/e1")).status).toBe(200);
		expect((await t.call(CAROL, "/api/v1/mailboxes/alice@x.com/emails/e1")).status).toBe(404);
		// A member cannot change who has access.
		const res = await t.call(CAROL, "/api/v1/mailboxes/shared@x.com/members", {
			method: "PUT",
			body: JSON.stringify({ members: ["sub-carol", "bob@x.com"] }),
		});
		expect(res.status).toBe(403);
	});

	it("the owner grants access; the grantee can then read", async () => {
		expect((await t.call(BOB, "/api/v1/mailboxes/shared@x.com/emails/e1")).status).toBe(404);
		const res = await t.call(ALICE, "/api/v1/mailboxes/shared@x.com/members", {
			method: "PUT",
			body: JSON.stringify({ members: ["sub-carol", "bob@x.com"] }),
		});
		expect(res.status).toBe(200);
		expect((await t.call(BOB, "/api/v1/mailboxes/shared@x.com/emails/e1")).status).toBe(200);
	});

	it("mailboxes without an ACL are admin/address-holder only", async () => {
		expect((await t.call(ALICE, "/api/v1/mailboxes/legacy@x.com/emails/e1")).status).toBe(404);
		expect((await t.call(ADMIN, "/api/v1/mailboxes/legacy@x.com/emails/e1")).status).toBe(200);
		const holder: Principal = { sub: "sub-legacy", email: "legacy@x.com" };
		expect((await t.call(holder, "/api/v1/mailboxes/legacy@x.com/emails/e1")).status).toBe(200);
	});

	it("the mailbox list shows only accessible mailboxes", async () => {
		const ids = async (p: Principal) =>
			((await (await t.call(p, "/api/v1/mailboxes")).json()) as { id: string }[]).map((m) => m.id).sort();
		expect(await ids(ALICE)).toEqual(["alice@x.com", "shared@x.com"]);
		expect(await ids(BOB)).toEqual(["bob@x.com"]);
		expect(await ids(CAROL)).toEqual(["shared@x.com"]);
		expect(await ids(ADMIN)).toEqual(["alice@x.com", "bob@x.com", "legacy@x.com", "shared@x.com"]);
	});

	it("an admin-created mailbox for an agent is owned by that agent only", async () => {
		const res = await t.call(ADMIN, "/api/v1/mailboxes", {
			method: "POST",
			body: JSON.stringify({ email: "bot@x.com", name: "Bot", owner: "sub-bot" }),
		});
		expect(res.status).toBe(201);
		expect(JSON.parse(t.bucket.store.get("mailbox-acl/bot@x.com.json")!)).toEqual({ owner: "sub-bot", members: [] });
		expect((await t.call({ sub: "sub-bot" }, "/api/v1/mailboxes/bot@x.com/emails/e1")).status).toBe(200);
		expect((await t.call(ALICE, "/api/v1/mailboxes/bot@x.com/emails/e1")).status).toBe(404);
	});
});

describe("delete keeps data (REST API)", () => {
	let t: ReturnType<typeof setup>;
	beforeEach(() => {
		t = setup();
	});

	it("deleting an email soft-deletes in the DO and keeps the R2 attachment blobs", async () => {
		const res = await t.call(BOB, "/api/v1/mailboxes/bob@x.com/emails/e1", { method: "DELETE" });
		expect(res.status).toBe(204);
		expect(t.stubs.get("bob@x.com")!.deleteEmail).toHaveBeenCalledWith("e1");
		expect(t.bucket.delete).not.toHaveBeenCalled();
		expect(t.bucket.store.has("attachments/e1/a1/f.txt")).toBe(true);
	});

	it("deleting a mailbox writes a tombstone and keeps settings, ACL and data", async () => {
		const res = await t.call(BOB, "/api/v1/mailboxes/bob@x.com", { method: "DELETE" });
		expect(res.status).toBe(204);
		expect(t.bucket.delete).not.toHaveBeenCalled();
		expect(t.bucket.store.has("mailboxes/bob@x.com.json")).toBe(true);
		expect(t.bucket.store.has("mailbox-acl/bob@x.com.json")).toBe(true);
		const tomb = JSON.parse(t.bucket.store.get("mailbox-deleted/bob@x.com.json")!);
		expect(tomb.deleted_by).toBe("bob@x.com");
		expect(tomb.deleted_at).toBeTruthy();
		// Hidden from reads afterwards, even for its owner and admins.
		expect((await t.call(BOB, "/api/v1/mailboxes/bob@x.com/emails/e1")).status).toBe(404);
		const adminList = (await (await t.call(ADMIN, "/api/v1/mailboxes")).json()) as { id: string }[];
		expect(adminList.map((m) => m.id)).not.toContain("bob@x.com");
		// The address stays taken rather than being silently re-created.
		const again = await t.call(BOB, "/api/v1/mailboxes", {
			method: "POST",
			body: JSON.stringify({ email: "bob@x.com", name: "Bob" }),
		});
		expect(again.status).toBe(409);
	});
});

describe("MCP gate", () => {
	let t: ReturnType<typeof setup>;
	beforeEach(() => {
		t = setup();
	});

	const toolCall = (mailboxId: string, extraHeaders: Record<string, string> = {}) =>
		new Request("https://emails.do/mcp", {
			method: "POST",
			headers: { "Content-Type": "application/json", ...extraHeaders },
			body: JSON.stringify({
				jsonrpc: "2.0",
				id: 7,
				method: "tools/call",
				params: { name: "get_email", arguments: { mailboxId, emailId: "e1" } },
			}),
		});

	it("denies tools/call on another user's mailbox before reaching the DO", async () => {
		const out = await gateMcpRequest(toolCall("bob@x.com"), t.env as never, ALICE);
		expect(out).toBeInstanceOf(Response);
		const res = out as Response;
		expect(res.status).toBe(403);
		expect(((await res.json()) as { id: number }).id).toBe(7);
	});

	it("denies batched calls when any message targets a foreign mailbox", async () => {
		const req = new Request("https://emails.do/mcp", {
			method: "POST",
			body: JSON.stringify([
				{ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_emails", arguments: { mailboxId: "alice@x.com" } } },
				{ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "list_emails", arguments: { mailboxId: "bob@x.com" } } },
			]),
		});
		expect(await gateMcpRequest(req, t.env as never, ALICE)).toBeInstanceOf(Response);
	});

	it("forwards allowed calls with the verified principal, replacing any spoofed header", async () => {
		const spoofed = toolCall("bob@x.com", { [PRINCIPAL_HEADER]: JSON.stringify(ADMIN) });
		const out = await gateMcpRequest(spoofed, t.env as never, BOB);
		expect(out).toBeInstanceOf(Request);
		const fwd = out as Request;
		expect(JSON.parse(fwd.headers.get(PRINCIPAL_HEADER)!)).toEqual(BOB);
		expect(JSON.parse(await fwd.text()).params.arguments.mailboxId).toBe("bob@x.com");

		// The same spoof does not unlock someone else's mailbox.
		const denied = await gateMcpRequest(
			toolCall("legacy@x.com", { [PRINCIPAL_HEADER]: JSON.stringify(ADMIN) }),
			t.env as never,
			BOB,
		);
		expect(denied).toBeInstanceOf(Response);
	});

	it("rejects an unauthenticated MCP request", async () => {
		const out = await gateMcpRequest(toolCall("bob@x.com"), t.env as never, undefined);
		expect((out as Response).status).toBe(401);
	});
});

describe("agent gate (/agents/*)", () => {
	let t: ReturnType<typeof setup>;
	beforeEach(() => {
		t = setup();
	});
	const req = (path: string) => new Request(`https://emails.do${path}`);

	it("denies another user's mailbox agent and allows the owner's", async () => {
		expect((await gateAgentRequest(req("/agents/email-agent/bob@x.com"), t.env as never, ALICE))?.status).toBe(404);
		expect(await gateAgentRequest(req("/agents/email-agent/bob@x.com/get-messages"), t.env as never, BOB)).toBeNull();
	});

	it("never exposes other agent namespaces (MCP sessions, mailbox DOs)", async () => {
		for (const path of ["/agents/email-mcp/streamable-http:abc", "/agents/mailbox/bob@x.com"]) {
			expect((await gateAgentRequest(req(path), t.env as never, ADMIN))?.status, path).toBe(404);
		}
	});
});

describe("principal extraction", () => {
	it("drops an email the IdP marks unverified", () => {
		expect(principalFromClaims({ sub: "s", email: "Bob@X.com", email_verified: false })).toEqual({ sub: "s" });
		expect(principalFromClaims({ sub: "s", email: "Bob@X.com" })).toEqual({ sub: "s" });
		expect(principalFromClaims({ sub: "s", email: "Bob@X.com", email_verified: true })).toEqual({ sub: "s", email: "bob@x.com" });
	});
});
