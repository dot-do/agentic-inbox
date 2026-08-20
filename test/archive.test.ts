// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Unit tests for the agents@ archive (workers/lib/archive.ts) and its wiring
 * into the outbound chokepoint (workers/email-sender.ts sendVia).
 *
 * These run in plain vitest/node with mocked bindings (EMAIL, MAILBOX, BUCKET)
 * — no workerd needed. The inbound wiring in storeInboundEmail is a thin
 * waitUntil+catch call into archiveInboundCopy, which is covered directly
 * here (importing workers/index.ts would drag in the agents SDK runtime).
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	archiveEnabled,
	archiveAddress,
	archiveOutboundCopy,
	archiveInboundCopy,
	DEFAULT_ARCHIVE_ADDRESS,
	MAX_ARCHIVE_BODY_CHARS,
} from "../workers/lib/archive";
import { sendVia } from "../workers/email-sender";

/**
 * sendVia never awaits the journal (failure isolation: a slow archive must
 * not delay the send path) — without an opts.ctx the journal runs detached.
 * Tests flush the macrotask queue to observe its effects.
 */
const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

// -- Mock env ---------------------------------------------------------

interface CreatedEmail {
	mailbox: string;
	folder: string;
	email: Record<string, any>;
	attachments: unknown[];
}

function makeEnv(overrides: Record<string, unknown> = {}) {
	const created: CreatedEmail[] = [];
	const bucket = new Map<string, string>();
	const folderCalls: string[] = [];

	const stubFor = (mailbox: string) => ({
		createEmail: vi.fn(async (folder: string, email: Record<string, any>, attachments: unknown[]) => {
			created.push({ mailbox, folder, email, attachments });
		}),
		getFolders: vi.fn(async () => {
			folderCalls.push(mailbox);
			return [];
		}),
	});
	const stubs = new Map<string, ReturnType<typeof stubFor>>();

	const env = {
		EMAIL: { send: vi.fn(async () => ({ messageId: "provider-msg-id@example" })) },
		MAILBOX: {
			idFromName: (name: string) => name,
			get: (id: string) => {
				if (!stubs.has(id)) stubs.set(id, stubFor(id));
				return stubs.get(id)!;
			},
		},
		BUCKET: {
			head: vi.fn(async (key: string) => (bucket.has(key) ? {} : null)),
			put: vi.fn(async (key: string, value: string) => void bucket.set(key, value)),
		},
		ARCHIVE_ADDRESS: "agents@do.industries",
		ARCHIVE_ENABLED: true,
		...overrides,
	} as any;

	return { env, created, bucket, stubs, folderCalls };
}

const outParams = () => ({
	to: "alice@example.com",
	from: "bob@emails.do",
	subject: "hello",
	html: "<p>hi</p>",
});

const inboundMsg = () => ({
	to: ["bob@emails.do"],
	from: "alice@example.com",
	subject: "inbound hello",
	text: "hi there",
	messageId: "<orig-123@example.com>",
	rawHeaders: [{ key: "from", value: "alice@example.com" }],
});

beforeEach(() => {
	vi.restoreAllMocks();
});

// -- Config accessors -------------------------------------------------

describe("config accessors", () => {
	it("defaults on and to agents@do.industries", () => {
		const { env } = makeEnv({ ARCHIVE_ADDRESS: undefined, ARCHIVE_ENABLED: undefined });
		expect(archiveEnabled(env)).toBe(true);
		expect(archiveAddress(env)).toBe(DEFAULT_ARCHIVE_ADDRESS);
	});

	it("honors ARCHIVE_ENABLED=false (boolean and string forms)", () => {
		expect(archiveEnabled(makeEnv({ ARCHIVE_ENABLED: false }).env)).toBe(false);
		expect(archiveEnabled(makeEnv({ ARCHIVE_ENABLED: "false" }).env)).toBe(false);
		expect(archiveEnabled(makeEnv({ ARCHIVE_ENABLED: "0" }).env)).toBe(false);
		expect(archiveEnabled(makeEnv({ ARCHIVE_ENABLED: "true" }).env)).toBe(true);
	});
});

// -- Outbound journal via sendVia (the chokepoint) --------------------

describe("outbound archived (sendVia local path)", () => {
	it("files a tagged journal copy after a successful local send", async () => {
		const { env, created } = makeEnv();
		const result = await sendVia(env, outParams());
		expect(result.messageId).toBe("provider-msg-id@example");
		expect(env.EMAIL.send).toHaveBeenCalledTimes(1);
		await flush(); // journal is detached — settle it before asserting

		expect(created).toHaveLength(1);
		const rec = created[0];
		expect(rec.mailbox).toBe("agents@do.industries");
		expect(rec.folder).toBe("inbox");
		expect(rec.attachments).toEqual([]); // never duplicate bytes
		const headers = JSON.parse(rec.email.raw_headers);
		expect(headers).toContainEqual({ key: "x-ledger-copy", value: "outbound" });
		expect(headers).toContainEqual({ key: "x-original-message-id", value: "<provider-msg-id@example>" });
		expect(rec.email.message_id).toBe("provider-msg-id@example");
		expect(rec.email.sender).toBe("bob@emails.do");
		expect(rec.email.recipient).toBe("alice@example.com");
		expect(rec.email.subject).toBe("hello");
		expect(rec.email.body).toBe("<p>hi</p>");
	});

	it("auto-creates the archive mailbox on first write", async () => {
		const { env, bucket, folderCalls } = makeEnv();
		await sendVia(env, outParams());
		await flush();
		expect(bucket.has("mailboxes/agents@do.industries.json")).toBe(true);
		expect(folderCalls).toContain("agents@do.industries");
		// Second send: mailbox exists, no re-provision (single settings put).
		await sendVia(env, outParams());
		await flush();
		expect(env.BUCKET.put).toHaveBeenCalledTimes(1);
	});

	it("records attachment R2 keys as references", async () => {
		const { env, created } = makeEnv();
		const keys = ["attachments/e1/a1/file.pdf", "attachments/e1/a2/pic.png"];
		await sendVia(env, outParams(), { attachmentKeys: keys });
		await flush();
		const headers = JSON.parse(created[0].email.raw_headers);
		expect(headers).toContainEqual({ key: "x-archive-attachment-refs", value: JSON.stringify(keys) });
		expect(created[0].attachments).toEqual([]);
	});

	it("never stalls the send path on a hung archive DO (no-ctx callers)", async () => {
		// lib/tools.ts calls sendVia without ctx from agent tool handlers; a
		// hung archive write must not delay their return (a stalled tool call
		// risks an agent retry → duplicate real send).
		const { env } = makeEnv();
		env.MAILBOX.get = () => ({
			createEmail: vi.fn(() => new Promise(() => {})), // never settles
			getFolders: vi.fn(async () => []),
		});
		const result = await Promise.race([
			sendVia(env, outParams()),
			new Promise<"stalled">((resolve) => setTimeout(() => resolve("stalled"), 250)),
		]);
		expect(result).toEqual({ messageId: "provider-msg-id@example" });
	});

	it("truncates oversized bodies and tags the record", async () => {
		const { env, created } = makeEnv();
		const hugeBody = "x".repeat(MAX_ARCHIVE_BODY_CHARS + 1000);
		const outcome = await archiveOutboundCopy(env, { ...outParams(), html: hugeBody }, "m1");
		expect(outcome).toBe("archived");
		expect(created[0].email.body.length).toBeLessThan(hugeBody.length);
		expect(created[0].email.body.endsWith("[archive: body truncated]")).toBe(true);
		const headers = JSON.parse(created[0].email.raw_headers);
		expect(headers).toContainEqual({ key: "x-archive-truncated", value: String(hugeBody.length) });
	});

	it("rides ctx.waitUntil when an ExecutionContext is provided", async () => {
		const { env, created } = makeEnv();
		const waited: Promise<unknown>[] = [];
		const ctx = { waitUntil: (p: Promise<unknown>) => waited.push(p) } as any;
		await sendVia(env, outParams(), { ctx });
		expect(waited).toHaveLength(1);
		await Promise.all(waited);
		expect(created).toHaveLength(1);
	});
});

describe("outbound archived (sendVia relay path)", () => {
	it("journals relayed sends too", async () => {
		const { env, created } = makeEnv({
			EMAIL_RELAYS: JSON.stringify({ "longtail.studio": "https://relay.longtail.studio" }),
			RELAY_SECRET: "test-secret-value-not-real",
		});
		const fetchMock = vi.fn(async () =>
			new Response(JSON.stringify({ messageId: "relay-msg-id@longtail" }), { status: 200 }),
		);
		vi.stubGlobal("fetch", fetchMock);
		try {
			const result = await sendVia(env, { ...outParams(), from: "domains@longtail.studio" });
			expect(result.messageId).toBe("relay-msg-id@longtail");
			expect(fetchMock).toHaveBeenCalledTimes(1);
			expect(env.EMAIL.send).not.toHaveBeenCalled();
			await flush();
			expect(created).toHaveLength(1);
			const headers = JSON.parse(created[0].email.raw_headers);
			expect(headers).toContainEqual({ key: "x-ledger-copy", value: "outbound" });
			expect(created[0].email.sender).toBe("domains@longtail.studio");
		} finally {
			vi.unstubAllGlobals();
		}
	});
});

// -- Inbound copy -----------------------------------------------------

describe("inbound archived", () => {
	it("files a tagged inbound copy with delivered-to and original message-id", async () => {
		const { env, created } = makeEnv();
		const outcome = await archiveInboundCopy(env, inboundMsg(), "bob@emails.do", ["attachments/e9/a1/x.txt"]);
		expect(outcome).toBe("archived");
		expect(created).toHaveLength(1);
		const rec = created[0];
		expect(rec.mailbox).toBe("agents@do.industries");
		expect(rec.folder).toBe("inbox");
		const headers = JSON.parse(rec.email.raw_headers);
		expect(headers).toContainEqual({ key: "x-ledger-copy", value: "inbound" });
		expect(headers).toContainEqual({ key: "x-delivered-to", value: "bob@emails.do" });
		expect(headers).toContainEqual({ key: "x-original-message-id", value: "<orig-123@example.com>" });
		expect(headers).toContainEqual({ key: "x-archive-attachment-refs", value: JSON.stringify(["attachments/e9/a1/x.txt"]) });
		expect(rec.email.message_id).toBe("orig-123@example.com");
		expect(rec.email.body).toBe("hi there");
	});
});

// -- Loop guards ------------------------------------------------------

describe("loop guards", () => {
	it("never archives a send already bearing X-Ledger-Copy (any case)", async () => {
		const { env, created } = makeEnv();
		expect(await archiveOutboundCopy(env, { ...outParams(), headers: { "X-Ledger-Copy": "outbound" } }, "m1"))
			.toBe("skipped:ledger-copy");
		expect(await archiveOutboundCopy(env, { ...outParams(), headers: { "x-ledger-copy": "outbound" } }, "m2"))
			.toBe("skipped:ledger-copy");
		expect(created).toHaveLength(0);
	});

	it("never archives the archive mailbox's own sends", async () => {
		const { env, created } = makeEnv();
		expect(await archiveOutboundCopy(env, { ...outParams(), from: "Agents <agents@do.industries>" }, "m1"))
			.toBe("skipped:from-archive");
		expect(created).toHaveLength(0);
	});

	it("never archives mail addressed to the archive address (to/cc/bcc)", async () => {
		const { env, created } = makeEnv();
		expect(await archiveOutboundCopy(env, { ...outParams(), to: ["agents@do.industries"] }, "m1"))
			.toBe("skipped:to-archive");
		expect(await archiveOutboundCopy(env, { ...outParams(), cc: "agents@do.industries" }, "m2"))
			.toBe("skipped:to-archive");
		expect(await archiveOutboundCopy(env, { ...outParams(), bcc: ["x@y.z", "Agents <agents@do.industries>"] }, "m3"))
			.toBe("skipped:to-archive");
		expect(created).toHaveLength(0);
	});

	it("never archives inbound already bearing X-Ledger-Copy", async () => {
		const { env, created } = makeEnv();
		const msg = { ...inboundMsg(), rawHeaders: [{ key: "X-Ledger-Copy", value: "inbound" }] };
		expect(await archiveInboundCopy(env, msg, "bob@emails.do")).toBe("skipped:ledger-copy");
		expect(created).toHaveLength(0);
	});

	it("never archives inbound delivered into the archive mailbox itself", async () => {
		const { env, created } = makeEnv();
		expect(await archiveInboundCopy(env, inboundMsg(), "agents@do.industries")).toBe("skipped:archive-mailbox");
		expect(created).toHaveLength(0);
	});

	it("never archives inbound from or addressed to the archive address", async () => {
		const { env, created } = makeEnv();
		expect(await archiveInboundCopy(env, { ...inboundMsg(), from: "agents@do.industries" }, "bob@emails.do"))
			.toBe("skipped:from-archive");
		expect(await archiveInboundCopy(env, { ...inboundMsg(), to: ["bob@emails.do", "agents@do.industries"] }, "bob@emails.do"))
			.toBe("skipped:to-archive");
		expect(created).toHaveLength(0);
	});

	it("skips everything when ARCHIVE_ENABLED=false", async () => {
		const { env, created } = makeEnv({ ARCHIVE_ENABLED: false });
		expect(await archiveOutboundCopy(env, outParams(), "m1")).toBe("skipped:disabled");
		expect(await archiveInboundCopy(env, inboundMsg(), "bob@emails.do")).toBe("skipped:disabled");
		await sendVia(env, outParams()); // journal path also no-ops
		await flush();
		expect(created).toHaveLength(0);
	});
});

// -- Failure isolation ------------------------------------------------

describe("archive failure does not fail the send", () => {
	it("sendVia resolves normally when the archive DO write throws", async () => {
		const { env } = makeEnv();
		env.MAILBOX.get = () => ({
			createEmail: vi.fn(async () => { throw new Error("DO exploded"); }),
			getFolders: vi.fn(async () => []),
		});
		const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		const result = await sendVia(env, outParams());
		expect(result.messageId).toBe("provider-msg-id@example");
		expect(env.EMAIL.send).toHaveBeenCalledTimes(1);
		await flush();
		expect(errSpy).toHaveBeenCalledWith(
			expect.stringContaining("Outbound archive write failed"),
			expect.any(String),
		);
	});

	it("sendVia resolves normally when archive provisioning (R2) throws", async () => {
		const { env } = makeEnv();
		env.BUCKET.head = vi.fn(async () => { throw new Error("R2 down"); });
		const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		const result = await sendVia(env, outParams());
		expect(result.messageId).toBe("provider-msg-id@example");
		await flush();
		expect(errSpy).toHaveBeenCalled();
	});

	it("waitUntil journal failures are contained (promise never rejects)", async () => {
		const { env } = makeEnv();
		env.MAILBOX.get = () => ({
			createEmail: vi.fn(async () => { throw new Error("DO exploded"); }),
			getFolders: vi.fn(async () => []),
		});
		vi.spyOn(console, "error").mockImplementation(() => {});
		const waited: Promise<unknown>[] = [];
		const ctx = { waitUntil: (p: Promise<unknown>) => waited.push(p) } as any;
		await sendVia(env, outParams(), { ctx });
		await expect(Promise.all(waited)).resolves.toBeDefined();
	});

	it("archiveInboundCopy rejections are for the caller's catch — direct call rejects, wired call is caught", async () => {
		const { env } = makeEnv();
		env.MAILBOX.get = () => ({
			createEmail: vi.fn(async () => { throw new Error("DO exploded"); }),
			getFolders: vi.fn(async () => []),
		});
		// Direct call rejects (by design)...
		await expect(archiveInboundCopy(env, inboundMsg(), "bob@emails.do")).rejects.toThrow("DO exploded");
		// ...and the storeInboundEmail wiring pattern (catch + log) contains it.
		const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		await expect(
			archiveInboundCopy(env, inboundMsg(), "bob@emails.do")
				.catch((e) => console.error("Inbound archive write failed (delivery unaffected):", (e as Error).message)),
		).resolves.toBeUndefined();
		expect(errSpy).toHaveBeenCalled();
	});
});
