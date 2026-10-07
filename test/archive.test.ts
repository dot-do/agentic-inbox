// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Unit tests for the estate email ledger (workers/lib/archive.ts) and its
 * wiring into the outbound chokepoint (workers/email-sender.ts sendVia).
 *
 * Founder ruling 2026-08-20: every ledgered message produces TWO artifacts —
 *  1. a REAL journal email delivered to ARCHIVE_ADDRESS (agents@do.industries,
 *     the Google Workspace mailbox) from the LEDGER_ADDRESS sender, and
 *  2. a queryable index record in the ledger DO (named ledger@emails.do).
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
	ledgerAddress,
	archiveOutboundCopy,
	archiveInboundCopy,
	DEFAULT_ARCHIVE_ADDRESS,
	DEFAULT_LEDGER_ADDRESS,
	MAX_ARCHIVE_BODY_CHARS,
} from "../workers/lib/archive";
import { sendVia } from "../workers/email-sender";

/**
 * sendVia never awaits the journal (failure isolation: a slow ledger must
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
	const sent: Record<string, any>[] = []; // every env.EMAIL.send message

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
		EMAIL: {
			send: vi.fn(async (message: Record<string, any>) => {
				sent.push(message);
				return { messageId: "provider-msg-id@example" };
			}),
		},
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
		LEDGER_ADDRESS: "ledger@emails.do",
		ARCHIVE_ENABLED: true,
		...overrides,
	} as any;

	/** Journal emails observed on the EMAIL binding (subject-prefixed). */
	const journals = () => sent.filter((m) => typeof m.subject === "string" && m.subject.startsWith("[ledger:"));
	/** Non-journal (real) sends observed on the EMAIL binding. */
	const realSends = () => sent.filter((m) => !(typeof m.subject === "string" && m.subject.startsWith("[ledger:")));

	return { env, created, bucket, stubs, folderCalls, sent, journals, realSends };
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
	it("defaults: on, archive=agents@do.industries, ledger=ledger@emails.do", () => {
		const { env } = makeEnv({ ARCHIVE_ADDRESS: undefined, LEDGER_ADDRESS: undefined, ARCHIVE_ENABLED: undefined });
		expect(archiveEnabled(env)).toBe(true);
		expect(archiveAddress(env)).toBe(DEFAULT_ARCHIVE_ADDRESS);
		expect(ledgerAddress(env)).toBe(DEFAULT_LEDGER_ADDRESS);
		expect(DEFAULT_ARCHIVE_ADDRESS).toBe("agents@do.industries");
		expect(DEFAULT_LEDGER_ADDRESS).toBe("ledger@emails.do");
	});

	it("honors ARCHIVE_ENABLED=false (boolean and string forms)", () => {
		expect(archiveEnabled(makeEnv({ ARCHIVE_ENABLED: false }).env)).toBe(false);
		expect(archiveEnabled(makeEnv({ ARCHIVE_ENABLED: "false" }).env)).toBe(false);
		expect(archiveEnabled(makeEnv({ ARCHIVE_ENABLED: "0" }).env)).toBe(false);
		expect(archiveEnabled(makeEnv({ ARCHIVE_ENABLED: "true" }).env)).toBe(true);
	});
});

// -- Outbound ledger via sendVia (the chokepoint) ---------------------

describe("outbound ledgered (sendVia local path)", () => {
	it("delivers a [ledger:outbound] journal email to the archive from the ledger sender", async () => {
		const { env, journals, realSends } = makeEnv();
		const result = await sendVia(env, outParams());
		expect(result.messageId).toBe("provider-msg-id@example");
		await flush(); // journal is detached — settle it before asserting

		expect(realSends()).toHaveLength(1); // exactly one REAL send
		const js = journals();
		expect(js).toHaveLength(1); // exactly one journal delivery
		const j = js[0];
		expect(j.to).toBe("agents@do.industries");
		expect(j.from).toEqual({ email: "ledger@emails.do", name: "Estate Ledger" });
		expect(j.subject).toBe("[ledger:outbound] hello");
		expect(j.html).toContain("<p>hi</p>");
		expect(j.headers["X-Ledger-Copy"]).toBe("outbound");
		expect(j.headers["X-Original-Message-Id"]).toBe("<provider-msg-id@example>");
		expect(j.headers["X-Original-From"]).toBe("bob@emails.do");
		expect(j.headers["X-Original-To"]).toBe("alice@example.com");
	});

	it("indexes the same message in the ledger DO under the LEDGER identity", async () => {
		const { env, created } = makeEnv();
		await sendVia(env, outParams());
		await flush();

		expect(created).toHaveLength(1);
		const rec = created[0];
		expect(rec.mailbox).toBe("ledger@emails.do"); // NOT agents@do.industries
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

	it("auto-creates the ledger index mailbox (ledger@emails.do) on first write", async () => {
		const { env, bucket, folderCalls } = makeEnv();
		await sendVia(env, outParams());
		await flush();
		expect(bucket.has("mailboxes/ledger@emails.do.json")).toBe(true);
		expect(bucket.has("mailboxes/agents@do.industries.json")).toBe(false); // no collision mailbox
		expect(folderCalls).toContain("ledger@emails.do");
		// Second send: mailbox exists, no re-provision (single settings put).
		await sendVia(env, outParams());
		await flush();
		expect(env.BUCKET.put).toHaveBeenCalledTimes(1);
	});

	it("renders attachments as reference links in the journal email, keys in the index", async () => {
		const { env, created, journals } = makeEnv();
		const keys = ["attachments/e1/a1/file.pdf", "attachments/e1/a2/pic.png"];
		await sendVia(env, outParams(), { attachmentKeys: keys });
		await flush();
		// Journal email: links, never re-attached bytes.
		const j = journals()[0];
		expect(j.attachments).toBeUndefined();
		expect(j.html).toContain("2 attachment(s) by reference");
		expect(j.html).toContain("attachments/e1/a1/file.pdf");
		expect(j.html).toContain("https://emails.do/api/v1/mailboxes/bob%40emails.do/emails/e1/attachments/a1");
		// DO index: R2 keys as raw-header refs.
		const headers = JSON.parse(created[0].email.raw_headers);
		expect(headers).toContainEqual({ key: "x-archive-attachment-refs", value: JSON.stringify(keys) });
		expect(created[0].attachments).toEqual([]);
	});

	it("never stalls the send path on a hung ledger DO (no-ctx callers)", async () => {
		// lib/tools.ts calls sendVia without ctx from agent tool handlers; a
		// hung ledger write must not delay their return (a stalled tool call
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

	it("truncates oversized bodies in both legs and tags the index record", async () => {
		const { env, created, journals } = makeEnv();
		const hugeBody = "x".repeat(MAX_ARCHIVE_BODY_CHARS + 1000);
		const outcome = await archiveOutboundCopy(env, { ...outParams(), html: hugeBody }, "m1");
		expect(outcome).toBe("archived");
		expect(created[0].email.body.length).toBeLessThan(hugeBody.length);
		expect(created[0].email.body.endsWith("[archive: body truncated]")).toBe(true);
		const headers = JSON.parse(created[0].email.raw_headers);
		expect(headers).toContainEqual({ key: "x-archive-truncated", value: String(hugeBody.length) });
		expect(journals()[0].html.length).toBeLessThan(hugeBody.length + 1000);
	});

	it("rides ctx.waitUntil when an ExecutionContext is provided", async () => {
		const { env, created, journals } = makeEnv();
		const waited: Promise<unknown>[] = [];
		const ctx = { waitUntil: (p: Promise<unknown>) => waited.push(p) } as any;
		await sendVia(env, outParams(), { ctx });
		expect(waited).toHaveLength(1);
		await Promise.all(waited);
		expect(created).toHaveLength(1);
		expect(journals()).toHaveLength(1);
	});
});

describe("outbound ledgered (sendVia relay path)", () => {
	it("journals relayed sends too — journal email goes out via the LOCAL binding", async () => {
		const { env, created, journals } = makeEnv({
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
			expect(fetchMock).toHaveBeenCalledTimes(1); // real send via relay
			await flush();
			// The journal email is a LOCAL env.EMAIL send (ledger@emails.do is local).
			const js = journals();
			expect(js).toHaveLength(1);
			expect(js[0].to).toBe("agents@do.industries");
			expect(js[0].subject).toBe("[ledger:outbound] hello");
			expect(js[0].headers["X-Original-Message-Id"]).toBe("<relay-msg-id@longtail>");
			expect(created).toHaveLength(1);
			const headers = JSON.parse(created[0].email.raw_headers);
			expect(headers).toContainEqual({ key: "x-ledger-copy", value: "outbound" });
			expect(created[0].email.sender).toBe("domains@longtail.studio");
			expect(created[0].mailbox).toBe("ledger@emails.do");
		} finally {
			vi.unstubAllGlobals();
		}
	});
});

// -- Inbound ledger ---------------------------------------------------

describe("inbound ledgered", () => {
	it("delivers a [ledger:inbound] journal email and indexes with delivered-to + original message-id", async () => {
		const { env, created, journals } = makeEnv();
		const outcome = await archiveInboundCopy(env, inboundMsg(), "bob@emails.do", ["attachments/e9/a1/x.txt"]);
		expect(outcome).toBe("archived");

		// Leg 1: journal email delivered to the archive.
		const js = journals();
		expect(js).toHaveLength(1);
		const j = js[0];
		expect(j.to).toBe("agents@do.industries");
		expect(j.from).toEqual({ email: "ledger@emails.do", name: "Estate Ledger" });
		expect(j.subject).toBe("[ledger:inbound] inbound hello");
		expect(j.text).toContain("hi there");
		expect(j.text).toContain("attachments/e9/a1/x.txt"); // refs, not re-attached
		expect(j.attachments).toBeUndefined();
		expect(j.headers["X-Ledger-Copy"]).toBe("inbound");
		expect(j.headers["X-Original-Message-Id"]).toBe("<orig-123@example.com>");
		expect(j.headers["X-Original-From"]).toBe("alice@example.com");
		expect(j.headers["X-Original-To"]).toBe("bob@emails.do");
		expect(j.headers["X-Delivered-To"]).toBe("bob@emails.do");

		// Leg 2: DO index under the ledger identity.
		expect(created).toHaveLength(1);
		const rec = created[0];
		expect(rec.mailbox).toBe("ledger@emails.do");
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

describe("loop guards (never journal a journal)", () => {
	it("never ledgers a send already bearing X-Ledger-Copy (any case)", async () => {
		const { env, created, journals } = makeEnv();
		expect(await archiveOutboundCopy(env, { ...outParams(), headers: { "X-Ledger-Copy": "outbound" } }, "m1"))
			.toBe("skipped:ledger-copy");
		expect(await archiveOutboundCopy(env, { ...outParams(), headers: { "x-ledger-copy": "outbound" } }, "m2"))
			.toBe("skipped:ledger-copy");
		expect(created).toHaveLength(0);
		expect(journals()).toHaveLength(0);
	});

	it("never ledgers sends FROM the ledger sender (the journal identity)", async () => {
		const { env, created, journals } = makeEnv();
		expect(await archiveOutboundCopy(env, { ...outParams(), from: "ledger@emails.do" }, "m1"))
			.toBe("skipped:from-ledger");
		expect(await archiveOutboundCopy(env, { ...outParams(), from: "Estate Ledger <ledger@emails.do>" }, "m2"))
			.toBe("skipped:from-ledger");
		expect(created).toHaveLength(0);
		expect(journals()).toHaveLength(0);
	});

	it("a journal send replayed through sendVia is skipped (belt: header; braces: ledger sender)", async () => {
		// The journal is sent via env.EMAIL.send directly, so it cannot recurse;
		// but even if one were replayed through sendVia, BOTH the ledger sender
		// guard and the X-Ledger-Copy header guard stop it.
		const { env, created, journals, realSends } = makeEnv();
		await sendVia(env, {
			to: "agents@do.industries",
			from: "ledger@emails.do",
			subject: "[ledger:outbound] hello",
			html: "<p>hi</p>",
			headers: { "X-Ledger-Copy": "outbound" },
		});
		await flush();
		expect(realSends()).toHaveLength(0); // the replayed send IS itself journal-shaped
		expect(journals()).toHaveLength(1); // only the message itself — no second-order journal
		expect(created).toHaveLength(0);
	});

	it("never ledgers the archive mailbox's own sends", async () => {
		const { env, created, journals } = makeEnv();
		expect(await archiveOutboundCopy(env, { ...outParams(), from: "Agents <agents@do.industries>" }, "m1"))
			.toBe("skipped:from-archive");
		expect(created).toHaveLength(0);
		expect(journals()).toHaveLength(0);
	});

	it("never ledgers mail addressed to the archive or ledger address (to/cc/bcc)", async () => {
		const { env, created, journals } = makeEnv();
		expect(await archiveOutboundCopy(env, { ...outParams(), to: ["agents@do.industries"] }, "m1"))
			.toBe("skipped:to-archive");
		expect(await archiveOutboundCopy(env, { ...outParams(), cc: "agents@do.industries" }, "m2"))
			.toBe("skipped:to-archive");
		expect(await archiveOutboundCopy(env, { ...outParams(), bcc: ["x@y.z", "Agents <agents@do.industries>"] }, "m3"))
			.toBe("skipped:to-archive");
		expect(await archiveOutboundCopy(env, { ...outParams(), to: ["ledger@emails.do"] }, "m4"))
			.toBe("skipped:to-ledger");
		expect(created).toHaveLength(0);
		expect(journals()).toHaveLength(0);
	});

	it("never ledgers inbound already bearing X-Ledger-Copy", async () => {
		const { env, created, journals } = makeEnv();
		const msg = { ...inboundMsg(), rawHeaders: [{ key: "X-Ledger-Copy", value: "inbound" }] };
		expect(await archiveInboundCopy(env, msg, "bob@emails.do")).toBe("skipped:ledger-copy");
		expect(created).toHaveLength(0);
		expect(journals()).toHaveLength(0);
	});

	it("never ledgers inbound delivered into the archive or ledger mailboxes", async () => {
		const { env, created, journals } = makeEnv();
		expect(await archiveInboundCopy(env, inboundMsg(), "agents@do.industries")).toBe("skipped:archive-mailbox");
		expect(await archiveInboundCopy(env, inboundMsg(), "ledger@emails.do")).toBe("skipped:ledger-mailbox");
		expect(created).toHaveLength(0);
		expect(journals()).toHaveLength(0);
	});

	it("never ledgers inbound from the ledger sender or from/to the archive address", async () => {
		const { env, created, journals } = makeEnv();
		expect(await archiveInboundCopy(env, { ...inboundMsg(), from: "agents@do.industries" }, "bob@emails.do"))
			.toBe("skipped:from-archive");
		expect(await archiveInboundCopy(env, { ...inboundMsg(), from: "ledger@emails.do" }, "bob@emails.do"))
			.toBe("skipped:from-ledger");
		expect(await archiveInboundCopy(env, { ...inboundMsg(), to: ["bob@emails.do", "agents@do.industries"] }, "bob@emails.do"))
			.toBe("skipped:to-archive");
		expect(created).toHaveLength(0);
		expect(journals()).toHaveLength(0);
	});

	it("skips everything when ARCHIVE_ENABLED=false", async () => {
		const { env, created, journals } = makeEnv({ ARCHIVE_ENABLED: false });
		expect(await archiveOutboundCopy(env, outParams(), "m1")).toBe("skipped:disabled");
		expect(await archiveInboundCopy(env, inboundMsg(), "bob@emails.do")).toBe("skipped:disabled");
		await sendVia(env, outParams()); // journal path also no-ops
		await flush();
		expect(created).toHaveLength(0);
		expect(journals()).toHaveLength(0);
	});
});

// -- Failure isolation ------------------------------------------------

describe("ledger failure does not fail the send", () => {
	it("sendVia resolves normally when the ledger DO write throws — journal email still delivered", async () => {
		const { env, journals } = makeEnv();
		const journalSend = env.EMAIL.send; // preserve mock to observe journal deliveries
		env.MAILBOX.get = () => ({
			createEmail: vi.fn(async () => { throw new Error("DO exploded"); }),
			getFolders: vi.fn(async () => []),
		});
		const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		const result = await sendVia(env, outParams());
		expect(result.messageId).toBe("provider-msg-id@example");
		await flush();
		// Legs are isolated from each other: the journal email still went out.
		expect(journals()).toHaveLength(1);
		expect(journalSend).toHaveBeenCalledTimes(2); // real + journal
		expect(errSpy).toHaveBeenCalledWith(
			expect.stringContaining("Outbound archive write failed"),
			expect.stringContaining("do-index"),
		);
	});

	it("sendVia resolves normally when the journal DELIVERY throws — DO index still written", async () => {
		const { env, created } = makeEnv();
		let calls = 0;
		env.EMAIL.send = vi.fn(async (message: Record<string, any>) => {
			calls += 1;
			if (calls === 1) return { messageId: "provider-msg-id@example" }; // the real send
			throw new Error("Email Service rejected journal"); // the journal send
		});
		const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		const result = await sendVia(env, outParams());
		expect(result.messageId).toBe("provider-msg-id@example");
		await flush();
		expect(created).toHaveLength(1); // index leg survived
		expect(errSpy).toHaveBeenCalledWith(
			expect.stringContaining("Outbound archive write failed"),
			expect.stringContaining("journal-delivery"),
		);
	});

	it("sendVia resolves normally when ledger provisioning (R2) throws", async () => {
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
