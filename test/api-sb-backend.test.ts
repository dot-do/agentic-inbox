// emails.do as a client of api.sb (StartupsStudio/sb#337): the UI's mailbox
// routes answered from api.sb's email primitive, in the emails row shape the
// React app renders. api.sb is an in-memory fake of its records surface.
import { describe, expect, it } from "vitest";
import { apiSbBackend, PRINCIPALS } from "../workers/routes/api-sb-backend";
import { folderOf, namespaceOf, rowOf } from "../workers/lib/api-sb";

type J = Record<string, any>;
const BOX = { id: "mailbox_abc123abc123", address: "support@acme.example", name: "Support", settings: JSON.stringify({ fromName: "Acme Support" }), status: "open" };

function fakeApiSb() {
	const messages: J[] = [
		{ id: "message_aaaaaaaaaaaa", mailbox: BOX.id, direction: "inbound", status: "received", from: "pat@x.example", to: BOX.address, subject: "Hello", text: "hi", receivedAt: "2026-09-01T00:00:00.000Z", thread: "conversation_t1t1t1t1t1t1" },
		{ id: "message_bbbbbbbbbbbb", mailbox: BOX.id, direction: "outbound", status: "sent", from: BOX.address, to: "pat@x.example", subject: "Re: Hello", html: "<p>yo</p>", sentAt: "2026-09-02T00:00:00.000Z", thread: "conversation_t1t1t1t1t1t1", read: true },
		{ id: "message_cccccccccccc", mailbox: BOX.id, direction: "inbound", status: "received", from: "lee@y.example", to: BOX.address, subject: "Old", text: "bye", receivedAt: "2026-08-01T00:00:00.000Z", labels: "archive", thread: "conversation_t2t2t2t2t2t2" },
		{ id: "message_dddddddddddd", mailbox: BOX.id, direction: "inbound", status: "received", from: "spam@z.example", to: BOX.address, subject: "Gone", text: "x", receivedAt: "2026-08-02T00:00:00.000Z", deletedAt: "2026-09-03T00:00:00.000Z" },
	];
	const calls: { method: string; path: string; auth: string | null; body?: J }[] = [];
	const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const u = new URL(String(input));
		const method = init?.method ?? "GET";
		const body = init?.body ? JSON.parse(String(init.body)) : undefined;
		calls.push({ method, path: u.pathname + u.search, auth: new Headers(init?.headers).get("authorization"), body });
		if (!u.pathname.startsWith("/acme.example/")) return Response.json({ error: { code: "not_address_owner" } }, { status: 403 });
		const p = u.pathname.replace(/^\/acme\.example/, "");
		if (p === "/mailboxes") return Response.json({ mailboxes: [BOX], links: {} });
		if (p === "/mailboxes/support-at-acme.example") return Response.json({ record: BOX });
		if (p === "/mailboxes/support-at-acme.example:send") {
			const m = { id: "message_eeeeeeeeeeee", mailbox: BOX.id, direction: "outbound", status: "sent", from: BOX.address, ...body };
			messages.push(m);
			return Response.json({ type: "OK", message: m }, { status: 201 });
		}
		if (p === "/messages" && method === "GET") {
			const mb = u.searchParams.get("mailbox"), th = u.searchParams.get("thread");
			return Response.json({ messages: messages.filter((m) => m.mailbox === mb && (!th || m.thread === th)), links: {} });
		}
		const one = /^\/messages\/([^/:]+)$/.exec(p);
		if (one) {
			const m = messages.find((x) => x.id === one[1]);
			if (!m) return Response.json({ error: { code: "not_found" } }, { status: 404 });
			if (method === "PATCH") Object.assign(m, body);
			return Response.json({ record: m });
		}
		return Response.json({ error: { code: "not_found" } }, { status: 404 });
	}) as typeof fetch;
	return { messages, calls, fetcher };
}

const env = {
	MAIL_BACKEND: "api.sb", API_SB_URL: "https://api.sb", API_SB_TOKEN: "service-token",
	MAILBOX_ADMINS: "admin@acme.example",
	// emails.do's own list of the addresses it serves (mailboxes/<address>.json), kept
	BUCKET: { async get() { return null; }, async head() { return null; }, async list() { return { objects: [{ key: "mailboxes/support@acme.example.json" }] }; } },
};

async function call(app: ReturnType<typeof apiSbBackend>, method: string, path: string, o: { body?: unknown; bearer?: string; who?: J } = {}) {
	const req = new Request(`https://emails.do${path}`, {
		method,
		headers: { ...(o.body !== undefined ? { "content-type": "application/json" } : {}), ...(o.bearer ? { authorization: `Bearer ${o.bearer}` } : {}) },
		...(o.body !== undefined ? { body: JSON.stringify(o.body) } : {}),
	});
	PRINCIPALS.set(req, (o.who ?? { email: "admin@acme.example" }) as never);
	const r = await app.fetch(req, env as never);
	return { status: r.status, body: r.status === 204 ? null : ((await r.json()) as J) };
}

describe("emails.do reads and sends through api.sb", () => {
	it("lists the Mailboxes api.sb holds, as the UI's mailbox list", async () => {
		const { fetcher, calls } = fakeApiSb();
		const r = await call(apiSbBackend(fetcher), "GET", "/api/v1/mailboxes");
		expect(r.body).toEqual([{ id: "support@acme.example", email: "support@acme.example", name: "support@acme.example" }]);
		expect(calls[0]!.auth).toBe("Bearer service-token");
	});

	it("shows a folder as a saved query over Messages, hidden ones never", async () => {
		const { fetcher } = fakeApiSb();
		const app = apiSbBackend(fetcher);
		const inbox = await call(app, "GET", "/api/v1/mailboxes/support@acme.example/emails?folder=inbox");
		expect(inbox.body).toMatchObject({ totalCount: 1, emails: [{ id: "message_aaaaaaaaaaaa", folder_id: "inbox", sender: "pat@x.example", body: "hi", read: 0 }] });
		const sent = await call(app, "GET", "/api/v1/mailboxes/support@acme.example/emails?folder=sent");
		expect(sent.body.emails.map((e: J) => [e.id, e.body, e.read])).toEqual([["message_bbbbbbbbbbbb", "<p>yo</p>", 1]]);
		const archive = await call(app, "GET", "/api/v1/mailboxes/support@acme.example/emails?folder=archive");
		expect(archive.body.totalCount).toBe(1);
		const thread = await call(app, "GET", "/api/v1/mailboxes/support@acme.example/threads/conversation_t1t1t1t1t1t1");
		expect(thread.body.map((e: J) => e.id)).toEqual(["message_aaaaaaaaaaaa", "message_bbbbbbbbbbbb"]);
	});

	it("marks read, moves and hides by PATCH on the Message, never a delete", async () => {
		const { fetcher, messages, calls } = fakeApiSb();
		const app = apiSbBackend(fetcher);
		expect((await call(app, "PUT", "/api/v1/mailboxes/support@acme.example/emails/message_aaaaaaaaaaaa", { body: { read: true } })).body.read).toBe(1);
		expect((await call(app, "POST", "/api/v1/mailboxes/support@acme.example/emails/message_aaaaaaaaaaaa/move", { body: { folderId: "archive" } })).status).toBe(200);
		expect(messages[0]!.labels).toBe("archive");
		expect((await call(app, "DELETE", "/api/v1/mailboxes/support@acme.example/emails/message_aaaaaaaaaaaa")).status).toBe(204);
		expect(messages[0]!.deletedAt).toEqual(expect.any(String));
		expect(calls.some((c) => c.method === "DELETE")).toBe(false);
	});

	it("sends through the Mailbox's :send with the caller's own bearer", async () => {
		const { fetcher, calls } = fakeApiSb();
		const r = await call(apiSbBackend(fetcher), "POST", "/api/v1/mailboxes/support@acme.example/emails", { bearer: "agent-token", body: { to: "pat@x.example", from: "support@acme.example", subject: "Hi", text: "Hello" } });
		expect(r.status).toBe(202);
		const send = calls.find((c) => c.path.endsWith(":send"))!;
		expect(send).toMatchObject({ method: "POST", auth: "Bearer agent-token", body: { to: "pat@x.example", subject: "Hi", text: "Hello" } });
	});

	it("keeps emails.do's per-mailbox access: a stranger sees nothing", async () => {
		const { fetcher } = fakeApiSb();
		const app = apiSbBackend(fetcher);
		const who = { email: "stranger@else.example" };
		expect((await call(app, "GET", "/api/v1/mailboxes", { who })).body).toEqual([]);
		expect((await call(app, "GET", "/api/v1/mailboxes/support@acme.example/emails?folder=inbox", { who })).status).toBe(404);
	});

	it("maps a Message to the emails row the UI renders", () => {
		expect(folderOf({ direction: "inbound", labels: "spam" })).toBe("spam");
		expect(folderOf({ direction: "outbound", status: "draft" })).toBe("draft");
		expect(rowOf({ id: "m", direction: "inbound", from: "a@b.c", to: "d@e.f", references: "r1 r2", text: "t", receivedAt: "2026-01-01T00:00:00.000Z" }))
			.toMatchObject({ id: "m", folder_id: "inbox", sender: "a@b.c", recipient: "d@e.f", email_references: '["r1","r2"]', body: "t", date: "2026-01-01T00:00:00.000Z" });
	});

	it("reads each Mailbox in the namespace of the Startup that owns its address, never emails.do's", async () => {
		const { fetcher, calls } = fakeApiSb();
		const app = apiSbBackend(fetcher);
		await call(app, "GET", "/api/v1/mailboxes");
		await call(app, "GET", "/api/v1/mailboxes/support@acme.example/emails?folder=inbox");
		await call(app, "POST", "/api/v1/mailboxes/support@acme.example/emails", { bearer: "agent-token", body: { to: "pat@x.example", subject: "Hi", text: "Hello" } });
		expect(calls.length).toBeGreaterThan(2);
		expect(calls.every((c) => c.path.startsWith("/acme.example/"))).toBe(true);
	});

	it("names the owner from the address: the Studio's names, else the Domain; the map wins", () => {
		expect(namespaceOf("team@startups.studio")).toBe("startups.studio");
		expect(namespaceOf("ops@api.sb")).toBe("startups.studio");
		expect(namespaceOf("Support@Mail.Acme.example")).toBe("acme.example");
		expect(namespaceOf("ledger@emails.do")).toBe("emails.do");
		expect(namespaceOf("hi@acme.co.uk", { API_SB_NAMESPACES: JSON.stringify({ "acme.co.uk": "acme.co.uk" }) })).toBe("acme.co.uk");
		expect(namespaceOf("hi@door.example", { API_SB_NAMESPACES: JSON.stringify({ "hi@door.example": "acme.example" }) })).toBe("acme.example");
	});
});
