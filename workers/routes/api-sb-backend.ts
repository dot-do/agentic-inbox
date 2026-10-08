// The UI's /api/v1 mailbox routes, served from api.sb's email primitive
// instead of the MailboxDO (StartupsStudio/sb#337). Mounted ahead of the
// legacy routes in workers/app.ts when MAIL_BACKEND = "api.sb"; otherwise
// nothing here runs and emails.do behaves exactly as before.
//
// Who may read a mailbox is still emails.do's rule (admin, address holder,
// ACL owner or member: workers/lib/access.ts; the ACL objects are kept). api.sb
// is called with the caller's own id.org.ai bearer when it brought one (an
// agent, the CLI, MCP), so a send goes out as its own identity (api.sb lets only
// a Mailbox's holder send from it); a browser session falls back to
// API_SB_TOKEN, which reads but cannot send as a person (follow-up: keep the
// id.org.ai access token in the session once the sign-in fix lands).
//
// Each Mailbox is read and sent through in the namespace of the Startup that
// owns its address (lib/api-sb.ts namespaceOf; founder, 2026-10-08), never in
// one of emails.do's own: emails.do is the provider.
//
// Routes not ported yet answer 501 not_on_api_sb rather than reading the old
// store, which stops changing once mail flows to api.sb.
import { Hono, type Context } from "hono";
import type { Env } from "../types";
import { canAccessMailbox, filterAccessibleMailboxes, type Principal } from "../lib/access";
import { listMailboxes } from "../lib/email-helpers";
import { ApiSbError, ApiSbMail, SYSTEM_FOLDERS, folderOf, rowOf, type ApiSbEnv } from "../lib/api-sb";

type BackendEnv = { Bindings: Env & ApiSbEnv; Variables: { principal: Principal } };
type C = Context<BackendEnv>;

/** The principal the outer app verified, handed to this app per request. */
export const PRINCIPALS = new WeakMap<Request, Principal>();

/** `fetcher`: api.sb's fetch (tests pass a fake; production uses the global). */
export function apiSbBackend(fetcher: typeof fetch = (input, init) => fetch(input, init)) {
	const app = new Hono<BackendEnv>();
	app.use("*", async (c, next) => {
		const p = PRINCIPALS.get(c.req.raw);
		if (!p) return c.json({ error: "Forbidden" }, 403);
		c.set("principal", p);
		return next();
	});

	const client = (c: C) => {
		const bearer = c.req.header("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
		const token = bearer ?? c.env.API_SB_TOKEN;
		if (!token) throw new ApiSbError(503, "api_sb_token_missing", "API_SB_TOKEN is not set and the request carried no bearer");
		return new ApiSbMail(c.env, token, fetcher);
	};
	const gate = async (c: C) => {
		const id = c.req.param("mailboxId")!.toLowerCase();
		if (!(await canAccessMailbox(c.env, c.get("principal"), id))) throw new ApiSbError(404, "not_found", "Not found");
		const box = await client(c).mailbox(id);
		if (!box) throw new ApiSbError(404, "not_found", "Not found");
		return { id, box, api: client(c) };
	};

	app.onError((e, c) => {
		if (e instanceof ApiSbError) return c.json({ error: e.message, code: e.code }, e.status as 400);
		throw e;
	});

	app.get("/api/v1/mailboxes", async (c) => {
		// the addresses emails.do serves (its own record of them, kept); each Mailbox read from its owner's namespace
		const addresses = (await listMailboxes(c.env.BUCKET)).map((m) => m.email);
		const boxes = await client(c).mailboxes(addresses);
		const mapped = boxes.map((m) => ({ id: String(m.address), email: String(m.address), name: String(m.address) }));
		return c.json(await filterAccessibleMailboxes(c.env, c.get("principal"), mapped));
	});

	app.get("/api/v1/mailboxes/:mailboxId", async (c) => {
		const { id, box } = await gate(c);
		let settings: unknown = { fromName: box.name };
		try { if (box.settings) settings = JSON.parse(box.settings); } catch { /* kept as is */ }
		return c.json({ id, name: id, email: id, settings });
	});

	app.get("/api/v1/mailboxes/:mailboxId/folders", async (c) => {
		const { box, api } = await gate(c);
		const msgs = await api.messages(box);
		const counts = new Map<string, number>();
		for (const m of msgs) if (!m.read) counts.set(folderOf(m), (counts.get(folderOf(m)) ?? 0) + 1);
		const custom = [...new Set(msgs.map(folderOf))].filter((f) => !SYSTEM_FOLDERS.some((s) => s.id === f));
		return c.json([...SYSTEM_FOLDERS.map((f) => ({ ...f, is_deletable: 0 })), ...custom.map((f) => ({ id: f, name: f, is_deletable: 1 }))]
			.map((f) => ({ ...f, unreadCount: counts.get(f.id) ?? 0 })));
	});

	app.get("/api/v1/mailboxes/:mailboxId/emails", async (c) => {
		const { box, api } = await gate(c);
		const folder = c.req.query("folder");
		const thread = c.req.query("thread_id");
		const page = Math.max(Number(c.req.query("page") ?? 1) || 1, 1);
		const limit = Math.min(Math.max(Number(c.req.query("limit") ?? 25) || 25, 1), 100);
		const rows = (await api.messages(box, folder, thread)).map(rowOf);
		const slice = rows.slice((page - 1) * limit, page * limit);
		return folder ? c.json({ emails: slice, totalCount: rows.length }) : c.json(slice);
	});

	app.get("/api/v1/mailboxes/:mailboxId/emails/:id", async (c) => {
		const { box, api } = await gate(c);
		const m = await api.message(box, c.req.param("id"));
		if (!m || m.mailbox !== box.id || m.deletedAt) return c.json({ error: "Email not found" }, 404);
		return c.json(rowOf(m));
	});

	app.put("/api/v1/mailboxes/:mailboxId/emails/:id", async (c) => {
		const { box, api } = await gate(c);
		const m = await api.message(box, c.req.param("id"));
		if (!m || m.mailbox !== box.id) return c.json({ error: "Email not found" }, 404);
		const { read, starred } = (await c.req.json()) as { read?: boolean; starred?: boolean };
		return c.json(rowOf(await api.update(box, m.id, { ...(read !== undefined ? { read } : {}), ...(starred !== undefined ? { starred } : {}) })));
	});

	// hidden, never deleted (ADR-0005): the Message keeps its row with deletedAt
	app.delete("/api/v1/mailboxes/:mailboxId/emails/:id", async (c) => {
		const { box, api } = await gate(c);
		const m = await api.message(box, c.req.param("id"));
		if (!m || m.mailbox !== box.id || m.deletedAt) return c.json({ error: "Not found" }, 404);
		await api.update(box, m.id, { deletedAt: new Date().toISOString() });
		return c.body(null, 204);
	});

	app.post("/api/v1/mailboxes/:mailboxId/emails/:id/move", async (c) => {
		const { box, api } = await gate(c);
		const m = await api.message(box, c.req.param("id"));
		if (!m || m.mailbox !== box.id) return c.json({ error: "Email not found" }, 404);
		const { folderId } = (await c.req.json()) as { folderId: string };
		const natural = m.status === "draft" ? "draft" : m.direction === "outbound" ? "sent" : "inbox";
		await api.update(box, m.id, { labels: folderId === natural ? "" : folderId });
		return c.json({ status: "moved" });
	});

	app.post("/api/v1/mailboxes/:mailboxId/emails", async (c) => {
		const { box, api } = await gate(c);
		const b = (await c.req.json()) as { to: string | string[]; cc?: string | string[]; bcc?: string | string[]; subject: string; html?: string; text?: string };
		const m = await api.send(box, { to: b.to, ...(b.cc ? { cc: b.cc } : {}), ...(b.bcc ? { bcc: b.bcc } : {}), subject: b.subject, ...(b.html ? { html: b.html } : {}), ...(b.text ? { text: b.text } : {}) });
		return c.json({ id: m.id, status: m.status }, 202);
	});

	app.post("/api/v1/mailboxes/:mailboxId/emails/:id/reply", async (c) => {
		const { box, api } = await gate(c);
		const m = await api.message(box, c.req.param("id"));
		if (!m || m.mailbox !== box.id) return c.json({ error: "Email not found" }, 404);
		const b = (await c.req.json()) as { to?: string | string[]; cc?: string | string[]; html?: string; text?: string };
		const r = await api.reply(box, m.id, { ...(b.to ? { to: b.to } : {}), ...(b.cc ? { cc: b.cc } : {}), ...(b.html ? { html: b.html } : {}), ...(b.text ? { text: b.text } : {}) });
		return c.json({ id: r.id, status: r.status }, 202);
	});

	app.get("/api/v1/mailboxes/:mailboxId/threads/:threadId", async (c) => {
		const { box, api } = await gate(c);
		return c.json((await api.messages(box, undefined, c.req.param("threadId"))).map(rowOf).reverse());
	});

	// not ported yet: say so, never fall back to the retiring store
	const notYet = (c: C) => c.json({ error: "not on api.sb yet (StartupsStudio/sb#337 follow-up)", code: "not_on_api_sb" }, 501);
	app.post("/api/v1/mailboxes", notYet);
	app.put("/api/v1/mailboxes/:mailboxId", notYet);
	app.delete("/api/v1/mailboxes/:mailboxId", notYet);
	app.all("/api/v1/mailboxes/:mailboxId/members", notYet);
	app.post("/api/v1/mailboxes/:mailboxId/drafts", notYet);
	app.post("/api/v1/mailboxes/:mailboxId/emails/:id/forward", notYet);
	app.post("/api/v1/mailboxes/:mailboxId/threads/:threadId/read", notYet);
	app.all("/api/v1/mailboxes/:mailboxId/folders/:id", notYet);
	app.post("/api/v1/mailboxes/:mailboxId/folders", notYet);
	app.get("/api/v1/mailboxes/:mailboxId/search", notYet);
	app.get("/api/v1/mailboxes/:mailboxId/emails/:emailId/attachments/:attachmentId", notYet);

	return app;
}
