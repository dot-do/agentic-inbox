// Request gates for the two non-REST surfaces that reach mailbox data:
//
//   /mcp      — EmailMCP tools take a `mailboxId` argument.
//   /agents/* — the per-mailbox EmailAgent (chat + tools over that mailbox).
//
// Both run in the worker, after authentication, before anything is handed
// to a Durable Object. See workers/lib/access.ts for the access rules.

import type { Env } from "../types";
import {
	canAccessMailbox,
	isMailboxDeleted,
	PRINCIPAL_HEADER,
	type Principal,
} from "./access";

/** Agent namespaces reachable through /agents/*. EMAIL_MCP and MAILBOX are
 * deliberately absent: they must only be reached through their own gates. */
const ALLOWED_AGENT_NAMESPACES = new Set(["email-agent"]);

function jsonRpcError(id: unknown, message: string, status: number): Response {
	return new Response(
		JSON.stringify({ jsonrpc: "2.0", id: id ?? null, error: { code: -32003, message } }),
		{ status, headers: { "Content-Type": "application/json" } },
	);
}

/** Serialize only the identity fields — never anything a client sent. */
function encodePrincipal(p: Principal): string {
	const out: Principal = {};
	if (p.sub) out.sub = p.sub;
	if (p.email) out.email = p.email;
	if (p.dev) out.dev = true;
	return JSON.stringify(out);
}

/**
 * Gate an /mcp request. Returns a Response to send back (denied) or the
 * Request to forward to the MCP handler, which:
 *  - has any client-supplied PRINCIPAL_HEADER removed and the verified
 *    principal set in its place (the EmailMCP tools re-check access with it);
 *  - has already been checked: every JSON-RPC `tools/call` naming a
 *    `mailboxId` targets a live mailbox the principal may read.
 */
export async function gateMcpRequest(
	req: Request,
	env: Env,
	principal: Principal | undefined,
): Promise<Request | Response> {
	if (!principal) return jsonRpcError(null, "Unauthenticated", 401);

	const headers = new Headers(req.headers);
	headers.delete(PRINCIPAL_HEADER);
	headers.set(PRINCIPAL_HEADER, encodePrincipal(principal));

	let body: string | undefined;
	if (req.method !== "GET" && req.method !== "HEAD") {
		body = await req.text();
		let parsed: unknown;
		try {
			parsed = body ? JSON.parse(body) : undefined;
		} catch {
			parsed = undefined; // malformed JSON: the MCP transport rejects it
		}
		const messages = Array.isArray(parsed) ? parsed : parsed ? [parsed] : [];
		for (const msg of messages) {
			if (!msg || typeof msg !== "object") continue;
			const m = msg as { id?: unknown; method?: unknown; params?: { arguments?: Record<string, unknown> } };
			if (m.method !== "tools/call") continue;
			const mailboxId = m.params?.arguments?.mailboxId;
			if (typeof mailboxId !== "string") continue;
			const allowed =
				!(await isMailboxDeleted(env.BUCKET, mailboxId)) &&
				(await canAccessMailbox(env, principal, mailboxId));
			if (!allowed) {
				return jsonRpcError(m.id, `Mailbox "${mailboxId}" not found or not accessible`, 403);
			}
		}
	}

	return new Request(req.url, { method: req.method, headers, body });
}

/**
 * Gate an /agents/* request. Returns a Response when denied, or null to let
 * routeAgentRequest handle it. The agent's DO name is the raw path segment
 * (partyserver does not decode it), so access is checked on exactly that.
 */
export async function gateAgentRequest(
	req: Request,
	env: Env,
	principal: Principal | undefined,
): Promise<Response | null> {
	const notFound = () => new Response("Agent not found", { status: 404 });
	const parts = new URL(req.url).pathname.split("/").filter(Boolean);
	// parts: ["agents", <namespace>, <name>, ...]
	const namespace = parts[1];
	const name = parts[2];
	if (!namespace || !name || !ALLOWED_AGENT_NAMESPACES.has(namespace)) return notFound();
	if (!principal) return notFound();
	if (!(await canAccessMailbox(env, principal, name))) return notFound();
	return null;
}
