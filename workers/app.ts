// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { routeAgentRequest } from "agents";
import { type Context, Hono } from "hono";
import { createRequestHandler } from "react-router";
import { app as apiApp, receiveEmail } from "./index";
import {
	authenticate,
	handleAuthCallback,
	handleLogin,
	handleLogout,
	isPublicAuthPath,
	redirectToCanonicalOrigin,
} from "./lib/auth";
import { EmailMCP } from "./mcp";
import type { Env } from "./types";
import type { Principal } from "./lib/access";
import { gateAgentRequest, gateMcpRequest } from "./lib/gates";

export { MailboxDO } from "./durableObject";
export { EmailAgent } from "./agent";
export { EmailMCP } from "./mcp";

declare module "react-router" {
	export interface AppLoadContext {
		cloudflare: {
			env: Env;
			ctx: ExecutionContext;
		};
	}
}

const requestHandler = createRequestHandler(
	() => import("virtual:react-router/server-build"),
	import.meta.env.MODE,
);

// Main app that wraps the API and adds React Router fallback
type AppEnv = { Bindings: Env; Variables: { principal: Principal } };
const app = new Hono<AppEnv>();

// Authentication middleware (production only). The actual verification lives
// in ./lib/auth and dispatches on env.AUTH_MODE: "cf-access" (default, the
// pre-existing Cloudflare Access JWT check) or "id.org.ai" (OIDC sessions for
// browsers, bearer-token verification for API/MCP/agents).
//
// Authorization: the verified principal is stored on the context and every
// mailbox read path checks it (workers/lib/access.ts — owner, granted
// members, MAILBOX_ADMINS allowlist; deny by default). The API routes use
// requireMailbox; /mcp and /agents/* are gated below.
app.use("*", async (c, next) => {
	// Skip validation in development (local dev acts as an admin)
	if (import.meta.env.DEV) {
		c.set("principal", { dev: true });
		return next();
	}

	// The server-to-server HMAC endpoints below carry no cookies and no
	// redirect_uri, so they are left on whatever origin the caller used.
	const serverToServer = c.req.path === "/api/v1/ingest" || c.req.path === "/api/v1/_admin/read";

	// Move browsers to the canonical origin (https, no trailing-dot host)
	// before anything else: a sign-in started on http://emails.do sends an
	// unregistered redirect_uri to id.org.ai (400 "Invalid redirect_uri") and
	// cannot keep its Secure cookies. See canonicalOrigin in ./lib/auth.
	if (!serverToServer) {
		const upgrade = redirectToCanonicalOrigin(c.req.raw);
		if (upgrade) return upgrade;
	}

	// The login-bootstrap routes (/auth/login, /auth/callback, /auth/logout)
	// must stay reachable for unauthenticated users, or nobody could ever
	// sign in. Everything else — including /mcp and the SPA — stays gated.
	if (isPublicAuthPath(c.req.path)) {
		return next();
	}

	// The relay ingest endpoint (POST /api/v1/ingest) is server-to-server: it
	// carries no browser session and no id.org.ai bearer. It is exempt from
	// this middleware and instead authenticated by the RELAY_SECRET HMAC that
	// its own handler verifies over the raw body (workers/lib/relay-hmac.ts).
	if (c.req.path === "/api/v1/ingest") {
		return next();
	}

	// Server-to-server admin read (POST /api/v1/_admin/read), HMAC-authed by its
	// own handler over the raw body — same RELAY_SECRET trust as ingest. Lets an
	// operator pull recent mail out of a mailbox without the browser/OIDC session.
	if (c.req.path === "/api/v1/_admin/read") {
		return next();
	}

	const r = await authenticate(c, c.env);
	if (!r.ok) {
		return r.response;
	}
	c.set("principal", r.principal);
	return next();
});

// Auth bootstrap routes (exempted from the middleware above). In cf-access
// mode these are inert: the handlers 404, and Cloudflare Access itself still
// fronts every request including these paths.
app.get("/auth/login", (c) => handleLogin(c, c.env));
app.get("/auth/callback", (c) => handleAuthCallback(c, c.env));
app.get("/auth/logout", (c) => handleLogout(c, c.env));

// MCP server endpoint — used by AI coding tools (ProtoAgent, Claude Code, Cursor, etc.)
// Must be before API routes and React Router catch-all
// Every MCP request goes through gateMcpRequest: it denies tools/call on a
// mailbox the principal may not read, and stamps the verified principal on a
// header the EmailMCP tools re-check (client-supplied copies are stripped).
const mcpHandler = EmailMCP.serve("/mcp", { binding: "EMAIL_MCP" });
const serveMcp = async (c: Context<AppEnv>) => {
	const gated = await gateMcpRequest(c.req.raw, c.env, c.get("principal"));
	if (gated instanceof Response) return gated;
	return mcpHandler.fetch(gated, c.env, c.executionCtx as ExecutionContext);
};
app.all("/mcp", (c) => serveMcp(c));
app.all("/mcp/*", (c) => serveMcp(c));

// Mount the API routes
app.route("/", apiApp);

// Agent WebSocket routing - must be before React Router catch-all
app.all("/agents/*", async (c) => {
	// Only the per-mailbox EmailAgent is reachable here, and only for a
	// mailbox the principal may read (its chat history and tools are that
	// mailbox's mail). Other agent namespaces (e.g. email-mcp) are not exposed.
	const denied = await gateAgentRequest(c.req.raw, c.env, c.get("principal"));
	if (denied) return denied;
	const response = await routeAgentRequest(c.req.raw, c.env);
	if (response) return response;
	return c.text("Agent not found", 404);
});

// React Router catch-all: serves the SPA for all non-API routes
app.all("*", (c) => {
	return requestHandler(c.req.raw, {
		cloudflare: { env: c.env, ctx: c.executionCtx as ExecutionContext },
	});
});

// Export the Hono app as the default export with an email handler
export default {
	fetch: app.fetch,
	async email(
		event: { raw: ReadableStream; rawSize: number },
		env: Env,
		ctx: ExecutionContext,
	) {
		try {
			await receiveEmail(event, env, ctx);
		} catch (e) {
			console.error("Failed to process incoming email:", (e as Error).message, (e as Error).stack);
			// Re-throw so Cloudflare's email routing can retry delivery or bounce the message.
			// Swallowing the error would silently drop the email.
			throw e;
		}
	},
};
