// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { routeAgentRequest } from "agents";
import { Hono } from "hono";
import { createRequestHandler } from "react-router";
import { app as apiApp, receiveEmail } from "./index";
import {
	authenticate,
	handleAuthCallback,
	handleLogin,
	handleLogout,
	isPublicAuthPath,
} from "./lib/auth";
import { EmailMCP } from "./mcp";
import type { Env } from "./types";

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
const app = new Hono<{ Bindings: Env }>();

// Authentication middleware (production only). The actual verification lives
// in ./lib/auth and dispatches on env.AUTH_MODE: "cf-access" (default, the
// pre-existing Cloudflare Access JWT check) or "id.org.ai" (OIDC sessions for
// browsers, bearer-token verification for API/MCP/agents).
//
// Authorization model note: any authenticated principal can access all
// mailboxes in this app by design (single trust boundary).
app.use("*", async (c, next) => {
	// Skip validation in development
	if (import.meta.env.DEV) {
		return next();
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

	const r = await authenticate(c, c.env);
	if (!r.ok) {
		return r.response;
	}
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
const mcpHandler = EmailMCP.serve("/mcp", { binding: "EMAIL_MCP" });
app.all("/mcp", async (c) => {
	return mcpHandler.fetch(c.req.raw, c.env, c.executionCtx as ExecutionContext);
});
app.all("/mcp/*", async (c) => {
	return mcpHandler.fetch(c.req.raw, c.env, c.executionCtx as ExecutionContext);
});

// Mount the API routes
app.route("/", apiApp);

// Agent WebSocket routing - must be before React Router catch-all
app.all("/agents/*", async (c) => {
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
