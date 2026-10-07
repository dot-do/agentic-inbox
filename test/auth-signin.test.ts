/**
 * Browser sign-in with id.org.ai: canonical origin and the full
 * login → callback round trip against a mocked id.org.ai.
 *
 * Regression: emails.do also answers http:// and the trailing-dot host
 * (`emails.do.`). A sign-in started there sent redirect_uri
 * http://emails.do/auth/callback, which id.org.ai does not have registered,
 * so /oauth/authorize answered 400 "Invalid redirect_uri" and nobody could
 * sign in from that entry point.
 */

import { Hono } from "hono";
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import type { Principal } from "../workers/lib/access";
import {
	authenticate,
	canonicalOrigin,
	canonicalRedirectTarget,
	handleAuthCallback,
	handleLogin,
	redirectToCanonicalOrigin,
} from "../workers/lib/auth";
import type { Env } from "../workers/types";

const ISSUER = "https://id.org.ai";
const CLIENT_ID = "cid_test_client";
const SESSION_SECRET = "test-session-secret-at-least-32-bytes-long!!";

const env = {
	AUTH_MODE: "id.org.ai",
	ID_ORG_AI_ISSUER: ISSUER,
	ID_ORG_AI_CLIENT_ID: CLIENT_ID,
	SESSION_SECRET,
} as unknown as Env;

type AppEnv = { Bindings: Env; Variables: { principal: Principal } };

/** The auth routes plus a gated probe, wired like workers/app.ts. */
function makeApp() {
	const app = new Hono<AppEnv>();
	app.use("*", async (c, next) => {
		const upgrade = redirectToCanonicalOrigin(c.req.raw);
		if (upgrade) return upgrade;
		if (c.req.path.startsWith("/auth/")) return next();
		const r = await authenticate(c, c.env);
		if (!r.ok) return r.response;
		c.set("principal", r.principal);
		return next();
	});
	app.get("/auth/login", (c) => handleLogin(c, c.env));
	app.get("/auth/callback", (c) => handleAuthCallback(c, c.env));
	app.get("/whoami", (c) => c.json(c.get("principal")));
	return app;
}

function cookiesFrom(res: Response): Record<string, string> {
	const out: Record<string, string> = {};
	for (const line of res.headers.getSetCookie()) {
		const [pair] = line.split(";");
		const eq = pair.indexOf("=");
		out[pair.slice(0, eq)] = pair.slice(eq + 1);
	}
	return out;
}

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("canonical origin", () => {
	it("upgrades http to https", () => {
		expect(canonicalRedirectTarget(new URL("http://emails.do/mailbox/a?x=1"))).toBe(
			"https://emails.do/mailbox/a?x=1",
		);
	});

	it("drops the trailing dot of the host", () => {
		expect(canonicalRedirectTarget(new URL("https://emails.do./"))).toBe("https://emails.do/");
		expect(canonicalOrigin(new URL("https://Emails.Do./x"))).toBe("https://emails.do");
	});

	it("leaves the canonical origin alone", () => {
		expect(canonicalRedirectTarget(new URL("https://emails.do/auth/login"))).toBeNull();
	});

	it("leaves loopback dev origins alone", () => {
		expect(canonicalRedirectTarget(new URL("http://localhost:5173/"))).toBeNull();
		expect(canonicalRedirectTarget(new URL("http://127.0.0.1:8787/x"))).toBeNull();
	});

	it("answers 308 so a POST keeps its method", () => {
		const res = redirectToCanonicalOrigin(new Request("http://emails.do/api/v1/mailboxes", { method: "POST" }));
		expect(res?.status).toBe(308);
		expect(res?.headers.get("location")).toBe("https://emails.do/api/v1/mailboxes");
	});
});

describe("/auth/login", () => {
	it("redirects http:// browsers to https before starting the flow", async () => {
		const res = await makeApp().request("http://emails.do/", { headers: { accept: "text/html" } }, env);
		expect(res.status).toBe(308);
		expect(res.headers.get("location")).toBe("https://emails.do/");
	});

	it("always sends the registered https redirect_uri, whatever origin it was reached on", async () => {
		for (const url of ["https://emails.do/auth/login", "http://emails.do/auth/login", "https://emails.do./auth/login"]) {
			// Call the handler directly (no canonical-origin middleware) to pin
			// the redirect_uri itself.
			const app = new Hono<AppEnv>();
			app.get("/auth/login", (c) => handleLogin(c, c.env));
			const res = await app.request(url, {}, env);
			expect(res.status).toBe(302);
			const authorize = new URL(res.headers.get("location") as string);
			expect(authorize.origin + authorize.pathname).toBe(`${ISSUER}/oauth/authorize`);
			expect(authorize.searchParams.get("redirect_uri")).toBe("https://emails.do/auth/callback");
			expect(authorize.searchParams.get("client_id")).toBe(CLIENT_ID);
			expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
			expect(authorize.searchParams.get("scope")).toBe("openid profile email offline_access");
		}
	});
});

describe("login → callback round trip against a mocked id.org.ai", () => {
	let privateKey: CryptoKey;
	let jwk: Record<string, unknown>;

	beforeAll(async () => {
		const pair = await generateKeyPair("ES256");
		privateKey = pair.privateKey as CryptoKey;
		jwk = { ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "ES256", use: "sig" };
	});

	async function idToken(claims: Record<string, unknown>) {
		return new SignJWT(claims)
			.setProtectedHeader({ alg: "ES256", kid: "k1" })
			.setIssuer(ISSUER)
			.setAudience(CLIENT_ID)
			.setSubject("human:user_01FOUNDER")
			.setIssuedAt()
			.setExpirationTime("1h")
			.sign(privateKey);
	}

	/** Mocks id.org.ai's /oauth/token and JWKS; returns the token requests seen. */
	function mockIdOrgAi(tokenResponse: () => Promise<Response>) {
		const tokenRequests: URLSearchParams[] = [];
		vi.stubGlobal(
			"fetch",
			vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
				const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
				if (url === `${ISSUER}/.well-known/jwks.json`) {
					return Response.json({ keys: [jwk] });
				}
				if (url === `${ISSUER}/oauth/token`) {
					tokenRequests.push(new URLSearchParams(String(init?.body)));
					return tokenResponse();
				}
				return new Response("unexpected fetch", { status: 599 });
			}),
		);
		return tokenRequests;
	}

	async function startLogin(app: Hono<AppEnv>) {
		const res = await app.request("https://emails.do/auth/login?returnTo=/mailbox/x", {}, env);
		const state = new URL(res.headers.get("location") as string).searchParams.get("state") as string;
		return { state, stateCookie: cookiesFrom(res).inbox_auth_state };
	}

	it("exchanges the code with PKCE, sets the session, and the session carries the verified email", async () => {
		const app = makeApp();
		const token = await idToken({ email: "Nathan@Example.com", email_verified: true, name: "Nathan" });
		const tokenRequests = mockIdOrgAi(async () => Response.json({ access_token: "at_x", token_type: "Bearer", id_token: token }));

		const { state, stateCookie } = await startLogin(app);
		const cb = await app.request(
			`https://emails.do/auth/callback?code=c0de&state=${state}&iss=${encodeURIComponent(ISSUER)}`,
			{ headers: { cookie: `inbox_auth_state=${stateCookie}` } },
			env,
		);
		expect(cb.status).toBe(302);
		expect(cb.headers.get("location")).toBe("/mailbox/x");

		// Public client: client_id + PKCE verifier, registered redirect_uri, no secret.
		expect(tokenRequests).toHaveLength(1);
		expect(tokenRequests[0].get("grant_type")).toBe("authorization_code");
		expect(tokenRequests[0].get("redirect_uri")).toBe("https://emails.do/auth/callback");
		expect(tokenRequests[0].get("client_id")).toBe(CLIENT_ID);
		expect(tokenRequests[0].get("code_verifier")).toBeTruthy();
		expect(tokenRequests[0].has("client_secret")).toBe(false);

		const session = cookiesFrom(cb).inbox_session;
		expect(session).toBeTruthy();
		const { payload } = await jwtVerify(session, new TextEncoder().encode(SESSION_SECRET));
		expect(payload.email).toBe("Nathan@Example.com");

		const who = await app.request("https://emails.do/whoami", { headers: { cookie: `inbox_session=${session}` } }, env);
		expect(await who.json()).toEqual({ sub: "human:user_01FOUNDER", email: "nathan@example.com" });
	});

	it("logs the IdP's error when the token exchange fails", async () => {
		const app = makeApp();
		mockIdOrgAi(async () =>
			Response.json({ error: "invalid_grant", error_description: "redirect_uri mismatch" }, { status: 400 }),
		);
		const log = vi.spyOn(console, "error").mockImplementation(() => {});

		const { state, stateCookie } = await startLogin(app);
		const cb = await app.request(
			`https://emails.do/auth/callback?code=c0de&state=${state}`,
			{ headers: { cookie: `inbox_auth_state=${stateCookie}` } },
			env,
		);
		expect(cb.status).toBe(403);
		expect(log).toHaveBeenCalledWith(
			"auth.callback.token_exchange_failed",
			400,
			expect.stringContaining("redirect_uri mismatch"),
		);
	});
});
