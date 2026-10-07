// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Review follow-ups to the per-mailbox access hotfix:
 *  1. no claiming arbitrary addresses via POST /mailboxes
 *  2. a missing email_verified means NOT verified
 *  3. bearer JWTs must carry the emails.do audience
 *  4. relay credentials are scoped to their relay's domains; /_admin/read is gone
 */

import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { Hono } from "hono";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("agents", () => ({ getAgentByName: vi.fn(async () => ({ fetch: vi.fn(async () => new Response("ok")) })) }));

import { app as apiApp } from "../workers/index";
import type { Principal } from "../workers/lib/access";
import { authenticate, principalFromClaims } from "../workers/lib/auth";
import { signingSecretFor } from "../workers/lib/relay-auth";
import { signRelayBody } from "../workers/lib/relay-hmac";

// -- Shared mocks -------------------------------------------------------

function makeBucket(initial: Record<string, unknown> = {}) {
	const store = new Map<string, string>(Object.entries(initial).map(([k, v]) => [k, JSON.stringify(v)]));
	return {
		store,
		get: vi.fn(async (key: string) => {
			const v = store.get(key);
			return v === undefined ? null : { json: async () => JSON.parse(v), text: async () => v };
		}),
		head: vi.fn(async (key: string) => (store.has(key) ? { key } : null)),
		put: vi.fn(async (key: string, value: string) => void store.set(key, typeof value === "string" ? value : "blob")),
		list: vi.fn(async ({ prefix }: { prefix: string }) => ({
			objects: [...store.keys()].filter((k) => k.startsWith(prefix)).map((key) => ({ key })),
		})),
		delete: vi.fn(async () => {
			throw new Error("BUCKET.delete must never be called");
		}),
	};
}

function makeEnv(extra: Record<string, unknown> = {}) {
	const created: { mailbox: string; email: Record<string, unknown> }[] = [];
	const env = {
		BUCKET: makeBucket(),
		MAILBOX: {
			idFromName: (name: string) => name,
			get: (mailbox: string) => ({
				getFolders: vi.fn(async () => []),
				findThreadBySubject: vi.fn(async () => null),
				createEmail: vi.fn(async (_f: string, email: Record<string, unknown>) => void created.push({ mailbox, email })),
				getEmails: vi.fn(async () => []),
				getEmail: vi.fn(async () => ({ id: "e1" })),
			}),
		},
		EMAIL_ADDRESSES: [],
		MAILBOX_ADMINS: "ops@x.com",
		ARCHIVE_ENABLED: false,
		...extra,
	};
	return { env, created };
}

const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

function api(env: unknown) {
	const outer = new Hono<{ Variables: { principal: Principal } }>();
	outer.use("*", async (c, next) => {
		const who = c.req.header("x-test-principal");
		if (who) c.set("principal", JSON.parse(who));
		await next();
	});
	outer.route("/", apiApp as never);
	return (who: Principal | null, path: string, init: RequestInit = {}) =>
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
			ctx as never,
		);
}

// -- 1. Mailbox claiming --------------------------------------------------

describe("POST /mailboxes: no claiming of arbitrary addresses", () => {
	const DANA: Principal = { sub: "sub-dana", email: "dana@x.com" };
	const create = (who: Principal | null, body: Record<string, unknown>) => {
		const { env } = makeEnv();
		return api(env)(who, "/api/v1/mailboxes", { method: "POST", body: JSON.stringify({ name: "n", ...body }) }).then(
			(res) => ({ res, env }),
		);
	};

	it("a user can create a mailbox only for their own verified address", async () => {
		const { res, env } = await create(DANA, { email: "dana@x.com" });
		expect(res.status).toBe(201);
		expect(JSON.parse(env.BUCKET.store.get("mailbox-acl/dana@x.com.json")!).owner).toBe("dana@x.com");
		// Normalizing case is fine: it is the same address.
		expect((await create(DANA, { email: "Dana@X.com" })).res.status).toBe(201);
	});

	it("rejects other addresses, aliases and look-alikes", async () => {
		for (const email of ["ceo@x.com", "dana+bot@x.com", "d.ana@x.com", "dana@x.co", "dаna@x.com" /* Cyrillic а */]) {
			const { res, env } = await create(DANA, { email });
			// 403, or 400 where the address is not even a valid email.
			expect([400, 403], email).toContain(res.status);
			expect(env.BUCKET.put, email).not.toHaveBeenCalled();
		}
	});

	it("rejects a principal without a verified email, and non-admin delegation", async () => {
		expect((await create({ sub: "sub-agent" }, { email: "agent@x.com" })).res.status).toBe(403);
		expect((await create(null, { email: "dana@x.com" })).res.status).toBe(403);
		expect((await create(DANA, { email: "dana@x.com", owner: "sub-other" })).res.status).toBe(403);
	});

	it("an admin can create any mailbox, on behalf of an owner", async () => {
		const { res, env } = await create({ sub: "sub-ops", email: "ops@x.com" }, { email: "agent@x.com", owner: "sub-agent" });
		expect(res.status).toBe(201);
		expect(JSON.parse(env.BUCKET.store.get("mailbox-acl/agent@x.com.json")!)).toEqual({ owner: "sub-agent", members: [] });
	});
});

// -- 2. email_verified -------------------------------------------------------

describe("email_verified", () => {
	it("missing or false means not verified; only true keeps the email", () => {
		expect(principalFromClaims({ sub: "s", email: "a@x.com" })).toEqual({ sub: "s" });
		expect(principalFromClaims({ sub: "s", email: "a@x.com", email_verified: false })).toEqual({ sub: "s" });
		expect(principalFromClaims({ sub: "s", email: "a@x.com", email_verified: "true" })).toEqual({ sub: "s" });
		expect(principalFromClaims({ sub: "s", email: "A@x.com", email_verified: true })).toEqual({ sub: "s", email: "a@x.com" });
	});

	it("Cloudflare Access emails are trusted explicitly (Access asserts them itself)", () => {
		expect(principalFromClaims({ sub: "s", email: "a@x.com" }, { trustEmail: true })).toEqual({ sub: "s", email: "a@x.com" });
	});
});

// -- 3. Bearer JWT audience -------------------------------------------------

describe("bearer JWT audience", () => {
	const ISSUER = "https://id.test";
	let privateKey: CryptoKey;

	beforeAll(async () => {
		const pair = await generateKeyPair("RS256");
		privateKey = pair.privateKey as CryptoKey;
		const jwk = { ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "RS256", use: "sig" };
		vi.stubGlobal(
			"fetch",
			vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
				const u = String(url instanceof Request ? url.url : url);
				if (u === `${ISSUER}/.well-known/jwks.json`) return Response.json({ keys: [jwk] });
				if (u === `${ISSUER}/oauth/introspect`) {
					const token = new URLSearchParams(String(init?.body)).get("token");
					if (token === "at_good") return Response.json({ active: true, sub: "sub-agent", token_type: "Bearer" });
					if (token === "rt_refresh") return Response.json({ active: true, sub: "sub-agent", token_type: "refresh_token" });
					return Response.json({ active: false });
				}
				return new Response("not found", { status: 404 });
			}),
		);
	});
	const env = (extra: Record<string, unknown> = {}) => ({
		AUTH_MODE: "id.org.ai",
		ID_ORG_AI_ISSUER: ISSUER,
		ID_ORG_AI_CLIENT_ID: "emails-client",
		ID_ORG_AI_CLIENT_SECRET: "client-secret",
		SESSION_SECRET: "s".repeat(32),
		ID_ORG_AI_AUDIENCE: "https://emails.do,https://emails.do/mcp",
		...extra,
	});

	async function whoami(token: string, e = env()) {
		const app = new Hono();
		app.get("/whoami", async (c) => {
			const r = await authenticate(c as never, c.env as never);
			return r.ok ? c.json(r.principal) : r.response;
		});
		return app.request("/whoami", { headers: { authorization: `Bearer ${token}` } }, e as never);
	}

	const jwt = (claims: Record<string, unknown>, aud?: string | string[]) => {
		const j = new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "k1" }).setIssuer(ISSUER).setIssuedAt().setExpirationTime("5m");
		if (aud) j.setAudience(aud);
		return j.sign(privateKey);
	};

	it("accepts a JWT bound to the emails.do resource", async () => {
		for (const aud of ["https://emails.do", "https://emails.do/mcp", ["https://other.example", "https://emails.do"]]) {
			const res = await whoami(await jwt({ sub: "sub-a", email: "a@x.com", email_verified: true }, aud));
			expect(res.status, String(aud)).toBe(200);
			expect(await res.json()).toEqual({ sub: "sub-a", email: "a@x.com" });
		}
	});

	it("rejects id.org.ai session JWTs (no aud) and tokens for other clients", async () => {
		expect((await whoami(await jwt({ sub: "sub-a", email: "a@x.com" }))).status).toBe(403);
		expect((await whoami(await jwt({ sub: "sub-a" }, "some-other-client"))).status).toBe(403);
		expect((await whoami(await jwt({ sub: "sub-a" }, "emails-client"))).status).toBe(403);
	});

	it("fails closed when no audience is configured", async () => {
		const res = await whoami(await jwt({ sub: "sub-a" }, "https://emails.do"), env({ ID_ORG_AI_AUDIENCE: "" }) as never);
		expect(res.status).toBe(403);
	});

	it("opaque tokens: access tokens pass introspection, refresh tokens do not", async () => {
		const ok = await whoami("at_good");
		expect(ok.status).toBe(200);
		expect(await ok.json()).toEqual({ sub: "sub-agent" });
		expect((await whoami("rt_refresh")).status).toBe(403);
		expect((await whoami("at_bogus")).status).toBe(403);
	});
});

// -- 4. Relay credentials ------------------------------------------------------

describe("relay credentials are scoped to their own relay's domains", () => {
	afterEach(() => vi.unstubAllGlobals());

	const relays = {
		EMAIL_RELAYS: JSON.stringify({
			"longtail.studio": "https://relay.longtail.studio",
			"other.example": "https://relay.other.example",
		}),
		RELAY_SECRET: "legacy-shared",
		RELAY_KEYS: JSON.stringify({ "https://relay.other.example": "other-key" }),
	};

	async function ingest(secret: string, to: string[]) {
		const { env, created } = makeEnv(relays);
		const body = JSON.stringify({ to, from: "sender@example.net", subject: "hi", text: "body" });
		const sig = await signRelayBody(secret, body);
		const res = await api(env)(null, "/api/v1/ingest", { method: "POST", body, headers: sig });
		return { res, created };
	}

	it("the legacy shared secret still delivers for its relay's domain (existing relay unchanged)", async () => {
		const { res, created } = await ingest("legacy-shared", ["x@longtail.studio"]);
		expect(res.status).toBe(200);
		expect(created.map((c) => c.mailbox)).toEqual(["x@longtail.studio"]);
	});

	it("no relay credential can deliver into a local (.do) mailbox", async () => {
		for (const secret of ["legacy-shared", "other-key"]) {
			const { res, created } = await ingest(secret, ["ceo@emails.do"]);
			expect(res.status, secret).toBe(403);
			expect(created).toEqual([]);
		}
	});

	it("a relay with its own key cannot deliver for another relay's domain, and vice versa", async () => {
		expect((await ingest("other-key", ["x@other.example"])).res.status).toBe(200);
		expect((await ingest("other-key", ["x@longtail.studio"])).res.status).toBe(403);
		// Once a relay has its own key, the shared secret no longer covers it.
		expect((await ingest("legacy-shared", ["x@other.example"])).res.status).toBe(403);
	});

	it("out-of-scope recipients are dropped from a mixed message", async () => {
		const { res, created } = await ingest("legacy-shared", ["ceo@emails.do", "x@longtail.studio"]);
		expect(res.status).toBe(200);
		expect(created).toHaveLength(1);
		expect(created[0].mailbox).toBe("x@longtail.studio");
		expect(created[0].email.recipient).toBe("x@longtail.studio");
	});

	it("an unknown key is rejected", async () => {
		expect((await ingest("wrong", ["x@longtail.studio"])).res.status).toBe(401);
	});

	it("outbound sends are signed with the relay's own key, else the legacy secret", () => {
		const env = relays as never;
		expect(signingSecretFor(env, "https://relay.other.example/")).toBe("other-key");
		expect(signingSecretFor(env, "https://relay.longtail.studio")).toBe("legacy-shared");
	});

	it("/api/v1/_admin/read no longer exists, even with a valid relay signature", async () => {
		const { env } = makeEnv(relays);
		const body = JSON.stringify({ list: true });
		const res = await api(env)(null, "/api/v1/_admin/read", {
			method: "POST",
			body,
			headers: await signRelayBody("legacy-shared", body),
		});
		expect(res.status).toBe(404);
	});
});
