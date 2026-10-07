// Pluggable authentication for the worker.
//
// Two modes, selected by env.AUTH_MODE:
//
//   "cf-access" (default) — the pre-existing Cloudflare Access JWT check,
//     moved here verbatim from workers/app.ts. Behavior is byte-for-byte
//     identical: fail closed (500) when POLICY_AUD/TEAM_DOMAIN are missing,
//     403 when the `cf-access-jwt-assertion` header is absent or invalid.
//
//   "id.org.ai" — OpenID Connect against the live provider at
//     https://id.org.ai (discovery verified: /oauth/authorize, /oauth/token,
//     /oauth/introspect, JWKS at /.well-known/jwks.json, PKCE S256,
//     token_endpoint_auth: none | client_secret_basic | client_secret_post).
//     Serves two principal types:
//       (a) Browsers (Accept: text/html, no bearer): session cookie, or a
//           302 into the authorization-code + PKCE flow. GET /auth/callback
//           exchanges the code, verifies the id_token, and sets an HttpOnly
//           session cookie (a compact JWT re-signed with SESSION_SECRET).
//       (b) API/MCP/agents (Authorization: Bearer ...): the bearer is
//           verified as a JWT against id.org.ai's JWKS; opaque tokens fall
//           back to POST /oauth/introspect (requires ID_ORG_AI_CLIENT_SECRET)
//           and must come back active:true. This covers device_code and
//           client_credentials agents.
//
// This module only AUTHENTICATES: it resolves who the caller is (a Principal:
// verified email and/or IdP sub). Per-mailbox AUTHORIZATION — owner, granted
// members, admin allowlist, deny by default — lives in workers/lib/access.ts.
//
// NOTE: the import.meta.env.DEV bypass stays in the middleware in
// workers/app.ts — authenticate() assumes it is only called in production.

import type { Context } from "hono";
import {
	createRemoteJWKSet,
	decodeProtectedHeader,
	jwtVerify,
	SignJWT,
} from "jose";
import type { Env } from "../types";
import type { Principal } from "./access";

// The Hono context shape of the outer app (workers/app.ts), which carries the
// authenticated principal as a context variable.
type AppContext = Context<{ Bindings: Env; Variables: { principal: Principal } }>;

/**
 * Result of an authentication attempt. When `ok` is false, `response` is
 * exactly what the middleware should return to the client: a 403, a 500
 * (misconfiguration, fail closed), or a 302 into the OIDC login flow.
 */
export type AuthResult =
	| { ok: true; principal: Principal }
	| { ok: false; response: Response };

/**
 * Build a Principal from verified token/claim fields.
 *
 * The email is kept ONLY when the claims positively assert it is verified
 * (`email_verified: true`). A missing or false `email_verified` means NOT
 * verified, and the email is dropped, so it can never match a mailbox
 * address or an ACL entry. id.org.ai id_tokens always carry an explicit
 * `email_verified` (its toIdentityInfo defaults it to false).
 *
 * `trustEmail` is only for Cloudflare Access JWTs: Access asserts the email
 * itself after its own IdP login and never emits `email_verified`.
 *
 * A principal with neither email nor sub cannot be authorized for anything
 * (access.ts denies by default).
 */
export function principalFromClaims(
	claims: Record<string, unknown>,
	opts: { trustEmail?: boolean } = {},
): Principal {
	const p: Principal = {};
	if (typeof claims.sub === "string" && claims.sub) p.sub = claims.sub;
	const verified = opts.trustEmail === true || claims.email_verified === true;
	if (typeof claims.email === "string" && claims.email && verified) {
		p.email = claims.email.trim().toLowerCase();
	}
	return p;
}

/**
 * Audiences a bearer JWT must carry (at least one) to be accepted here:
 * ID_ORG_AI_AUDIENCE, comma/space separated or a JSON array — for emails.do
 * the RFC 8707 resource URLs "https://emails.do" and "https://emails.do/mcp"
 * that id.org.ai binds into a token's audience. Unset or empty means no JWT
 * bearer is accepted (fail closed).
 */
export function expectedAudiences(env: Env): string[] {
	const raw = (env as unknown as { ID_ORG_AI_AUDIENCE?: unknown }).ID_ORG_AI_AUDIENCE;
	let items: unknown[] = [];
	if (Array.isArray(raw)) items = raw;
	else if (typeof raw === "string" && raw.trim()) {
		const s = raw.trim();
		if (s.startsWith("[")) {
			try {
				const parsed = JSON.parse(s);
				if (Array.isArray(parsed)) items = parsed;
			} catch {
				items = [];
			}
		} else items = s.split(/[\s,]+/);
	}
	return items.filter((x): x is string => typeof x === "string" && x.length > 0);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default OIDC issuer when ID_ORG_AI_ISSUER is not set. */
const DEFAULT_ID_ORG_AI_ISSUER = "https://id.org.ai";

/** Scopes requested in the browser login flow. */
const OIDC_SCOPE = "openid profile email offline_access";

/** Session cookie: holds a compact JWT signed with SESSION_SECRET (HS256). */
const SESSION_COOKIE = "inbox_session";

/** Short-lived signed cookie carrying {state, code_verifier, returnTo}. */
const STATE_COOKIE = "inbox_auth_state";

/** issuer/audience claims we stamp on our own HS256 cookies so tokens from
 * other contexts (e.g. an id.org.ai id_token pasted into the cookie) can
 * never validate as one of ours. */
const SELF_JWT_ISSUER = "agentic-inbox";
const SESSION_JWT_AUDIENCE = "agentic-inbox:session";
const STATE_JWT_AUDIENCE = "agentic-inbox:state";

/** Session lifetime. The id_token itself is typically short-lived; we mint
 * our own session with a longer TTL (refresh-token renewal can come later). */
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

/** Login attempts must complete within this window (state cookie TTL). */
const STATE_TTL_SECONDS = 60 * 10; // 10 minutes

/**
 * Paths that must NOT be gated by the auth middleware (they bootstrap the
 * login flow). The next phase's middleware should consult this list.
 */
export const PUBLIC_AUTH_PATHS = ["/auth/login", "/auth/callback", "/auth/logout"];

/** True when `pathname` is one of the ungated auth-bootstrap routes. */
export function isPublicAuthPath(pathname: string): boolean {
	return PUBLIC_AUTH_PATHS.includes(pathname);
}

// ---------------------------------------------------------------------------
// Canonical origin
// ---------------------------------------------------------------------------
//
// The custom domain also answers plain http:// (the zone does not force
// HTTPS) and the trailing-dot spelling of the host (`emails.do.`). Neither
// can complete a sign-in:
//
//   - redirect_uri is derived from the request origin, and id.org.ai only
//     has https://<host>/auth/callback registered, so it answers
//     400 {"error":"invalid_request","error_description":"Invalid redirect_uri"}
//     and the browser is stranded on a JSON error page;
//   - the state and session cookies are `Secure` and host-only, so they are
//     never stored over http, and a cookie set on `emails.do.` is never sent
//     to `emails.do`.
//
// So every browser request is first moved to the canonical origin
// (https, no trailing dot), and redirect_uri is always built from it.

/**
 * The canonical form of `url`'s origin: https, hostname without a trailing
 * dot. Loopback hosts keep their scheme and port (local `wrangler dev`).
 */
export function canonicalOrigin(url: URL): string {
	const host = url.hostname.replace(/\.+$/, "").toLowerCase();
	if (host === "localhost" || host === "127.0.0.1" || host === "[::1]") {
		return url.origin;
	}
	return `https://${host}`;
}

/**
 * Where a request on a non-canonical origin should go instead, or null when
 * it is already canonical. The path and query are kept; the method is kept
 * too (the caller answers 308).
 */
export function canonicalRedirectTarget(url: URL): string | null {
	const origin = canonicalOrigin(url);
	if (origin === url.origin) return null;
	return `${origin}${url.pathname}${url.search}`;
}

/**
 * 308 to the canonical origin when `request` arrived on another spelling of
 * it (http://, trailing-dot host); null when it is already canonical. 308
 * keeps the method and body, so a non-GET caller is not silently downgraded.
 */
export function redirectToCanonicalOrigin(request: Request): Response | null {
	const target = canonicalRedirectTarget(new URL(request.url));
	if (!target) return null;
	return new Response(null, { status: 308, headers: { location: target } });
}

// ---------------------------------------------------------------------------
// Entry point: dispatch on AUTH_MODE
// ---------------------------------------------------------------------------

/**
 * Authenticate the request per env.AUTH_MODE. Defaults to "cf-access" so
 * existing deployments are untouched; any unrecognized value also falls
 * through to cf-access (fail toward the stricter, known-good path).
 */
export async function authenticate(
	c: AppContext,
	env: Env,
): Promise<AuthResult> {
	if (env.AUTH_MODE === "id.org.ai") {
		return idOrgAiVerify(c, env);
	}
	return cfAccessVerify(c, env);
}

// ---------------------------------------------------------------------------
// Mode 1: Cloudflare Access (existing logic, moved verbatim from app.ts)
// ---------------------------------------------------------------------------

/**
 * Derive the Access issuer origin and JWKS URL from the team domain.
 * (Moved unchanged from workers/app.ts.)
 */
export function getAccessUrls(teamDomain: string) {
	const certsPath = "/cdn-cgi/access/certs";
	const teamUrl = new URL(teamDomain);
	const issuer = teamUrl.origin;
	const certsUrl = teamUrl.pathname.endsWith(certsPath)
		? teamUrl
		: new URL(certsPath, issuer);

	return { issuer, certsUrl };
}

/**
 * The pre-existing Cloudflare Access check. Same env vars, same header,
 * same jose verification, same response texts and status codes as the
 * middleware previously inlined in workers/app.ts.
 */
export async function cfAccessVerify(
	c: AppContext,
	env: Env,
): Promise<AuthResult> {
	const { POLICY_AUD, TEAM_DOMAIN } = env;

	// Fail closed in production if Access is not configured.
	if (!POLICY_AUD || !TEAM_DOMAIN) {
		return {
			ok: false,
			response: c.text(
				"Cloudflare Access must be configured in production. Set POLICY_AUD and TEAM_DOMAIN.",
				500,
			),
		};
	}

	const token = c.req.header("cf-access-jwt-assertion");
	if (!token) {
		return { ok: false, response: c.text("Missing required CF Access JWT", 403) };
	}

	try {
		const { issuer, certsUrl } = getAccessUrls(TEAM_DOMAIN);
		const JWKS = createRemoteJWKSet(certsUrl);
		const { payload } = await jwtVerify(token, JWKS, {
			issuer,
			audience: POLICY_AUD,
		});
		// Access identities are verified by Access itself; per-mailbox
		// authorization happens in workers/lib/access.ts.
		return { ok: true, principal: principalFromClaims(payload, { trustEmail: true }) };
	} catch {
		return { ok: false, response: c.text("Invalid or expired Access token", 403) };
	}
}

// ---------------------------------------------------------------------------
// Mode 2: id.org.ai OIDC
// ---------------------------------------------------------------------------

/** Resolve issuer origin (trailing-slash tolerant). */
function getIssuer(env: Env): string {
	return (env.ID_ORG_AI_ISSUER || DEFAULT_ID_ORG_AI_ISSUER).replace(/\/+$/, "");
}

// Cache RemoteJWKSet instances per URL: jose caches fetched keys inside the
// instance, so reusing it across requests in a warm isolate avoids
// re-fetching the JWKS on every request.
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getRemoteJwks(jwksUrl: string) {
	let jwks = jwksCache.get(jwksUrl);
	if (!jwks) {
		jwks = createRemoteJWKSet(new URL(jwksUrl));
		jwksCache.set(jwksUrl, jwks);
	}
	return jwks;
}

/** HMAC key for our own HS256 session/state cookies. */
function sessionKey(env: Env): Uint8Array {
	return new TextEncoder().encode(env.SESSION_SECRET);
}

/**
 * id.org.ai verification. Dispatches on the shape of the request:
 * bearer token → API/agent path; otherwise → browser session/redirect path.
 */
export async function idOrgAiVerify(
	c: AppContext,
	env: Env,
): Promise<AuthResult> {
	// Fail closed, mirroring cf-access mode: a misconfigured production
	// deployment must not become an open server.
	if (!env.ID_ORG_AI_CLIENT_ID || !env.SESSION_SECRET) {
		return {
			ok: false,
			response: c.text(
				"id.org.ai auth must be configured in production. Set ID_ORG_AI_CLIENT_ID and SESSION_SECRET.",
				500,
			),
		};
	}

	const authorization = c.req.header("authorization");
	const bearerMatch = authorization?.match(/^Bearer\s+(.+)$/i);
	if (bearerMatch) {
		return verifyBearer(c, env, bearerMatch[1].trim());
	}
	return verifyBrowser(c, env);
}

/** JWT-shaped = three dot-separated segments with a decodable JOSE header. */
function isJwtShaped(token: string): boolean {
	if (token.split(".").length !== 3) return false;
	try {
		decodeProtectedHeader(token);
		return true;
	} catch {
		return false;
	}
}

/**
 * (b) API/MCP/agent principals: Authorization: Bearer <token>.
 *
 * JWT bearers are verified locally against id.org.ai's JWKS for issuer AND
 * audience: `aud` must include one of ID_ORG_AI_AUDIENCE (the emails.do
 * resource URLs). That rejects id.org.ai session JWTs (no `aud`) and
 * id_tokens minted for other clients (`aud` = that client) — tokens meant
 * for some other relying party can't be replayed here.
 *
 * Opaque tokens (id.org.ai `at_…` access tokens) fall back to RFC 7662 token
 * introspection with client_secret_basic, requiring `active: true` and an
 * access token (refresh tokens introspect as active too and are refused).
 * That fallback is what lets device_code and client_credentials agents in.
 * id.org.ai's introspection response carries no audience/resource, so those
 * tokens are bound by client authentication only.
 */
async function verifyBearer(
	c: AppContext,
	env: Env,
	token: string,
): Promise<AuthResult> {
	const issuer = getIssuer(env);

	if (isJwtShaped(token)) {
		const audience = expectedAudiences(env);
		if (audience.length === 0) {
			return { ok: false, response: c.text("JWT bearer tokens are not accepted: ID_ORG_AI_AUDIENCE is not configured", 403) };
		}
		try {
			const jwks = getRemoteJwks(`${issuer}/.well-known/jwks.json`);
			const { payload } = await jwtVerify(token, jwks, { issuer, audience });
			return { ok: true, principal: principalFromClaims(payload) };
		} catch {
			// Structurally a JWT but failed verification (bad signature, expired,
			// wrong issuer). Do NOT fall back to introspection for these — a JWT
			// that fails verification is simply invalid.
			return { ok: false, response: c.text("Invalid or expired bearer token", 403) };
		}
	}

	// Opaque token → introspect. Introspection authenticates the CLIENT via
	// client_secret_basic, so a confidential client secret is required.
	if (!env.ID_ORG_AI_CLIENT_SECRET) {
		return {
			ok: false,
			response: c.text(
				"Opaque bearer tokens require introspection; ID_ORG_AI_CLIENT_SECRET is not configured.",
				403,
			),
		};
	}

	try {
		// RFC 6749 §2.3.1: client_id/secret are form-urlencoded before being
		// placed into the HTTP Basic credentials.
		const basic = btoa(
			`${encodeURIComponent(env.ID_ORG_AI_CLIENT_ID as string)}:${encodeURIComponent(env.ID_ORG_AI_CLIENT_SECRET)}`,
		);
		const res = await fetch(`${issuer}/oauth/introspect`, {
			method: "POST",
			headers: {
				authorization: `Basic ${basic}`,
				"content-type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({ token }).toString(),
		});
		if (res.ok) {
			const body = (await res.json()) as Record<string, unknown> & { active?: boolean };
			// Refresh tokens also introspect as active; only access tokens may
			// call the API.
			if (body.active === true && body.token_type !== "refresh_token") {
				return { ok: true, principal: principalFromClaims(body) };
			}
		}
	} catch {
		// Network/parse failure → treat as unauthenticated (fail closed).
	}
	return { ok: false, response: c.text("Invalid or expired bearer token", 403) };
}

/**
 * (a) Browser principals: no bearer header.
 *
 * A valid session cookie (our own HS256 JWT) authenticates the request.
 * Otherwise, HTML-accepting requests are 302'd into the id.org.ai
 * authorization-code + PKCE flow; non-HTML requests get a plain 403
 * (redirecting an XHR/fetch into an IdP is useless and confusing).
 */
async function verifyBrowser(c: AppContext, env: Env): Promise<AuthResult> {
	const cookies = parseCookies(c.req.header("cookie"));
	const session = cookies[SESSION_COOKIE];
	if (session) {
		try {
			const { payload } = await jwtVerify(session, sessionKey(env), {
				issuer: SELF_JWT_ISSUER,
				audience: SESSION_JWT_AUDIENCE,
			});
			return { ok: true, principal: principalFromClaims(payload) };
		} catch {
			// Expired/invalid session — fall through to re-login (or 403).
		}
	}

	const accept = c.req.header("accept") ?? "";
	if (!accept.includes("text/html")) {
		return {
			ok: false,
			response: c.text(
				"Unauthenticated. Provide an Authorization: Bearer token or sign in at /auth/login.",
				403,
			),
		};
	}

	// Preserve where the user was headed; carried through the state cookie.
	const url = new URL(c.req.url);
	const returnTo = sanitizeReturnTo(url.pathname + url.search);
	return { ok: false, response: await buildAuthorizeRedirect(c, env, returnTo) };
}

/** Only same-origin absolute paths are allowed (blocks open redirects). */
function sanitizeReturnTo(candidate: string | null | undefined): string {
	if (candidate && candidate.startsWith("/") && !candidate.startsWith("//")) {
		return candidate;
	}
	return "/";
}

/**
 * Build the 302 into id.org.ai's /oauth/authorize with PKCE (S256), and set
 * the short-lived signed state cookie holding {state, code_verifier,
 * returnTo}. The cookie is an HS256 JWT so it is tamper-evident; the
 * code_verifier is HttpOnly and never exposed to page script.
 */
async function buildAuthorizeRedirect(
	c: AppContext,
	env: Env,
	returnTo: string,
): Promise<Response> {
	const issuer = getIssuer(env);

	// PKCE: 32 random bytes → base64url verifier; S256 challenge.
	const codeVerifier = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
	const challengeBytes = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(codeVerifier),
	);
	const codeChallenge = base64UrlEncode(new Uint8Array(challengeBytes));

	// CSRF state: random, echoed back by the IdP, matched against the cookie.
	const state = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));

	const stateJwt = await new SignJWT({ st: state, cv: codeVerifier, rt: returnTo })
		.setProtectedHeader({ alg: "HS256" })
		.setIssuer(SELF_JWT_ISSUER)
		.setAudience(STATE_JWT_AUDIENCE)
		.setIssuedAt()
		.setExpirationTime(`${STATE_TTL_SECONDS}s`)
		.sign(sessionKey(env));

	const authorizeUrl = new URL(`${issuer}/oauth/authorize`);
	authorizeUrl.searchParams.set("response_type", "code");
	authorizeUrl.searchParams.set("client_id", env.ID_ORG_AI_CLIENT_ID as string);
	authorizeUrl.searchParams.set("redirect_uri", getRedirectUri(c));
	authorizeUrl.searchParams.set("scope", OIDC_SCOPE);
	authorizeUrl.searchParams.set("state", state);
	authorizeUrl.searchParams.set("code_challenge", codeChallenge);
	authorizeUrl.searchParams.set("code_challenge_method", "S256");

	const headers = new Headers({ location: authorizeUrl.toString() });
	headers.append(
		"set-cookie",
		serializeCookie(STATE_COOKIE, stateJwt, { maxAge: STATE_TTL_SECONDS }),
	);
	return new Response(null, { status: 302, headers });
}

/** redirect_uri is always <canonical origin>/auth/callback (see canonicalOrigin). */
function getRedirectUri(c: AppContext): string {
	return `${canonicalOrigin(new URL(c.req.url))}/auth/callback`;
}

// ---------------------------------------------------------------------------
// Route handlers (mounted ungated in the next phase)
// ---------------------------------------------------------------------------

/**
 * GET /auth/login[?returnTo=/path] — explicitly start the browser login
 * flow. Useful for a "Sign in" link and for re-auth after logout.
 */
export async function handleLogin(c: AppContext, env: Env): Promise<Response> {
	if (env.AUTH_MODE !== "id.org.ai") {
		return c.text("Login is handled by Cloudflare Access in this deployment.", 404);
	}
	if (!env.ID_ORG_AI_CLIENT_ID || !env.SESSION_SECRET) {
		return c.text(
			"id.org.ai auth must be configured in production. Set ID_ORG_AI_CLIENT_ID and SESSION_SECRET.",
			500,
		);
	}
	const returnTo = sanitizeReturnTo(new URL(c.req.url).searchParams.get("returnTo"));
	return buildAuthorizeRedirect(c, env, returnTo);
}

/**
 * GET /auth/callback?code=...&state=... — the OIDC redirect target.
 *
 * 1. Match `state` against the signed state cookie (CSRF protection).
 * 2. Exchange the code at /oauth/token with the PKCE code_verifier
 *    (public client "none", or client_secret_post when a secret is issued).
 * 3. Verify the returned id_token against id.org.ai's JWKS
 *    (issuer = ID_ORG_AI_ISSUER, audience = client_id).
 * 4. Mint our own HS256 session JWT, set it as an HttpOnly cookie, clear
 *    the state cookie, and 302 back to where the user was headed.
 */
export async function handleAuthCallback(
	c: AppContext,
	env: Env,
): Promise<Response> {
	if (env.AUTH_MODE !== "id.org.ai") {
		return c.text("Not found", 404);
	}
	if (!env.ID_ORG_AI_CLIENT_ID || !env.SESSION_SECRET) {
		return c.text(
			"id.org.ai auth must be configured in production. Set ID_ORG_AI_CLIENT_ID and SESSION_SECRET.",
			500,
		);
	}

	const issuer = getIssuer(env);
	const url = new URL(c.req.url);

	// The IdP reports user-visible failures (access_denied, ...) via ?error=.
	const idpError = url.searchParams.get("error");
	if (idpError) {
		console.error("auth.callback.idp_error", idpError, url.searchParams.get("error_description") ?? "");
		return c.text(`Login failed: ${idpError}`, 403);
	}

	const code = url.searchParams.get("code");
	const state = url.searchParams.get("state");
	if (!code || !state) {
		return c.text("Missing code or state", 400);
	}

	// 1. Recover and verify the signed state cookie.
	const stateCookie = parseCookies(c.req.header("cookie"))[STATE_COOKIE];
	if (!stateCookie) {
		return c.text("Missing login state cookie. Please try signing in again.", 403);
	}
	let codeVerifier: string;
	let returnTo: string;
	try {
		const { payload } = await jwtVerify(stateCookie, sessionKey(env), {
			issuer: SELF_JWT_ISSUER,
			audience: STATE_JWT_AUDIENCE,
		});
		if (payload.st !== state) {
			return c.text("State mismatch. Please try signing in again.", 403);
		}
		codeVerifier = payload.cv as string;
		returnTo = sanitizeReturnTo(payload.rt as string | undefined);
	} catch {
		return c.text("Invalid or expired login state. Please try signing in again.", 403);
	}

	// 2. Exchange the authorization code for tokens.
	const tokenParams = new URLSearchParams({
		grant_type: "authorization_code",
		code,
		redirect_uri: getRedirectUri(c),
		client_id: env.ID_ORG_AI_CLIENT_ID,
		code_verifier: codeVerifier,
	});
	// Confidential clients authenticate with client_secret_post; public
	// clients (auth method "none") send only client_id + PKCE verifier.
	if (env.ID_ORG_AI_CLIENT_SECRET) {
		tokenParams.set("client_secret", env.ID_ORG_AI_CLIENT_SECRET);
	}

	let idToken: string;
	try {
		const tokenRes = await fetch(`${issuer}/oauth/token`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: tokenParams.toString(),
		});
		if (!tokenRes.ok) {
			// Log the IdP's OAuth error (never the code or tokens) so
			// `wrangler tail` shows why a sign-in failed.
			const detail = (await tokenRes.text().catch(() => "")).slice(0, 300);
			console.error("auth.callback.token_exchange_failed", tokenRes.status, detail);
			return c.text("Token exchange failed. Please try signing in again.", 403);
		}
		const tokens = (await tokenRes.json()) as { id_token?: string };
		if (!tokens.id_token) {
			console.error("auth.callback.no_id_token");
			return c.text("Token response did not include an id_token.", 403);
		}
		idToken = tokens.id_token;
	} catch (err) {
		console.error("auth.callback.token_exchange_error", String(err));
		return c.text("Token exchange failed. Please try signing in again.", 502);
	}

	// 3. Verify the id_token cryptographically (RS256/ES256 via JWKS).
	let claims: {
		sub?: string;
		name?: string;
		preferred_username?: string;
		email?: string;
		email_verified?: boolean;
		picture?: string;
	};
	try {
		const jwks = getRemoteJwks(`${issuer}/.well-known/jwks.json`);
		const { payload } = await jwtVerify(idToken, jwks, {
			issuer,
			audience: env.ID_ORG_AI_CLIENT_ID,
		});
		claims = payload;
	} catch (err) {
		console.error("auth.callback.id_token_invalid", String(err));
		return c.text("Invalid id_token. Please try signing in again.", 403);
	}

	// 4. Mint our session JWT. We re-sign rather than store the raw id_token
	// so per-request verification is a local HMAC check (no JWKS fetch) and
	// the session TTL is decoupled from the id_token's short expiry.
	const sessionJwt = await new SignJWT({
		sub: claims.sub,
		name: claims.name,
		preferred_username: claims.preferred_username,
		email: claims.email,
		email_verified: claims.email_verified,
		picture: claims.picture,
	})
		.setProtectedHeader({ alg: "HS256" })
		.setIssuer(SELF_JWT_ISSUER)
		.setAudience(SESSION_JWT_AUDIENCE)
		.setIssuedAt()
		.setExpirationTime(`${SESSION_TTL_SECONDS}s`)
		.sign(sessionKey(env));

	const headers = new Headers({ location: returnTo });
	headers.append(
		"set-cookie",
		serializeCookie(SESSION_COOKIE, sessionJwt, { maxAge: SESSION_TTL_SECONDS }),
	);
	// Clear the single-use state cookie.
	headers.append("set-cookie", serializeCookie(STATE_COOKIE, "", { maxAge: 0 }));
	return new Response(null, { status: 302, headers });
}

/** GET /auth/logout — clear the session cookie and land on the root. */
export async function handleLogout(c: AppContext, env: Env): Promise<Response> {
	// env is accepted for signature symmetry with the other handlers (and so
	// a future IdP-side logout / token revocation hook has what it needs).
	void env;
	const headers = new Headers({ location: "/" });
	headers.append("set-cookie", serializeCookie(SESSION_COOKIE, "", { maxAge: 0 }));
	headers.append("set-cookie", serializeCookie(STATE_COOKIE, "", { maxAge: 0 }));
	return new Response(null, { status: 302, headers });
}

// ---------------------------------------------------------------------------
// Small helpers: cookies + base64url
// ---------------------------------------------------------------------------

/** Parse a Cookie request header into a name → value map. */
function parseCookies(header: string | undefined): Record<string, string> {
	const out: Record<string, string> = {};
	if (!header) return out;
	for (const part of header.split(";")) {
		const eq = part.indexOf("=");
		if (eq === -1) continue;
		const name = part.slice(0, eq).trim();
		const value = part.slice(eq + 1).trim();
		if (name) out[name] = value;
	}
	return out;
}

/**
 * Serialize a Set-Cookie value with our standard hardened attributes:
 * HttpOnly (no script access), Secure (HTTPS only — auth modes only run in
 * production), SameSite=Lax (sent on top-level navigations, so the IdP
 * redirect back to /auth/callback still carries the state cookie), Path=/.
 * maxAge 0 expires the cookie immediately (used for clearing).
 */
function serializeCookie(
	name: string,
	value: string,
	opts: { maxAge: number },
): string {
	return [
		`${name}=${value}`,
		`Max-Age=${opts.maxAge}`,
		"Path=/",
		"HttpOnly",
		"Secure",
		"SameSite=Lax",
	].join("; ");
}

/** base64url (RFC 4648 §5, unpadded) encode raw bytes. */
function base64UrlEncode(bytes: Uint8Array): string {
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
