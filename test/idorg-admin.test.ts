/**
 * Mailbox admins come from id.org.ai, not a hardcoded list.
 *
 * Admin = the principal's id.org.ai `sub` holds owner/admin in the WorkOS org
 * MAILBOX_ADMIN_ORG_ID, asked over AUTH_SERVICE.orgRole and cached briefly.
 * MAILBOX_ADMINS stays only as a break-glass override, empty by default.
 */

import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("agents", () => ({ getAgentByName: vi.fn() }));

import { app as apiApp } from "../workers/index";
import {
	ADMIN_ROLE_TTL_MS,
	canAccessMailbox,
	clearAdminRoleCache,
	isAdmin,
	type Principal,
} from "../workers/lib/access";

const ORG = "org_platform";
const RONA: Principal = { sub: "idn_rona", email: "rona@x.com" };

function makeAuthService(roles: Record<string, string | null>) {
	return {
		orgRole: vi.fn(async (sub: string, _orgId?: string) => roles[sub] ?? null),
	};
}

function makeEnv(over: Record<string, unknown> = {}) {
	return {
		AUTH_MODE: "id.org.ai",
		MAILBOX_ADMIN_ORG_ID: ORG,
		BUCKET: { get: vi.fn(async () => null), head: vi.fn(async () => null) },
		...over,
	} as never;
}

beforeEach(() => clearAdminRoleCache());
afterEach(() => vi.useRealTimers());

describe("isAdmin from id.org.ai", () => {
	it("owner or admin of the admin org is a mailbox admin", async () => {
		for (const role of ["admin", "owner"]) {
			clearAdminRoleCache();
			const svc = makeAuthService({ idn_rona: role });
			expect(await isAdmin(makeEnv({ AUTH_SERVICE: svc }), RONA), role).toBe(true);
			expect(svc.orgRole).toHaveBeenCalledWith("idn_rona", ORG);
		}
	});

	it("editor, viewer, or no membership is not an admin", async () => {
		for (const role of ["editor", "viewer", "member", null]) {
			clearAdminRoleCache();
			const svc = makeAuthService({ idn_rona: role });
			expect(await isAdmin(makeEnv({ AUTH_SERVICE: svc }), RONA), String(role)).toBe(false);
		}
	});

	it("leaves the org to id.org.ai's default when MAILBOX_ADMIN_ORG_ID is unset", async () => {
		const svc = makeAuthService({ idn_rona: "admin" });
		expect(await isAdmin(makeEnv({ AUTH_SERVICE: svc, MAILBOX_ADMIN_ORG_ID: undefined }), RONA)).toBe(true);
		expect(svc.orgRole).toHaveBeenCalledWith("idn_rona", undefined);
	});

	it("caches the answer briefly, then asks again (a revoked role lapses)", async () => {
		vi.useFakeTimers();
		const roles: Record<string, string | null> = { idn_rona: "admin" };
		const svc = makeAuthService(roles);
		const env = makeEnv({ AUTH_SERVICE: svc });
		expect(await isAdmin(env, RONA)).toBe(true);
		roles.idn_rona = null; // revoked in WorkOS
		expect(await isAdmin(env, RONA)).toBe(true); // still cached
		expect(svc.orgRole).toHaveBeenCalledTimes(1);
		vi.advanceTimersByTime(ADMIN_ROLE_TTL_MS + 1);
		expect(await isAdmin(env, RONA)).toBe(false);
		expect(svc.orgRole).toHaveBeenCalledTimes(2);
	});

	it("caches negative answers too (no lookup per mailbox in a list)", async () => {
		const svc = makeAuthService({});
		const env = makeEnv({ AUTH_SERVICE: svc });
		for (let i = 0; i < 5; i++) expect(await isAdmin(env, RONA)).toBe(false);
		expect(svc.orgRole).toHaveBeenCalledTimes(1);
	});

	it("a failed lookup grants nothing and is not cached", async () => {
		const svc = { orgRole: vi.fn().mockRejectedValueOnce(new Error("boom")).mockResolvedValueOnce("admin") };
		const env = makeEnv({ AUTH_SERVICE: svc });
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		expect(await isAdmin(env, RONA)).toBe(false);
		expect(await isAdmin(env, RONA)).toBe(true);
		expect(svc.orgRole).toHaveBeenCalledTimes(2);
		warn.mockRestore();
	});

	it("never asks outside id.org.ai mode (an Access sub is not an id.org.ai identity)", async () => {
		const svc = makeAuthService({ idn_rona: "admin" });
		expect(await isAdmin(makeEnv({ AUTH_SERVICE: svc, AUTH_MODE: "cf-access" }), RONA)).toBe(false);
		expect(svc.orgRole).not.toHaveBeenCalled();
	});

	it("never asks for a principal without a sub", async () => {
		const svc = makeAuthService({});
		expect(await isAdmin(makeEnv({ AUTH_SERVICE: svc }), { email: "rona@x.com" })).toBe(false);
		expect(svc.orgRole).not.toHaveBeenCalled();
	});

	it("caches per sub (one person's answer is never reused for another)", async () => {
		const svc = makeAuthService({ idn_rona: "admin" });
		const env = makeEnv({ AUTH_SERVICE: svc });
		expect(await isAdmin(env, RONA)).toBe(true);
		expect(await isAdmin(env, { sub: "idn_other", email: "other@x.com" })).toBe(false);
	});
});

describe("MAILBOX_ADMINS break-glass", () => {
	it("is empty by default: no binding and no secret means no admins", async () => {
		expect(await isAdmin(makeEnv(), RONA)).toBe(false);
	});

	it("still admits a listed principal when id.org.ai is unbound or failing", async () => {
		expect(await isAdmin(makeEnv({ MAILBOX_ADMINS: "rona@x.com" }), RONA)).toBe(true);
		const failing = { orgRole: vi.fn().mockRejectedValue(new Error("down")) };
		expect(await isAdmin(makeEnv({ AUTH_SERVICE: failing, MAILBOX_ADMINS: "idn_rona" }), RONA)).toBe(true);
		// The override short-circuits: id.org.ai is not asked.
		expect(failing.orgRole).not.toHaveBeenCalled();
	});
});

describe("an id.org.ai admin through the API", () => {
	function setup(roles: Record<string, string | null>) {
		const store = new Map<string, string>([
			["mailboxes/alice@x.com.json", JSON.stringify({ fromName: "a" })],
			["mailboxes/legacy@x.com.json", JSON.stringify({ fromName: "l" })],
			["mailbox-acl/alice@x.com.json", JSON.stringify({ owner: "alice@x.com", members: [] })],
		]);
		const bucket = {
			store,
			get: vi.fn(async (key: string) => {
				const v = store.get(key);
				return v === undefined ? null : { json: async () => JSON.parse(v), text: async () => v, body: v };
			}),
			head: vi.fn(async (key: string) => (store.has(key) ? { key } : null)),
			put: vi.fn(async (key: string, value: string) => void store.set(key, value)),
			list: vi.fn(async ({ prefix }: { prefix: string }) => ({
				objects: [...store.keys()].filter((k) => k.startsWith(prefix)).map((key) => ({ key })),
			})),
			delete: vi.fn(async () => {
				throw new Error("BUCKET.delete must never be called");
			}),
		};
		const svc = makeAuthService(roles);
		const env = {
			AUTH_MODE: "id.org.ai",
			MAILBOX_ADMIN_ORG_ID: ORG,
			AUTH_SERVICE: svc,
			BUCKET: bucket,
			MAILBOX: {
				idFromName: (n: string) => n,
				get: () => ({ getFolders: vi.fn(async () => []), getEmails: vi.fn(async () => []), countEmails: vi.fn(async () => 0) }),
			},
			EMAIL_ADDRESSES: [],
		};
		const outer = new Hono<{ Variables: { principal: Principal } }>();
		outer.use("*", async (c, next) => {
			const who = c.req.header("x-test-principal");
			if (who) c.set("principal", JSON.parse(who));
			await next();
		});
		outer.route("/", apiApp as never);
		const call = (who: Principal, path: string, init: RequestInit = {}) =>
			outer.request(
				path,
				{ ...init, headers: { "Content-Type": "application/json", "x-test-principal": JSON.stringify(who) } },
				env as never,
			);
		return { env, call, svc };
	}

	it("sees every mailbox, including ones with no ACL", async () => {
		const t = setup({ idn_rona: "admin" });
		const list = (await (await t.call(RONA, "/api/v1/mailboxes")).json()) as Array<{ id: string }>;
		expect(list.map((m) => m.id).sort()).toEqual(["alice@x.com", "legacy@x.com"]);
		expect(await canAccessMailbox(t.env as never, RONA, "legacy@x.com")).toBe(true);
	});

	it("a non-admin sees only what they own or were granted", async () => {
		const t = setup({ idn_rona: "editor" });
		const list = (await (await t.call(RONA, "/api/v1/mailboxes")).json()) as Array<{ id: string }>;
		expect(list).toEqual([]);
	});

	it("may create a mailbox on someone else's behalf", async () => {
		const t = setup({ idn_rona: "owner" });
		const res = await t.call(RONA, "/api/v1/mailboxes", {
			method: "POST",
			body: JSON.stringify({ name: "Agent", email: "agent@x.com", owner: "alice@x.com" }),
		});
		expect(res.status).toBe(201);
	});
});
