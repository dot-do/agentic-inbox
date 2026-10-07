// Per-mailbox authorization.
//
// Replaces the old "single trust boundary" model (any signed-in principal
// could read every mailbox). Deny by default: a principal may use a mailbox
// only when ONE of these holds:
//
//   1. The principal is an admin (see "Who is an admin" below).
//   2. The principal's verified email IS the mailbox address (the address
//      holder owns their own mailbox).
//   3. The mailbox ACL (R2 object `mailbox-acl/<mailboxId>.json`) names the
//      principal as `owner` or lists it in `members`.
//
// Mailboxes with no ACL object (legacy rows, wildcard catch-all
// auto-provisioned mailboxes, the ledger index) are therefore readable only
// by admins and by the address holder.
//
// The ACL lives in its own R2 object, NOT inside the settings JSON, so a
// member who PUTs mailbox settings can never rewrite who has access.
//
// Identities come from the authenticated principal (workers/lib/auth.ts):
// id.org.ai session cookie, id.org.ai bearer token, or a Cloudflare Access
// JWT. Matching is case-insensitive on email and sub.
//
// Who is an admin. Admin is a role held in id.org.ai, not a list kept here:
//
//   a. id.org.ai (the source of truth): the principal's id.org.ai `sub` holds
//      the `owner` or `admin` role in the WorkOS organization
//      MAILBOX_ADMIN_ORG_ID (unset: id.org.ai's platform org), asked over the
//      AUTH_SERVICE binding (`orgRole(sub, orgId)`). The answer is cached per
//      isolate for ADMIN_ROLE_TTL_MS, so a granted or revoked role takes
//      effect within a minute. Only in AUTH_MODE "id.org.ai" (an Access `sub`
//      is not an id.org.ai identity). A failed lookup is not cached and
//      grants nothing.
//   b. Break-glass only: the MAILBOX_ADMINS secret (emails or subs, comma/space
//      separated or a JSON array). Empty by default; set it only to regain
//      access when id.org.ai is unreachable or misconfigured, and remove it
//      afterwards (`wrangler secret delete MAILBOX_ADMINS`).

import type { Env } from "../types";

/** The authenticated caller, as resolved by workers/lib/auth.ts. */
export interface Principal {
	/** Stable subject id from the IdP (id.org.ai `sub`, Access `sub`). */
	sub?: string;
	/** Email, only set when the IdP did not mark it unverified. */
	email?: string;
	/**
	 * Local development only (import.meta.env.DEV, where auth is skipped).
	 * Never produced by any production auth path.
	 */
	dev?: true;
}

export interface MailboxAcl {
	/** Email or sub of the owner. */
	owner?: string;
	/** Emails or subs of explicitly granted members. */
	members: string[];
}

/** Header the worker uses to hand the principal to the MCP Durable Object.
 * Always stripped from the inbound request and re-set by the worker, so a
 * client can never supply its own. */
export const PRINCIPAL_HEADER = "x-inbox-principal";

/** R2 key prefix for mailbox ACL objects. */
export const ACL_PREFIX = "mailbox-acl/";

/** R2 key prefix for soft-delete tombstones of whole mailboxes. */
export const MAILBOX_TOMBSTONE_PREFIX = "mailbox-deleted/";

export function aclKey(mailboxId: string): string {
	return `${ACL_PREFIX}${mailboxId}.json`;
}

export function mailboxTombstoneKey(mailboxId: string): string {
	return `${MAILBOX_TOMBSTONE_PREFIX}${mailboxId}.json`;
}

const norm = (s: string) => s.trim().toLowerCase();

/** Lower-cased identifiers this principal can be matched by. */
export function principalIds(p: Principal | undefined | null): string[] {
	if (!p) return [];
	const ids: string[] = [];
	if (p.email) ids.push(norm(p.email));
	if (p.sub) ids.push(norm(p.sub));
	return ids.filter(Boolean);
}

/** Preferred single id to record as an owner: email, else sub. */
export function primaryId(p: Principal): string | undefined {
	return p.email ? norm(p.email) : p.sub ? norm(p.sub) : undefined;
}

/** Parse MAILBOX_ADMINS: JSON array, or comma/whitespace-separated list. */
export function parseAdminList(raw: unknown): Set<string> {
	let items: unknown[] = [];
	if (Array.isArray(raw)) {
		items = raw;
	} else if (typeof raw === "string" && raw.trim()) {
		const s = raw.trim();
		if (s.startsWith("[")) {
			try {
				const parsed = JSON.parse(s);
				if (Array.isArray(parsed)) items = parsed;
			} catch {
				items = [];
			}
		} else {
			items = s.split(/[\s,]+/);
		}
	}
	return new Set(
		items.filter((x): x is string => typeof x === "string").map(norm).filter(Boolean),
	);
}

/** Roles in the admin org that make a principal a mailbox admin. */
export const ADMIN_ROLES: ReadonlySet<string> = new Set(["owner", "admin"]);

/** How long an id.org.ai role answer is reused within an isolate. */
export const ADMIN_ROLE_TTL_MS = 60_000;

/** Cap on cached answers per isolate; the cache is cleared when exceeded. */
const ADMIN_ROLE_CACHE_MAX = 1_000;

/** The slice of id.org.ai's AuthService RPC this module uses. */
export interface OrgRoleService {
	orgRole(sub: string, orgId?: string): Promise<string | null>;
}

const adminRoleCache = new Map<string, { admin: boolean; expires: number }>();

/** Test hook: forget cached id.org.ai answers. */
export function clearAdminRoleCache(): void {
	adminRoleCache.clear();
}

// Bindings and vars read through tolerant accessors: wrangler types renders
// them into the generated Cloudflare.Env, so they are not redeclared on Env.
function orgRoleService(env: Env): OrgRoleService | undefined {
	const svc = (env as unknown as { AUTH_SERVICE?: Partial<OrgRoleService> }).AUTH_SERVICE;
	return svc && typeof svc.orgRole === "function" ? (svc as OrgRoleService) : undefined;
}

function adminOrgId(env: Env): string | undefined {
	const v = (env as unknown as { MAILBOX_ADMIN_ORG_ID?: unknown }).MAILBOX_ADMIN_ORG_ID;
	return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

/** Break-glass: MAILBOX_ADMINS lists this principal's email or sub. */
export function isBreakGlassAdmin(env: Env, p: Principal | undefined | null): boolean {
	if (!p) return false;
	const admins = parseAdminList(env.MAILBOX_ADMINS);
	return principalIds(p).some((id) => admins.has(id));
}

/** id.org.ai: the principal's sub holds owner/admin in the admin org (cached). */
export async function isIdOrgAiAdmin(env: Env, p: Principal | undefined | null): Promise<boolean> {
	if (!p?.sub || env.AUTH_MODE !== "id.org.ai") return false;
	const svc = orgRoleService(env);
	if (!svc) return false;
	const org = adminOrgId(env);
	const key = `${org ?? ""}|${p.sub}`;
	const now = Date.now();
	const hit = adminRoleCache.get(key);
	if (hit && hit.expires > now) return hit.admin;
	let admin: boolean;
	try {
		const role = await svc.orgRole(p.sub, org);
		admin = typeof role === "string" && ADMIN_ROLES.has(role);
	} catch (err) {
		// Not cached: the next request asks again. Grants nothing meanwhile.
		console.warn("[access] id.org.ai orgRole lookup failed", err instanceof Error ? err.message : err);
		return false;
	}
	if (adminRoleCache.size >= ADMIN_ROLE_CACHE_MAX) adminRoleCache.clear();
	adminRoleCache.set(key, { admin, expires: now + ADMIN_ROLE_TTL_MS });
	return admin;
}

/** Admin: an id.org.ai org owner/admin, or listed in the break-glass MAILBOX_ADMINS. */
export async function isAdmin(env: Env, p: Principal | undefined | null): Promise<boolean> {
	if (!p) return false;
	if (p.dev) return true;
	if (isBreakGlassAdmin(env, p)) return true;
	return isIdOrgAiAdmin(env, p);
}

/** True when the principal's verified email is the mailbox address. */
export function isAddressHolder(p: Principal | undefined | null, mailboxId: string): boolean {
	return !!p?.email && norm(p.email) === norm(mailboxId);
}

/**
 * True only when `address` is exactly the principal's own verified email:
 * plain ASCII, compared after trim + lower-case, nothing else. Plus/dot
 * aliases ("me+bot@x", "m.e@x") are different addresses and never match.
 * Principal.email is only ever set for verified emails (workers/lib/auth.ts).
 */
export function isOwnVerifiedAddress(p: Principal | undefined | null, address: string): boolean {
	if (!p?.email) return false;
	const a = address.trim();
	if (!/^[\x21-\x7e]+$/.test(a)) return false;
	return norm(a) === norm(p.email);
}

export async function getMailboxAcl(bucket: R2Bucket, mailboxId: string): Promise<MailboxAcl | null> {
	const obj = await bucket.get(aclKey(mailboxId));
	if (!obj) return null;
	try {
		const raw = (await obj.json()) as Partial<MailboxAcl>;
		return {
			owner: typeof raw.owner === "string" ? norm(raw.owner) : undefined,
			members: Array.isArray(raw.members)
				? raw.members.filter((m): m is string => typeof m === "string").map(norm).filter(Boolean)
				: [],
		};
	} catch {
		// A corrupt ACL grants nothing (deny by default).
		return { members: [] };
	}
}

export async function putMailboxAcl(bucket: R2Bucket, mailboxId: string, acl: MailboxAcl): Promise<MailboxAcl> {
	const clean: MailboxAcl = {
		owner: acl.owner ? norm(acl.owner) : undefined,
		members: [...new Set(acl.members.map(norm).filter(Boolean))],
	};
	await bucket.put(aclKey(mailboxId), JSON.stringify(clean));
	return clean;
}

/** Read access: admin, address holder, ACL owner, or ACL member. */
export async function canAccessMailbox(
	env: Env,
	p: Principal | undefined | null,
	mailboxId: string,
): Promise<boolean> {
	if (!p) return false;
	if (await isAdmin(env, p)) return true;
	if (isAddressHolder(p, mailboxId)) return true;
	const ids = principalIds(p);
	if (ids.length === 0) return false;
	const acl = await getMailboxAcl(env.BUCKET, mailboxId);
	if (!acl) return false;
	if (acl.owner && ids.includes(acl.owner)) return true;
	return acl.members.some((m) => ids.includes(m));
}

/** Manage access (grant members, delete mailbox): admin, address holder, or ACL owner. */
export async function canManageMailbox(
	env: Env,
	p: Principal | undefined | null,
	mailboxId: string,
): Promise<boolean> {
	if (!p) return false;
	if (await isAdmin(env, p)) return true;
	if (isAddressHolder(p, mailboxId)) return true;
	const ids = principalIds(p);
	const acl = await getMailboxAcl(env.BUCKET, mailboxId);
	return !!acl?.owner && ids.includes(acl.owner);
}

export async function isMailboxDeleted(bucket: R2Bucket, mailboxId: string): Promise<boolean> {
	return !!(await bucket.head(mailboxTombstoneKey(mailboxId)));
}

/** Keep only the mailboxes this principal may read. */
export async function filterAccessibleMailboxes<T extends { id: string }>(
	env: Env,
	p: Principal | undefined | null,
	mailboxes: T[],
): Promise<T[]> {
	if (!p) return [];
	if (await isAdmin(env, p)) return mailboxes;
	const allowed = await Promise.all(mailboxes.map((m) => canAccessMailbox(env, p, m.id)));
	return mailboxes.filter((_, i) => allowed[i]);
}

/** Decode the principal the worker attached for the MCP Durable Object. */
export function principalFromHeaders(headers: Record<string, string | string[] | undefined> | undefined): Principal | null {
	const raw = headers?.[PRINCIPAL_HEADER];
	const value = Array.isArray(raw) ? raw[0] : raw;
	if (!value) return null;
	try {
		const p = JSON.parse(value) as Principal;
		if (!p || typeof p !== "object") return null;
		const out: Principal = {};
		if (typeof p.sub === "string" && p.sub) out.sub = p.sub;
		if (typeof p.email === "string" && p.email) out.email = p.email;
		if (p.dev === true) out.dev = true;
		return out.sub || out.email || out.dev ? out : null;
	} catch {
		return null;
	}
}
