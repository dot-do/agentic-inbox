// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Hono middleware to handle repetitive Mailbox Durable Object instantiation.
 * Checks the mailbox exists in R2 (and is not soft-deleted), checks the
 * authenticated principal may access it (workers/lib/access.ts — deny by
 * default), then instantiates the DO stub and attaches it to the Hono
 * context (`c.var.mailboxStub`).
 */
import { createMiddleware } from "hono/factory";
import type { MailboxDO } from "../durableObject";
import type { Env } from "../types";
import { canAccessMailbox, isMailboxDeleted, type Principal } from "./access";

export type MailboxContext = {
	Bindings: Env;
	Variables: {
		mailboxStub: DurableObjectStub<MailboxDO>;
		/** Set by the auth middleware in workers/app.ts. */
		principal: Principal;
		/** Decoded mailbox id, set by requireMailbox. */
		mailboxId: string;
	};
};

export const requireMailbox = createMiddleware<MailboxContext>(async (c, next) => {
	const rawId = c.req.param("mailboxId");
	if (!rawId) return c.json({ error: "Mailbox ID required" }, 400);
	const mailboxId = decodeURIComponent(rawId);

	// Verify mailbox exists and has not been soft-deleted
	const key = `mailboxes/${mailboxId}.json`;
	const obj = await c.env.BUCKET.head(key);
	if (!obj || (await isMailboxDeleted(c.env.BUCKET, mailboxId))) {
		return c.json({ error: "Not found" }, 404);
	}

	// Authorize. A mailbox the caller may not read answers exactly like a
	// missing one, so access checks do not leak which addresses exist.
	if (!(await canAccessMailbox(c.env, c.get("principal"), mailboxId))) {
		return c.json({ error: "Not found" }, 404);
	}

	// Instantiate DO stub
	const ns = c.env.MAILBOX;
	const id = ns.idFromName(mailboxId);
	const stub = ns.get(id);

	c.set("mailboxStub", stub);
	c.set("mailboxId", mailboxId);

	await next();
});
