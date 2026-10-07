// Dynamic domain discovery for mailbox provisioning.
//
// The static DOMAINS env var stays authoritative when set, but accounts with
// hundreds or thousands of zones need discovery, not enumeration-by-hand.
// When CF_API_TOKEN (Zone:Read) is configured, we list the account's zones via
// the Cloudflare API, cache the result in R2 (the app's existing bucket) with
// a TTL, and serve substring search over the union of both sources.
//
// Note the app itself imposes no domain restriction on mailbox creation,
// inbound routing, or sending — a domain listed here is a *suggestion*. Mail
// only flows for zones whose Email Routing catch-all targets this Worker, and
// sending only works for domains onboarded to Email Service; keeping zones in
// that state belongs to whatever reconciles zone config (API/terraform/cron),
// not to this app.

const CACHE_KEY = "config/zones-cache.json";
const CACHE_TTL_MS = 15 * 60 * 1000;
const PAGE_SIZE = 50; // Cloudflare API max per_page for zones

interface ZonesCache {
	fetchedAt: number;
	zones: string[];
}

async function fetchAllZones(token: string, accountId?: string): Promise<string[]> {
	const zones: string[] = [];
	let page = 1;
	// Hard stop at 100 pages (5000 zones) as a runaway guard.
	while (page <= 100) {
		const params = new URLSearchParams({
			page: String(page),
			per_page: String(PAGE_SIZE),
			status: "active",
		});
		if (accountId) params.set("account.id", accountId);
		const res = await fetch(`https://api.cloudflare.com/client/v4/zones?${params}`, {
			headers: { Authorization: `Bearer ${token}` },
		});
		if (!res.ok) throw new Error(`Cloudflare zones API returned ${res.status}`);
		const data = (await res.json()) as {
			result: { name: string }[];
			result_info: { total_pages: number };
		};
		zones.push(...data.result.map((z) => z.name));
		if (page >= (data.result_info?.total_pages ?? 1)) break;
		page++;
	}
	return zones.sort();
}

/**
 * All known domains: static DOMAINS env union cached account zones.
 * Zone fetch failures degrade to the static list (never break the UI).
 */
export async function listDomains(env: {
	DOMAINS?: string;
	CF_API_TOKEN?: string;
	CF_ACCOUNT_ID?: string;
	BUCKET: R2Bucket;
}): Promise<{ domains: string[]; dynamic: boolean }> {
	const staticDomains = (env.DOMAINS || "").split(",").map((d) => d.trim()).filter(Boolean);
	if (!env.CF_API_TOKEN) return { domains: staticDomains, dynamic: false };

	let zones: string[] = [];
	try {
		const cached = await env.BUCKET.get(CACHE_KEY);
		if (cached) {
			const parsed = (await cached.json()) as ZonesCache;
			if (Date.now() - parsed.fetchedAt < CACHE_TTL_MS) zones = parsed.zones;
		}
		if (zones.length === 0) {
			zones = await fetchAllZones(env.CF_API_TOKEN, env.CF_ACCOUNT_ID);
			await env.BUCKET.put(
				CACHE_KEY,
				JSON.stringify({ fetchedAt: Date.now(), zones } satisfies ZonesCache),
			);
		}
	} catch (e) {
		console.error("Zone discovery failed, serving static DOMAINS only:", (e as Error).message);
	}

	return { domains: [...new Set([...staticDomains, ...zones])].sort(), dynamic: true };
}

/** Case-insensitive substring search, capped for combobox use. */
export function searchDomains(domains: string[], q: string, limit = 50): string[] {
	const needle = q.trim().toLowerCase();
	if (!needle) return domains.slice(0, limit);
	return domains.filter((d) => d.includes(needle)).slice(0, limit);
}
