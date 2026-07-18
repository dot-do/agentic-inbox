// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

export interface Env extends Cloudflare.Env {
	POLICY_AUD: string;
	TEAM_DOMAIN: string;
	// Optional: dynamic domain discovery via the Cloudflare API. When set,
	// /api/v1/domains serves the account's zone list (cached in R2) in addition
	// to the static DOMAINS env var, and the UI becomes a searchable combobox.
	CF_API_TOKEN?: string; // needs Zone:Read
	CF_ACCOUNT_ID?: string; // optional: restrict zone listing to one account
}
