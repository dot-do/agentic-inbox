// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

// Standalone vitest config — deliberately does NOT extend vite.config.ts
// (the @cloudflare/vite-plugin there is incompatible with vitest's node
// runner). Tests in test/ exercise worker modules with mocked bindings.
import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["test/**/*.test.ts"],
		environment: "node",
	},
});
