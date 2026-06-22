import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// Alias the runtime to its TypeScript source so the example runs without a build step;
// vitest transpiles it. A real consumer would instead `pnpm add @demesne/runtime`.
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // The round-trip boots a real Postgres; give it room.
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
  resolve: {
    alias: {
      "@demesne/runtime": fileURLToPath(new URL("../runtime/src/index.ts", import.meta.url)),
    },
  },
});
