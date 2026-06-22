import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],

    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
  resolve: {
    alias: {
      "@demesne/runtime": fileURLToPath(new URL("../runtime/src/index.ts", import.meta.url)),
    },
  },
});
