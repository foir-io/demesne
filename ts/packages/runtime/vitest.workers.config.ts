import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      miniflare: {
        compatibilityDate: "2026-01-01",
        modulesRules: [{ type: "CompiledWasm", include: ["**/*.wasm"] }],
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
    maxWorkers: 1,
    fsModuleCache: false,
  },
  resolve: {
    alias: [{ find: /^\.\.\/src\/index\.js$/, replacement: fileURLToPath(new URL("./src/index.workerd.ts", import.meta.url)) }],
  },
});
