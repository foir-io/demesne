import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export default defineWorkersConfig({
  plugins: [
    {
      name: "wasm-as-workerd-module",
      enforce: "pre",
      resolveId(id, importer) {
        return id.endsWith(".wasm") && importer !== undefined ? { id: resolve(dirname(importer), id), external: true } : null;
      },
    },
  ],
  test: {
    include: ["test/**/*.test.ts"],
    server: { deps: { external: [/\.wasm$/] } },
    poolOptions: {
      workers: {
        singleWorker: true,
        miniflare: { compatibilityDate: "2026-01-01" },
      },
    },
  },
  resolve: {
    alias: [{ find: /^\.\.\/src\/index\.js$/, replacement: fileURLToPath(new URL("./src/index.workerd.ts", import.meta.url)) }],
  },
});
