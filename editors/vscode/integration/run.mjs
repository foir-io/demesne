import { runTests } from "@vscode/test-electron";
import { fileURLToPath } from "node:url";

await runTests({
  extensionDevelopmentPath: fileURLToPath(new URL("..", import.meta.url)),
  extensionTestsPath: fileURLToPath(new URL("./suite.js", import.meta.url)),
  launchArgs: ["--disable-extensions", "--disable-workspace-trust"],
});
