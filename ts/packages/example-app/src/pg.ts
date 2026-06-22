

import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export function pgCtlAvailable(): boolean {
  try {
    execFileSync("pg_ctl", ["--version"], { stdio: "ignore" });
    execFileSync("initdb", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

export interface Cluster {

  socketDir: string;
  stop(): void;
}

export function startCluster(): Cluster {
  const base = mkdtempSync(join(tmpdir(), "demesne-rt-"));
  const dataDir = join(base, "data");
  const socketDir = join(base, "sock");
  mkdirSync(socketDir, { recursive: true });

  execFileSync("initdb", ["-D", dataDir, "-U", "postgres", "--auth=trust", "-E", "UTF8"], {
    stdio: "ignore",
  });
  execFileSync(
    "pg_ctl",
    ["-D", dataDir, "-o", `-c listen_addresses='' -c unix_socket_directories='${socketDir}'`, "-w", "start"],
    { stdio: "ignore" },
  );

  return {
    socketDir,
    stop() {
      try {
        execFileSync("pg_ctl", ["-D", dataDir, "-w", "stop"], { stdio: "ignore" });
      } catch {

      }
      rmSync(base, { recursive: true, force: true });
    },
  };
}
