/**
 * Throwaway Postgres lifecycle for the round-trip — a private cluster on a unix socket
 * (no TCP, no port contention) under a temp dir, torn down after. Uses the local
 * `pg_ctl` / `initdb` (Homebrew Postgres); no Docker. Returns null-friendly availability
 * so the round-trip test skips cleanly where Postgres is absent.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Whether pg_ctl / initdb are on PATH. */
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
  /** The unix-socket directory to pass as the pg client `host`. */
  socketDir: string;
  stop(): void;
}

/** Initializes and starts a private cluster; throws if pg_ctl is unavailable. */
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
        // best-effort; the temp dir is removed regardless.
      }
      rmSync(base, { recursive: true, force: true });
    },
  };
}
