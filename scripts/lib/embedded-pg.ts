// Embedded PostgreSQL lifecycle shared by `bun run dev` (mode A) and scripts/spikes/embedded-pg.ts.
//
// `embedded-postgres` does initdb and starts `postgres` as a child of this process. Two of its
// behaviours are overridden here on purpose:
//  * On import it registers async-exit-hook handlers for SIGINT/SIGTERM/beforeExit/exit that stop
//    every cluster and then call process.exit(). That would race (and pre-empt) the dev
//    supervisor's own ordered shutdown, and `beforeExit` would turn every exit code into 0, so the
//    handlers are removed right after the import.
//  * Its stop() is `taskkill /f /t` on Windows (a crash, followed by WAL recovery on the next
//    start). We stop with `pg_ctl stop -m fast` and only fall back to the library's kill.
import { existsSync } from "node:fs";
import { appendFile, mkdir, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import type EmbeddedPostgresClass from "embedded-postgres";
import { isListening } from "./net.ts";

export interface EmbeddedPgOptions {
  /** Cluster root; holds data/, log/ and socket/ (contract §2.3 uses `.monaca/pg`). */
  baseDir: string;
  port: number;
  user: string;
  password: string;
  /** Receives every PostgreSQL log line (initdb and server). Defaults to discarding them. */
  onLog?: (line: string) => void;
  /**
   * Extra `postgres` flags, for a disposable benchmark cluster: `shared_preload_libraries`,
   * `fsync=off`, and any other setting the run must record. They are appended after the fixed
   * `listen_addresses` flag, so the later `-c` wins.
   */
  extraPostgresFlags?: string[];
  /**
   * How long to wait for "ready to accept connections". Generous on purpose: after an unclean
   * shutdown PostgreSQL fsyncs the whole data directory before it starts (measured 55 s for a
   * small cluster on this machine), and that recovery is not a failure.
   */
  startTimeoutMs?: number;
}

export interface EmbeddedPgHandle {
  readonly dataDir: string;
  readonly logFile: string;
  readonly port: number;
  /** Whether this start ran initdb (fresh cluster). */
  readonly initialised: boolean;
  readonly timings: { initialiseMs: number | null; startMs: number };
  /** `postgres://user:pass@127.0.0.1:port/db`; defaults to the superuser and `postgres`. */
  url(database?: string, user?: string, password?: string): string;
  /** Graceful `pg_ctl stop -m fast`; idempotent. Resolves once the port is closed. */
  stop(): Promise<{ graceful: boolean; ms: number }>;
}

interface PgBinaries {
  postgres: string;
  pg_ctl: string;
  initdb: string;
}

const EXIT_HOOK_EVENTS = ["exit", "beforeExit", "SIGHUP", "SIGINT", "SIGTERM", "SIGBREAK", "message"];

let loaded: Promise<{ ctor: typeof EmbeddedPostgresClass; bins: PgBinaries }> | undefined;

function platformPackage(): string {
  const { platform, arch } = process;
  if (platform === "win32" && arch === "x64") return "@embedded-postgres/windows-x64";
  if (platform === "linux" || platform === "darwin") return `@embedded-postgres/${platform}-${arch}`;
  throw new Error(`embedded PostgreSQL is not available for ${platform}-${arch}`);
}

async function loadEmbeddedPostgres(): Promise<{ ctor: typeof EmbeddedPostgresClass; bins: PgBinaries }> {
  const before = new Map<string, Function[]>(
    EXIT_HOOK_EVENTS.map((ev) => [ev, [...process.listeners(ev as NodeJS.Signals)]]),
  );
  const mod = (await import("embedded-postgres")) as { default: typeof EmbeddedPostgresClass };
  for (const ev of EXIT_HOOK_EVENTS) {
    const keep = before.get(ev) ?? [];
    for (const listener of process.listeners(ev as NodeJS.Signals)) {
      if (!keep.includes(listener)) process.removeListener(ev, listener as (...args: unknown[]) => void);
    }
  }
  // The platform binary package is a dependency of embedded-postgres, not of the repo root, so
  // it is resolved from embedded-postgres's own location (Bun's isolated node_modules/.bun layout).
  const libDir = dirname(Bun.resolveSync("embedded-postgres", import.meta.dir));
  const binsPath = Bun.resolveSync(platformPackage(), libDir);
  const bins = (await import(binsPath)) as PgBinaries;
  return { ctor: mod.default, bins };
}

function lineSplitter(sink: (line: string) => void): (chunk: string) => void {
  let pending = "";
  return (chunk) => {
    pending += chunk;
    const parts = pending.split(/\r?\n/);
    pending = parts.pop() ?? "";
    for (const part of parts) if (part.trim() !== "") sink(part);
  };
}

async function runQuiet(cmd: string[]): Promise<{ code: number; output: string }> {
  const proc = Bun.spawn(cmd, { stdout: "pipe", stderr: "pipe", stdin: "ignore" });
  const [out, err, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { code, output: (out + err).trim() };
}

export async function startEmbeddedPg(opts: EmbeddedPgOptions): Promise<EmbeddedPgHandle> {
  loaded ??= loadEmbeddedPostgres();
  const { ctor: EmbeddedPostgres, bins } = await loaded;

  const dataDir = join(opts.baseDir, "data");
  const logDir = join(opts.baseDir, "log");
  const socketDir = join(opts.baseDir, "socket");
  const logFile = join(logDir, "postgres.log");
  await mkdir(logDir, { recursive: true });
  await mkdir(socketDir, { recursive: true });

  const recent: string[] = [];
  const sink = (line: string): void => {
    recent.push(line);
    if (recent.length > 40) recent.shift();
    void appendFile(logFile, line + "\n").catch(() => undefined);
    opts.onLog?.(line);
  };
  const onChunk = lineSplitter(sink);

  // Windows PostgreSQL builds have no default Unix socket directory; Linux builds default to a
  // system path that may not be writable, so the socket always goes under baseDir there.
  const postgresFlags = ["-c", "listen_addresses=127.0.0.1"];
  if (process.platform !== "win32") postgresFlags.push("-k", socketDir);
  postgresFlags.push(...(opts.extraPostgresFlags ?? []));

  const pg = new EmbeddedPostgres({
    databaseDir: dataDir,
    port: opts.port,
    user: opts.user,
    password: opts.password,
    authMethod: "scram-sha-256",
    persistent: true,
    initdbFlags: ["--encoding=UTF8", "--locale=C"],
    postgresFlags,
    onLog: (message: string) => onChunk(message.replace(/^\[STDERR\] /, "")),
    onError: (error: unknown) => sink(error instanceof Error ? error.message : String(error)),
  });

  let initialiseMs: number | null = null;
  const initialised = !existsSync(join(dataDir, "PG_VERSION"));
  if (initialised) {
    // A data dir without PG_VERSION is a half-finished initdb; initdb refuses non-empty dirs.
    await rm(dataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
    const t0 = performance.now();
    await pg.initialise();
    initialiseMs = Math.round(performance.now() - t0);
  }

  const timeoutMs = opts.startTimeoutMs ?? 180_000;
  const t1 = performance.now();
  let timer: Timer | undefined;
  try {
    await Promise.race([
      pg.start().catch((err: unknown) => {
        // The library rejects with no reason when postgres exits during startup.
        const reason = err instanceof Error ? err.message : "postgres exited during startup";
        throw new Error(`${reason}\n--- last PostgreSQL log lines ---\n${recent.join("\n")}`);
      }),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`PostgreSQL did not become ready within ${timeoutMs} ms (log: ${logFile})`)),
          timeoutMs,
        );
      }),
    ]);
  } catch (err) {
    await pg.stop().catch(() => undefined);
    throw err;
  } finally {
    clearTimeout(timer);
  }
  const startMs = Math.round(performance.now() - t1);

  let stopped: Promise<{ graceful: boolean; ms: number }> | undefined;
  const stop = (): Promise<{ graceful: boolean; ms: number }> => {
    stopped ??= (async () => {
      const t = performance.now();
      const result = await runQuiet([bins.pg_ctl, "stop", "-D", dataDir, "-m", "fast", "-w", "-t", "30"]);
      let graceful = result.code === 0;
      // pg_ctl fails when the server is already gone (e.g. it received the console Ctrl-C itself);
      // only a still-open port means it really is still running.
      if (!graceful && (await isListening(opts.port))) {
        sink(`pg_ctl stop failed (${result.output}); forcing the server down`);
        await pg.stop();
      } else if (!graceful) {
        graceful = true;
      }
      return { graceful, ms: Math.round(performance.now() - t) };
    })();
    return stopped;
  };

  const enc = encodeURIComponent;
  return {
    dataDir,
    logFile,
    port: opts.port,
    initialised,
    timings: { initialiseMs, startMs },
    url: (database = "postgres", user = opts.user, password = opts.password) =>
      `postgres://${enc(user)}:${enc(password)}@127.0.0.1:${opts.port}/${enc(database)}`,
    stop,
  };
}

/** Double-quotes an identifier; the shape check keeps DDL free of anything user-shaped. */
export function quoteIdent(name: string): string {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(name)) throw new Error(`refusing unusual identifier ${JSON.stringify(name)}`);
  return `"${name}"`;
}

/** CREATE DATABASE unless it exists (CREATE DATABASE has no IF NOT EXISTS). */
export async function ensureDatabase(adminUrl: string, name: string): Promise<boolean> {
  const sql = new Bun.SQL(adminUrl, { max: 1 });
  try {
    const rows: unknown[] = await sql`select 1 from pg_database where datname = ${name}`;
    if (rows.length > 0) return false;
    await sql.unsafe(`CREATE DATABASE ${quoteIdent(name)}`);
    return true;
  } finally {
    await sql.close();
  }
}
