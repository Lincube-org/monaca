// Shared plumbing for `scripts/bench/run.ts`: a disposable PostgreSQL, the server process, HTTP
// calls with timings, percentiles, pg_stat_statements, and the tenant-pool counters on /metrics.
//
// Every helper here is deliberately small and synchronous with the run: the benchmark is one
// process that owns its fixtures, so there is no hidden state a later profile could inherit.

import { existsSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";

import { quoteIdent, startEmbeddedPg, type EmbeddedPgHandle } from "../lib/embedded-pg.ts";
import { describeNetError, waitForHttp } from "../lib/net.ts";

export const ROOT = join(import.meta.dir, "..", "..");

/** The benchmark's disposable cluster; fixed so a rerun reuses the same data directory. */
const EMBEDDED_PORT = 5442;
const EMBEDDED_BASE = join(ROOT, ".monaca", "bench", "pg");

/** Durability is off on purpose: the cluster is disposable and the numbers are comparative. */
const PG_FLAGS = [
  "-c",
  "shared_preload_libraries=pg_stat_statements",
  "-c",
  "fsync=off",
  "-c",
  "synchronous_commit=off",
  "-c",
  "full_page_writes=off",
  "-c",
  "max_connections=500",
  "-c",
  "shared_buffers=256MB",
  "-c",
  "work_mem=8MB",
];

interface RawSql {
  unsafe: (query: string, values?: unknown[]) => Promise<unknown[]>;
}

/** `Bun.SQL` hides `unsafe` behind a type the benchmark needs for dynamic identifiers. */
export const raw = (db: Bun.SQL, query: string, values?: unknown[]): Promise<unknown[]> =>
  (db as unknown as RawSql).unsafe(query, values);

export function withDatabase(url: string, database: string): string {
  const parsed = new URL(url);
  parsed.pathname = `/${database}`;
  return parsed.toString();
}

export function withCredentials(url: string, user: string, password: string): string {
  const parsed = new URL(url);
  parsed.username = user;
  parsed.password = password;
  return parsed.toString();
}

export interface BenchPg {
  /** A URL whose database can be replaced; always the `postgres` maintenance database. */
  readonly adminUrl: string;
  readonly port: number;
  readonly source: "embedded" | "external";
  readonly version: string;
  readonly settings: Record<string, string>;
  readonly statsAvailable: boolean;
  readonly statsError: string;
  stop(): Promise<void>;
}

export interface StartPgOptions {
  /** `MONACA_BENCH_PG_URL` — a `postgres` database URL on an externally started cluster. */
  externalUrl?: string;
}

/** Start (or attach to) the disposable cluster and prove `pg_stat_statements` is usable. */
export async function startPg(options: StartPgOptions): Promise<BenchPg> {
  let handle: EmbeddedPgHandle | undefined;
  let adminUrl: string;
  let source: BenchPg["source"];

  if (options.externalUrl !== undefined && options.externalUrl !== "") {
    adminUrl = withDatabase(options.externalUrl, "postgres");
    source = "external";
  } else {
    await mkdir(dirname(EMBEDDED_BASE), { recursive: true });
    handle = await startEmbeddedPg({
      baseDir: EMBEDDED_BASE,
      port: EMBEDDED_PORT,
      user: "postgres",
      password: "postgres",
      extraPostgresFlags: PG_FLAGS,
      onLog: () => undefined,
    });
    adminUrl = handle.url("postgres");
    source = "embedded";
  }

  const sql = new Bun.SQL(adminUrl);
  try {
    const versionRow = (await raw(sql, "SHOW server_version")) as { server_version: string }[];
    const version = versionRow[0]?.server_version ?? "unknown";

    const settingRows = (await raw(
      sql,
      "SELECT name, setting FROM pg_settings WHERE name IN " +
        "('shared_buffers','max_connections','fsync','synchronous_commit','full_page_writes','work_mem')",
    )) as { name: string; setting: string }[];
    const settings: Record<string, string> = {};
    for (const row of settingRows) settings[row.name] = row.setting;

    let statsAvailable = true;
    let statsError = "";
    try {
      await raw(sql, "CREATE EXTENSION IF NOT EXISTS pg_stat_statements");
    } catch (err) {
      statsAvailable = false;
      statsError = err instanceof Error ? err.message : String(err);
    }

    const parsed = new URL(adminUrl);
    const port = Number(parsed.port === "" ? "5432" : parsed.port);
    const stop = async (): Promise<void> => {
      if (handle !== undefined) {
        await handle.stop();
      }
    };
    return { adminUrl, port, source, version, settings, statsAvailable, statsError, stop };
  } catch (err) {
    await handle?.stop();
    throw err;
  } finally {
    await sql.close();
  }
}

/** Drop every database a previous benchmark run could have left behind. */
export async function resetDatabases(pg: BenchPg): Promise<void> {
  const sql = new Bun.SQL(pg.adminUrl);
  try {
    const rows = (await raw(
      sql,
      "SELECT datname FROM pg_database WHERE datname LIKE 'mt_%' OR datname = 'monaca_control'",
    )) as { datname: string }[];
    for (const row of rows) {
      const name = quoteIdent(row.datname);
      await raw(
        sql,
        `SELECT pg_terminate_backend(pid) FROM pg_stat_activity
         WHERE datname = ${literal(row.datname)} AND pid <> pg_backend_pid()`,
      );
      await raw(sql, `DROP DATABASE IF EXISTS ${name}`);
    }
    await raw(sql, "CREATE DATABASE monaca_control");
  } finally {
    await sql.close();
  }
}

export async function createDatabase(pg: BenchPg, name: string): Promise<void> {
  const sql = new Bun.SQL(pg.adminUrl);
  try {
    await raw(sql, `CREATE DATABASE ${quoteIdent(name)}`);
  } finally {
    await sql.close();
  }
}

function literal(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

/** Run `monaca-server migrate` / `bootstrap` and fail with its combined output when it fails. */
export async function runServerCommand(
  bin: string,
  args: string[],
  env: Record<string, string>,
  label: string,
): Promise<void> {
  const proc = Bun.spawn([bin, ...args], {
    cwd: ROOT,
    env: { ...process.env, ...env },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  if (code !== 0) {
    throw new Error(`${label} exited ${code}\n--- stdout ---\n${stdout}\n--- stderr ---\n${stderr}`);
  }
}

export interface ServerHandle {
  readonly base: string;
  stop(): Promise<void>;
}

/** Start `monaca-server serve` and wait for `/healthz`; keep the last stderr lines for failures. */
export async function startServer(
  bin: string,
  base: string,
  env: Record<string, string>,
): Promise<ServerHandle> {
  const log: string[] = [];
  const proc = Bun.spawn([bin, "serve"], {
    cwd: ROOT,
    env: { ...process.env, ...env },
    stdout: "ignore",
    stderr: "pipe",
  });
  const reader = (async (): Promise<void> => {
    for await (const chunk of proc.stderr) {
      const text = String(chunk);
      log.push(text);
      while (log.join("").length > 8_000) log.shift();
    }
  })().catch(() => undefined);

  const up = await waitForHttp(`${base}/healthz`, {
    timeoutMs: 30_000,
    intervalMs: 250,
    alive: () => proc.exitCode === null,
  });
  if (!up) {
    proc.kill();
    await proc.exited;
    await reader;
    throw new Error(`server did not answer ${base}/healthz\n--- server stderr ---\n${log.join("")}`);
  }

  return {
    base,
    async stop(): Promise<void> {
      proc.kill();
      await proc.exited;
      await reader;
    },
  };
}

export interface HttpResult {
  readonly status: number;
  readonly ms: number;
  readonly body: string;
  readonly headers: Headers;
}

/** One HTTP call with its wall time; network failures become status `0` rather than throwing. */
export async function request(url: string, init?: RequestInit): Promise<HttpResult> {
  const started = performance.now();
  try {
    const response = await fetch(url, { ...init, signal: AbortSignal.timeout(30_000) });
    const body = await response.text();
    return {
      status: response.status,
      ms: performance.now() - started,
      body,
      headers: response.headers,
    };
  } catch (err) {
    return {
      status: 0,
      ms: performance.now() - started,
      body: `fetch failed: ${describeNetError(err)}`,
      headers: new Headers(),
    };
  }
}

export interface LatencySummary {
  readonly count: number;
  readonly min_ms: number;
  readonly p50_ms: number;
  readonly p95_ms: number;
  readonly p99_ms: number;
  readonly max_ms: number;
  readonly mean_ms: number;
}

/** Nearest-rank percentiles over the measured calls, rounded to 0.001 ms. */
export function summarise(latencies: readonly number[]): LatencySummary {
  if (latencies.length === 0) {
    return {
      count: 0,
      min_ms: 0,
      p50_ms: 0,
      p95_ms: 0,
      p99_ms: 0,
      max_ms: 0,
      mean_ms: 0,
    };
  }
  const sorted = [...latencies].sort((a, b) => a - b);
  const at = (fraction: number): number => {
    const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(fraction * sorted.length) - 1));
    return sorted[index] ?? 0;
  };
  const sum = sorted.reduce((total, value) => total + value, 0);
  return {
    count: sorted.length,
    min_ms: round(sorted[0] ?? 0),
    p50_ms: round(at(0.5)),
    p95_ms: round(at(0.95)),
    p99_ms: round(at(0.99)),
    max_ms: round(sorted[sorted.length - 1] ?? 0),
    mean_ms: round(sum / sorted.length),
  };
}

function round(value: number): number {
  return Math.round(value * 1_000) / 1_000;
}

export interface Outcome {
  readonly status: number;
  readonly ms: number;
}

export interface Measurement {
  readonly name: string;
  readonly requests: number;
  readonly errors: number;
  readonly error_rate: number;
  readonly latency: LatencySummary;
  readonly throughput_rps: number;
  readonly first_error: string;
}

export interface MeasureOptions {
  readonly name: string;
  readonly expected: readonly number[];
  readonly warmup: number;
  readonly requests: number;
  readonly concurrency: number;
  readonly once: (index: number) => Promise<Outcome>;
  /** Runs after warm-up and before the measured calls, for example to reset pg_stat_statements. */
  readonly beforeMeasured?: () => Promise<void>;
}

/**
 * Warm up, then measure `requests` calls at `concurrency`. A status outside `expected` is an error;
 * the timer is the one the caller built (`once` may compose several requests into one flow).
 */
export async function measure(options: MeasureOptions): Promise<Measurement> {
  for (let i = 0; i < options.warmup; i++) {
    const warmed = await options.once(i);
    if (!options.expected.includes(warmed.status)) {
      throw new Error(
        `${options.name} warm-up ${i} answered ${warmed.status}, expected ${options.expected.join("/")}`,
      );
    }
  }

  await options.beforeMeasured?.();

  const latencies: number[] = [];
  let errors = 0;
  let firstError = "";
  let next = 0;
  const wallStart = performance.now();

  const worker = async (): Promise<void> => {
    for (;;) {
      const index = next++;
      if (index >= options.requests) return;
      const outcome = await options.once(index);
      latencies.push(outcome.ms);
      if (!options.expected.includes(outcome.status)) {
        errors += 1;
        if (firstError === "") firstError = `request ${index} answered ${outcome.status}`;
      }
    }
  };

  const workers = Math.max(1, Math.min(options.concurrency, options.requests));
  await Promise.all(Array.from({ length: workers }, () => worker()));
  const wallMs = performance.now() - wallStart;

  return {
    name: options.name,
    requests: options.requests,
    errors,
    error_rate: round(errors / options.requests),
    latency: summarise(latencies),
    throughput_rps: round(options.requests / (wallMs / 1_000)),
    first_error: firstError,
  };
}

/** Sequential requests for the tenant-pool phases, with the same error accounting. */
export async function sequential(
  urls: readonly string[],
): Promise<{ latencies: number[]; errors: number; first_error: string }> {
  const latencies: number[] = [];
  let errors = 0;
  let firstError = "";
  for (const url of urls) {
    const result = await request(url, { headers: { accept: "application/json" } });
    latencies.push(result.ms);
    if (result.status !== 200) {
      errors += 1;
      if (firstError === "") firstError = `${url} answered ${result.status}: ${result.body.slice(0, 120)}`;
    }
  }
  return { latencies, errors, first_error: firstError };
}

export interface StatementStat {
  readonly database: string;
  readonly query: string;
  readonly calls: number;
  readonly rows: number;
}

export async function resetStatements(db: Bun.SQL): Promise<void> {
  await raw(db, "SELECT pg_stat_statements_reset()");
}

/** Every statement pg_stat_statements has seen since the reset, newest to oldest irrelevant. */
export async function statements(db: Bun.SQL): Promise<StatementStat[]> {
  const rows = (await raw(
    db,
    "SELECT d.datname AS database, s.calls::bigint AS calls, s.rows::bigint AS rows, s.query AS query " +
      "FROM pg_stat_statements s JOIN pg_database d ON d.oid = s.dbid " +
      "ORDER BY s.calls DESC",
  )) as { database: string; calls: string | number; rows: string | number; query: string }[];
  return rows.map((row) => ({
    database: row.database,
    query: row.query,
    calls: Number(row.calls),
    rows: Number(row.rows),
  }));
}

export interface PoolCounters {
  readonly hits: number;
  readonly misses: number;
  readonly lookupSum: number;
  readonly lookupCount: number;
  readonly connectSum: number;
  readonly connectCount: number;
}

/** Read one `name{labels} value` line; the label match is a literal substring. */
export function metric(text: string, name: string, labels = ""): number {
  for (const line of text.split("\n")) {
    if (!line.startsWith(name)) continue;
    if (!line.includes(labels)) continue;
    const value = Number(line.slice(line.lastIndexOf(" ") + 1));
    if (Number.isFinite(value)) return value;
  }
  return 0;
}

export function poolCounters(text: string): PoolCounters {
  return {
    hits: metric(text, "monaca_tenant_pool_cache_total", 'result="hit"'),
    misses: metric(text, "monaca_tenant_pool_cache_total", 'result="miss"'),
    lookupSum: metric(text, "monaca_tenant_pool_cache_lookup_seconds_sum"),
    lookupCount: metric(text, "monaca_tenant_pool_cache_lookup_seconds_count"),
    connectSum: metric(text, "monaca_tenant_pool_connect_seconds_sum"),
    connectCount: metric(text, "monaca_tenant_pool_connect_seconds_count"),
  };
}

export async function scrapeMetrics(base: string): Promise<string> {
  const result = await request(`${base}/metrics`, { headers: { accept: "text/plain" } });
  if (result.status !== 200) {
    throw new Error(`GET /metrics answered ${result.status}: ${result.body.slice(0, 200)}`);
  }
  return result.body;
}

export function poolDelta(
  before: PoolCounters,
  after: PoolCounters,
  cold: number,
  warm: number,
): {
  hits: number;
  misses: number;
  hit_rate: number;
  lookup_avg_ms: number;
  connect_avg_ms: number;
  cold_requests: number;
  warm_requests: number;
} {
  const hits = after.hits - before.hits;
  const misses = after.misses - before.misses;
  const lookups = hits + misses;
  const lookupMs = (after.lookupSum - before.lookupSum) * 1_000;
  const connectMs = (after.connectSum - before.connectSum) * 1_000;
  return {
    hits,
    misses,
    hit_rate: lookups === 0 ? 0 : round(hits / lookups),
    lookup_avg_ms: lookups === 0 ? 0 : round(lookupMs / lookups),
    connect_avg_ms: misses === 0 ? 0 : round(connectMs / misses),
    cold_requests: cold,
    warm_requests: warm,
  };
}

/** Whether `MONACA_SERVER_BIN` (or the fetched default) exists. */
export function resolveServerBin(platform: string = process.platform): string {
  const fromEnv = process.env.MONACA_SERVER_BIN;
  if (fromEnv !== undefined && fromEnv !== "") return fromEnv;
  const name = platform === "win32" ? "monaca-server.exe" : "monaca-server";
  return join(ROOT, ".monaca", "bin", name);
}

export function assertServerBin(bin: string): void {
  if (!existsSync(bin)) {
    throw new Error(
      `no server binary at ${bin}; run \`bun run fetch:native\` or set MONACA_SERVER_BIN`,
    );
  }
}
