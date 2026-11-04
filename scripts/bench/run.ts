// Reproducible latency/throughput baseline for the M0 request paths (docs/roadmap.md §C).
//
// One command builds a disposable fixture and measures it:
//
//   bun run bench --profile smoke     # ~10 tenants, CI-sized
//   bun run bench --profile full      # 200 tenants, 200 accounts, 20 clients
//
// The PostgreSQL instance is either the embedded cluster under `.monaca/bench/pg` (default, with
// `pg_stat_statements` and durability off for repeatability) or an external cluster named by
// `MONACA_BENCH_PG_URL`. The server binary is `MONACA_SERVER_BIN`, defaulting to the fetched
// `.monaca/bin/monaca-server{,.exe}`. Every number is written to `.monaca/reports/bench-<profile>.json`
// and can be archived with `--archive docs/bench/results/<name>.json`.
//
// The fixture is fixed per profile: tenant counts, demo accounts, demo clients, warmup and measured
// iterations are all declared in PROFILES and echoed into the report's `meta`. Fixtures are created
// through the same HTTP API and CLI the acceptance walk-through uses, so a run cannot silently
// depend on a developer's local database.

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { arch, cpus, platform, release, totalmem } from "node:os";

import {
  assertServerBin,
  measure,
  poolCounters,
  poolDelta,
  raw,
  request,
  resetStatements,
  resolveServerBin,
  resetDatabases,
  runServerCommand,
  scrapeMetrics,
  sequential,
  startPg,
  startServer,
  statements,
  summarise,
  withCredentials,
  withDatabase,
  type BenchPg,
  type HttpResult,
  type LatencySummary,
  type Measurement,
  type PoolDelta,
  type StatementStat,
  ROOT,
} from "./harness.ts";

const ADMIN_CLIENT_ID = "monaca-admin";
const CONSOLE_CLIENT_ID = "monaca-console";
const TENANT = "demo";
const ORG = "acme";
const ADMIN_SECRET = "bench-admin-secret";
const CONSOLE_SECRET = "bench-console-secret";
const ADMIN_EMAIL = "admin@demo.localhost";
const ADMIN_PASSWORD = "monaca-dev-password";
const APP_USER = "monaca_app";
const APP_PASSWORD = "bench-app-password";
const INTERNAL_SECRET = "bench-internal-secret";
const KEK = "00000000000000000000000000000000000000000000000000000000000000ff";
const REDIRECT_URI = "http://localhost:5173/bff/callback";
const CONTROL_PORT = 8092;
const APP_PORT = 8093;
const CONTROL_BASE = `http://127.0.0.1:${CONTROL_PORT}`;
const APP_BASE = `http://127.0.0.1:${APP_PORT}`;

interface Profile {
  readonly name: "smoke" | "full" | "scale";
  readonly extraTenants: number;
  readonly accounts: number;
  readonly clients: number;
  readonly warmup: number;
  readonly iterations: number;
  readonly flowWarmup: number;
  readonly flowIterations: number;
  readonly rampRequests: number;
  readonly rampConcurrency: readonly number[];
  readonly appRoleWarmup: number;
  readonly appRoleIterations: number;
  readonly poolSizes: readonly number[];
}

const PROFILES: Record<"smoke" | "full" | "scale", Profile> = {
  smoke: {
    name: "smoke",
    extraTenants: 8,
    accounts: 50,
    clients: 10,
    warmup: 20,
    iterations: 100,
    flowWarmup: 10,
    flowIterations: 40,
    rampRequests: 200,
    rampConcurrency: [1, 4, 16],
    appRoleWarmup: 10,
    appRoleIterations: 80,
    poolSizes: [8],
  },
  full: {
    name: "full",
    extraTenants: 198,
    accounts: 200,
    clients: 20,
    warmup: 50,
    iterations: 1_000,
    flowWarmup: 20,
    flowIterations: 200,
    rampRequests: 1_000,
    rampConcurrency: [1, 4, 16, 64],
    appRoleWarmup: 20,
    appRoleIterations: 300,
    poolSizes: [50, 100, 200],
  },
  // The scale curve is a pool-only profile: it provisions 400 tenant databases and measures
  // 50/100/200/400 active tenants. Run it with `--only-pool`; accounts and clients are irrelevant.
  scale: {
    name: "scale",
    extraTenants: 398,
    accounts: 0,
    clients: 0,
    warmup: 10,
    iterations: 100,
    flowWarmup: 5,
    flowIterations: 20,
    rampRequests: 200,
    rampConcurrency: [1, 4, 16, 64],
    appRoleWarmup: 10,
    appRoleIterations: 50,
    poolSizes: [50, 100, 200, 400],
  },
};

interface Args {
  readonly profile: Profile;
  readonly out: string;
  readonly archive?: string;
  readonly appRole: boolean;
  readonly pool: boolean;
  readonly onlyPool: boolean;
}

function usage(): string {
  return `usage: bun scripts/bench/run.ts [--profile smoke|full|scale] [--out <path>] [--archive <path>]
                                  [--no-app-role] [--no-pool] [--only-pool]


  smoke  10 tenants, 50 accounts, 10 clients, 100 measured iterations
  full   200 tenants, 200 accounts, 20 clients, 1000 measured iterations
  scale  400 tenants, pool-only curve at 50/100/200/400 (use --only-pool)

Environment:
  MONACA_BENCH_PG_URL   an external PostgreSQL admin URL (…/postgres); unset starts embedded PG
  MONACA_SERVER_BIN     the server binary; default .monaca/bin/monaca-server{,.exe}
`;
}

function parseArgs(argv: readonly string[]): Args {
  let profile: Profile = PROFILES.smoke;
  let out = "";
  let archive: string | undefined;
  let appRole = true;
  let pool = true;
  let onlyPool = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? "";
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage());
      process.exit(0);
    } else if (arg === "--profile") {
      const value = argv[++i] ?? "";
      if (value !== "smoke" && value !== "full" && value !== "scale") {
        throw new Error(`unknown profile ${JSON.stringify(value)}`);
      }
      profile = PROFILES[value];
    } else if (arg.startsWith("--profile=")) {
      const value = arg.slice("--profile=".length);
      if (value !== "smoke" && value !== "full" && value !== "scale") {
        throw new Error(`unknown profile ${JSON.stringify(value)}`);
      }
      profile = PROFILES[value];
    } else if (arg === "--out") {
      out = argv[++i] ?? "";
      if (out === "") throw new Error("--out needs a path");
    } else if (arg.startsWith("--out=")) {
      out = arg.slice("--out=".length);
    } else if (arg === "--archive") {
      archive = argv[++i];
      if (archive === undefined || archive === "") throw new Error("--archive needs a path");
    } else if (arg.startsWith("--archive=")) {
      archive = arg.slice("--archive=".length);
    } else if (arg === "--no-app-role") {
      appRole = false;
    } else if (arg === "--no-pool") {
      pool = false;
    } else if (arg === "--only-pool") {
      onlyPool = true;
      appRole = false;
    } else {
      throw new Error(`unknown argument ${JSON.stringify(arg)}\n${usage()}`);
    }
  }

  return {
    profile,
    out: out === "" ? join(ROOT, ".monaca", "reports", `bench-${profile.name}.json`) : out,
    archive,
    appRole,
    pool,
    onlyPool,
  };
}

function sqlLiteral(value: string): string {
  return `'${value.replaceAll("'", "''")}'`;
}

function extraSlug(index: number): string {
  return `bench-${String(index).padStart(3, "0")}`;
}

function extraShort(index: number): string {
  return `b${String(index).padStart(3, "0")}`;
}

function extraDatabase(index: number): string {
  return `mt_${extraShort(index)}`;
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

async function sha256(value: string): Promise<string> {
  return base64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))),
  );
}

function parseJson(body: string): Record<string, unknown> | undefined {
  try {
    const parsed: unknown = JSON.parse(body);
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

function accessToken(result: HttpResult): string {
  const body = parseJson(result.body);
  const token = body?.access_token;
  if (typeof token !== "string" || token === "") {
    throw new Error(`the token endpoint returned no access_token (${result.status}): ${result.body.slice(0, 200)}`);
  }
  return token;
}

function serverEnv(pg: BenchPg, port: number, appRole: boolean): Record<string, string> {
  const controlUrl = withDatabase(pg.adminUrl, "monaca_control");
  const env: Record<string, string> = {
    MONACA_ENV: "ci",
    MONACA_SERVER_ADDR: `127.0.0.1:${port}`,
    MONACA_SERVER_URL: `http://127.0.0.1:${port}`,
    MONACA_PUBLIC_BASE_URL: `http://127.0.0.1:${port}`,
    MONACA_AUTH_UI_URL: "http://localhost:5174",
    MONACA_CONTROL_DATABASE_URL: controlUrl,
    MONACA_ADMIN_DATABASE_URL: withDatabase(pg.adminUrl, "postgres"),
    MONACA_APP_DB_USER: APP_USER,
    MONACA_APP_DB_PASSWORD: APP_PASSWORD,
    MONACA_DEV_KEK: KEK,
    MONACA_INTERNAL_SECRET: INTERNAL_SECRET,
    MONACA_BOOTSTRAP_ADMIN_EMAIL: ADMIN_EMAIL,
    MONACA_BOOTSTRAP_ADMIN_PASSWORD: ADMIN_PASSWORD,
    MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET: ADMIN_SECRET,
    MONACA_CONSOLE_CLIENT_SECRET: CONSOLE_SECRET,
    MONACA_TENANT_POOL_SIZE: "5",
    MONACA_TENANT_POOL_CACHE: "64",
    MONACA_LOG_LEVEL: "warn",
    MONACA_METRICS_ADDR: "",
    // Never inherit a developer's app DSN into the control pass.
    MONACA_APP_DATABASE_URL: "",
  };
  if (appRole) {
    env.MONACA_APP_DATABASE_URL = withCredentials(controlUrl, APP_USER, APP_PASSWORD);
  }
  return env;
}

async function migrateAndSeed(
  bin: string,
  pg: BenchPg,
  profile: Profile,
  env: Record<string, string>,
): Promise<string[]> {
  await resetDatabases(pg);
  await runServerCommand(bin, ["migrate"], env, "migrate (control)");
  await runServerCommand(bin, ["bootstrap"], env, "bootstrap");

  const control = new Bun.SQL(withDatabase(pg.adminUrl, "monaca_control"));
  try {
    const clusters = (await raw(control, "SELECT id FROM clusters WHERE name = 'local'")) as {
      id: string;
    }[];
    const clusterId = clusters[0]?.id;
    if (clusterId === undefined) throw new Error("bootstrap did not create the `local` cluster row");

    for (let i = 1; i <= profile.extraTenants; i++) {
      const slug = extraSlug(i);
      const short = extraShort(i);
      const database = extraDatabase(i);
      const issuer = `${CONTROL_BASE}/t/${slug}`;
      await raw(
        control,
        `INSERT INTO tenants (id, slug, short, cluster_id, db_name, issuer, state)
         VALUES ($1,$2,$3,$4,$5,$6,'provisioning')
         ON CONFLICT (slug) DO NOTHING`,
        [crypto.randomUUID(), slug, short, clusterId, database, issuer],
      );
    }
  } finally {
    await control.close();
  }

  const admin = new Bun.SQL(pg.adminUrl);
  try {
    for (let i = 1; i <= profile.extraTenants; i++) {
      await raw(admin, `CREATE DATABASE "${extraDatabase(i)}"`);
    }
  } finally {
    await admin.close();
  }

  // Applies the tenant migration set to every row, including the newly inserted provisioning
  // tenants. It also replays the org set for demo, which is the upgrade path the CI job uses.
  await runServerCommand(bin, ["migrate"], env, "migrate (tenants)");

  return Array.from({ length: profile.extraTenants }, (_, index) => extraSlug(index + 1));
}

async function mintAdmin(base: string): Promise<string> {
  const result = await request(`${base}/t/${TENANT}/oauth2/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${btoa(`${ADMIN_CLIENT_ID}:${ADMIN_SECRET}`)}`,
    },
    body: new URLSearchParams({ grant_type: "client_credentials", scope: "monaca:admin" }).toString(),
  });
  if (result.status !== 200) {
    throw new Error(`admin token mint answered ${result.status}: ${result.body.slice(0, 200)}`);
  }
  return accessToken(result);
}

async function patchGates(base: string, adminToken: string): Promise<void> {
  const items = ["authorize", "token", "userinfo", "management"].map((endpoint) => ({
    endpoint,
    limit: 1_000_000,
    window_secs: 60,
  }));
  const result = await request(`${base}/v1/rate-limits`, {
    method: "PATCH",
    headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" },
    body: JSON.stringify({ items }),
  });
  if (result.status !== 200) {
    throw new Error(`PATCH /v1/rate-limits answered ${result.status}: ${result.body.slice(0, 200)}`);
  }
}

async function seedAccounts(base: string, adminToken: string, count: number): Promise<void> {
  let firstError = "";
  let next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const index = next++;
      if (index >= count) return;
      const email = `bench-${String(index + 1).padStart(3, "0")}@demo.localhost`;
      const result = await request(`${base}/v1/accounts`, {
        method: "POST",
        headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" },
        body: JSON.stringify({
          email,
          display_name: `Bench ${index + 1}`,
          password: "bench-Password-123",
        }),
      });
      if (result.status !== 201 && firstError === "") {
        firstError = `POST /v1/accounts ${index + 1} answered ${result.status}: ${result.body.slice(0, 200)}`;
      }
    }
  };
  await Promise.all(Array.from({ length: 8 }, () => worker()));
  if (firstError !== "") throw new Error(firstError);
}

async function seedClients(base: string, adminToken: string, count: number): Promise<void> {
  for (let i = 1; i <= count; i++) {
    const clientId = `bench-app-${String(i).padStart(3, "0")}`;
    const result = await request(`${base}/v1/clients`, {
      method: "POST",
      headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" },
      body: JSON.stringify({
        client_id: clientId,
        name: `Bench App ${i}`,
        kind: "public",
        redirect_uris: [REDIRECT_URI],
        scopes: ["openid", "profile", "email"],
      }),
    });
    if (result.status !== 201) {
      throw new Error(`POST /v1/clients ${i} answered ${result.status}: ${result.body.slice(0, 200)}`);
    }
  }
}

const PKCE_VERIFIER = `bench-verifier-${"v".repeat(32)}`;

async function authorizeUrl(base: string, tag: string, prompt?: string): Promise<string> {
  const challenge = await sha256(PKCE_VERIFIER);
  return `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
    response_type: "code",
    client_id: CONSOLE_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: "openid profile email offline_access",
    state: `bench-${tag}`,
    nonce: `bench-nonce-${tag}`,
    code_challenge: challenge,
    code_challenge_method: "S256",
    organization: ORG,
    ...(prompt === undefined ? {} : { prompt }),
  })}`;
}

/** One interactive sign-in; returns the code and the freshly minted user access token. */
async function mintUserToken(base: string, tag: string): Promise<string> {
  const authorize = await request(await authorizeUrl(base, `${tag}-a`), { redirect: "manual" });
  if (authorize.status !== 302) {
    throw new Error(`authorize answered ${authorize.status}: ${authorize.body.slice(0, 200)}`);
  }
  const location = new URL(authorize.headers.get("location") ?? "", base);
  const interaction = location.searchParams.get("interaction");
  if (interaction === null) throw new Error("authorize did not return an interaction");

  const signIn = await request(
    `${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
    },
  );
  const redirectTo = parseJson(signIn.body)?.redirect_to;
  if (signIn.status !== 200 || typeof redirectTo !== "string") {
    throw new Error(`sign-in answered ${signIn.status}: ${signIn.body.slice(0, 200)}`);
  }
  const code = new URL(redirectTo).searchParams.get("code");
  if (code === null) throw new Error("sign-in did not return a code");

  const exchanged = await request(`${base}/t/${TENANT}/oauth2/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${btoa(`${CONSOLE_CLIENT_ID}:${CONSOLE_SECRET}`)}`,
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CONSOLE_CLIENT_ID,
      code_verifier: PKCE_VERIFIER,
    }).toString(),
  });
  if (exchanged.status !== 200) {
    throw new Error(`code exchange answered ${exchanged.status}: ${exchanged.body.slice(0, 200)}`);
  }
  return accessToken(exchanged);
}

/** The full browser sequence as one measured operation (authorize + sign-in + exchange). */
async function flowOnce(base: string, index: number): Promise<{ status: number; ms: number }> {
  const started = performance.now();
  const authorize = await request(await authorizeUrl(base, `flow-${index}`), { redirect: "manual" });
  if (authorize.status !== 302) return { status: authorize.status, ms: performance.now() - started };
  const interaction = new URL(authorize.headers.get("location") ?? "", base).searchParams.get("interaction");
  if (interaction === null) return { status: 400, ms: performance.now() - started };

  const signIn = await request(
    `${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
    },
  );
  if (signIn.status !== 200) return { status: signIn.status, ms: performance.now() - started };
  const redirectTo = parseJson(signIn.body)?.redirect_to;
  if (typeof redirectTo !== "string") return { status: 400, ms: performance.now() - started };
  const code = new URL(redirectTo).searchParams.get("code");
  if (code === null) return { status: 400, ms: performance.now() - started };

  const exchanged = await request(`${base}/t/${TENANT}/oauth2/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${btoa(`${CONSOLE_CLIENT_ID}:${CONSOLE_SECRET}`)}`,
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CONSOLE_CLIENT_ID,
      code_verifier: PKCE_VERIFIER,
    }).toString(),
  });
  return { status: exchanged.status, ms: performance.now() - started };
}

function once(fn: () => Promise<HttpResult>): () => Promise<{ status: number; ms: number }> {
  return async () => {
    const result = await fn();
    return { status: result.status, ms: result.ms };
  };
}

interface DbReport {
  readonly available: boolean;
  readonly reason: string;
  readonly statements: readonly StatementStat[];
  readonly total_calls: number;
  readonly queries_per_request: number;
  readonly named: Record<string, number>;
}

const BACKGROUND_SQL = [
  "FROM tenants WHERE state = 'active'",
  "tenant.email_connector",
  "pg_stat_statements_reset",
];

function dbReport(all: readonly StatementStat[], requests: number, available: boolean, reason: string): DbReport {
  const filtered = all.filter((row) => !BACKGROUND_SQL.some((marker) => row.query.includes(marker)));
  const total = filtered.reduce((sum, row) => sum + row.calls, 0);
  const patterns: Record<string, string> = {
    rate_limit_counter: "INSERT INTO tenant.rate_limit_counters",
    revocation_lookup: "tenant.revoked_access_tokens",
    interaction_state: "tenant.interactions",
    tenant_lookup: "FROM tenants",
    account_lookup: "tenant.accounts",
    rate_limit_config: "FROM tenant.rate_limits",
    signing_keys: "tenant.signing_keys",
  };
  const named: Record<string, number> = {};
  for (const [name, pattern] of Object.entries(patterns)) {
    named[name] = filtered
      .filter((row) => row.query.includes(pattern))
      .reduce((sum, row) => sum + row.calls, 0);
  }
  return {
    available,
    reason,
    statements: filtered,
    total_calls: total,
    queries_per_request: requests === 0 ? 0 : Math.round((total / requests) * 1_000) / 1_000,
    named,
  };
}

interface ScenarioRun {
  readonly name: string;
  readonly expected: readonly number[];
  readonly measurement: Measurement;
  readonly db: DbReport;
}

async function scenario(
  name: string,
  expected: readonly number[],
  warmup: number,
  requests: number,
  fn: (index: number) => Promise<{ status: number; ms: number }>,
  stats: { available: boolean; sql: Bun.SQL | undefined; reason: string },
): Promise<ScenarioRun> {
  const measurement = await measure({
    name,
    expected,
    warmup,
    requests,
    concurrency: 1,
    once: fn,
    beforeMeasured: async () => {
      if (stats.available && stats.sql !== undefined) await resetStatements(stats.sql);
    },
  });
  const all = stats.available && stats.sql !== undefined ? await statements(stats.sql) : [];
  return {
    name,
    expected,
    measurement,
    db: dbReport(all, requests, stats.available, stats.reason),
  };
}

interface PhaseRun {
  readonly latency: LatencySummary;
  readonly errors: number;
  readonly first_error: string;
}

interface PoolPhase {
  readonly tenants: number;
  readonly seconds: number;
  readonly activation_seconds: number;
  readonly activation_base_connections: number;
  readonly activation_peak_connections: number;
  readonly cold: PhaseRun;
  readonly hot: PhaseRun;
  readonly mixed: PhaseRun;
  readonly cold_pool: PoolDelta;
  readonly hot_pool: PoolDelta;
  readonly mixed_pool: PoolDelta;
  readonly connections_after_cold: number;
  readonly connections_after_hot: number;
  readonly connections_after_mixed: number;
  readonly mailer_ticks: number;
  readonly connector_queries: number;
  readonly index_queries: number;
  readonly errors: number;
  readonly first_error: string;
  readonly mailer_tick_possible: boolean;
}

function emptyPhaseRun(): PhaseRun {
  return {
    latency: summarise([]),
    errors: 0,
    first_error: "",
  };
}

/** Read the current state for each slug so a phase can put the rows back exactly as it found them. */
async function tenantStates(
  control: Bun.SQL,
  slugs: readonly string[],
): Promise<Map<string, string>> {
  const states = new Map<string, string>();
  if (slugs.length === 0) return states;
  const rows = (await raw(
    control,
    `SELECT slug, state FROM tenants WHERE slug IN (${slugs.map(sqlLiteral).join(",")})`,
  )) as { slug: string; state: string }[];
  for (const row of rows) states.set(row.slug, row.state);
  return states;
}

async function restoreTenantStates(
  control: Bun.SQL,
  states: Map<string, string>,
): Promise<void> {
  const groups = new Map<string, string[]>();
  for (const [slug, state] of states) {
    const group = groups.get(state);
    if (group === undefined) groups.set(state, [slug]);
    else group.push(slug);
  }
  for (const [state, slugs] of groups) {
    await raw(
      control,
      `UPDATE tenants SET state = $1, updated_at = now()
       WHERE slug IN (${slugs.map(sqlLiteral).join(",")})`,
      [state],
    );
  }
}

async function activateTenants(control: Bun.SQL, slugs: readonly string[]): Promise<void> {
  if (slugs.length === 0) return;
  await raw(
    control,
    `UPDATE tenants SET state = 'active', updated_at = now()
     WHERE slug IN (${slugs.map(sqlLiteral).join(",")})`,
  );
}

async function connectionCount(control: Bun.SQL): Promise<number> {
  const rows = (await raw(
    control,
    "SELECT count(*)::bigint AS count FROM pg_stat_activity WHERE datname LIKE 'mt_%'",
  )) as { count: string }[];
  return Number(rows[0]?.count ?? 0);
}

function emptyPoolDelta(): PoolDelta {
  return { hits: 0, misses: 0, hit_rate: 0, lookup_avg_ms: 0, connect_avg_ms: 0 };
}

async function poolPhase(
  bin: string,
  env: Record<string, string>,
  base: string,
  control: Bun.SQL,
  slugs: readonly string[],
  size: number,
  stats: { available: boolean; sql: Bun.SQL | undefined; reason: string },
): Promise<PoolPhase> {
  const subset = slugs.slice(0, size);
  const previous = await tenantStates(control, subset);
  const server = await startServer(bin, base, env);
  // Let the mailer's immediately-ready first tick finish against only system/demo. The extras
  // stay provisioning until the phase starts, so their pools are not created by the poller.
  await Bun.sleep(1_200);

  try {
    await activateTenants(control, subset);
    if (stats.available && stats.sql !== undefined) await resetStatements(stats.sql);

    // One mailer cycle after activation: the connection delta is the cost of the poller seeing N
    // tenants. Sample every 500 ms for 6 s so a 5 s tick is inside the window.
    const activationStart = performance.now();
    const samples: number[] = [];
    for (let i = 0; i < 13; i++) {
      samples.push(await connectionCount(control));
      await Bun.sleep(500);
    }
    const activationSeconds = (performance.now() - activationStart) / 1_000;
    const baseConnections = samples[0] ?? 0;
    const peakConnections = samples.reduce((max, value) => Math.max(max, value), 0);

    const before = poolCounters(await scrapeMetrics(base));
    const phaseStart = performance.now();

    const coldRun = await sequential(
      subset.map((slug) => `${base}/t/${slug}/sign-in-experience`),
    );
    const afterColdCounters = poolCounters(await scrapeMetrics(base));
    const connectionsAfterCold = await connectionCount(control);

    // The warm-set pass: the first 50 tenants are a working set that fits the default cache. A
    // repeat immediately after the cold sweep is the "does the cache retain the hot set" test.
    const hotSet = subset.slice(0, Math.min(50, subset.length));
    let hotRun = emptyPhaseRun();
    let hotPool = emptyPoolDelta();
    if (hotSet.length > 0) {
      await sequential(hotSet.map((slug) => `${base}/t/${slug}/sign-in-experience`));
      const hotBefore = poolCounters(await scrapeMetrics(base));
      const repeats = Math.max(2, Math.ceil(100 / hotSet.length));
      const hotUrls = Array.from({ length: repeats }, () =>
        hotSet.map((slug) => `${base}/t/${slug}/sign-in-experience`),
      ).flat();
      const measured = await sequential(hotUrls);
      hotRun = {
        latency: summarise(measured.latencies),
        errors: measured.errors,
        first_error: measured.first_error,
      };
      hotPool = poolDelta(hotBefore, poolCounters(await scrapeMetrics(base)));
    }
    const connectionsAfterHot = await connectionCount(control);

    // Mixed pass: alternate a hot tenant with a tenant from the cold remainder. LRU should keep
    // the hot set through the churn; arbitrary eviction loses it. Only hot-request latency is
    // reported; the churn requests are workload, not a measured path.
    const churnSet = subset.slice(hotSet.length);
    let mixedRun = emptyPhaseRun();
    let mixedPool = emptyPoolDelta();
    if (hotSet.length > 0 && churnSet.length > 0) {
      const warmupPairs = Math.min(20, churnSet.length);
      for (let i = 0; i < warmupPairs; i++) {
        const hot = hotSet[i % hotSet.length];
        const churn = churnSet[i % churnSet.length];
        if (hot !== undefined) await request(`${base}/t/${hot}/sign-in-experience`);
        if (churn !== undefined) await request(`${base}/t/${churn}/sign-in-experience`);
      }
      const mixedBefore = poolCounters(await scrapeMetrics(base));
      const pairs = Math.max(100, hotSet.length * 2);
      const latencies: number[] = [];
      let errors = 0;
      let firstError = "";
      for (let i = 0; i < pairs; i++) {
        const hot = hotSet[i % hotSet.length];
        const churn = churnSet[i % churnSet.length];
        if (hot !== undefined) {
          const result = await request(`${base}/t/${hot}/sign-in-experience`);
          latencies.push(result.ms);
          if (result.status !== 200) {
            errors += 1;
            if (firstError === "") firstError = `${hot} answered ${result.status}`;
          }
        }
        if (churn !== undefined) {
          const result = await request(`${base}/t/${churn}/sign-in-experience`);
          if (result.status !== 200) {
            errors += 1;
            if (firstError === "") firstError = `${churn} answered ${result.status}`;
          }
        }
      }
      mixedRun = {
        latency: summarise(latencies),
        errors,
        first_error: firstError,
      };
      mixedPool = poolDelta(mixedBefore, poolCounters(await scrapeMetrics(base)));
    }
    const connectionsAfterMixed = await connectionCount(control);
    const seconds = (performance.now() - phaseStart) / 1_000;

    const all =
      stats.available && stats.sql !== undefined ? await statements(stats.sql) : [];
    const activeListQueries = all
      .filter((row) => {
        if (row.query.includes("tenant_email_connectors")) return true;
        const trimmed = row.query.trimStart();
        return (
          !trimmed.startsWith("UPDATE") &&
          row.query.includes("FROM tenants") &&
          row.query.includes("state =")
        );
      })
      .reduce((sum, row) => sum + row.calls, 0);
    const connectorQueries = all
      .filter((row) => row.query.includes("tenant.email_connector"))
      .reduce((sum, row) => sum + row.calls, 0);
    const indexQueries = all
      .filter((row) => row.query.includes("tenant_email_connectors"))
      .reduce((sum, row) => sum + row.calls, 0);

    return {
      tenants: subset.length,
      seconds: Math.round(seconds * 1_000) / 1_000,
      activation_seconds: Math.round(activationSeconds * 1_000) / 1_000,
      activation_base_connections: baseConnections,
      activation_peak_connections: peakConnections,
      cold: {
        latency: summarise(coldRun.latencies),
        errors: coldRun.errors,
        first_error: coldRun.first_error,
      },
      hot: hotRun,
      mixed: mixedRun,
      cold_pool: poolDelta(before, afterColdCounters),
      hot_pool: hotPool,
      mixed_pool: mixedPool,
      connections_after_cold: connectionsAfterCold,
      connections_after_hot: connectionsAfterHot,
      connections_after_mixed: connectionsAfterMixed,
      mailer_ticks: activeListQueries,
      connector_queries: connectorQueries,
      index_queries: indexQueries,
      errors: coldRun.errors + hotRun.errors + mixedRun.errors,
      first_error: coldRun.first_error || hotRun.first_error || mixedRun.first_error,
      mailer_tick_possible: seconds >= 4,
    };
  } finally {
    await restoreTenantStates(control, previous);
    await server.stop();
  }
}

interface AppPass {
  readonly mode: "control" | "app";
  readonly scenarios: readonly ScenarioRun[];
  readonly seconds: number;
}

async function appPass(
  bin: string,
  pg: BenchPg,
  profile: Profile,
  mode: "control" | "app",
  port: number,
  base: string,
  stats: { available: boolean; sql: Bun.SQL | undefined; reason: string },
): Promise<AppPass> {
  const started = performance.now();
  const env = serverEnv(pg, port, mode === "app");
  const server = await startServer(bin, base, env);
  try {
    const adminToken = await mintAdmin(base);
    const userToken = await mintUserToken(base, `ab-${mode}`);
    const runs: ScenarioRun[] = [];

    runs.push(
      await scenario(
        "management",
        [200],
        profile.appRoleWarmup,
        profile.appRoleIterations,
        once(async () =>
          request(`${base}/v1/accounts?limit=1`, { headers: { authorization: `Bearer ${adminToken}` } }),
        ),
        stats,
      ),
    );
    runs.push(
      await scenario(
        "authorize",
        [302],
        profile.appRoleWarmup,
        profile.appRoleIterations,
        once(async () => request(await authorizeUrl(base, `ab-auth-${mode}`), { redirect: "manual" })),
        stats,
      ),
    );
    runs.push(
      await scenario(
        "token",
        [200],
        profile.appRoleWarmup,
        profile.appRoleIterations,
        once(async () =>
          request(`${base}/t/${TENANT}/oauth2/token`, {
            method: "POST",
            headers: {
              "content-type": "application/x-www-form-urlencoded",
              authorization: `Basic ${btoa(`${ADMIN_CLIENT_ID}:${ADMIN_SECRET}`)}`,
            },
            body: new URLSearchParams({ grant_type: "client_credentials", scope: "monaca:admin" }).toString(),
          }),
        ),
        stats,
      ),
    );
    runs.push(
      await scenario(
        "userinfo",
        [200],
        profile.appRoleWarmup,
        profile.appRoleIterations,
        once(async () =>
          request(`${base}/t/${TENANT}/oauth2/userinfo`, {
            headers: { authorization: `Bearer ${userToken}` },
          }),
        ),
        stats,
      ),
    );
    return { mode, scenarios: runs, seconds: Math.round((performance.now() - started) / 100) / 10 };
  } finally {
    await server.stop();
  }
}

async function runVerifyAppRole(bin: string, env: Record<string, string>): Promise<void> {
  const script = join(ROOT, "scripts", "verify-app-role.ts");
  const proc = Bun.spawn([process.execPath, script], {
    cwd: ROOT,
    env: {
      ...process.env,
      ...env,
      MONACA_SERVER_BIN: bin,
      MONACA_APP_DB_TENANT: TENANT,
      MONACA_APP_DB_PASSWORD: APP_PASSWORD,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  if (code !== 0) {
    throw new Error(`verify-app-role exited ${code}\n${stdout}\n${stderr}`);
  }
  process.stdout.write(stdout);
}

async function gitCommit(): Promise<string> {
  const proc = Bun.spawn(["git", "rev-parse", "HEAD"], {
    cwd: ROOT,
    stdout: "pipe",
    stderr: "ignore",
  });
  return (await new Response(proc.stdout).text()).trim() || "unknown";
}

function printMeasurements(title: string, runs: readonly ScenarioRun[]): void {
  process.stdout.write(`\n${title}\n`);
  process.stdout.write(
    "  scenario         requests errors  err%    p50ms   p95ms   p99ms   rps      dbq/req\n",
  );
  for (const run of runs) {
    const m = run.measurement;
    process.stdout.write(
      `  ${run.name.padEnd(16)} ${String(m.requests).padStart(8)} ${String(m.errors).padStart(6)} ` +
        `${(m.error_rate * 100).toFixed(2).padStart(6)} ${m.latency.p50_ms.toFixed(2).padStart(7)} ` +
        `${m.latency.p95_ms.toFixed(2).padStart(7)} ${m.latency.p99_ms.toFixed(2).padStart(7)} ` +
        `${m.throughput_rps.toFixed(0).padStart(8)} ${String(run.db.queries_per_request).padStart(8)}\n`,
    );
  }
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  const bin = resolveServerBin();
  assertServerBin(bin);

  const pg = await startPg({ externalUrl: process.env.MONACA_BENCH_PG_URL });
  const env = serverEnv(pg, CONTROL_PORT, false);
  const stats = {
    available: pg.statsAvailable,
    sql: undefined as Bun.SQL | undefined,
    reason: pg.statsError,
  };
  if (pg.statsAvailable) {
    stats.sql = new Bun.SQL(pg.adminUrl);
    await resetStatements(stats.sql);
  }

  const control = new Bun.SQL(withDatabase(pg.adminUrl, "monaca_control"));
  const runs: ScenarioRun[] = [];
  const ramp: Measurement[] = [];
  const pool: PoolPhase[] = [];
  const appRolePasses: AppPass[] = [];
  let appRoleComparison: Record<string, unknown> = {};
  let serverVersion = "unknown";
  let accountsInDemo = 0;
  try {
    process.stdout.write(
      `benchmark ${args.profile.name}: ${args.profile.extraTenants + 2} tenants, ` +
        `${args.profile.accounts} accounts, ${args.profile.clients} clients, ` +
        `${args.profile.iterations} iterations\n`,
    );

    const extras = await migrateAndSeed(bin, pg, args.profile, env);
    const controlRow = (await raw(control, "SELECT db_name FROM tenants WHERE slug = $1", [TENANT])) as {
      db_name: string;
    }[];
    const demoDb = controlRow[0]?.db_name;
    if (demoDb === undefined) throw new Error("bootstrap did not create the demo tenant");

    if (!args.onlyPool) {
    const server = await startServer(bin, CONTROL_BASE, env);
    try {
      const version = await request(`${CONTROL_BASE}/version`);
      const body = parseJson(version.body);
      serverVersion = typeof body?.version === "string" ? body.version : "unknown";

      const adminToken = await mintAdmin(CONTROL_BASE);
      await patchGates(CONTROL_BASE, adminToken);
      await seedAccounts(CONTROL_BASE, adminToken, args.profile.accounts);
      await seedClients(CONTROL_BASE, adminToken, args.profile.clients);
      const userToken = await mintUserToken(CONTROL_BASE, "main");

      const fixturesSql = new Bun.SQL(withDatabase(pg.adminUrl, demoDb));
      const accountCount = (await raw(fixturesSql, "SELECT count(*)::bigint AS count FROM tenant.accounts")) as {
        count: string;
      }[];
      accountsInDemo = Number(accountCount[0]?.count ?? 0);
      await fixturesSql.close();

      runs.push(
        await scenario(
          "authorize",
          [302],
          args.profile.warmup,
          args.profile.iterations,
          once(async () => request(await authorizeUrl(CONTROL_BASE, "authorize"), { redirect: "manual" })),
          stats,
        ),
      );
      runs.push(
        await scenario(
          "token",
          [200],
          args.profile.warmup,
          args.profile.iterations,
          once(async () =>
            request(`${CONTROL_BASE}/t/${TENANT}/oauth2/token`, {
              method: "POST",
              headers: {
                "content-type": "application/x-www-form-urlencoded",
                authorization: `Basic ${btoa(`${ADMIN_CLIENT_ID}:${ADMIN_SECRET}`)}`,
              },
              body: new URLSearchParams({ grant_type: "client_credentials", scope: "monaca:admin" }).toString(),
            }),
          ),
          stats,
        ),
      );
      runs.push(
        await scenario(
          "userinfo",
          [200],
          args.profile.warmup,
          args.profile.iterations,
          once(async () =>
            request(`${CONTROL_BASE}/t/${TENANT}/oauth2/userinfo`, {
              headers: { authorization: `Bearer ${userToken}` },
            }),
          ),
          stats,
        ),
      );

      const managementToken = await mintAdmin(CONTROL_BASE);
      runs.push(
        await scenario(
          "management",
          [200],
          args.profile.warmup,
          args.profile.iterations,
          once(async () =>
            request(`${CONTROL_BASE}/v1/accounts?limit=1`, {
              headers: { authorization: `Bearer ${managementToken}` },
            }),
          ),
          stats,
        ),
      );

      const revokedToken = await mintAdmin(CONTROL_BASE);
      const revoked = await request(`${CONTROL_BASE}/t/${TENANT}/oauth2/revoke`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          authorization: `Basic ${btoa(`${ADMIN_CLIENT_ID}:${ADMIN_SECRET}`)}`,
        },
        body: new URLSearchParams({ token: revokedToken, token_type_hint: "access_token" }).toString(),
      });
      if (revoked.status !== 200) throw new Error(`revoke answered ${revoked.status}`);
      runs.push(
        await scenario(
          "management-revoked",
          [401],
          args.profile.warmup,
          args.profile.iterations,
          once(async () =>
            request(`${CONTROL_BASE}/v1/accounts?limit=1`, {
              headers: { authorization: `Bearer ${revokedToken}` },
            }),
          ),
          stats,
        ),
      );

      runs.push(
        await scenario(
          "flow",
          [200],
          args.profile.flowWarmup,
          args.profile.flowIterations,
          (index) => flowOnce(CONTROL_BASE, index),
          stats,
        ),
      );

      printMeasurements("request paths (concurrency 1)", runs);
      process.stdout.write("\n  db statements (excluding the mailer poller)\n");
      for (const run of runs) {
        process.stdout.write(
          `    ${run.name}: ${run.db.queries_per_request} queries/request ` +
            `(${Object.entries(run.db.named)
              .filter(([, calls]) => calls > 0)
              .map(([key, calls]) => `${key}=${calls}`)
              .join(", ")})\n`,
        );
      }

      const rampToken = await mintAdmin(CONTROL_BASE);
      for (const concurrency of args.profile.rampConcurrency) {
        ramp.push(
          await measure({
            name: `management-c${concurrency}`,
            expected: [200],
            warmup: concurrency === 1 ? 20 : 5,
            requests: args.profile.rampRequests,
            concurrency,
            once: once(async () =>
              request(`${CONTROL_BASE}/v1/accounts?limit=1`, {
                headers: { authorization: `Bearer ${rampToken}` },
              }),
            ),
          }),
        );
      }
      process.stdout.write("\nrate-limit hot row (one tenant counter row)\n");
      process.stdout.write("  concurrency  requests  errors    p50ms    p95ms    p99ms      rps\n");
      for (const point of ramp) {
        process.stdout.write(
          `  ${String(point.name).padEnd(12)} ${String(point.requests).padStart(8)} ` +
            `${String(point.errors).padStart(6)} ${point.latency.p50_ms.toFixed(2).padStart(8)} ` +
            `${point.latency.p95_ms.toFixed(2).padStart(8)} ${point.latency.p99_ms.toFixed(2).padStart(8)} ` +
            `${point.throughput_rps.toFixed(0).padStart(8)}\n`,
        );
      }
    } finally {
      await server.stop();
    }
    }

    const allSlugs = [...extras, "system", "demo"];
    if (args.pool) {
      for (const size of args.profile.poolSizes) {
        if (size > allSlugs.length) continue;
        pool.push(
          await poolPhase(bin, env, CONTROL_BASE, control, allSlugs, size, stats),
        );
      }
      process.stdout.write(
        "\ntenant pool (cold sweep, hot set, then hot/cold churn)\n" +
          "  tenants  sec   act-conn base→peak  coldP50/P99   hotP50/P99   hot-hit  mixedP50  mixed-hit  conns c/h/m   ticks  cred-q\n",
      );
      for (const phase of pool) {
        process.stdout.write(
          `  ${String(phase.tenants).padStart(7)} ${phase.seconds.toFixed(1).padStart(5)} ` +
            `${String(phase.activation_base_connections).padStart(8)}→${String(phase.activation_peak_connections).padStart(3)} ` +
            `${phase.cold.latency.p50_ms.toFixed(1).padStart(8)}/${phase.cold.latency.p99_ms.toFixed(1).padStart(7)} ` +
            `${phase.hot.latency.p50_ms.toFixed(1).padStart(8)}/${phase.hot.latency.p99_ms.toFixed(1).padStart(7)} ` +
            `${(phase.hot_pool.hit_rate * 100).toFixed(1).padStart(6)}% ` +
            `${phase.mixed.latency.p50_ms.toFixed(1).padStart(9)} ` +
            `${(phase.mixed_pool.hit_rate * 100).toFixed(1).padStart(8)}% ` +
            `${String(phase.connections_after_cold).padStart(3)}/${String(phase.connections_after_hot).padStart(3)}/${String(phase.connections_after_mixed).padStart(3)} ` +
            `${String(phase.mailer_ticks).padStart(7)} ${String(phase.connector_queries).padStart(7)}\n`,
        );
      }
    }

    if (args.appRole) {
      await runVerifyAppRole(bin, env);
      await raw(control, "UPDATE tenants SET state = 'provisioning', updated_at = now() WHERE slug = 'system'");

      appRolePasses.push(
        await appPass(bin, pg, args.profile, "control", CONTROL_PORT, CONTROL_BASE, stats),
      );
      appRolePasses.push(await appPass(bin, pg, args.profile, "app", APP_PORT, APP_BASE, stats));
      appRolePasses.push(
        await appPass(bin, pg, args.profile, "control", CONTROL_PORT, CONTROL_BASE, stats),
      );

      const controls = appRolePasses.filter((pass) => pass.mode === "control");
      const app = appRolePasses.find((pass) => pass.mode === "app");
      if (app !== undefined && controls.length === 2) {
        const comparison: Record<string, unknown> = {};
        for (const scenarioName of ["management", "authorize", "token", "userinfo"]) {
          const appRun = app.scenarios.find((run) => run.name === scenarioName);
          const controlRuns = controls
            .map((pass) => pass.scenarios.find((run) => run.name === scenarioName))
            .filter((run): run is ScenarioRun => run !== undefined);
          if (appRun === undefined || controlRuns.length !== 2) continue;
          const mean = (values: number[]): number => values.reduce((sum, value) => sum + value, 0) / values.length;
          const controlP50 = mean(controlRuns.map((run) => run.measurement.latency.p50_ms));
          const controlP95 = mean(controlRuns.map((run) => run.measurement.latency.p95_ms));
          const controlP99 = mean(controlRuns.map((run) => run.measurement.latency.p99_ms));
          const controlRps = mean(controlRuns.map((run) => run.measurement.throughput_rps));
          const delta = (value: number, base: number): number =>
            base === 0 ? 0 : Math.round(((value - base) / base) * 10_000) / 100;
          comparison[scenarioName] = {
            control_p50_ms: Math.round(controlP50 * 1_000) / 1_000,
            app_p50_ms: appRun.measurement.latency.p50_ms,
            p50_delta_pct: delta(appRun.measurement.latency.p50_ms, controlP50),
            control_p95_ms: Math.round(controlP95 * 1_000) / 1_000,
            app_p95_ms: appRun.measurement.latency.p95_ms,
            p95_delta_pct: delta(appRun.measurement.latency.p95_ms, controlP95),
            control_p99_ms: Math.round(controlP99 * 1_000) / 1_000,
            app_p99_ms: appRun.measurement.latency.p99_ms,
            p99_delta_pct: delta(appRun.measurement.latency.p99_ms, controlP99),
            control_rps: Math.round(controlRps * 10) / 10,
            app_rps: appRun.measurement.throughput_rps,
            rps_delta_pct: delta(appRun.measurement.throughput_rps, controlRps),
          };
        }
        appRoleComparison = comparison;

        process.stdout.write("\napp pool vs control pool (mean of two control passes)\n");
        process.stdout.write("  scenario     p50-ctrl  p50-app  p50%   p99-ctrl  p99-app  p99%   rps-ctrl  rps-app  rps%\n");
        for (const [name, value] of Object.entries(comparison)) {
          const row = value as Record<string, number>;
          process.stdout.write(
            `  ${name.padEnd(12)} ${row.control_p50_ms?.toFixed(2).padStart(9)} ${row.app_p50_ms?.toFixed(2).padStart(8)} ` +
              `${row.p50_delta_pct?.toFixed(1).padStart(6)}% ${row.control_p99_ms?.toFixed(2).padStart(9)} ` +
              `${row.app_p99_ms?.toFixed(2).padStart(8)} ${row.p99_delta_pct?.toFixed(1).padStart(6)}% ` +
              `${row.control_rps?.toFixed(0).padStart(9)} ${row.app_rps?.toFixed(0).padStart(8)} ` +
              `${row.rps_delta_pct?.toFixed(1).padStart(6)}%\n`,
          );
        }
      }
    }

    const report = {
      meta: {
        generated_at: new Date().toISOString(),
        profile: args.profile.name,
        commit: await gitCommit(),
        host: {
          platform: platform(),
          release: release(),
          arch: arch(),
          cpu: cpus()[0]?.model ?? "unknown",
          memory_gb: Math.round((totalmem() / 1024 ** 3) * 10) / 10,
          bun: Bun.version,
        },
        server: { binary: bin, version: serverVersion },
        pg: {
          source: pg.source,
          port: pg.port,
          version: pg.version,
          settings: pg.settings,
          stats_available: pg.statsAvailable,
          stats_error: pg.statsError,
        },
        fixtures: {
          tenants: args.profile.extraTenants + 2,
          extra_tenants: args.profile.extraTenants,
          scenario_tenant: TENANT,
          accounts: args.profile.accounts,
          accounts_in_demo: accountsInDemo,
          clients: args.profile.clients,
          instances: 1,
          tenant_pool_size: 5,
          tenant_pool_cache: 64,
        },
        iterations: {
          warmup: args.profile.warmup,
          measured: args.profile.iterations,
          flow_warmup: args.profile.flowWarmup,
          flow_measured: args.profile.flowIterations,
        },
        notes: [
          "The PostgreSQL cluster is disposable: fsync=off, synchronous_commit=off, full_page_writes=off.",
          "Numbers are comparative and machine-specific; the fixture and parameters are fixed per profile.",
          "Metrics on /metrics are per process; this run uses one server instance at a time.",
        ],
      },
      scenarios: runs,
      rate_limit_ramp: ramp,
      tenant_pool: pool,
      app_role: { passes: appRolePasses, comparison: appRoleComparison },
    };

    const json = `${JSON.stringify(report, null, 2)}\n`;
    await mkdir(dirname(args.out), { recursive: true });
    await writeFile(args.out, json, "utf8");
    if (args.archive !== undefined) {
      await mkdir(dirname(args.archive), { recursive: true });
      await writeFile(args.archive, json, "utf8");
    }
    process.stdout.write(`\nreport: ${args.out}${args.archive ? ` (archived at ${args.archive})` : ""}\n`);

    const failures =
      runs.reduce((sum, run) => sum + run.measurement.errors, 0) +
      ramp.reduce((sum, point) => sum + point.errors, 0) +
      pool.reduce((sum, phase) => sum + phase.errors, 0) +
      appRolePasses.reduce(
        (sum, pass) => sum + pass.scenarios.reduce((inner, run) => inner + run.measurement.errors, 0),
        0,
      );
    if (!pg.statsAvailable) {
      process.stdout.write(`note: pg_stat_statements unavailable (${pg.statsError})\n`);
    }
    if (failures > 0) {
      process.stderr.write(`benchmark recorded ${failures} unexpected response(s)\n`);
      return 1;
    }
    return 0;
  } finally {
    await control.close();
    await stats.sql?.close();
    await pg.stop();
  }
}

// `main` is the only entry point; a thrown error prints one line and exits non-zero.
main()
  .then((code) => process.exit(code))
  .catch((err: unknown) => {
    process.stderr.write(`bench: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
    process.exit(1);
  });

