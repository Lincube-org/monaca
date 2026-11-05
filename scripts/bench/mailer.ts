// Mailer budget benchmark: one queued mail for every connector tenant, then measure how long the
// poller takes to start each tenant, how long each mail waited, and the connection peak.
//
// It uses the 400-tenant fixture a `--profile scale --all-connectors` run leaves behind, plus its
// embedded PostgreSQL. Seed the fixture once with:
//
//   MONACA_SERVER_BIN=.monaca/bin/monaca-server bun run bench --profile scale --only-pool --all-connectors
//
// then run, with the same or a newer binary:
//
//   MONACA_SERVER_BIN=.monaca/bin/monaca-server bun scripts/bench/mailer.ts --out .monaca/reports/mailer.json
//
// `--slow-tenant <slug>` makes the mock hold that tenant's request past the mailer's timeout, to
// prove one hung provider cannot hold the tick.

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { cpus, platform, release, totalmem } from "node:os";

import {
  metric,
  raw,
  startPg,
  withDatabase,
  ROOT,
} from "./harness.ts";

const TENANTS = 400;
const SERVER_PORT = 8090;
const MOCK_PORT = 39999;
const BASE = `http://127.0.0.1:${SERVER_PORT}`;
const KEY = "00000000000000000000000000000000000000000000000000000000000000ff";
const ADMIN_SECRET = "bench-admin-secret";
const CONSOLE_SECRET = "bench-console-secret";

interface Args {
  readonly out: string;
  readonly slowTenant: string | null;
  readonly hotTenant: string | null;
  readonly timeoutSecs: number;
}

function usage(): string {
  return `usage: bun scripts/bench/mailer.ts [--out <path>] [--slow-tenant <slug>] [--hot-tenant <slug>]
                                    [--timeout <secs>]

  --slow-tenant  the mock holds this tenant's request longer than the delivery timeout
  --hot-tenant   the request-path tenant probed during the sweep (default: demo when present)
  --timeout      how long to wait for the last mail (default 180)
`;
}

function parseArgs(argv: readonly string[]): Args {
  let out = join(ROOT, ".monaca", "reports", "mailer.json");
  let slowTenant: string | null = null;
  let hotTenant: string | null = null;
  let timeoutSecs = 180;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? "";
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage());
      process.exit(0);
    } else if (arg === "--out") {
      out = argv[++i] ?? out;
    } else if (arg.startsWith("--out=")) {
      out = arg.slice("--out=".length);
    } else if (arg === "--slow-tenant") {
      slowTenant = argv[++i] ?? null;
    } else if (arg === "--hot-tenant") {
      hotTenant = argv[++i] ?? null;
    } else if (arg === "--timeout") {
      timeoutSecs = Number(argv[++i] ?? timeoutSecs);
    } else {
      throw new Error(`unknown argument ${JSON.stringify(arg)}\n${usage()}`);
    }
  }
  return { out, slowTenant, hotTenant, timeoutSecs };
}

interface PoolCounters {
  readonly hits: number;
  readonly misses: number;
  readonly connectSum: number;
  readonly connectCount: number;
}

/** Read the cache counters behind one pool prefix (`monaca_tenant_pool`/`monaca_mailer_pool`). */
function poolCounters(text: string, prefix: string): PoolCounters {
  return {
    hits: metric(text, `${prefix}_cache_total`, 'result="hit"'),
    misses: metric(text, `${prefix}_cache_total`, 'result="miss"'),
    connectSum: metric(text, `${prefix}_connect_seconds_sum`),
    connectCount: metric(text, `${prefix}_connect_seconds_count`),
  };
}

function poolDelta(before: PoolCounters, after: PoolCounters): PoolCounters & { connect_avg_ms: number } {
  const hits = after.hits - before.hits;
  const misses = after.misses - before.misses;
  const connectSeconds = after.connectSum - before.connectSum;
  const connects = after.connectCount - before.connectCount;
  return {
    hits,
    misses,
    connectSum: connectSeconds,
    connectCount: connects,
    connect_avg_ms:
      connects === 0 ? 0 : Math.round((connectSeconds * 1_000 * 1_000) / connects) / 1_000,
  };
}

function percentile(values: readonly number[], fraction: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(fraction * sorted.length) - 1));
  return sorted[index] ?? 0;
}

async function serverVersion(binary: string): Promise<string> {
  const proc = Bun.spawn([binary, "--version"], { stdout: "pipe", stderr: "pipe" });
  const text = await new Response(proc.stdout).text();
  await proc.exited;
  return text.trim();
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  const binary = process.env.MONACA_SERVER_BIN ?? join(ROOT, ".monaca", "bin", "monaca-server.exe");
  const pg = await startPg({ externalUrl: process.env.MONACA_BENCH_PG_URL });

  const control = new Bun.SQL(withDatabase(pg.adminUrl, "monaca_control"));
  let server: ReturnType<typeof Bun.spawn> | undefined;
  let serverReader: Promise<void> | undefined;
  let mock: ReturnType<typeof Bun.serve> | undefined;
  const received = new Map<string, number>();
  const finished: { id: string; tenant: string; at: number }[] = [];

  try {
    const tenants = (await raw(
      control,
      `SELECT t.slug, t.db_name
       FROM tenants t
       JOIN tenant_delivery_connectors c ON c.tenant_id = t.id
       ORDER BY t.slug`,
    )) as { slug: string; db_name: string }[];
    if (tenants.length !== TENANTS) {
      throw new Error(
        `the fixture holds ${tenants.length} connector tenants, expected ${TENANTS}; provision it with --all-connectors first`,
      );
    }
    // The bench fixture keeps its extra tenants `provisioning` between runs; the mailer only lists
    // active tenants, so activate them for the measurement and put them back afterwards.
    await raw(control, "UPDATE tenants SET state = 'active' WHERE slug LIKE 'bench-%'");

    // --- one mock provider for every tenant ------------------------------------------------------
    mock = Bun.serve({
      port: MOCK_PORT,
      hostname: "127.0.0.1",
      async fetch(request) {
        const body = (await request.json().catch(() => ({}))) as { id?: string; tenant?: string };
        const tenant = String(body.tenant ?? "");
        if (args.slowTenant !== null && tenant === args.slowTenant) {
          // The server gives up after its delivery timeout; the mock holds longer on purpose so a
          // request that finishes after the deadline cannot be counted as delivered.
          await Bun.sleep(30_000);
          return new Response(null, { status: 504 });
        }
        const id = String(body.id ?? "");
        if (!received.has(id)) {
          received.set(id, Date.now());
          finished.push({ id, tenant, at: Date.now() });
        }
        return new Response(null, { status: 202 });
      },
    });

    // --- clear the outbox and queue exactly one mail per tenant ----------------------------------
    const seedOne = async (tenant: { slug: string; db_name: string }): Promise<void> => {
      const db = new Bun.SQL(withDatabase(pg.adminUrl, tenant.db_name), { max: 1 });
      try {
        await raw(db, "DELETE FROM tenant.outbox WHERE topic = 'mail.verification'");
        const id = crypto.randomUUID();
        await raw(
          db,
          `INSERT INTO tenant.outbox (id, topic, payload, created_at)
           VALUES ($1, 'mail.verification', $2, now())`,
          [
            id,
            JSON.stringify({
              tenant: tenant.slug,
              to: "bench@example.test",
              purpose: "sign_up",
              subject: "Bench",
              body: "bench mail",
            }),
          ],
        );
      } finally {
        await db.close();
      }
    };
    for (let i = 0; i < tenants.length; i += 8) {
      await Promise.all(tenants.slice(i, i + 8).map(seedOne));
    }

    // --- start the binary under test --------------------------------------------------------------
    const env: Record<string, string> = {};
    for (const [key, value] of Object.entries(process.env)) {
      if (value !== undefined) env[key] = value;
    }
    Object.assign(env, {
      MONACA_ENV: "ci",
      MONACA_SERVER_ADDR: `127.0.0.1:${SERVER_PORT}`,
      MONACA_SERVER_URL: BASE,
      MONACA_PUBLIC_BASE_URL: BASE,
      MONACA_AUTH_UI_URL: "http://localhost:5174",
      MONACA_CONTROL_DATABASE_URL: withDatabase(pg.adminUrl, "monaca_control"),
      MONACA_ADMIN_DATABASE_URL: pg.adminUrl,
      MONACA_DEV_KEK: KEY,
      MONACA_INTERNAL_SECRET: "bench-internal-secret",
      MONACA_BOOTSTRAP_ADMIN_EMAIL: "admin@demo.localhost",
      MONACA_BOOTSTRAP_ADMIN_PASSWORD: "monaca-dev-password",
      MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET: ADMIN_SECRET,
      MONACA_CONSOLE_CLIENT_SECRET: CONSOLE_SECRET,
      MONACA_TENANT_POOL_SIZE: "5",
      MONACA_TENANT_POOL_CACHE: "64",
      MONACA_IP_RATE_LIMIT_PER_MINUTE: "0",
      MONACA_LOG_LEVEL: "warn",
      MONACA_METRICS_ADDR: "",
      // The capacity fixture provisions 400 databases and does not exercise the app-role grants;
      // the escape hatch is explicit so `serve` does not refuse to start.
      MONACA_APP_DATABASE_URL: "",
      MONACA_ALLOW_SUPERUSER_TENANT_POOLS: "1",
    });
    delete env.MONACA_KEK;
    delete env.MONACA_KEK_PREVIOUS;
    server = Bun.spawn([binary, "serve"], {
      cwd: ROOT,
      env,
      stdout: "ignore",
      stderr: "pipe",
    });
    const serverLog: string[] = [];
    serverReader = (async (): Promise<void> => {
      const stderr = server!.stderr as ReadableStream<Uint8Array>;
      for await (const chunk of stderr) {
        serverLog.push(String(chunk));
        while (serverLog.join("").length > 8_000) serverLog.shift();
      }
    })().catch(() => undefined);
    const spawnedAt = Date.now();
    let healthy = false;
    for (let i = 0; i < 120; i++) {
      try {
        const response = await fetch(`${BASE}/healthz`, { signal: AbortSignal.timeout(1_000) });
        if (response.ok) {
          healthy = true;
          break;
        }
      } catch {
        // not listening yet
      }
      await Bun.sleep(250);
    }
    if (!healthy) {
      throw new Error(
        `the server never answered /healthz (exit ${server.exitCode})\n--- server stderr ---\n${serverLog.join("")}`,
      );
    }

    // --- a request-path tenant, warmed before the sweep -----------------------------------------
    const hotTenant =
      args.hotTenant ?? (tenants.some((tenant) => tenant.slug === "demo") ? "demo" : tenants[0]!.slug);
    const hotUrl = `${BASE}/t/${hotTenant}/sign-in-experience`;
    const warm = await fetch(hotUrl, { signal: AbortSignal.timeout(5_000) }).catch(() => undefined);
    if (warm === undefined || !warm.ok) {
      throw new Error(
        `the hot tenant ${hotTenant} did not answer ${hotUrl}\n--- server stderr ---\n${serverLog.join("")}`,
      );
    }
    let metricsBefore = "";
    try {
      metricsBefore = await (await fetch(`${BASE}/metrics`)).text();
    } catch {
      // the before binary has no split counters; the report records the absence below
    }
    const hotPoolBefore = poolCounters(metricsBefore, "monaca_tenant_pool");
    const mailerPoolBefore = poolCounters(metricsBefore, "monaca_mailer_pool");

    // --- wait for every mail, sampling connections and the hot request path ----------------------
    const admin = new Bun.SQL(pg.adminUrl);
    const connectionSamples: number[] = [];
    const hotLatencies: number[] = [];
    let hotErrors = 0;
    const deadline = Date.now() + args.timeoutSecs * 1_000;
    while (finished.length < tenants.length && Date.now() < deadline) {
      const rows = (await raw(
        admin,
        "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname LIKE 'mt\\_%'",
      )) as { n: number }[];
      connectionSamples.push(rows[0]?.n ?? 0);

      const hotStarted = performance.now();
      try {
        const response = await fetch(hotUrl, { signal: AbortSignal.timeout(5_000) });
        hotLatencies.push(performance.now() - hotStarted);
        if (!response.ok) hotErrors += 1;
      } catch {
        hotErrors += 1;
      }
      await Bun.sleep(200);
    }
    const sampled = connectionSamples;
    const stopAt = Date.now();
    await admin.close();

    // --- metrics from the server (the budget-aware binary publishes the tick gauges) -------------
    let tickMax: number | null = null;
    let ticks: number | null = null;
    let tenantsLast: number | null = null;
    let metricsAfter = "";
    let mailerPoolAfter = mailerPoolBefore;
    try {
      metricsAfter = await (await fetch(`${BASE}/metrics`)).text();
      const maxMatch = /^monaca_mailer_tick_seconds_max ([\d.]+)$/m.exec(metricsAfter);
      const ticksMatch = /^monaca_mailer_ticks_total (\d+)$/m.exec(metricsAfter);
      const tenantsMatch = /^monaca_mailer_tenants_last (\d+)$/m.exec(metricsAfter);
      tickMax = maxMatch === null ? null : Number(maxMatch[1]);
      ticks = ticksMatch === null ? null : Number(ticksMatch[1]);
      tenantsLast = tenantsMatch === null ? null : Number(tenantsMatch[1]);
      mailerPoolAfter = poolCounters(metricsAfter, "monaca_mailer_pool");
    } catch {
      // the metrics endpoint is optional for the before run
    }
    const hotPool = poolDelta(hotPoolBefore, poolCounters(metricsAfter, "monaca_tenant_pool"));
    const mailerPool = poolDelta(mailerPoolBefore, mailerPoolAfter);

    const latencies = finished.map((entry) => entry.at - spawnedAt);
    const slowest = finished
      .map((entry) => ({ tenant: entry.tenant, ms: entry.at - spawnedAt }))
      .sort((a, b) => b.ms - a.ms)
      .slice(0, 5);
    const delivered = finished.length;
    const report = {
      meta: {
        generated_at: new Date().toISOString(),
        fixture: "scale-all-connectors",
        tenants: tenants.length,
        binary,
        version: await serverVersion(binary),
        slow_tenant: args.slowTenant,
        hot_tenant: hotTenant,
        split_pool_counters: metricsAfter.includes("monaca_mailer_pool_cache_total"),
        host: {
          platform: platform(),
          release: release(),
          arch: process.arch,
          cpu: cpus()[0]?.model ?? "unknown",
          memory_gb: Math.round((totalmem() / 1024 ** 3) * 10) / 10,
        },
        pg_source: pg.source,
      },
      queued_at: new Date(spawnedAt).toISOString(),
      delivered,
      missing: tenants.length - delivered,
      delivery_latency_ms: {
        p50: percentile(latencies, 0.5),
        p99: percentile(latencies, 0.99),
        max: Math.max(0, ...latencies),
        count: latencies.length,
        slowest,
      },
      // The old poller has no tick gauge; the first pass is the interval from spawn to the last
      // mail. The new one reports both, and `tick_seconds_max` is the tighter number.
      first_pass_ms: delivered === tenants.length ? stopAt - spawnedAt : null,
      tick_seconds_max: tickMax,
      mailer_ticks_total: ticks,
      mailer_tenants_last: tenantsLast,
      hot_path_latency_ms: {
        p50: percentile(hotLatencies, 0.5),
        p99: percentile(hotLatencies, 0.99),
        max: Math.max(0, ...hotLatencies),
        count: hotLatencies.length,
        errors: hotErrors,
      },
      hot_pool: {
        hits: hotPool.hits,
        misses: hotPool.misses,
        hit_rate: hotPool.hits + hotPool.misses === 0 ? 0 : hotPool.hits / (hotPool.hits + hotPool.misses),
        connect_avg_ms: hotPool.connect_avg_ms,
      },
      mailer_pool: {
        hits: mailerPool.hits,
        misses: mailerPool.misses,
        connect_avg_ms: mailerPool.connect_avg_ms,
      },
      connections_peak: Math.max(0, ...sampled),
      sample_count: sampled.length,
    };

    await mkdir(dirname(args.out), { recursive: true });
    await writeFile(args.out, `${JSON.stringify(report, null, 2)}\n`);
    process.stdout.write(
      `mailer: ${delivered}/${tenants.length} delivered, p50 ${report.delivery_latency_ms.p50} ms, ` +
        `p99 ${report.delivery_latency_ms.p99} ms, first pass ${report.first_pass_ms ?? "unfinished"} ms, ` +
        `tick max ${tickMax === null ? "n/a" : `${(tickMax * 1000).toFixed(0)} ms`}, ` +
        `hot p99 ${report.hot_path_latency_ms.p99.toFixed(0)} ms ` +
        `(hit ${(report.hot_pool.hit_rate * 100).toFixed(1)}%), ` +
        `connections ${report.connections_peak}\nreport: ${args.out}\n`,
    );
    return args.slowTenant === null
      ? delivered === tenants.length
        ? 0
        : 1
      : delivered >= tenants.length - 1
        ? 0
        : 1;
  } finally {
    if (server !== undefined) {
      server.kill();
      await server.exited;
    }
    await serverReader;
    mock?.stop(true);
    try {
      await raw(control, "UPDATE tenants SET state = 'provisioning' WHERE slug LIKE 'bench-%'");
    } catch {
      // the control connection is already gone; the fixture is disposable either way
    }
    await control.close();
    try {
      await pg.stop();
    } catch {
      // the embedded cluster may already be gone after a forced stop
    }
  }
}

process.exitCode = await main();
