// Compare two `bench-<profile>.json` reports and report paths that moved beyond a threshold.
//
//   bun run bench:compare --baseline <old.json> --candidate <new.json> [--threshold 15]
//                        [--warn-only] [--out .monaca/reports/bench-compare.json]
//
// Latency and DB-query counts are lower-is-better; throughput and cache-hit rate are
// higher-is-better. A regression is a move beyond the threshold in the bad direction; an
// improvement is the same move in the good direction. The exit code is 1 when a regression is
// found, unless `--warn-only` is set (the CI job uses that so the comparison never blocks a build).

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

interface Report {
  meta?: {
    profile?: string;
    fixtures?: { tenants?: number };
  };
  scenarios?: {
    name?: string;
    measurement?: {
      requests?: number;
      errors?: number;
      error_rate?: number;
      throughput_rps?: number;
      latency?: { p50_ms?: number; p95_ms?: number; p99_ms?: number };
    };
    db?: { queries_per_request?: number };
  }[];
  rate_limit_ramp?: {
    name?: string;
    errors?: number;
    throughput_rps?: number;
    latency?: { p50_ms?: number; p99_ms?: number };
  }[];
  tenant_pool?: {
    tenants?: number;
    seconds?: number;
    activation_peak_connections?: number;
    mailer_ticks?: number;
    connector_queries?: number;
    cold?: { latency?: { p50_ms?: number; p99_ms?: number } };
    cold_pool?: { hit_rate?: number };
    hot?: { latency?: { p50_ms?: number; p99_ms?: number }; errors?: number };
    mixed?: { latency?: { p50_ms?: number; p99_ms?: number }; errors?: number };
    hot_pool?: { hit_rate?: number };
    mixed_pool?: { hit_rate?: number };
  }[];
  app_role?: {
    comparison?: Record<
      string,
      {
        control_p50_ms?: number;
        app_p50_ms?: number;
        p50_delta_pct?: number;
        control_p99_ms?: number;
        app_p99_ms?: number;
        p99_delta_pct?: number;
        control_rps?: number;
        app_rps?: number;
        rps_delta_pct?: number;
      }
    >;
  };
}

interface Delta {
  readonly kind: string;
  readonly key: string;
  readonly metric: string;
  readonly baseline: number;
  readonly candidate: number;
  readonly delta_pct: number;
  readonly direction: "regression" | "improvement";
}

interface Args {
  readonly baseline: string;
  readonly candidate: string;
  readonly threshold: number;
  readonly warnOnly: boolean;
  readonly out: string;
}

function usage(): string {
  return `usage: bun scripts/bench/compare.ts --baseline <json> --candidate <json>
                                  [--threshold 15] [--warn-only] [--out <json>]
`;
}

function parseArgs(argv: readonly string[]): Args {
  let baseline = "";
  let candidate = "";
  let threshold = 15;
  let warnOnly = false;
  let out = ".monaca/reports/bench-compare.json";

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? "";
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage());
      process.exit(0);
    } else if (arg === "--baseline") {
      baseline = argv[++i] ?? "";
    } else if (arg.startsWith("--baseline=")) {
      baseline = arg.slice("--baseline=".length);
    } else if (arg === "--candidate") {
      candidate = argv[++i] ?? "";
    } else if (arg.startsWith("--candidate=")) {
      candidate = arg.slice("--candidate=".length);
    } else if (arg === "--threshold") {
      threshold = Number(argv[++i] ?? "");
    } else if (arg.startsWith("--threshold=")) {
      threshold = Number(arg.slice("--threshold=".length));
    } else if (arg === "--warn-only") {
      warnOnly = true;
    } else if (arg === "--out") {
      out = argv[++i] ?? "";
    } else if (arg.startsWith("--out=")) {
      out = arg.slice("--out=".length);
    } else {
      throw new Error(`unknown argument ${JSON.stringify(arg)}\n${usage()}`);
    }
  }

  if (baseline === "" || candidate === "") {
    throw new Error(`--baseline and --candidate are required\n${usage()}`);
  }
  if (!Number.isFinite(threshold) || threshold < 0) {
    throw new Error("--threshold must be a non-negative number");
  }
  return { baseline, candidate, threshold, warnOnly, out };
}

function pct(base: number, candidate: number): number {
  if (base === 0) return candidate === 0 ? 0 : Number.POSITIVE_INFINITY;
  return Math.round(((candidate - base) / base) * 10_000) / 100;
}

function add(
  deltas: Delta[],
  kind: string,
  key: string,
  metric: string,
  base: number | undefined,
  candidate: number | undefined,
  lowerIsBetter: boolean,
  threshold: number,
): void {
  if (base === undefined || candidate === undefined || !Number.isFinite(base) || !Number.isFinite(candidate)) {
    return;
  }
  const delta = pct(base, candidate);
  if (!Number.isFinite(delta)) return;
  const regressed = lowerIsBetter ? delta > threshold : delta < -threshold;
  const improved = lowerIsBetter ? delta < -threshold : delta > threshold;
  if (regressed) {
    deltas.push({ kind, key, metric, baseline: base, candidate, delta_pct: delta, direction: "regression" });
  } else if (improved) {
    deltas.push({ kind, key, metric, baseline: base, candidate, delta_pct: delta, direction: "improvement" });
  }
}

function indexBy<T>(items: readonly T[] | undefined, key: (item: T) => string | undefined): Map<string, T> {
  const map = new Map<string, T>();
  for (const item of items ?? []) {
    const found = key(item);
    if (found !== undefined) map.set(found, item);
  }
  return map;
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  const baseline = JSON.parse(await readFile(args.baseline, "utf8")) as Report;
  const candidate = JSON.parse(await readFile(args.candidate, "utf8")) as Report;
  const deltas: Delta[] = [];

  const baseScenarios = indexBy(baseline.scenarios, (scenario) => scenario.name);
  const candidateScenarios = indexBy(candidate.scenarios, (scenario) => scenario.name);
  for (const [name, base] of baseScenarios) {
    const next = candidateScenarios.get(name);
    if (next === undefined) continue;
    add(deltas, "scenario", name, "p50_ms", base.measurement?.latency?.p50_ms, next.measurement?.latency?.p50_ms, true, args.threshold);
    add(deltas, "scenario", name, "p95_ms", base.measurement?.latency?.p95_ms, next.measurement?.latency?.p95_ms, true, args.threshold);
    add(deltas, "scenario", name, "p99_ms", base.measurement?.latency?.p99_ms, next.measurement?.latency?.p99_ms, true, args.threshold);
    add(deltas, "scenario", name, "rps", base.measurement?.throughput_rps, next.measurement?.throughput_rps, false, args.threshold);
    add(deltas, "scenario", name, "db_queries_per_request", base.db?.queries_per_request, next.db?.queries_per_request, true, args.threshold);
    if ((next.measurement?.error_rate ?? 0) > (base.measurement?.error_rate ?? 0)) {
      deltas.push({
        kind: "scenario",
        key: name,
        metric: "error_rate",
        baseline: base.measurement?.error_rate ?? 0,
        candidate: next.measurement?.error_rate ?? 0,
        delta_pct: Number.POSITIVE_INFINITY,
        direction: "regression",
      });
    }
  }

  const baseRamp = indexBy(baseline.rate_limit_ramp, (point) => point.name);
  const candidateRamp = indexBy(candidate.rate_limit_ramp, (point) => point.name);
  for (const [name, base] of baseRamp) {
    const next = candidateRamp.get(name);
    if (next === undefined) continue;
    add(deltas, "rate_limit_ramp", name, "p50_ms", base.latency?.p50_ms, next.latency?.p50_ms, true, args.threshold);
    add(deltas, "rate_limit_ramp", name, "p99_ms", base.latency?.p99_ms, next.latency?.p99_ms, true, args.threshold);
    add(deltas, "rate_limit_ramp", name, "rps", base.throughput_rps, next.throughput_rps, false, args.threshold);
  }

  const basePool = indexBy(baseline.tenant_pool, (phase) => String(phase.tenants ?? ""));
  const candidatePool = indexBy(candidate.tenant_pool, (phase) => String(phase.tenants ?? ""));
  for (const [key, base] of basePool) {
    const next = candidatePool.get(key);
    if (next === undefined) continue;
    add(deltas, "tenant_pool", key, "cold_p50_ms", base.cold?.latency?.p50_ms, next.cold?.latency?.p50_ms, true, args.threshold);
    add(deltas, "tenant_pool", key, "cold_p99_ms", base.cold?.latency?.p99_ms, next.cold?.latency?.p99_ms, true, args.threshold);
    add(deltas, "tenant_pool", key, "hot_p50_ms", base.hot?.latency?.p50_ms, next.hot?.latency?.p50_ms, true, args.threshold);
    add(deltas, "tenant_pool", key, "hot_p99_ms", base.hot?.latency?.p99_ms, next.hot?.latency?.p99_ms, true, args.threshold);
    add(deltas, "tenant_pool", key, "mixed_p50_ms", base.mixed?.latency?.p50_ms, next.mixed?.latency?.p50_ms, true, args.threshold);
    add(deltas, "tenant_pool", key, "cold_hit_rate", base.cold_pool?.hit_rate, next.cold_pool?.hit_rate, false, args.threshold);
    add(deltas, "tenant_pool", key, "hot_hit_rate", base.hot_pool?.hit_rate, next.hot_pool?.hit_rate, false, args.threshold);
    add(deltas, "tenant_pool", key, "mixed_hit_rate", base.mixed_pool?.hit_rate, next.mixed_pool?.hit_rate, false, args.threshold);
    add(deltas, "tenant_pool", key, "activation_peak_connections", base.activation_peak_connections, next.activation_peak_connections, true, args.threshold);
    // `seconds` and `mailer_ticks` changed meaning when the hot/mixed passes lengthened the
    // phase; comparing them against an older report would be a false regression. The per-pass
    // latency, hit-rate and connector-query metrics are the comparable ones.
    add(deltas, "tenant_pool", key, "connector_queries", base.connector_queries, next.connector_queries, true, args.threshold);
  }

  const baseApp = baseline.app_role?.comparison ?? {};
  const candidateApp = candidate.app_role?.comparison ?? {};
  for (const [name, base] of Object.entries(baseApp)) {
    const next = candidateApp[name];
    if (next === undefined) continue;
    // Compare the app pass against the app pass across runs. The signed delta against the control
    // pass is a derived ratio; comparing those directly would invert the meaning when the control
    // value is negative or near zero.
    add(deltas, "app_role", name, "app_p50_ms", base.app_p50_ms, next.app_p50_ms, true, args.threshold);
    add(deltas, "app_role", name, "app_p99_ms", base.app_p99_ms, next.app_p99_ms, true, args.threshold);
    add(deltas, "app_role", name, "app_rps", base.app_rps, next.app_rps, false, args.threshold);
  }

  const regressions = deltas.filter((delta) => delta.direction === "regression");
  const improvements = deltas.filter((delta) => delta.direction === "improvement");
  const profileMatch = baseline.meta?.profile === candidate.meta?.profile;

  const output = {
    generated_at: new Date().toISOString(),
    baseline: args.baseline,
    candidate: args.candidate,
    threshold_pct: args.threshold,
    profile_match: profileMatch,
    comparisons: deltas.length,
    regressions,
    improvements,
  };
  await mkdir(dirname(args.out), { recursive: true });
  await writeFile(args.out, `${JSON.stringify(output, null, 2)}\n`, "utf8");

  process.stdout.write(
    `benchmark comparison (threshold ${args.threshold}%): ${args.baseline} → ${args.candidate}\n`,
  );
  if (!profileMatch) {
    process.stdout.write(
      `WARNING: profiles differ (${baseline.meta?.profile ?? "unknown"} vs ${candidate.meta?.profile ?? "unknown"}); comparisons may not be meaningful.\n`,
    );
  }
  if (deltas.length === 0) {
    process.stdout.write("  no metric moved beyond the threshold\n");
  } else {
    process.stdout.write("  kind              key                  metric                    baseline      candidate    delta\n");
    for (const delta of [...regressions, ...improvements]) {
      const mark = delta.direction === "regression" ? "REGRESS" : "improve";
      const deltaText = Number.isFinite(delta.delta_pct)
        ? `${delta.delta_pct.toFixed(1)}%`
        : `+∞`;
      process.stdout.write(
        `  ${mark} ${delta.kind.padEnd(16)} ${delta.key.padEnd(20)} ${delta.metric.padEnd(24)} ` +
          `${String(delta.baseline).padStart(11)} ${String(delta.candidate).padStart(13)} ${deltaText.padStart(9)}\n`,
      );
    }
  }
  process.stdout.write(`  regressions: ${regressions.length}; improvements: ${improvements.length}\n`);
  process.stdout.write(`  report: ${args.out}\n`);

  return regressions.length > 0 && !args.warnOnly ? 1 : 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err: unknown) => {
    process.stderr.write(`bench-compare: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
    process.exit(2);
  });
