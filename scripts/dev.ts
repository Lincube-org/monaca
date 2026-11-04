// `bun run dev` — the single entry point for the three local dev modes (contract §3, plan §9).
//
//   mode a  local full stack: fetched server binary + PostgreSQL + gateway + console + auth-ui
//   mode b  remote dev:       Vue apps only, Vite proxied to the deployed dev gateway
//   mode c  ci only:          typecheck + unit tests locally; builds and e2e run on GitHub Actions
//
// The first run with no `--mode` prompts once and records the answer in `.monaca/dev.json`.
// Ctrl-C stops every child and the embedded database, in that order.
import { existsSync } from "node:fs";
import { join } from "node:path";
import { isListening, waitForHttp, waitForPort } from "./lib/net.ts";
import { startEmbeddedPg, type EmbeddedPgHandle } from "./lib/embedded-pg.ts";
import { runChild, Supervisor, startChild, type ChildSpec } from "./lib/proc.ts";
import { MODE_HELP, chooseMode, parseArgs, type DevMode } from "./lib/dev-config.ts";

const ROOT = join(import.meta.dir, "..");

/** The port out of a `host:port` value, falling back to the contract default. */
function portOf(value: string | undefined, fallback: number): number {
  const raw = value?.split(":").pop();
  const parsed = raw === undefined ? Number.NaN : Number(raw);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

/** Contract §2.1: the ports that must not be double-bound. Addresses win over bare ports. */
const PORTS = {
  server: portOf(process.env.MONACA_SERVER_ADDR, 8081),
  gateway: portOf(process.env.MONACA_GATEWAY_ADDR, 8080),
  console: Number(process.env.MONACA_CONSOLE_PORT ?? 5173),
  authUi: Number(process.env.MONACA_AUTH_UI_PORT ?? 5174),
} as const;

const ENV = {
  serverUrl: process.env.MONACA_SERVER_URL ?? `http://127.0.0.1:${PORTS.server}`,
  publicBaseUrl: process.env.MONACA_PUBLIC_BASE_URL ?? `http://localhost:${PORTS.gateway}`,
  consoleUrl: process.env.MONACA_CONSOLE_URL ?? `http://localhost:${PORTS.console}`,
  authUiUrl: process.env.MONACA_AUTH_UI_URL ?? `http://localhost:${PORTS.authUi}`,
  tenant: process.env.MONACA_CONSOLE_TENANT ?? "demo",
};

const supervisor = new Supervisor();
let stopping = false;
/** The embedded cluster, once one is running; `die` and the signal handler both stop it. */
let activePg: EmbeddedPgHandle | undefined;

/**
 * How long `monaca-server migrate` / `bootstrap` may take. This is a hang guard, not a performance
 * target: on a loaded machine (or a first run that applies every migration) it has to be loose
 * enough that a slow-but-working run is never killed. Override with MONACA_DEV_MIGRATE_TIMEOUT_MS.
 */
const MIGRATE_TIMEOUT_MS = Number(process.env.MONACA_DEV_MIGRATE_TIMEOUT_MS ?? 600_000);

function heading(text: string): void {
  process.stdout.write(`\n\x1b[1m${text}\x1b[0m\n`);
}

function info(text: string): void {
  process.stdout.write(`  ${text}\n`);
}

/** Refuses to start a second copy of a child whose port is already taken (contract §3). */
async function requireFreePort(label: string, port: number): Promise<void> {
  if (await isListening(port)) {
    throw new Error(
      `port ${port} (${label}) is already in use — stop the other process, or set the matching *_PORT env var`,
    );
  }
}

/**
 * The gateway entry is `src/main.ts`; `src/index.ts` is accepted for a tree that renamed it.
 * `MONACA_DEV_GATEWAY_ENTRY` overrides it, which is how a stub gateway can be exercised.
 */
function gatewayEntry(): string {
  const override = process.env.MONACA_DEV_GATEWAY_ENTRY;
  if (override !== undefined && override !== "") return override;
  const main = join(ROOT, "apps", "gateway", "src", "main.ts");
  const index = join(ROOT, "apps", "gateway", "src", "index.ts");
  if (existsSync(main)) return main;
  if (existsSync(index)) return index;
  throw new Error(`no gateway entry point: expected ${main} or ${index}`);
}

function viteSpec(app: "console" | "auth-ui", color: "green" | "blue", extraEnv: Record<string, string>): ChildSpec {
  const port = app === "console" ? PORTS.console : PORTS.authUi;
  const spec: ChildSpec = {
    name: app === "console" ? "console" : "auth-ui",
    color,
    // The app's own `dev` script pins its port; repeating --port after `--` makes the
    // contract's MONACA_*_PORT override win without the app having to change (vite takes the last).
    cmd: ["bun", "run", "dev", "--", "--port", String(port), "--strictPort"],
    cwd: join(ROOT, "apps", app),
    env: { ...extraEnv, MONACA_CONSOLE_PORT: String(PORTS.console), MONACA_AUTH_UI_PORT: String(PORTS.authUi) },
  };
  return spec;
}

/** Spawns a child and arranges for its unexpected exit to take the whole stack down. */
function spawn(name: string, spec: ChildSpec, onExit: (name: string, code: number) => void): void {
  const child = supervisor.add(startChild(spec));
  void child.exited.then((code) => {
    if (!stopping) onExit(name, code);
  });
}

/** Runs a child to completion; a non-zero code is reported and returned. */
async function mustRun(label: string, spec: ChildSpec & { timeoutMs?: number }): Promise<void> {
  info(`running ${label} …`);
  const { code, ms } = await runChild(spec);
  if (code !== 0) throw new Error(`${label} failed (exit ${code}, ${ms} ms)`);
  info(`${label} ok (${ms} ms)`);
}

/**
 * Stops everything, at most once. The first caller does the work; a second caller (a failing child
 * racing the signal handler) waits for that same promise instead of returning early. Children go
 * down first so they release their ports and database connections, then PostgreSQL.
 */
let shutdownPromise: Promise<void> | undefined;

async function shutdown(exitCode = 0): Promise<number> {
  stopping = true;
  shutdownPromise ??= (async () => {
    await supervisor.stopAll();
    const pg = activePg;
    activePg = undefined;
    if (!pg) return;
    heading("stopping embedded PostgreSQL");
    const { graceful, ms } = await pg.stop();
    info(`${graceful ? "stopped" : "killed"} in ${ms} ms`);
  })();
  await shutdownPromise;
  return exitCode;
}

// --- mode A -----------------------------------------------------------------

async function modeA(withGateway: boolean): Promise<number> {
  if (withGateway) info("note: --with-gateway is a mode b flag; mode a always runs the gateway");

  const serverBin =
    process.env.MONACA_SERVER_BIN ?? join(ROOT, ".monaca", "bin", process.platform === "win32" ? "monaca-server.exe" : "monaca-server");
  if (!existsSync(serverBin)) {
    process.stderr.write(
      `\nmode a needs the server binary, which is not at ${serverBin}\n\n` +
        `  run: bun run fetch:native\n\n` +
        `The Rust server is built by GitHub Actions (this machine has no Rust toolchain);\n` +
        `fetch:native downloads the artifact for the current commit. Use --mode b to develop\n` +
        `the frontends against the deployed dev gateway instead.\n\n`,
    );
    return 1;
  }

  await requireFreePort("gateway", PORTS.gateway);
  await requireFreePort("console", PORTS.console);
  await requireFreePort("auth-ui", PORTS.authUi);

  const reuseUrl = process.env.DATABASE_URL;
  let controlUrl: string;
  let adminUrl: string;

  if (reuseUrl) {
    heading(`using the PostgreSQL in DATABASE_URL (${redact(reuseUrl)})`);
    controlUrl = reuseUrl;
    adminUrl = withDatabaseName(reuseUrl, "postgres");
  } else {
    const port = Number(process.env.MONACA_EMBEDDED_PG_PORT ?? 54329);
    await requireFreePort("embedded PostgreSQL", port);
    heading(`starting embedded PostgreSQL on 127.0.0.1:${port} (.monaca/pg)`);
    const pg = await startEmbeddedPg({
      baseDir: join(ROOT, ".monaca", "pg"),
      port,
      user: process.env.MONACA_EMBEDDED_PG_USER ?? "monaca",
      password: process.env.MONACA_EMBEDDED_PG_PASSWORD ?? "monaca",
      onLog: process.env.MONACA_LOG_LEVEL === "debug" ? (line) => info(`pg │ ${line}`) : undefined,
    });
    activePg = pg;
    info(
      `postgres ${pg.initialised ? "initialised and started" : "started"} in ` +
        `${pg.timings.initialiseMs === null ? "" : `${pg.timings.initialiseMs} ms initdb + `}${pg.timings.startMs} ms`,
    );
    info(`log: ${pg.logFile}`);
    controlUrl = process.env.MONACA_CONTROL_DATABASE_URL ?? pg.url("monaca_control");
    adminUrl = process.env.MONACA_ADMIN_DATABASE_URL ?? pg.url("postgres");
  }

  const serverEnv: Record<string, string> = {
    MONACA_SERVER_ADDR: `127.0.0.1:${PORTS.server}`,
    MONACA_SERVER_URL: ENV.serverUrl,
    MONACA_PUBLIC_BASE_URL: ENV.publicBaseUrl,
    MONACA_CONTROL_DATABASE_URL: controlUrl,
    MONACA_ADMIN_DATABASE_URL: adminUrl,
    // The dev gateway and the server are on this host and the gateway appends X-Forwarded-For.
    MONACA_TRUSTED_PROXY_CIDRS: "127.0.0.1/32,::1/128",
  };

  try {
    if (process.env.MONACA_DEV_SKIP_MIGRATE === "1") {
      info("MONACA_DEV_SKIP_MIGRATE=1: skipping migrate and bootstrap");
    } else {
      heading("migrating and seeding the database");
      await mustRun("monaca-server migrate", {
        name: "server",
        color: "red",
        cmd: [serverBin, "migrate"],
        env: serverEnv,
        timeoutMs: MIGRATE_TIMEOUT_MS,
      });
      await mustRun("monaca-server bootstrap", {
        name: "server",
        color: "red",
        cmd: [serverBin, "bootstrap"],
        env: serverEnv,
        timeoutMs: MIGRATE_TIMEOUT_MS,
      });
    }
  } catch (err) {
    process.stderr.write(`\n${err instanceof Error ? err.message : String(err)}\n`);
    await shutdown(1);
    return 1;
  }

  heading("starting the stack");
  try {
    spawn(
      "server",
      { name: "server", color: "red", cmd: [serverBin, "serve"], env: serverEnv },
      (name, code) => void die(`${name} exited with code ${code}`),
    );
    spawn(
      "gateway",
      {
        name: "gateway",
        color: "magenta",
        cmd: ["bun", "--watch", gatewayEntry()],
        env: { ...serverEnv, MONACA_DEV_PROXY: "1", MONACA_GATEWAY_ADDR: `127.0.0.1:${PORTS.gateway}` },
      },
      (name, code) => void die(`${name} exited with code ${code}`),
    );
    spawn("console", viteSpec("console", "green", { VITE_MONACA_GATEWAY_URL: ENV.publicBaseUrl }), (name, code) =>
      void die(`${name} exited with code ${code}`),
    );
    spawn("auth-ui", viteSpec("auth-ui", "blue", { VITE_MONACA_GATEWAY_URL: ENV.publicBaseUrl }), (name, code) =>
      void die(`${name} exited with code ${code}`),
    );
  } catch (err) {
    // A spawn that never started still has to take the database down with it.
    process.stderr.write(`\n${err instanceof Error ? err.message : String(err)}\n`);
    return await shutdown(1);
  }

  const ready = await waitForHttp(`${ENV.publicBaseUrl}/healthz`, { timeoutMs: 60_000, alive: () => !stopping });
  if (!ready) {
    // `stopping` is set either by a child that died (already reported above) or by the deadline.
    if (!stopping) {
      process.stderr.write(
        `\ngateway did not answer ${ENV.publicBaseUrl}/healthz within 60 s — see the gateway lines above\n\n`,
      );
    }
    return await shutdown(1);
  }
  // The gateway answers before vite has finished starting; "ready" has to mean every URL works.
  const apps = await Promise.all([waitForPort(PORTS.console, { timeoutMs: 60_000 }), waitForPort(PORTS.authUi, { timeoutMs: 60_000 })]);
  if (!apps.every(Boolean)) {
    process.stderr.write(`\nthe vite dev servers did not start within 60 s — see the console/auth-ui lines above\n\n`);
    return await shutdown(1);
  }

  heading("ready — open these");
  info(`console      ${ENV.consoleUrl}`);
  info(`sign-in      ${ENV.authUiUrl}`);
  info(`gateway      ${ENV.publicBaseUrl}  (issuer ${ENV.publicBaseUrl}/t/${ENV.tenant})`);
  info(`server       ${ENV.serverUrl}  (internal only)`);
  info(`admin login  ${process.env.MONACA_BOOTSTRAP_ADMIN_EMAIL ?? "admin@demo.localhost"} / ${process.env.MONACA_BOOTSTRAP_ADMIN_PASSWORD ?? "monaca-dev-password"}`);
  info("Ctrl-C stops everything, including the database.");
  process.stdout.write("\n");

  return await holdUntilSignal();
}

/** Replaces the path component of a PostgreSQL URL with `name`. */
function withDatabaseName(url: string, name: string): string {
  try {
    const parsed = new URL(url);
    parsed.pathname = `/${name}`;
    return parsed.toString();
  } catch {
    return url;
  }
}

/** Hides the password of a DSN before it reaches a terminal or a log. */
function redact(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.password !== "") parsed.password = "***";
    return parsed.toString();
  } catch {
    return "<unparseable DATABASE_URL>";
  }
}

// --- mode B -----------------------------------------------------------------

async function modeB(withGateway: boolean): Promise<number> {
  const remote = process.env.MONACA_REMOTE_URL;
  if (!remote) {
    process.stderr.write(
      `\nmode b needs MONACA_REMOTE_URL — the deployed dev gateway to proxy to.\n\n` +
        `  set MONACA_REMOTE_URL=https://dev.monaca.example in .env.local (see .env.example)\n` +
        `  or use --mode a for a full local stack.\n\n`,
    );
    return 1;
  }
  await requireFreePort("console", PORTS.console);
  await requireFreePort("auth-ui", PORTS.authUi);

  const reachable = await waitForHttp(`${remote.replace(/\/$/, "")}/healthz`, { timeoutMs: 10_000 });
  heading(`mode b — frontends proxy to ${remote}`);
  if (!reachable) {
    info(`warning: ${remote}/healthz did not answer; the UI will still start, but API calls will fail`);
  }

  if (withGateway) {
    await requireFreePort("gateway", PORTS.gateway);
    spawn(
      "gateway",
      {
        name: "gateway",
        color: "magenta",
        cmd: ["bun", "--watch", gatewayEntry()],
        env: {
          MONACA_SERVER_URL: process.env.MONACA_SERVER_URL ?? remote,
          MONACA_PUBLIC_BASE_URL: process.env.MONACA_PUBLIC_BASE_URL ?? `http://localhost:${PORTS.gateway}`,
          MONACA_DEV_PROXY: "1",
          MONACA_GATEWAY_ADDR: `127.0.0.1:${PORTS.gateway}`,
        },
      },
      (name, code) => void die(`${name} exited with code ${code}`),
    );
    info(`local gateway on http://localhost:${PORTS.gateway} → server ${process.env.MONACA_SERVER_URL ?? remote}`);
  }

  const proxyTarget = withGateway ? `http://localhost:${PORTS.gateway}` : remote;
  spawn("console", viteSpec("console", "green", { VITE_MONACA_GATEWAY_URL: proxyTarget }), (name, code) =>
    void die(`${name} exited with code ${code}`),
  );
  spawn("auth-ui", viteSpec("auth-ui", "blue", { VITE_MONACA_GATEWAY_URL: proxyTarget }), (name, code) =>
    void die(`${name} exited with code ${code}`),
  );

  const apps = await Promise.all([
    waitForPort(PORTS.console, { timeoutMs: 60_000, alive: () => !stopping }),
    waitForPort(PORTS.authUi, { timeoutMs: 60_000, alive: () => !stopping }),
  ]);
  if (!apps.every(Boolean)) {
    if (!stopping) {
      process.stderr.write(`\nthe vite dev servers did not start within 60 s — see the console/auth-ui lines above\n\n`);
    }
    return await shutdown(1);
  }

  heading("ready — open these");
  info(`console      ${ENV.consoleUrl}`);
  info(`sign-in      ${ENV.authUiUrl}`);
  info(`proxy target ${proxyTarget}`);
  info("Ctrl-C stops everything.");
  process.stdout.write("\n");

  return await holdUntilSignal();
}

// --- mode C -----------------------------------------------------------------

async function modeC(): Promise<number> {
  heading("mode c — local typecheck and unit tests; builds and e2e run on GitHub Actions");

  const typecheck = await runChild({
    name: "typecheck",
    color: "yellow",
    cmd: ["bun", "run", "typecheck"],
    cwd: ROOT,
  });
  const test = await runChild({ name: "test", color: "yellow", cmd: ["bun", "test"], cwd: ROOT });

  heading("summary");
  info(`bun run typecheck  ${typecheck.code === 0 ? "ok" : `FAILED (exit ${typecheck.code})`} in ${typecheck.ms} ms`);
  info(`bun test           ${test.code === 0 ? "ok" : `FAILED (exit ${test.code})`} in ${test.ms} ms`);
  info("");
  info("mode c does not build the Rust side or run the acceptance script — that happens in CI:");
  info("  bun run verify:ci                      # dispatch rust.yml + web.yml on this branch and watch them");
  info("  gh run list --workflow=rust.yml        # inspect a run manually");
  info("  bun run fetch:native                   # pull the artifacts of the current commit once CI is green");
  info("  bun run e2e:skeleton --base-url <url>  # the same acceptance script CI runs");
  process.stdout.write("\n");

  return typecheck.code !== 0 ? typecheck.code : test.code;
}

// --- shared -----------------------------------------------------------------

/**
 * Ctrl-C (or a fatal child exit) unwinds here. Installed before any child starts, so a Ctrl-C
 * during startup — the common case, since initdb and vite both take seconds — still takes the
 * children and the database down instead of leaving an orphaned PostgreSQL behind.
 *
 * It waits on either shutdown route: the one the signal handler started, or the one a dying child
 * started. `main` returns from here and its caller calls `process.exit`, so resolving before the
 * shutdown finished would cut it short and leave ports bound.
 */
function holdUntilSignal(): Promise<number> {
  return new Promise<number>((resolve) => {
    const check = setInterval(() => {
      const pending = shutdownPromise ?? supervisor.shuttingDown;
      if (pending) {
        clearInterval(check);
        process.stdout.write("\n");
        void pending.then(() => resolve(0), () => resolve(0));
      }
    }, 50);
  });
}

/** A child died on its own: take the rest of the stack down with it, database included. */
async function die(message: string, exitCode = 1): Promise<never> {
  // A second child can die while the first shutdown is still running (killing one tree often takes
  // its neighbours with it). Waiting on the same promise keeps that shutdown intact instead of
  // exiting over the top of it and leaving ports bound.
  if (!stopping) process.stderr.write(`\n\x1b[31m${message}\x1b[0m — shutting the stack down\n\n`);
  await shutdown(exitCode);
  process.exit(exitCode);
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(
      [
        "usage: bun run dev [--mode a|b|c] [--with-gateway]",
        "",
        ...(["a", "b", "c"] as DevMode[]).map((m) => `  ${m}  ${MODE_HELP[m]}`),
        "",
        "The first run without --mode prompts once and records the answer in .monaca/dev.json.",
        "--with-gateway is meaningful in mode b only.",
      ].join("\n"),
    );
    return 0;
  }
  if (args.unknown.length > 0) {
    process.stderr.write(`unrecognised argument(s): ${args.unknown.join(" ")}\nrun: bun run dev --help\n`);
    return 1;
  }

  // Before anything is spawned, so Ctrl-C during startup still cleans up.
  supervisor.install(async () => {
    await shutdown();
  });

  const { mode, source } = await chooseMode(ROOT, args, process.stdin.isTTY === true);
  heading(`monaca dev — mode ${mode} (from ${source})`);
  info(MODE_HELP[mode]);

  switch (mode) {
    case "a":
      return await modeA(args.withGateway);
    case "b":
      return await modeB(args.withGateway);
    case "c":
      if (args.withGateway) info("note: --with-gateway is a mode b flag; mode c runs no servers");
      return await modeC();
  }
}

try {
  process.exit(await main());
} catch (err) {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`\n\x1b[31mdev: ${message}\x1b[0m\n`);
  if (err instanceof Error && err.stack && process.env.MONACA_LOG_LEVEL === "debug") {
    process.stderr.write(`${err.stack}\n`);
  }
  process.exit(1);
}
