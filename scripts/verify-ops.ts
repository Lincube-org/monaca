// One-command operations acceptance: empty database → migrate → bootstrap → seed → backup →
// restore → start and verify → rotate the KEK → rewrap → restart and verify.
//
// It calls the real `deploy/backup.sh` and `deploy/restore-drill.sh`, and the real server
// subcommands, against a dockerised PostgreSQL. `deploy/verify-ops.sh` is the documented entry
// point; this file is the orchestration it runs. Any failed step exits non-zero.
//
//   bash deploy/verify-ops.sh --container <id|name> [--server-bin <path>]

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..");
const TENANT = "demo";
const ORG = "acme";
const DEFAULT_KEY_A = "00000000000000000000000000000000000000000000000000000000000000ff";
const DEFAULT_KEY_B = "22".repeat(32);

interface Args {
  readonly container: string;
  readonly serverBin: string;
  readonly workDir: string;
  readonly port: number;
  readonly dbUser: string;
}

function usage(): string {
  return `usage: verify-ops.sh --container <id|name> [--server-bin <path>] [--work-dir <dir>]
                          [--port <port>] [--db-user <role>]
`;
}

function parseArgs(argv: readonly string[]): Args {
  let container = "";
  let serverBin = process.env.MONACA_SERVER_BIN ?? join(ROOT, ".monaca", "bin", process.platform === "win32" ? "monaca-server.exe" : "monaca-server");
  let workDir = join(ROOT, ".monaca", "ops");
  let port = 8083;
  let dbUser = "postgres";
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? "";
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage());
      process.exit(0);
    } else if (arg === "--container") {
      container = argv[++i] ?? "";
    } else if (arg === "--server-bin") {
      serverBin = argv[++i] ?? serverBin;
    } else if (arg === "--work-dir") {
      workDir = argv[++i] ?? workDir;
    } else if (arg === "--port") {
      port = Number(argv[++i] ?? port);
    } else if (arg === "--db-user") {
      dbUser = argv[++i] ?? dbUser;
    } else {
      throw new Error(`unknown argument ${JSON.stringify(arg)}\n${usage()}`);
    }
  }
  if (container === "") throw new Error(`--container is required\n${usage()}`);
  return { container, serverBin, workDir, port, dbUser };
}

interface Step {
  name: string;
  ok: boolean;
  ms: number;
  detail: string;
}
interface Check {
  name: string;
  passed: boolean;
  detail: string;
}

const steps: Step[] = [];
const checks: Check[] = [];
function check(name: string, passed: boolean, detail = ""): void {
  checks.push({ name, passed, detail });
  process.stdout.write(`  ${passed ? "pass" : "FAIL"}  ${name}${detail === "" ? "" : `  ${detail}`}\n`);
}

function fail(why: string): never {
  throw new Error(`verify-ops: ${why}`);
}

async function step(
  name: string,
  body: (log: (line: string) => void) => Promise<void>,
): Promise<void> {
  const started = performance.now();
  const detail: string[] = [];
  const log = (line: string): void => {
    detail.push(line);
    process.stdout.write(`  ${line}\n`);
  };
  try {
    await body(log);
    steps.push({ name, ok: true, ms: Math.round(performance.now() - started), detail: detail.join("\n") });
  } catch (err) {
    steps.push({
      name,
      ok: false,
      ms: Math.round(performance.now() - started),
      detail: `${detail.join("\n")}\n${err instanceof Error ? err.message : String(err)}`,
    });
    throw err;
  }
}

interface HttpResult {
  status: number;
  body: unknown;
  headers: Headers;
}

async function call(url: string, init: RequestInit = {}): Promise<HttpResult> {
  const response = await fetch(url, init);
  const text = await response.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {
    // keep the text
  }
  return { status: response.status, body, headers: response.headers };
}

const jsonHeaders = (token: string): Record<string, string> => ({
  authorization: `Bearer ${token}`,
  "content-type": "application/json",
});

function copyEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) if (value !== undefined) env[key] = value;
  return env;
}

/** Run a server subcommand and fail with its combined output. */
async function runServer(args: string[], env: Record<string, string>, label: string): Promise<string> {
  const proc = Bun.spawn([args[0]!, ...args.slice(1)], {
    cwd: ROOT,
    env: { ...copyEnv(), ...env },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  if (code !== 0) fail(`${label} exited ${code}\n--- stdout ---\n${stdout}\n--- stderr ---\n${stderr}`);
  return stdout.trim();
}

/** One psql query inside the postgres container. */
async function psql(args: Args, database: string, sql: string): Promise<string> {
  const proc = Bun.spawn(
    [
      "docker",
      "exec",
      "-i",
      args.container,
      "psql",
      "-U",
      args.dbUser,
      "-d",
      database,
      "-v",
      "ON_ERROR_STOP=1",
      "-tAc",
      sql,
    ],
    { stdout: "pipe", stderr: "pipe" },
  );
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  if (code !== 0) fail(`psql ${database}: ${sql}\n${stdout}\n${stderr}`);
  return stdout.trim();
}

async function dropDatabase(args: Args, database: string): Promise<void> {
  await psql(
    args,
    "postgres",
    `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${database}' AND pid <> pg_backend_pid()`,
  );
  await psql(args, "postgres", `DROP DATABASE IF EXISTS "${database}"`);
}

async function runScript(command: string[], label: string): Promise<string> {
  const proc = Bun.spawn(["bash", ...command], {
    cwd: ROOT,
    env: copyEnv(),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  if (code !== 0) fail(`${label} exited ${code}\n--- stdout ---\n${stdout}\n--- stderr ---\n${stderr}`);
  return stdout.trim();
}

let server: ReturnType<typeof Bun.spawn> | undefined;
let serverReader: Promise<void> | undefined;

function base(args: Args): string {
  return `http://127.0.0.1:${args.port}`;
}

function serverEnv(args: Args, kek: string, previous?: string): Record<string, string> {
  const env = copyEnv();
  env.MONACA_ENV = "ci";
  env.MONACA_SERVER_ADDR = `127.0.0.1:${args.port}`;
  env.MONACA_SERVER_URL = base(args);
  env.MONACA_PUBLIC_BASE_URL = base(args);
  env.MONACA_DEV_KEK = kek;
  env.MONACA_LOG_LEVEL = "warn";
  env.MONACA_IP_RATE_LIMIT_PER_MINUTE = "0";
  delete env.MONACA_KEK;
  if (previous === undefined) delete env.MONACA_KEK_PREVIOUS;
  else env.MONACA_KEK_PREVIOUS = previous;
  return env;
}

async function startServer(args: Args, kek: string, previous?: string): Promise<void> {
  const log: string[] = [];
  server = Bun.spawn([args.serverBin, "serve"], {
    cwd: ROOT,
    env: serverEnv(args, kek, previous),
    stdout: "ignore",
    stderr: "pipe",
  });
  serverReader = (async (): Promise<void> => {
    const stderr = server!.stderr as ReadableStream<Uint8Array>;
    for await (const chunk of stderr) {
      log.push(String(chunk));
      while (log.join("").length > 8_000) log.shift();
    }
  })().catch(() => undefined);
  for (let i = 0; i < 120; i++) {
    try {
      const response = await fetch(`${base(args)}/healthz`, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) return;
    } catch {
      // not listening yet
    }
    await Bun.sleep(250);
  }
  fail(`the server never answered /healthz\n${log.join("")}`);
}

async function stopServer(): Promise<void> {
  if (server === undefined) return;
  server.kill();
  await server.exited;
  server = undefined;
  await serverReader;
  serverReader = undefined;
  await Bun.sleep(250);
}

async function adminToken(args: Args, log: (line: string) => void): Promise<string> {
  const secret = process.env.MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET ?? "dev-admin-client-secret";
  const response = await call(`${base(args)}/t/${TENANT}/oauth2/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${btoa(`monaca-admin:${secret}`)}`,
    },
    body: new URLSearchParams({ grant_type: "client_credentials", scope: "monaca:admin" }).toString(),
  });
  const token = (response.body as { access_token?: string })?.access_token ?? "";
  if (response.status !== 200 || token === "") {
    fail(`no management token: ${response.status} ${JSON.stringify(response.body)}`);
  }
  log("a management token was minted");
  return token;
}

/** A console interaction with PKCE, as the hosted page opens it. */
async function begin(args: Args): Promise<{ interaction: string; verifier: string }> {
  const verifier = `ops-${Date.now().toString(36)}-${"v".repeat(40)}`;
  const challenge = Buffer.from(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
  )
    .toString("base64url");
  const response = await call(
    `${base(args)}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: "http://localhost:5173/bff/callback",
      scope: "openid profile email",
      state: `ops-${Date.now().toString(36)}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
    })}`,
    { redirect: "manual" },
  );
  const interaction = new URL(response.headers.get("location") ?? "", base(args)).searchParams.get(
    "interaction",
  );
  if (response.status !== 302 || interaction === null) {
    fail(`authorize answered ${response.status} ${JSON.stringify(response.body)}`);
  }
  return { interaction: encodeURIComponent(interaction), verifier };
}

async function signIn(args: Args, email: string, password: string): Promise<HttpResult> {
  const started = await begin(args);
  return call(`${base(args)}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identifier: email, password }),
  });
}

async function requestReset(args: Args, email: string): Promise<void> {
  const started = await begin(args);
  const response = await call(
    `${base(args)}/t/${TENANT}/interaction/${started.interaction}/password/forgot`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email }),
    },
  );
  if (response.status !== 200) fail(`password/forgot answered ${response.status}`);
}

interface Mail {
  id: string;
  authorization: string;
  at: number;
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  await mkdir(args.workDir, { recursive: true });
  const keyA = process.env.MONACA_OPS_KEK_A ?? DEFAULT_KEY_A;
  const keyB = process.env.MONACA_OPS_KEK_B ?? DEFAULT_KEY_B;
  const email = `ops-${Date.now().toString(36)}@demo.localhost`;
  const password = `Ops-Restore-${Date.now().toString(36)}-9xQ`;
  const connectorSecret = `ops-connector-secret-${Date.now().toString(36)}`;
  const mails: Mail[] = [];
  let resetCounter = 0;
  // A fresh address keeps `password/forgot` out of the per-address resend cooldown. The endpoint
  // answers the same for an unknown address, so this still proves the connector, not the account.
  const resetTarget = (): string =>
    `ops-reset-${Date.now().toString(36)}-${resetCounter++}@demo.localhost`;
  let mock: ReturnType<typeof Bun.serve> | undefined;

  const report = {
    generated_at: "",
    container: args.container,
    server_binary: args.serverBin,
    tenant: TENANT,
    org: ORG,
    steps,
    checks,
    passed: false,
  };

  try {
    await step("empty database", async (log) => {
      await dropDatabase(args, "monaca_control");
      await dropDatabase(args, "mt_demo");
      await psql(args, "postgres", "CREATE DATABASE monaca_control");
      log("dropped monaca_control and mt_demo, created an empty monaca_control");
    });

    await step("migrate and bootstrap", async (log) => {
      const env = serverEnv(args, keyA);
      await runServer([args.serverBin, "migrate"], env, "migrate");
      await runServer([args.serverBin, "bootstrap"], env, "bootstrap");
      await runServer([args.serverBin, "migrate"], env, "migrate (replay)");
      const dbName = await psql(args, "monaca_control", "SELECT db_name FROM tenants WHERE slug = 'demo'");
      if (dbName === "") fail("bootstrap did not provision demo");
      log(`migrated, bootstrapped and replayed; demo lives in ${dbName}`);
    });

    await step("seed an account and an email connector", async (log) => {
      mock = Bun.serve({
        port: 0,
        hostname: "127.0.0.1",
        async fetch(request) {
          const body = (await request.json().catch(() => ({}))) as { id?: string };
          mails.push({
            id: String(body.id ?? ""),
            authorization: request.headers.get("authorization") ?? "",
            at: Date.now(),
          });
          return new Response(null, { status: 202 });
        },
      });
      const endpoint = `http://127.0.0.1:${mock.port}/send`;
      await startServer(args, keyA);
      const token = await adminToken(args, log);
      const created = await call(`${base(args)}/v1/accounts`, {
        method: "POST",
        headers: jsonHeaders(token),
        body: JSON.stringify({ email, display_name: "Ops Account", password }),
      });
      const accountId = (created.body as { id?: string })?.id ?? "";
      if (created.status !== 201 || !accountId.startsWith("acc_")) {
        fail(`POST /v1/accounts answered ${created.status} ${JSON.stringify(created.body)}`);
      }
      await call(`${base(args)}/v1/orgs/${ORG}/members`, {
        method: "POST",
        headers: jsonHeaders(token),
        body: JSON.stringify({ account_id: accountId, role: "member" }),
      });
      const connector = await call(`${base(args)}/v1/email-connector`, {
        method: "PATCH",
        headers: jsonHeaders(token),
        body: JSON.stringify({
          provider: "http",
          endpoint,
          from_address: "no-reply@demo.localhost",
          secret: connectorSecret,
        }),
      });
      if (connector.status !== 200) fail(`PATCH /v1/email-connector answered ${connector.status}`);
      const signed = await signIn(args, email, password);
      check("the seeded account signs in", signed.status === 200, `${signed.status}`);
      if (signed.status !== 200) fail("the seeded account cannot sign in");
      await requestReset(args, resetTarget());
      for (let i = 0; i < 120 && mails.length === 0; i++) await Bun.sleep(250);
      check(
        "the seeded connector delivers a reset mail",
        mails.at(-1)?.authorization === `Bearer ${connectorSecret}`,
        mails.length === 0 ? "no mail" : mails.at(-1)?.authorization ?? "",
      );
      if (mails.length === 0) fail("the connector delivered no mail");
      log(`seeded account ${email} and connector ${endpoint}`);
    });

    const dbName = await psql(args, "monaca_control", "SELECT db_name FROM tenants WHERE slug = 'demo'");
    if (dbName === "") fail("demo has no database name");

    await step("backup every database", async (log) => {
      await stopServer();
      const controlDump = join(args.workDir, "monaca_control.dump");
      const tenantDump = join(args.workDir, `${dbName}.dump`);
      await runScript(
        [
          "deploy/backup.sh",
          "--container",
          args.container,
          "--db",
          "monaca_control",
          "--db-user",
          args.dbUser,
          "--out",
          controlDump,
        ],
        "backup.sh monaca_control",
      );
      await runScript(
        [
          "deploy/backup.sh",
          "--container",
          args.container,
          "--db",
          dbName,
          "--db-user",
          args.dbUser,
          "--out",
          tenantDump,
        ],
        `backup.sh ${dbName}`,
      );
      log(`dumped monaca_control and ${dbName}`);
    });

    await step("restore into fresh databases", async (log) => {
      const controlDump = join(args.workDir, "monaca_control.dump");
      const tenantDump = join(args.workDir, `${dbName}.dump`);
      await dropDatabase(args, "monaca_control");
      await dropDatabase(args, dbName);
      await runScript(
        [
          "deploy/restore-drill.sh",
          "--container",
          args.container,
          "--db-user",
          args.dbUser,
          "--dump",
          controlDump,
          "--target-db",
          "monaca_control",
          "--recreate",
        ],
        "restore-drill.sh monaca_control",
      );
      await runScript(
        [
          "deploy/restore-drill.sh",
          "--container",
          args.container,
          "--db-user",
          args.dbUser,
          "--dump",
          tenantDump,
          "--target-db",
          dbName,
          "--recreate",
        ],
        `restore-drill.sh ${dbName}`,
      );
      log(`restored monaca_control and ${dbName} from the dumps`);
    });

    await step("migrate and audit-verify the restored copy", async (log) => {
      const env = { ...serverEnv(args, keyA), MONACA_AUDIT_TENANT: TENANT, MONACA_AUDIT_ORG: ORG };
      await runServer([args.serverBin, "migrate"], env, "migrate (restored)");
      await runServer([args.serverBin, "audit", "verify"], env, "audit verify");
      log("migrate replayed and the audit chain verifies");
    });

    await step("start on the restored copy and verify the data", async (log) => {
      await startServer(args, keyA);
      const token = await adminToken(args, log);
      check("a management token is minted from the restored signing key", token.length > 0);
      const signed = await signIn(args, email, password);
      check("the restored account signs in", signed.status === 200, `${signed.status}`);
      if (signed.status !== 200) fail("the restored account cannot sign in");
      const before = mails.length;
      await requestReset(args, resetTarget());
      for (let i = 0; i < 120 && mails.length <= before; i++) await Bun.sleep(250);
      check(
        "the restored connector delivers a reset mail",
        mails.length > before && mails.at(-1)?.authorization === `Bearer ${connectorSecret}`,
        mails.at(-1)?.authorization ?? "no mail",
      );
      if (mails.length <= before) fail("the restored connector delivered no mail");
      log("restored account, signing key and connector all work");
    });

    await step("rotate the KEK and rewrap", async (log) => {
      await stopServer();
      await startServer(args, keyB, keyA);
      const output = await runServer(
        [args.serverBin, "rewrap", "--tenant", TENANT],
        serverEnv(args, keyB, keyA),
        "rewrap",
      );
      const summary = /re-wrapped (\d+) value\(s\).*failed (\d+)/.exec(output);
      check(
        "rewrap moves the restored values with no failures",
        summary !== null && Number(summary[1]) > 0 && Number(summary[2]) === 0,
        output,
      );
      if (summary === null || Number(summary[2]) !== 0) fail(output);
      await stopServer();
      await startServer(args, keyB);
      log("rotated to the new KEK and removed the old one");
    });

    await step("verify after the rotation", async (log) => {
      const token = await adminToken(args, log);
      check("a management token is minted with only the new KEK", token.length > 0);
      const signed = await signIn(args, email, password);
      check("the account signs in after the rotation", signed.status === 200, `${signed.status}`);
      if (signed.status !== 200) fail("the account cannot sign in after the rotation");
      const before = mails.length;
      await requestReset(args, resetTarget());
      for (let i = 0; i < 120 && mails.length <= before; i++) await Bun.sleep(250);
      check(
        "the rewrapped connector delivers a reset mail",
        mails.length > before && mails.at(-1)?.authorization === `Bearer ${connectorSecret}`,
        mails.at(-1)?.authorization ?? "no mail",
      );
      if (mails.length <= before) fail("the rewrapped connector delivered no mail");
      log("signing key, account and connector still work with only the new KEK");
    });
  } catch (err) {
    process.stderr.write(`\nops acceptance failed: ${err instanceof Error ? err.message : String(err)}\n`);
    report.passed = false;
    report.generated_at = new Date().toISOString();
    await stopServer();
    mock?.stop(true);
    await writeReport(report);
    process.exit(1);
  } finally {
    await stopServer();
    mock?.stop(true);
  }

  report.passed = checks.every((entry) => entry.passed);
  report.generated_at = new Date().toISOString();
  await writeReport(report);
  process.stdout.write(
    `\nops acceptance: ${report.passed ? "ok" : "FAILED"} (${checks.length} checks, ${steps.length} steps)\n`,
  );
  return report.passed ? 0 : 1;
}

async function writeReport(
  report: {
    generated_at: string;
    container: string;
    server_binary: string;
    tenant: string;
    org: string;
    steps: Step[];
    checks: Check[];
    passed: boolean;
  },
): Promise<void> {
  const dir = join(ROOT, ".monaca", "reports");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "ops-verify.json"), `${JSON.stringify(report, null, 2)}\n`);
}

process.exitCode = await main();
