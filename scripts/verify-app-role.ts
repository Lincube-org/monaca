// Provisions the least-privilege tenant login and proves it can do the request-path work while
// still being unable to run DDL or read an org schema directly (docs/contracts/m0.md §5.1, §6.4).
//
// It is deliberately opt-in: MONACA_APP_DATABASE_URL is unset by default, so no existing
// deployment changes. Running this script sets up the role, grants it the tenant schema and the
// org roles it must SET ROLE into, revokes PUBLIC CONNECT from the tenant database, starts a
// second server with the app URL and exercises a real write/read through it. It exits non-zero on
// the first failed proof.
//
//   MONACA_CONTROL_DATABASE_URL=… MONACA_ADMIN_DATABASE_URL=… \
//   MONACA_APP_DB_PASSWORD=… MONACA_SERVER_BIN=.monaca/bin/monaca-server \
//     bun scripts/verify-app-role.ts

import { existsSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..");
const TENANT = "demo";
const PORT = 8085;

interface RawSql {
  unsafe: (query: string, values?: unknown[]) => Promise<unknown[]>;
}

const adminUrl = process.env.MONACA_ADMIN_DATABASE_URL ?? "";
const controlUrl = process.env.MONACA_CONTROL_DATABASE_URL ?? "";
const appUser = process.env.MONACA_APP_DB_USER ?? "monaca_app";
const appPassword = process.env.MONACA_APP_DB_PASSWORD ?? "";
const serverBin =
  process.env.MONACA_SERVER_BIN ??
  join(ROOT, ".monaca", "bin", process.platform === "win32" ? "monaca-server.exe" : "monaca-server");
const adminSecret = process.env.MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET ?? "";

const checks: [string, boolean][] = [];
const fail = (why: string): never => {
  process.stderr.write(`verify-app-role: ${why}\n`);
  process.exit(1);
};
const identifier = (value: string, what: string): string => {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    fail(`${what} ${JSON.stringify(value)} is not a safe SQL identifier`);
  }
  return value;
};
const raw = (db: Bun.SQL, query: string, values?: unknown[]): Promise<unknown[]> =>
  (db as unknown as RawSql).unsafe(query, values);
const withDatabase = (url: string, database: string): string => {
  const parsed = new URL(url);
  parsed.pathname = `/${database}`;
  return parsed.toString();
};

if (adminUrl === "" || controlUrl === "") {
  fail("MONACA_ADMIN_DATABASE_URL and MONACA_CONTROL_DATABASE_URL are required");
}
if (appPassword === "") {
  fail("MONACA_APP_DB_PASSWORD is required");
}
if (!existsSync(serverBin)) {
  fail(`no server binary at ${serverBin}; set MONACA_SERVER_BIN or run bun run fetch:native`);
}
if (adminSecret === "") {
  fail("MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET is required for the server smoke");
}

const role = identifier(appUser, "MONACA_APP_DB_USER");
const control = new Bun.SQL(controlUrl);
const admin = new Bun.SQL(adminUrl);
let tenantDb = "";
let adminTenant: Bun.SQL | undefined;
let app: Bun.SQL | undefined;
let server: ReturnType<typeof Bun.spawn> | undefined;

try {
  const rows = (await control`SELECT db_name FROM tenants WHERE slug = ${TENANT}`) as {
    db_name: string;
  }[];
  tenantDb = identifier(rows[0]?.db_name ?? "", "tenant database");
  adminTenant = new Bun.SQL(withDatabase(adminUrl, tenantDb));

  const exists = (await admin`SELECT 1::bigint FROM pg_roles WHERE rolname = ${role}`) as unknown[];
  if (exists.length === 0) {
    await raw(
      admin,
      `CREATE ROLE "${role}" LOGIN NOINHERIT PASSWORD $1`,
      [appPassword],
    );
  }
  await raw(admin, `ALTER ROLE "${role}" PASSWORD $1`, [appPassword]);
  checks.push(["the app login exists", true]);

  const databases = new Bun.SQL(withDatabase(adminUrl, "postgres"));
  await raw(databases, `REVOKE CONNECT ON DATABASE "${tenantDb}" FROM PUBLIC`);
  await raw(databases, `GRANT CONNECT ON DATABASE "${tenantDb}" TO "${role}"`);
  await databases.close();

  await raw(adminTenant, `GRANT USAGE ON SCHEMA tenant TO "${role}"`);
  await raw(
    adminTenant,
    `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA tenant TO "${role}"`,
  );
  await raw(
    adminTenant,
    `ALTER DEFAULT PRIVILEGES IN SCHEMA tenant
     GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "${role}"`,
  );
  const orgRoles = (await adminTenant`SELECT rolname FROM pg_roles WHERE rolname ~ '^t[0-9a-z]+_o[0-9a-z]+$'`) as {
    rolname: string;
  }[];
  for (const row of orgRoles) {
    await raw(adminTenant, `GRANT "${identifier(row.rolname, "org role")}" TO "${role}"`);
  }
  checks.push(["tenant grants and org-role memberships are in place", true]);

  const appUrl = withDatabase(controlUrl, tenantDb);
  const appParsed = new URL(appUrl);
  appParsed.username = role;
  appParsed.password = appPassword;
  app = new Bun.SQL(appParsed.toString());

  const accounts = (await app`SELECT count(*)::bigint AS count FROM tenant.accounts`) as {
    count: string;
  }[];
  const read = (await app`SELECT count(*)::bigint AS count FROM tenant.sessions`) as {
    count: string;
  }[];
  await raw(app, "UPDATE tenant.accounts SET display_name = display_name WHERE false");
  checks.push([
    "the app role reads and writes tenant tables",
    accounts.length === 1 && read.length === 1,
  ]);

  let ddlDenied = false;
  try {
    await raw(app, `CREATE TABLE tenant.role_probe_${process.pid} (id integer)`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    ddlDenied = message.includes("permission denied") || message.includes("42501");
  }
  checks.push(["the app role cannot run DDL in the tenant schema", ddlDenied]);

  const schemaRows = (await app`SELECT schema_name FROM tenant.organizations LIMIT 1`) as {
    schema_name: string;
  }[];
  const orgSchema = schemaRows[0]?.schema_name ?? "";
  let orgDenied = false;
  try {
    await raw(app, `SELECT count(*) FROM "${identifier(orgSchema, "org schema")}".accounts`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    orgDenied = message.includes("permission denied") || message.includes("42501");
  }
  checks.push(["the app role cannot read an org schema without SET ROLE", orgDenied]);

  const probe = `monaca_role_probe_${process.pid}`;
  const maintenance = new Bun.SQL(withDatabase(adminUrl, "postgres"));
  await raw(maintenance, `DROP DATABASE IF EXISTS "${probe}"`);
  await raw(maintenance, `CREATE DATABASE "${probe}"`);
  await raw(maintenance, `REVOKE CONNECT ON DATABASE "${probe}" FROM PUBLIC`);
  let crossDenied = false;
  try {
    const probeDb = new Bun.SQL(withDatabase(appParsed.toString(), probe));
    await probeDb`SELECT 1`;
    await probeDb.close();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    crossDenied =
      message.includes("permission denied") || message.includes("does not exist");
  }
  await raw(maintenance, `DROP DATABASE IF EXISTS "${probe}"`);
  await maintenance.close();
  checks.push(["the app role cannot open another database", crossDenied]);

  // A real server with the app tenant pool: one write and one read through the management API,
  // plus a public tenant read.
  const appServerUrl = withDatabase(controlUrl, "monaca_control");
  const appServerParsed = new URL(appServerUrl);
  appServerParsed.username = role;
  appServerParsed.password = appPassword;
  server = Bun.spawn([serverBin, "serve"], {
    cwd: ROOT,
    env: {
      ...process.env,
      MONACA_SERVER_ADDR: `127.0.0.1:${PORT}`,
      MONACA_SERVER_URL: `http://127.0.0.1:${PORT}`,
      MONACA_APP_DATABASE_URL: appServerParsed.toString(),
      MONACA_METRICS_ADDR: "",
      MONACA_LOG_LEVEL: "warn",
    },
    stdout: "ignore",
    stderr: "ignore",
  });
  let up = false;
  for (let i = 0; i < 120; i++) {
    try {
      const response = await fetch(`http://127.0.0.1:${PORT}/healthz`, {
        signal: AbortSignal.timeout(2_000),
      });
      if (response.ok) {
        up = true;
        break;
      }
    } catch {
      // not listening yet
    }
    await Bun.sleep(250);
  }
  if (!up) fail("the app-pool server did not answer /healthz");

  const tokenResponse = await fetch(`http://127.0.0.1:${PORT}/t/${TENANT}/oauth2/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${btoa(`monaca-admin:${adminSecret}`)}`,
    },
    body: "grant_type=client_credentials&scope=monaca:admin",
  });
  const token = ((await tokenResponse.json()) as { access_token?: string }).access_token;
  if (tokenResponse.status !== 200 || token === undefined) {
    fail(`the app-pool server could not mint a management token (${tokenResponse.status})`);
  }
  const email = `app-role-${Date.now().toString(36)}@demo.localhost`;
  const created = await fetch(`http://127.0.0.1:${PORT}/v1/accounts`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify({ email, display_name: "App Role", password: "pw-app-role-probe" }),
  });
  const account = (await created.json()) as { id?: string };
  const fetched = await fetch(`http://127.0.0.1:${PORT}/v1/accounts/${account.id ?? ""}`, {
    headers: { authorization: `Bearer ${token}` },
  });
  const publicRead = await fetch(`http://127.0.0.1:${PORT}/t/${TENANT}/sign-in-experience`);
  checks.push([
    "a real server using the app pool creates and reads an account",
    created.status === 201 && fetched.status === 200 && publicRead.status === 200,
  ]);
} catch (error) {
  checks.push([
    `the verification completed without an exception (${error instanceof Error ? error.message : String(error)})`,
    false,
  ]);
} finally {
  server?.kill();
  await server?.exited;
  await app?.close();
  await adminTenant?.close();
  await control.close();
  await admin.close();
}

const ok = checks.every(([, passed]) => passed);
for (const [name, passed] of checks) {
  process.stdout.write(`${passed ? "PASS" : "FAIL"}  ${name}\n`);
}
process.stdout.write(`${JSON.stringify({ ok, checks: checks.length, tenantDb }, null, 2)}\n`);
process.exit(ok ? 0 : 1);
