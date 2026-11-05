// Real multi-instance acceptance: N separate server processes on N ports, one PostgreSQL, a
// round-robin dispatch layer in this process. Every assertion below is measured, not inferred.
//
//   bun scripts/multi-instance.ts [--instances 3] [--pool-size 4] [--audit-writes 300]
//
// Requires the same environment as the e2e job: MONACA_SERVER_BIN, the control/admin/app DSNs and
// MONACA_PUBLIC_BASE_URL. The script provisions one fresh tenant through `tenant create`, so the
// counts and audit sequences start from a known point. Instances share that tenant database; only
// their ports, processes and connection pools are separate.

import { startServer, measure, raw, request, withDatabase, type HttpResult } from "./bench/harness.ts";
import { ROOT } from "./bench/harness.ts";

const CONTROL_URL = process.env.MONACA_CONTROL_DATABASE_URL ?? "";
const ADMIN_URL = process.env.MONACA_ADMIN_DATABASE_URL ?? "";
const APP_URL = process.env.MONACA_APP_DATABASE_URL ?? "";
const SERVER_BIN = process.env.MONACA_SERVER_BIN ?? `${ROOT}/.monaca/bin/monaca-server`;
const PUBLIC_BASE = process.env.MONACA_PUBLIC_BASE_URL ?? "http://127.0.0.1:8081";

interface Check {
  readonly name: string;
  readonly ok: boolean;
  readonly detail: string;
}

const checks: Check[] = [];

function check(name: string, ok: boolean, detail: string): void {
  checks.push({ name, ok, detail });
  console.log(`  ${ok ? "pass" : "FAIL"}  ${name}  ${detail}`);
}

function parseArg(argv: string[], name: string, fallback: number): number {
  const at = argv.indexOf(name);
  if (at < 0) return fallback;
  const value = Number(argv[at + 1]);
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

const argv = process.argv.slice(2);
const INSTANCES = parseArg(argv, "--instances", 3);
const POOL_SIZE = parseArg(argv, "--pool-size", 4);
const AUDIT_WRITES = parseArg(argv, "--audit-writes", 300);
const RUN = Date.now().toString(36);
const TENANT = `mnode-${RUN}`;
const ADMIN_EMAIL = `admin@${TENANT}.localhost`;
const ADMIN_PASSWORD = "Mnode-Admin-Pass-91";
const ADMIN_CLIENT = `mnode-admin-${RUN}`;
const ADMIN_SECRET = `mnode-admin-secret-${RUN}`;
const LOGIN_CLIENT = `mnode-login-${RUN}`;
const REDIRECT_URI = "http://localhost:5173/bff/callback";

function withApplicationName(url: string, name: string): string {
  const parsed = new URL(url);
  parsed.searchParams.set("application_name", name);
  return parsed.toString();
}

function instanceEnv(index: number, port: number, poolName: string): Record<string, string> {
  const name = `${poolName}-${index}`;
  const env: Record<string, string> = {
    MONACA_SERVER_ADDR: `127.0.0.1:${port}`,
    MONACA_SERVER_URL: `http://127.0.0.1:${port}`,
    MONACA_PUBLIC_BASE_URL: PUBLIC_BASE,
    MONACA_TENANT_POOL_SIZE: String(POOL_SIZE),
    MONACA_MAILER_TENANT_CONCURRENCY: "1",
    MONACA_MAILER_POOL_SIZE: "1",
    MONACA_ADMIN_DATABASE_URL: ADMIN_URL,
  };
  if (APP_URL !== "") {
    env.MONACA_APP_DATABASE_URL = withApplicationName(APP_URL, name);
    env.MONACA_CONTROL_DATABASE_URL = CONTROL_URL;
  } else {
    env.MONACA_CONTROL_DATABASE_URL = withApplicationName(CONTROL_URL, name);
    env.MONACA_ALLOW_SUPERUSER_TENANT_POOLS = "1";
  }
  return env;
}

function managementHeaders(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}`, "content-type": "application/json" };
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function jsonBody(result: HttpResult): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(result.body);
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

async function provisionTenant(): Promise<void> {
  console.log(`\nprovisioning tenant ${TENANT} through the CLI`);
  const proc = Bun.spawn(
    [
      SERVER_BIN,
      "tenant",
      "create",
      "--slug",
      TENANT,
      "--admin-email",
      ADMIN_EMAIL,
      "--admin-password",
      ADMIN_PASSWORD,
      "--admin-client-id",
      ADMIN_CLIENT,
      "--admin-client-secret",
      ADMIN_SECRET,
      "--login-client-id",
      LOGIN_CLIENT,
      "--login-redirect-uri",
      REDIRECT_URI,
    ],
    { cwd: ROOT, env: { ...process.env }, stdout: "pipe", stderr: "pipe" },
  );
  const [out, err, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  if (code !== 0) throw new Error(`tenant create exited ${code}\n${out}\n${err}`);
  console.log(`  tenant create ok (${TENANT})`);
}

async function adminToken(base: string): Promise<string> {
  const result = await request(`${base}/t/${TENANT}/oauth2/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${btoa(`${ADMIN_CLIENT}:${ADMIN_SECRET}`)}`,
    },
    body: new URLSearchParams({ grant_type: "client_credentials", scope: "monaca:admin" }).toString(),
  });
  const token = jsonBody(result).access_token;
  if (result.status !== 200 || typeof token !== "string") {
    throw new Error(`admin token answered ${result.status}: ${result.body.slice(0, 200)}`);
  }
  return token;
}

async function createAccount(
  base: string,
  token: string,
  email: string,
  password: string,
  name: string,
): Promise<string> {
  const result = await request(`${base}/v1/accounts`, {
    method: "POST",
    headers: managementHeaders(token),
    body: JSON.stringify({ email, display_name: name, password }),
  });
  const id = jsonBody(result).id;
  if (result.status !== 201 || typeof id !== "string") {
    throw new Error(`create ${email} answered ${result.status}: ${result.body.slice(0, 200)}`);
  }
  await request(`${base}/v1/orgs/acme/members`, {
    method: "POST",
    headers: managementHeaders(token),
    body: JSON.stringify({ account_id: id, role: "member" }),
  });
  return id;
}

interface SignedIn {
  readonly access: string;
  readonly refresh: string;
}

async function signIn(base: string, email: string, password: string, tag: string): Promise<SignedIn> {
  const verifier = `mnode-${tag}-${RUN}-${"v".repeat(24)}`;
  const challenge = base64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
  );
  const authorize = await request(
    `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: LOGIN_CLIENT,
      redirect_uri: REDIRECT_URI,
      scope: "openid offline_access",
      state: `mnode-${tag}`,
      nonce: `mnode-${tag}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: "acme",
    })}`,
    { redirect: "manual" },
  );
  const location = authorize.headers.get("location") ?? "";
  const interaction = new URL(location, base).searchParams.get("interaction");
  if (authorize.status !== 302 || interaction === null) {
    throw new Error(`authorize(${tag}) answered ${authorize.status}: ${authorize.body.slice(0, 200)}`);
  }
  const sign = await request(`${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identifier: email, password }),
  });
  const redirectTo = jsonBody(sign).redirect_to;
  if (sign.status !== 200 || typeof redirectTo !== "string") {
    throw new Error(`sign-in(${tag}) answered ${sign.status}: ${sign.body.slice(0, 200)}`);
  }
  const code = new URL(redirectTo).searchParams.get("code") ?? "";
  const exchange = await request(`${base}/t/${TENANT}/oauth2/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: LOGIN_CLIENT,
      code_verifier: verifier,
    }).toString(),
  });
  const body = jsonBody(exchange);
  if (exchange.status !== 200 || typeof body.access_token !== "string" || typeof body.refresh_token !== "string") {
    throw new Error(`code exchange(${tag}) answered ${exchange.status}: ${exchange.body.slice(0, 200)}`);
  }
  return { access: body.access_token, refresh: body.refresh_token };
}

async function userinfo(base: string, access: string): Promise<number> {
  return (await request(`${base}/t/${TENANT}/oauth2/userinfo`, {
    headers: { authorization: `Bearer ${access}` },
  })).status;
}

async function renew(base: string, refresh: string): Promise<number> {
  return (await request(`${base}/t/${TENANT}/oauth2/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refresh,
      client_id: LOGIN_CLIENT,
    }).toString(),
  })).status;
}

async function main(): Promise<number> {
  const startedAt = performance.now();
  if (CONTROL_URL === "" || ADMIN_URL === "") {
    throw new Error("MONACA_CONTROL_DATABASE_URL and MONACA_ADMIN_DATABASE_URL are required");
  }
  console.log(`multi-instance: ${INSTANCES} processes, pool ${POOL_SIZE}, tenant ${TENANT}`);

  await provisionTenant();

  const control = new Bun.SQL(CONTROL_URL, { max: 1 });
  const rows = (await raw(control, "SELECT db_name FROM tenants WHERE slug = $1", [TENANT])) as {
    db_name: string;
  }[];
  const dbName = rows[0]?.db_name;
  await control.close();
  if (dbName === undefined) throw new Error(`tenant ${TENANT} has no database row`);
  const tenantSql = new Bun.SQL(withDatabase(ADMIN_URL, dbName), { max: 2 });

  const ports = Array.from({ length: INSTANCES }, (_, i) => 8083 + i);
  const servers = await Promise.all(
    ports.map((port, i) => startServer(SERVER_BIN, `http://127.0.0.1:${port}`, instanceEnv(i, port, "mnode"))),
  );
  console.log(
    `  instances: ${servers.map((s) => `${s.base} pid=${s.pid}`).join(", ")}`,
  );
  console.log(`  dispatch: round-robin over those ${INSTANCES} bases; shared tenant db ${dbName}`);

  let turn = 0;
  const nextBase = (): string => servers[(turn++) % servers.length]!.base;
  const dispatch = (path: string, init?: RequestInit): Promise<HttpResult> =>
    request(`${nextBase()}${path}`, init);

  let token: string;
  try {
    token = await adminToken(servers[0]!.base);
  } catch (err) {
    throw new Error(`could not mint the admin token: ${err instanceof Error ? err.message : String(err)}`);
  }

  // --- a. revocation is visible on the next request of another instance --------------------
  console.log("\na. cross-instance revocation");
  const disabledEmail = `disabled-${RUN}@${TENANT}.localhost`;
  const disabledId = await createAccount(
    nextBase(),
    token,
    disabledEmail,
    "Mnode-User-Pass-92",
    "Disabled",
  );
  const disabledSession = await signIn(servers[0]!.base, disabledEmail, "Mnode-User-Pass-92", "disabled");
  const beforeDisable = await userinfo(servers[0]!.base, disabledSession.access);
  check("the account token works before the disable", beforeDisable === 200, `userinfo=${beforeDisable}`);
  const patched = await dispatch(`/v1/accounts/${disabledId}`, {
    method: "PATCH",
    headers: managementHeaders(token),
    body: JSON.stringify({ state: "disabled" }),
  });
  check("the disable is answered on one instance", patched.status === 200, `PATCH=${patched.status}`);
  const afterDisable = await Promise.all(
    servers.slice(1).map((server) => userinfo(server.base, disabledSession.access)),
  );
    check(
    "the next userinfo on every other instance is 401",
    afterDisable.every((status) => status === 401),
    `statuses=${afterDisable.join("/")}`,
  );
  const renewedAfterDisable = await renew(servers[servers.length - 1]!.base, disabledSession.refresh);
  check("the next renewal on another instance is invalid_grant", renewedAfterDisable === 400, `renew=${renewedAfterDisable}`);

  const kickedEmail = `kicked-${RUN}@${TENANT}.localhost`;
  const kickedId = await createAccount(nextBase(), token, kickedEmail, "Mnode-User-Pass-93", "Kicked");
  const kickedSession = await signIn(servers[1 % servers.length]!.base, kickedEmail, "Mnode-User-Pass-93", "kicked");
  const sessionList = await dispatch(`/v1/accounts/${kickedId}/sessions`, {
    headers: managementHeaders(token),
  });
  const sessionId = (jsonBody(sessionList).items as { id?: unknown }[] | undefined)?.[0]?.id;
  if (typeof sessionId !== "string") throw new Error(`session list answered ${sessionList.status}`);
  const kicked = await dispatch(`/v1/accounts/${kickedId}/sessions/${sessionId}`, {
    method: "DELETE",
    headers: managementHeaders(token),
  });
  check("the session kick is answered on one instance", kicked.status === 204, `DELETE=${kicked.status}`);
  const afterKick = await Promise.all(servers.map((server) => userinfo(server.base, kickedSession.access)));
  check(
    "the next userinfo on every instance is 401",
    afterKick.every((status) => status === 401),
    `statuses=${afterKick.join("/")}`,
  );
  const renewedAfterKick = await renew(servers[0]!.base, kickedSession.refresh);
  check("the next renewal after the kick is invalid_grant", renewedAfterKick === 400, `renew=${renewedAfterKick}`);

  // --- b. the shared rate-limit counter under N-instance concurrency -----------------------
  console.log("\nb. rate limit across instances");
  const limit = 10;
  const rateClient = `mnode-rate-${RUN}`;
  const clientCreated = await dispatch("/v1/clients", {
    method: "POST",
    headers: managementHeaders(token),
    body: JSON.stringify({
      client_id: rateClient,
      name: "Multi-instance rate client",
      kind: "confidential",
      scopes: ["openid"],
    }),
  });
  const clientSecret = jsonBody(clientCreated).client_secret;
  if (clientCreated.status !== 201 || typeof clientSecret !== "string") {
    throw new Error(`client create answered ${clientCreated.status}: ${clientCreated.body.slice(0, 200)}`);
  }
  const patchedLimits = await dispatch("/v1/rate-limits", {
    method: "PATCH",
    headers: managementHeaders(token),
    body: JSON.stringify({
      items: [{ endpoint: "token", client_id: rateClient, limit, window_secs: 60 }],
    }),
  });
  if (patchedLimits.status !== 200) {
    throw new Error(`rate-limit PATCH answered ${patchedLimits.status}: ${patchedLimits.body.slice(0, 200)}`);
  }
  const burst = await Promise.all(
    Array.from({ length: INSTANCES * limit }, (_, i) =>
      request(`${servers[i % servers.length]!.base}/t/${TENANT}/oauth2/token`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          authorization: `Basic ${btoa(`${rateClient}:${clientSecret}`)}`,
        },
        body: new URLSearchParams({ grant_type: "client_credentials", scope: "openid" }).toString(),
      }),
    ),
  );
  const immediatePassed = burst.filter((result) => result.status === 200).length;
  console.log(
    `  immediate burst after PATCH: passed=${immediatePassed}/${INSTANCES * limit} ` +
      `(the 5 s configuration cache is per instance; only the writer invalidates its own copy)`,
  );

  // Re-apply the same limit: the write resets the shared counters, and one request per instance
  // loads the new configuration into that instance's cache. The burst below is therefore testing
  // the shared counter, not the documented configuration-cache delay.
  const reapplied = await dispatch("/v1/rate-limits", {
    method: "PATCH",
    headers: managementHeaders(token),
    body: JSON.stringify({
      items: [{ endpoint: "token", client_id: rateClient, limit, window_secs: 60 }],
    }),
  });
  if (reapplied.status !== 200) throw new Error(`rate-limit re-apply answered ${reapplied.status}`);
  await Promise.all(
    servers.map((server) =>
      request(`${server.base}/v1/accounts?limit=1`, { headers: managementHeaders(token) }),
    ),
  );
  const primedBurst = await Promise.all(
    Array.from({ length: INSTANCES * limit }, (_, i) =>
      request(`${servers[i % servers.length]!.base}/t/${TENANT}/oauth2/token`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          authorization: `Basic ${btoa(`${rateClient}:${clientSecret}`)}`,
        },
        body: new URLSearchParams({ grant_type: "client_credentials", scope: "openid" }).toString(),
      }),
    ),
  );
  const passed = primedBurst.filter((result) => result.status === 200).length;
  const throttled = primedBurst.filter((result) => result.status === 429).length;
  check(
    "the shared limit passes exactly the configured number after every instance loads it",
    passed === limit && throttled === INSTANCES * limit - limit,
    `requests=${primedBurst.length} passed=${passed} 429=${throttled}`,
  );
  const retryAfter = primedBurst
    .filter((result) => result.status === 429)
    .every((result) => (result.headers.get("retry-after") ?? "") !== "");
  check("every rejected request carries Retry-After", retryAfter, `429s=${throttled}`);

  // The management endpoint needs a high ceiling for the audit and bench phases; priming each
  // instance makes the new configuration visible before the measured requests begin.
  const raised = await dispatch("/v1/rate-limits", {
    method: "PATCH",
    headers: managementHeaders(token),
    body: JSON.stringify({
      items: [{ endpoint: "management", limit: 1_000_000, window_secs: 60 }],
    }),
  });
  if (raised.status !== 200) throw new Error(`management limit raise answered ${raised.status}`);
  await Promise.all(
    servers.map((server) =>
      request(`${server.base}/v1/accounts?limit=1`, { headers: managementHeaders(token) }),
    ),
  );

  // --- e. the same scenarios on one process and on N processes -------------------------------
  console.log("\ne. single instance vs N instances");
  const benchEmail = `bench-${RUN}@${TENANT}.localhost`;
  const benchPassword = "Mnode-Bench-Pass-95";
  const benchId = await createAccount(nextBase(), token, benchEmail, benchPassword, "Bench");
  const benchSession = await signIn(servers[0]!.base, benchEmail, benchPassword, "bench");
  const managementPath = `/v1/accounts?limit=1`;
  const multiManagement = await measure({
    name: "management-multi",
    expected: [200],
    warmup: 20,
    requests: 400,
    concurrency: 16,
    once: async () => dispatch(managementPath, { headers: managementHeaders(token) }),
  });
  const multiUserinfo = await measure({
    name: "userinfo-multi",
    expected: [200],
    warmup: 20,
    requests: 400,
    concurrency: 16,
    once: async () => dispatch(`/t/${TENANT}/oauth2/userinfo`, {
      headers: { authorization: `Bearer ${benchSession.access}` },
    }),
  });
  const single = await startServer(SERVER_BIN, "http://127.0.0.1:8089", instanceEnv(0, 8089, "mnode-single"));
  console.log(`  single instance: ${single.base} pid=${single.pid}`);
  try {
    await request(`${single.base}/healthz`);
    await request(`${single.base}${managementPath}`, { headers: managementHeaders(token) });
    const singleManagement = await measure({
      name: "management-single",
      expected: [200],
      warmup: 20,
      requests: 400,
      concurrency: 16,
      once: async () => request(`${single.base}${managementPath}`, { headers: managementHeaders(token) }),
    });
    const singleUserinfo = await measure({
      name: "userinfo-single",
      expected: [200],
      warmup: 20,
      requests: 400,
      concurrency: 16,
      once: async () =>
        request(`${single.base}/t/${TENANT}/oauth2/userinfo`, {
          headers: { authorization: `Bearer ${benchSession.access}` },
        }),
    });
    for (const [label, multi, one] of [
      ["management", multiManagement, singleManagement],
      ["userinfo", multiUserinfo, singleUserinfo],
    ] as const) {
      check(
        `${label}: the N-instance bench completed without errors`,
        multi.errors === 0 && one.errors === 0,
        `single p95/p99=${one.latency.p95_ms}/${one.latency.p99_ms} rps=${one.throughput_rps}; ` +
          `multi p95/p99=${multi.latency.p95_ms}/${multi.latency.p99_ms} rps=${multi.throughput_rps}`,
      );
    }
  } finally {
    await single.stop();
  }
  check("the benchmark account exists", typeof benchId === "string", benchId);

  // --- usage must equal the real rows, not a second estimate --------------------------------
  console.log("\nusage counter vs direct database counts");
  const usageResult = await dispatch("/v1/usage", { headers: managementHeaders(token) });
  const usage = jsonBody(usageResult);
  const direct = (await raw(
    tenantSql,
    "SELECT (SELECT count(*) FROM tenant.accounts)::bigint AS accounts, \
            (SELECT count(*) FROM tenant.usage_daily \
             WHERE day = (now() AT TIME ZONE 'UTC')::date)::bigint AS active, \
            (SELECT coalesce(sum(logins),0)::bigint FROM tenant.usage_daily \
             WHERE day = (now() AT TIME ZONE 'UTC')::date) AS logins",
  )) as { accounts: string | number; active: string | number; logins: string | number }[];
  const row = direct[0];
  const users = usage.users as { total?: unknown } | undefined;
  const daily = usage.daily as { active_accounts?: unknown; logins?: unknown } | undefined;
  check(
    "users.total equals count(tenant.accounts)",
    Number(users?.total) === Number(row?.accounts),
    `api=${String(users?.total)} db=${String(row?.accounts)}`,
  );
  check(
    "daily activity equals the usage_daily rows for the UTC day",
    Number(daily?.active_accounts) === Number(row?.active) &&
      Number(daily?.logins) === Number(row?.logins),
    `api active/logins=${String(daily?.active_accounts)}/${String(daily?.logins)} ` +
      `db=${String(row?.active)}/${String(row?.logins)}`,
  );

  // --- c. audit sequence under concurrent writers -------------------------------------------
  console.log(`\nc. audit seq with ${AUDIT_WRITES} concurrent account creations`);
  const startRow = (await raw(tenantSql, "SELECT coalesce(max(seq),0)::bigint AS seq FROM tenant.audit_events")) as {
    seq: string | number;
  }[];
  const startSeq = Number(startRow[0]?.seq ?? 0);
  const statuses: number[] = [];
  for (let offset = 0; offset < AUDIT_WRITES; offset += 30) {
    const wave = Array.from({ length: Math.min(30, AUDIT_WRITES - offset) }, (_, i) =>
      dispatch("/v1/accounts", {
        method: "POST",
        headers: managementHeaders(token),
        body: JSON.stringify({
          email: `bulk-${RUN}-${offset + i}@${TENANT}.localhost`,
          display_name: `Bulk ${offset + i}`,
          password: "Mnode-Bulk-Pass-94",
        }),
      }),
    );
    const results = await Promise.all(wave);
    statuses.push(...results.map((result) => result.status));
  }
  const created = statuses.filter((status) => status === 201).length;
  check(
    "every concurrent account creation succeeded",
    created === AUDIT_WRITES,
    `created=${created}/${AUDIT_WRITES}`,
  );
  const range = (await raw(
    tenantSql,
    "WITH r AS (SELECT seq FROM tenant.audit_events WHERE seq > $1) \
     SELECT count(*)::bigint AS n, count(DISTINCT seq)::bigint AS distinct_n, \
            coalesce(min(seq),0)::bigint AS lo, coalesce(max(seq),0)::bigint AS hi FROM r",
    [startSeq],
  )) as { n: string | number; distinct_n: string | number; lo: string | number; hi: string | number }[];
  const n = Number(range[0]?.n ?? 0);
  const distinctN = Number(range[0]?.distinct_n ?? 0);
  const lo = Number(range[0]?.lo ?? 0);
  const hi = Number(range[0]?.hi ?? 0);
  check(
    "the audit sequence is contiguous with no gaps or duplicates",
    n === AUDIT_WRITES && distinctN === AUDIT_WRITES && hi - lo + 1 === AUDIT_WRITES,
    `rows=${n} distinct=${distinctN} range=${lo}..${hi}`,
  );

  // --- d. cold-start pool bound ------------------------------------------------------------
  console.log("\nd. cold-start pool single-flight");
  await Promise.all(servers.map((server) => server.stop()));
  const coldPorts = Array.from({ length: INSTANCES }, (_, i) => 8086 + i);
  const cold = await Promise.all(
    coldPorts.map((port, i) =>
      startServer(SERVER_BIN, `http://127.0.0.1:${port}`, instanceEnv(i, port, "mnode-pool")),
    ),
  );
  const peaks = new Map<string, number>();
  let sampling = true;
  const sample = (async (): Promise<void> => {
    while (sampling) {
      const rows = (await raw(
        tenantSql,
        "SELECT application_name, count(*)::bigint AS c FROM pg_stat_activity \
         WHERE datname = $1 AND application_name LIKE 'mnode-pool-%' GROUP BY application_name",
        [dbName],
      )) as { application_name: string; c: string | number }[];
      for (const row of rows) {
        const name = row.application_name;
        peaks.set(name, Math.max(peaks.get(name) ?? 0, Number(row.c)));
      }
      await Bun.sleep(5);
    }
  })();
  const coldBurst = await Promise.all(
    Array.from({ length: INSTANCES * POOL_SIZE * 2 }, (_, i) =>
      request(`${cold[i % cold.length]!.base}${managementPath.replace("limit=1", "limit=200")}`, {
        headers: managementHeaders(token),
      }),
    ),
  );
  sampling = false;
  await sample;
  check(
    "the cold burst answered 200 everywhere",
    coldBurst.every((result) => result.status === 200),
    `statuses=${[...new Set(coldBurst.map((result) => result.status))].join("/")}`,
  );
  const perInstance = [...peaks.values()];
  const totalPeak = perInstance.reduce((sum, value) => sum + value, 0);
  check(
    "no instance exceeds its pool size and the total stays at N × pool_size",
    peaks.size >= INSTANCES &&
      perInstance.every((value) => value <= POOL_SIZE) &&
      totalPeak <= INSTANCES * POOL_SIZE,
    `pids=${cold.map((server) => server.pid).join("/")} peaks=${JSON.stringify(Object.fromEntries(peaks))} totalPeak=${totalPeak} bound=${INSTANCES * POOL_SIZE}`,
  );
  await Promise.all(cold.map((server) => server.stop()));

  await tenantSql.close();

  const failed = checks.filter((entry) => !entry.ok);
  const seconds = Math.round((performance.now() - startedAt) / 100) / 10;
  console.log(`\n${checks.length} checks in ${seconds}s: ${checks.length - failed.length} passed, ${failed.length} failed`);
  if (failed.length > 0) {
    for (const entry of failed) console.error(`FAILED: ${entry.name} — ${entry.detail}`);
    return 1;
  }
  return 0;
}

const code = await main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.stack ?? err.message : String(err));
  return 1;
});
process.exit(code);
