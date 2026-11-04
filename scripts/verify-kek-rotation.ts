// A real KEK rotation: create data under the current key, rotate to a new one, re-wrap, remove
// the old key, and prove the data still works (docs/contracts/m0.md §10.7).
//
// The drill owns its own server process on port 8087 and uses the CI database after the
// acceptance walk-through has migrated and bootstrapped it. It does not change the deployed key
// of any running server: it only moves the sealed rows in `demo`, which the walk-through leaves
// disposable.
//
//   MONACA_CONTROL_DATABASE_URL=… MONACA_ADMIN_DATABASE_URL=… \
//   MONACA_DEV_KEK=<current> MONACA_SERVER_BIN=.monaca/bin/monaca-server \
//   MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET=… \
//     bun scripts/verify-kek-rotation.ts
//
// Exit code 0 means every check passed; the JSON report is written to
// `.monaca/reports/kek-rotation.json`.

import { createHmac } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..");
const TENANT = "demo";
const PORT = 8087;
const BASE = `http://127.0.0.1:${PORT}`;
const REDIRECT_URI = "http://localhost:5173/bff/callback";

const controlUrl = process.env.MONACA_CONTROL_DATABASE_URL ?? "";
const adminUrl = process.env.MONACA_ADMIN_DATABASE_URL ?? "";
const serverBin =
  process.env.MONACA_SERVER_BIN ??
  join(ROOT, ".monaca", "bin", process.platform === "win32" ? "monaca-server.exe" : "monaca-server");
const currentKek = process.env.MONACA_KEK_CURRENT ?? process.env.MONACA_DEV_KEK ?? process.env.MONACA_KEK ?? "";
const nextKek = process.env.MONACA_KEK_NEXT ?? "22".repeat(32);
const adminSecret = process.env.MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET ?? "dev-admin-client-secret";
const consoleSecret = process.env.MONACA_CONSOLE_CLIENT_SECRET ?? "dev-console-client-secret";

const checks: { name: string; passed: boolean; detail: string }[] = [];
function fail(why: string): never {
  throw new Error(`verify-kek-rotation: ${why}`);
}
const check = (name: string, passed: boolean, detail = ""): void => {
  checks.push({ name, passed, detail });
  process.stdout.write(`  ${passed ? "pass" : "FAIL"}  ${name}${detail === "" ? "" : `  ${detail}`}\n`);
};

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

function serverEnv(kek: string, previous?: string): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined) env[key] = value;
  }
  env.MONACA_ENV = "ci";
  env.MONACA_SERVER_ADDR = `127.0.0.1:${PORT}`;
  env.MONACA_SERVER_URL = BASE;
  env.MONACA_PUBLIC_BASE_URL = BASE;
  env.MONACA_DEV_KEK = kek;
  env.MONACA_LOG_LEVEL = "warn";
  delete env.MONACA_KEK;
  if (previous === undefined) delete env.MONACA_KEK_PREVIOUS;
  else env.MONACA_KEK_PREVIOUS = previous;
  return env;
}

let server: ReturnType<typeof Bun.spawn> | undefined;
let provider: ReturnType<typeof Bun.serve> | undefined;

async function startServer(kek: string, previous?: string): Promise<void> {
  server = Bun.spawn([serverBin, "serve"], {
    cwd: ROOT,
    env: serverEnv(kek, previous),
    stdout: "ignore",
    stderr: "ignore",
  });
  for (let i = 0; i < 120; i++) {
    try {
      const response = await fetch(`${BASE}/healthz`, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) return;
    } catch {
      // not listening yet
    }
    await Bun.sleep(250);
  }
  fail(`the server did not answer /healthz with KEK ${kek.slice(0, 4)}…`);
}

async function stopServer(): Promise<void> {
  if (server === undefined) return;
  server.kill();
  await server.exited;
  server = undefined;
  await Bun.sleep(250);
}

async function rewrap(): Promise<string> {
  const proc = Bun.spawn([serverBin, "rewrap", "--tenant", TENANT], {
    cwd: ROOT,
    env: serverEnv(nextKek, currentKek),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  if (code !== 0) fail(`rewrap exited ${code}\n${stdout}\n${stderr}`);
  return stdout.trim();
}

function base32Decode(input: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const symbol of input.replaceAll("=", "").toUpperCase()) {
    const index = alphabet.indexOf(symbol);
    if (index < 0) throw new Error(`invalid base32 symbol ${JSON.stringify(symbol)}`);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

function totpFromBase32(secret: string): string {
  const step = Math.floor(Date.now() / 1000 / 30);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const value =
    ((digest[offset]! & 0x7f) << 24) |
    (digest[offset + 1]! << 16) |
    (digest[offset + 2]! << 8) |
    digest[offset + 3]!;
  return String(value % 1_000_000).padStart(6, "0");
}

async function adminToken(): Promise<string> {
  const response = await call(`${BASE}/t/${TENANT}/oauth2/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${btoa(`monaca-admin:${adminSecret}`)}`,
    },
    body: new URLSearchParams({ grant_type: "client_credentials", scope: "monaca:admin" }).toString(),
  });
  const token = (response.body as { access_token?: string })?.access_token;
  if (response.status !== 200 || token === undefined) {
    fail(`no management token: ${response.status} ${JSON.stringify(response.body)}`);
  }
  return token;
}

async function begin(): Promise<{ interaction: string; verifier: string }> {
  const verifier = `kek-${Date.now().toString(36)}-${"v".repeat(40)}`;
  const challenge = btoa(
    String.fromCharCode(
      ...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    ),
  )
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
  const url = `${BASE}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
    response_type: "code",
    client_id: "monaca-console",
    redirect_uri: REDIRECT_URI,
    scope: "openid profile email",
    state: `kek-${Date.now().toString(36)}`,
    code_challenge: challenge,
    code_challenge_method: "S256",
  })}`;
  const response = await call(url, { redirect: "manual" });
  const interaction = new URL(response.headers.get("location") ?? "", BASE).searchParams.get("interaction");
  if (response.status !== 302 || interaction === null) {
    fail(`authorize → ${response.status} ${JSON.stringify(response.body)}`);
  }
  return { interaction: encodeURIComponent(interaction), verifier };
}

async function exchange(redirectTo: string, verifier: string): Promise<HttpResult> {
  const code = new URL(redirectTo).searchParams.get("code") ?? "";
  return call(`${BASE}/t/${TENANT}/oauth2/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${btoa(`monaca-console:${consoleSecret}`)}`,
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: "monaca-console",
      code_verifier: verifier,
    }).toString(),
  });
}

const sessionCookie = (result: HttpResult): string | undefined =>
  /monaca_session=([0-9a-f-]{36})/.exec(result.headers.get("set-cookie") ?? "")?.[1];

if (controlUrl === "" || adminUrl === "") {
  fail("MONACA_CONTROL_DATABASE_URL and MONACA_ADMIN_DATABASE_URL are required");
}
if (!existsSync(serverBin)) {
  fail(`no server binary at ${serverBin}; set MONACA_SERVER_BIN or run bun run fetch:native`);
}
if (currentKek.length !== 64 || nextKek.length !== 64) {
  fail("MONACA_DEV_KEK/MONACA_KEK_CURRENT and MONACA_KEK_NEXT must be 64 hex characters");
}

const email = `kek-${Date.now().toString(36)}@demo.localhost`;
const password = `R0tate-Drill-${Date.now().toString(36)}-9xQ`;
let accountId = "";
let totpSecret = "";
const delivered: { id: string; authorization: string; receivedAt: number }[] = [];

try {
  provider = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(request) {
      const body = (await request.json().catch(() => ({}))) as { id?: string };
      delivered.push({
        id: String(body.id ?? ""),
        authorization: request.headers.get("authorization") ?? "",
        receivedAt: Date.now(),
      });
      return new Response(null, { status: 202 });
    },
  });
  const providerUrl = `http://127.0.0.1:${provider.port}/send`;

  // --- 1. data under the current key ------------------------------------------------------------
  await startServer(currentKek);
  const token = await adminToken();
  check("a token is minted under the current KEK", token.length > 0);

  const created = await call(`${BASE}/v1/accounts`, {
    method: "POST",
    headers: jsonHeaders(token),
    body: JSON.stringify({ email, display_name: "Rotation Account", password }),
  });
  accountId = (created.body as { id?: string })?.id ?? "";
  check(
    "the drill account is created",
    created.status === 201 && accountId.startsWith("acc_"),
    `${created.status} ${JSON.stringify(created.body)}`,
  );

  const member = await call(`${BASE}/v1/orgs/acme/members`, {
    method: "POST",
    headers: jsonHeaders(token),
    body: JSON.stringify({ account_id: accountId, role: "member" }),
  });
  check("the drill account joins acme", member.status === 201, `${member.status}`);

  const nested = await begin();
  const signedIn = await call(`${BASE}/t/${TENANT}/interaction/${nested.interaction}/sign-in`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identifier: email, password }),
  });
  const cookie = sessionCookie(signedIn);
  check(
    "the account signs in and gets a session",
    signedIn.status === 200 && cookie !== undefined,
    `${signedIn.status} ${JSON.stringify(signedIn.body)}`,
  );
  if (cookie === undefined) fail("no session cookie; cannot enroll a factor");

  const enrollment = await call(`${BASE}/t/${TENANT}/account/mfa/totp`, {
    method: "POST",
    headers: { cookie: `monaca_session=${cookie}` },
  });
  totpSecret = (enrollment.body as { secret?: string })?.secret ?? "";
  check("TOTP enrollment returns a secret", enrollment.status === 200 && totpSecret !== "", `${enrollment.status}`);

  const confirmed = await call(`${BASE}/t/${TENANT}/account/mfa/totp/verify`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: `monaca_session=${cookie}` },
    body: JSON.stringify({ code: totpFromBase32(totpSecret) }),
  });
  check("the TOTP factor is enabled", confirmed.status === 200, `${confirmed.status}`);

  const connector = await call(`${BASE}/v1/email-connector`, {
    method: "PATCH",
    headers: jsonHeaders(token),
    body: JSON.stringify({
      provider: "http",
      endpoint: providerUrl,
      from_address: "no-reply@demo.localhost",
      secret: "drill-connector-secret",
    }),
  });
  check("the email connector stores a sealed secret", connector.status === 200, `${connector.status}`);

  await stopServer();

  // --- 2. rotate: new key current, old key previous, then re-wrap --------------------------------
  await startServer(nextKek, currentKek);
  const report = await rewrap();
  const summary = /re-wrapped (\d+) value\(s\).*failed (\d+)/.exec(report);
  check(
    "rewrap moves sealed values with the retiring key",
    summary !== null && Number(summary[1]) > 0 && Number(summary[2]) === 0,
    report,
  );
  await stopServer();

  // --- 3. old key removed; every existing value must still open ----------------------------------
  await startServer(nextKek);
  const rotated = await adminToken();
  check("a management token is minted with only the new KEK", rotated.length > 0);

  const challenged = await begin();
  const signIn = await call(`${BASE}/t/${TENANT}/interaction/${challenged.interaction}/sign-in`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identifier: email, password }),
  });
  check(
    "the account still signs in and the factor is still enrolled",
    signIn.status === 200 && (signIn.body as { mfa_required?: boolean })?.mfa_required === true,
    `${signIn.status}`,
  );

  const verified = await call(`${BASE}/t/${TENANT}/interaction/${challenged.interaction}/mfa/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ code: totpFromBase32(totpSecret) }),
  });
  const redirectTo = (verified.body as { redirect_to?: string })?.redirect_to ?? "";
  const minted = await exchange(redirectTo, challenged.verifier);
  check(
    "the rewrapped TOTP secret completes sign-in and mints tokens",
    verified.status === 200 && minted.status === 200 && (minted.body as { id_token?: string })?.id_token !== undefined,
    `${verified.status}/${minted.status}`,
  );

  // A password reset queues a mail; the mailer opens the rewrapped connector secret and posts it.
  const resetFlow = await begin();
  const forgot = await call(`${BASE}/t/${TENANT}/interaction/${resetFlow.interaction}/password/forgot`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email }),
  });
  check("a password reset is queued", forgot.status === 200, `${forgot.status}`);
  for (let i = 0; i < 80 && delivered.length === 0; i++) await Bun.sleep(250);
  const mail = delivered[0];
  check(
    "the rewrapped connector secret is used for delivery",
    mail !== undefined && mail.authorization === "Bearer drill-connector-secret",
    mail === undefined ? "no mail was delivered" : mail.authorization,
  );

  const read = await call(`${BASE}/v1/email-connector`, { headers: { authorization: `Bearer ${rotated}` } });
  check("the connector row is still readable", read.status === 200, `${read.status}`);

  // Leave the tenant without a connector to a dead port: the acceptance database is disposable,
  // but a dangling route would make the main server log delivery failures after this drill.
  await call(`${BASE}/v1/email-connector`, {
    method: "DELETE",
    headers: { authorization: `Bearer ${rotated}` },
  });
} finally {
  await stopServer();
  provider?.stop(true);
  const report = {
    generated_at: new Date().toISOString(),
    tenant: TENANT,
    old_kek_prefix: currentKek.slice(0, 4),
    new_kek_prefix: nextKek.slice(0, 4),
    checks,
    passed: checks.every((entry) => entry.passed),
  };
  const dir = join(ROOT, ".monaca", "reports");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "kek-rotation.json"), `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`\nKEK rotation drill: ${report.passed ? "ok" : "FAILED"} (${checks.length} checks)\n`);
  process.exit(report.passed ? 0 : 1);
}
