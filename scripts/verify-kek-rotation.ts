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
  if (captchaSiteverifyUrl !== "") env.MONACA_CAPTCHA_SITEVERIFY_URL = captchaSiteverifyUrl;
  if (socialProviderBaseUrl !== "") env.MONACA_SOCIAL_PROVIDER_BASE_URL = socialProviderBaseUrl;
  // CI carries the app DSN; a local drill without one uses the explicit escape hatch rather than
  // silently falling back.
  if (!env.MONACA_APP_DATABASE_URL) env.MONACA_ALLOW_SUPERUSER_TENANT_POOLS = "1";
  delete env.MONACA_KEK;
  if (previous === undefined) delete env.MONACA_KEK_PREVIOUS;
  else env.MONACA_KEK_PREVIOUS = previous;
  return env;
}

let server: ReturnType<typeof Bun.spawn> | undefined;
let provider: ReturnType<typeof Bun.serve> | undefined;
let captchaSiteverifyUrl = "";
let socialProviderBaseUrl = "";

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

interface RawSql {
  unsafe: (query: string, values?: unknown[]) => Promise<unknown[]>;
}

async function rawSql(db: Bun.SQL, query: string, values: unknown[] = []): Promise<unknown[]> {
  return (db as unknown as RawSql).unsafe(query, values);
}

function withDatabase(url: string, database: string): string {
  const parsed = new URL(url);
  parsed.pathname = `/${database}`;
  return parsed.toString();
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function base64UrlJson(value: unknown): string {
  return base64Url(new TextEncoder().encode(JSON.stringify(value)));
}

function base64UrlDecode(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

/** `SHA-256(kek || "monaca:tenant-dek:v1" || tenant_uuid)`, exactly as monaca-crypto derives it. */
async function tenantDek(kekHex: string, tenantUuid: string): Promise<CryptoKey> {
  // The KEK is 32 decoded bytes, not the 64 hex characters it is written as.
  const material = new Uint8Array(32 + 20 + 16);
  material.set(Buffer.from(kekHex, "hex"), 0);
  material.set(new TextEncoder().encode("monaca:tenant-dek:v1"), 32);
  material.set(Buffer.from(tenantUuid.replaceAll("-", ""), "hex"), 52);
  const digest = await crypto.subtle.digest("SHA-256", material);
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["decrypt"]);
}

/**
 * Whether the sealed bytes open under this KEK. A wrong key fails the AES-GCM tag check, which is
 * the negative control: after a real rotation the old key must not open the row any more.
 */
async function opensWith(kekHex: string, sealedHex: string, tenantUuid: string): Promise<boolean> {
  if (sealedHex === "") return false;
  const key = await tenantDek(kekHex, tenantUuid);
  const sealed = Buffer.from(sealedHex, "hex");
  if (sealed.length <= 12) return false;
  try {
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: sealed.subarray(0, 12) },
      key,
      sealed.subarray(12),
    );
    return true;
  } catch {
    return false;
  }
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

/** Open a social sign-in and stop at the provider, leaving the sealed state verifier behind. */
async function socialAuthorize(
  connector: string,
): Promise<{ startLocation: string; stateCookie: string; verifier: string } | undefined> {
  const started = await begin();
  const authorize = await call(
    `${BASE}/t/${TENANT}/connectors/${connector}/authorize?interaction=${started.interaction}`,
    { redirect: "manual" },
  );
  const startLocation = authorize.headers.get("location") ?? "";
  const stateCookie =
    /monaca_social_state=([0-9a-f-]{36})/.exec(authorize.headers.get("set-cookie") ?? "")?.[1] ?? "";
  if (authorize.status !== 302 || startLocation === "" || stateCookie === "") return undefined;
  return { startLocation, stateCookie, verifier: started.verifier };
}

/** Finish a provider round-trip started by [`socialAuthorize`]. */
async function socialCallback(
  pending: { startLocation: string; stateCookie: string; verifier: string },
): Promise<{ verifier: string; callback: HttpResult; callbackUrl: string; redirectTo: string }> {
  const atProvider = await call(pending.startLocation, { redirect: "manual" });
  const callbackUrl = atProvider.headers.get("location") ?? "";
  const callback = await call(callbackUrl, {
    headers: { cookie: `monaca_social_state=${pending.stateCookie}` },
    redirect: "manual",
  });
  return {
    verifier: pending.verifier,
    callback,
    callbackUrl,
    redirectTo: callback.headers.get("location") ?? "",
  };
}

/**
 * Every sealed value the four business flows touch, as hex, plus the tenant id that derives the
 * DEK. Reading the bytes directly is what makes the negative control possible: after a rotation
 * the old KEK must no longer authenticate these rows.
 */
async function sealedSnapshot(): Promise<{ tenantUuid: string; values: Record<string, string> }> {
  const control = new Bun.SQL(controlUrl);
  try {
    const rows = (await rawSql(
      control,
      "SELECT id::text AS id, db_name FROM tenants WHERE slug = $1",
      [TENANT],
    )) as { id: string; db_name: string }[];
    const tenant = rows[0];
    if (tenant === undefined) fail(`tenant ${TENANT} is not registered`);
    const tenantDb = new Bun.SQL(withDatabase(adminUrl, tenant.db_name));
    try {
      const read = async (column: string, from: string): Promise<string> => {
        const result = (await rawSql(
          tenantDb,
          `SELECT encode(${column}, 'hex') AS sealed FROM ${from} LIMIT 1`,
        )) as { sealed: string | null }[];
        return result[0]?.sealed ?? "";
      };
      return {
        tenantUuid: tenant.id,
        values: {
          "signing key": await read("private_enc", "tenant.signing_keys"),
          "TOTP seed": await read(
            "secret_enc",
            "tenant.credentials WHERE kind = 'totp'",
          ),
          "email connector secret": await read("secret_enc", "tenant.email_connector"),
          "social connector secret": await read(
            "client_secret_enc",
            "tenant.social_connectors WHERE connector_id = 'drill-social'",
          ),
          "webhook secret": await read("secret_enc", "tenant.webhooks"),
          "CAPTCHA secret": await read("captcha_secret_enc", "tenant.sign_in_experience"),
          "social state verifier": await read(
            "code_verifier_enc",
            "tenant.social_states WHERE consumed_at IS NULL",
          ),
        },
      };
    } finally {
      await tenantDb.close();
    }
  } finally {
    await control.close();
  }
}

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
const socialEmail = `kek-social-${Date.now().toString(36)}@example.test`;
const adminEmail = process.env.MONACA_BOOTSTRAP_ADMIN_EMAIL ?? "admin@demo.localhost";
const adminPassword = process.env.MONACA_BOOTSTRAP_ADMIN_PASSWORD ?? "monaca-dev-password";
const socialSecret = `drill-social-secret-${Date.now().toString(36)}`;
const captchaSecret = `drill-captcha-secret-${Date.now().toString(36)}`;
const captchaToken = `drill-captcha-token-${Date.now().toString(36)}`;
let accountId = "";
let totpSecret = "";
let webhookSecret = "";
let pendingSocial:
  | { startLocation: string; stateCookie: string; verifier: string }
  | undefined;
let sealedBefore: { tenantUuid: string; values: Record<string, string> } | undefined;
const delivered: { id: string; authorization: string; receivedAt: number }[] = [];
const hookDeliveries: { body: string; signature: string; event: string }[] = [];
const siteverifyCalls: { secret: string; response: string }[] = [];
const tokenSecrets: string[] = [];

try {
  provider = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(request) {
      const url = new URL(request.url);
      if (url.pathname === "/send") {
        const body = (await request.json().catch(() => ({}))) as { id?: string };
        delivered.push({
          id: String(body.id ?? ""),
          authorization: request.headers.get("authorization") ?? "",
          receivedAt: Date.now(),
        });
        return new Response(null, { status: 202 });
      }
      if (url.pathname === "/hook") {
        hookDeliveries.push({
          body: await request.text(),
          signature: request.headers.get("x-monaca-signature") ?? "",
          event: request.headers.get("x-monaca-event") ?? "",
        });
        return new Response(null, { status: 200 });
      }
      if (url.pathname === "/github/authorize") {
        const target = new URL(url.searchParams.get("redirect_uri") ?? "");
        target.searchParams.set("code", `github-drill-code-${Date.now().toString(36)}`);
        target.searchParams.set("state", url.searchParams.get("state") ?? "");
        return Response.redirect(target.toString(), 302);
      }
      if (url.pathname === "/github/token") {
        const form = await request.formData();
        tokenSecrets.push(String(form.get("client_secret") ?? ""));
        const code = String(form.get("code") ?? "");
        if (code === "") return Response.json({ error: "invalid_grant" }, { status: 400 });
        return Response.json({ access_token: code, token_type: "Bearer" });
      }
      if (url.pathname === "/github/userinfo") {
        return Response.json({ id: 4242, login: "drill-social", name: "Drill Social" });
      }
      if (url.pathname === "/github/emails") {
        return Response.json([{ email: socialEmail, primary: true, verified: true }]);
      }
      if (url.pathname === "/authorize") {
        const target = new URL(url.searchParams.get("redirect_uri") ?? "");
        target.searchParams.set(
          "code",
          base64UrlJson({
            sub: url.searchParams.get("sub") ?? "",
            email: url.searchParams.get("email") ?? "",
            email_verified: url.searchParams.get("verified") === "1",
            name: url.searchParams.get("name") ?? "",
          }),
        );
        target.searchParams.set("state", url.searchParams.get("state") ?? "");
        return Response.redirect(target.toString(), 302);
      }
      if (url.pathname === "/token") {
        const form = await request.formData();
        tokenSecrets.push(String(form.get("client_secret") ?? ""));
        const code = String(form.get("code") ?? "");
        if (code === "") return Response.json({ error: "invalid_grant" }, { status: 400 });
        return Response.json({ access_token: code, token_type: "Bearer", expires_in: 600 });
      }
      if (url.pathname === "/userinfo") {
        const token = (request.headers.get("authorization") ?? "").replace(/^Bearer /, "");
        return new Response(new TextDecoder().decode(base64UrlDecode(token)), {
          headers: { "content-type": "application/json" },
        });
      }
      if (url.pathname === "/siteverify") {
        const form = await request.formData();
        const postedSecret = String(form.get("secret") ?? "");
        const response = String(form.get("response") ?? "");
        siteverifyCalls.push({ secret: postedSecret, response });
        return Response.json({ success: response === captchaToken });
      }
      return new Response("not found", { status: 404 });
    },
  });
  const providerBase = `http://127.0.0.1:${provider.port}`;
  const providerUrl = `${providerBase}/send`;
  captchaSiteverifyUrl = `${providerBase}/siteverify`;
  socialProviderBaseUrl = providerBase;

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

  // --- 1b. the four business-flow secrets, all sealed under the current key ---------------------
  const webhook = await call(`${BASE}/v1/webhooks`, {
    method: "POST",
    headers: jsonHeaders(token),
    body: JSON.stringify({ url: `${providerBase}/hook`, events: ["account.created"] }),
  });
  webhookSecret = (webhook.body as { secret?: string })?.secret ?? "";
  check(
    "the webhook stores a sealed signing key",
    webhook.status === 201 && webhookSecret.startsWith("whsec_"),
    `${webhook.status}`,
  );

  const hookEmail = `kek-hook-${Date.now().toString(36)}@demo.localhost`;
  const hookAccount = await call(`${BASE}/v1/accounts`, {
    method: "POST",
    headers: jsonHeaders(token),
    body: JSON.stringify({ email: hookEmail, display_name: "Hook Account", password }),
  });
  for (let i = 0; i < 40 && hookDeliveries.length === 0; i++) await Bun.sleep(100);
  const preHook = hookDeliveries.at(-1);
  const preHookExpected =
    preHook === undefined
      ? ""
      : `sha256=${createHmac("sha256", webhookSecret).update(preHook.body).digest("hex")}`;
  check(
    "the webhook signing key produces a valid signature before rotation",
    hookAccount.status === 201 &&
      preHook !== undefined &&
      preHook.event === "account.created" &&
      preHook.signature === preHookExpected,
    preHook === undefined ? "no delivery" : preHook.event,
  );

  const socialConnector = await call(`${BASE}/v1/connectors`, {
    method: "POST",
    headers: jsonHeaders(token),
    body: JSON.stringify({
      connector_id: "drill-social",
      display_name: "Drill Social",
      provider: "github",
      client_id: "drill-social-client",
      client_secret: socialSecret,
      scopes: ["read:user", "user:email"],
    }),
  });
  check(
    "the social connector stores a sealed client secret",
    socialConnector.status === 201,
    `${socialConnector.status}`,
  );

  const socialStart = await socialAuthorize("drill-social");
  if (socialStart === undefined) fail("the social connector did not start an authorize round-trip");
  const socialDone = await socialCallback(socialStart);
  const socialToken = await exchange(socialDone.redirectTo, socialDone.verifier);
  check(
    "the social client secret is used for a real callback before rotation",
    socialDone.callback.status === 302 &&
      socialToken.status === 200 &&
      tokenSecrets.at(-1) === socialSecret,
    `${socialDone.callback.status}/${socialToken.status}`,
  );

  // A second round-trip is left parked at the provider: its sealed PKCE verifier must survive the
  // rotation and finish the callback afterwards.
  pendingSocial = await socialAuthorize("drill-social");
  if (pendingSocial === undefined) fail("the pending social authorize did not start");

  const captcha = await call(`${BASE}/v1/sign-in-experience`, {
    method: "PATCH",
    headers: jsonHeaders(token),
    body: JSON.stringify({
      captcha: {
        enabled: true,
        provider: "hcaptcha",
        site_key: "drill-site-key",
        secret: captchaSecret,
        on_sign_in: true,
        on_sign_up: false,
        on_password_reset: false,
      },
    }),
  });
  check(
    "the CAPTCHA secret is stored sealed and reported set",
    captcha.status === 200 &&
      (captcha.body as { captcha?: { secret_set?: boolean } })?.captcha?.secret_set === true &&
      !JSON.stringify(captcha.body).includes(captchaSecret),
    `${captcha.status}`,
  );

  sealedBefore = await sealedSnapshot();
  for (const [name, sealed] of Object.entries(sealedBefore.values)) {
    const oldOpens = await opensWith(currentKek, sealed, sealedBefore.tenantUuid);
    const newOpens = await opensWith(nextKek, sealed, sealedBefore.tenantUuid);
    check(
      `before rotation the old KEK opens the ${name}`,
      oldOpens && !newOpens,
      `old=${oldOpens} new=${newOpens}`,
    );
  }

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

  const sealedAfter = await sealedSnapshot();
  for (const [name, sealed] of Object.entries(sealedAfter.values)) {
    const oldOpens = await opensWith(currentKek, sealed, sealedAfter.tenantUuid);
    const newOpens = await opensWith(nextKek, sealed, sealedAfter.tenantUuid);
    check(
      `after rotation only the new KEK opens the ${name}`,
      newOpens && !oldOpens,
      `old=${oldOpens} new=${newOpens}`,
    );
  }

  const challenged = await begin();
  const signIn = await call(`${BASE}/t/${TENANT}/interaction/${challenged.interaction}/sign-in`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identifier: email, password, captcha_token: captchaToken }),
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

  // The social round-trip parked before the rotation still has its sealed PKCE verifier.
  if (pendingSocial === undefined) fail("the pending social authorize was lost");
  const resumed = await socialCallback(pendingSocial);
  const resumedToken = await exchange(resumed.redirectTo, resumed.verifier);
  check(
    "the rewrapped social state verifier completes the parked callback",
    resumed.callback.status === 302 &&
      resumedToken.status === 200 &&
      tokenSecrets.at(-1) === socialSecret,
    `${resumed.callback.status}/${resumedToken.status}`,
  );

  // The webhook secret must sign a fresh delivery after the old key is gone.
  const hookBeforeCount = hookDeliveries.length;
  const hook2Email = `kek-hook2-${Date.now().toString(36)}@demo.localhost`;
  const hook2 = await call(`${BASE}/v1/accounts`, {
    method: "POST",
    headers: jsonHeaders(rotated),
    body: JSON.stringify({ email: hook2Email, display_name: "Hook Account 2", password }),
  });
  for (let i = 0; i < 40 && hookDeliveries.length <= hookBeforeCount; i++) await Bun.sleep(100);
  const postHook = hookDeliveries.at(-1);
  const postHookExpected =
    postHook === undefined
      ? ""
      : `sha256=${createHmac("sha256", webhookSecret).update(postHook.body).digest("hex")}`;
  check(
    "the rewrapped webhook secret signs a delivery after rotation",
    hook2.status === 201 &&
      postHook !== undefined &&
      postHook.event === "account.created" &&
      postHook.signature === postHookExpected,
    postHook === undefined ? "no delivery" : postHook.event,
  );

  // The siteverify call carries the secret the server just opened with the new key.
  const captchaFlow = await begin();
  const captchaSignIn = await call(
    `${BASE}/t/${TENANT}/interaction/${captchaFlow.interaction}/sign-in`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        identifier: adminEmail,
        password: adminPassword,
        captcha_token: captchaToken,
      }),
    },
  );
  check(
    "the rewrapped CAPTCHA secret still passes siteverify",
    captchaSignIn.status === 200 &&
      siteverifyCalls.some(
        (entry) => entry.secret === captchaSecret && entry.response === captchaToken,
      ),
    `${captchaSignIn.status} siteverify=${siteverifyCalls.length}`,
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
