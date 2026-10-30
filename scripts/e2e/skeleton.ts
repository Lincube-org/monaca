// `bun run e2e:skeleton --base-url <url>` — the single acceptance script (contract §12, plan §13).
//
// Runs the whole M0 walk-through against any origin: localhost:8080 (the dev gateway), the deployed
// dev gateway, or the CI server started from the `server-*` artifact. Steps 4 and 4b need the demo
// MCP module, which only the gateway mounts — against the server alone they are reported as
// `skip`, which is the honest answer rather than a silent pass.
//
// The walk-through, verbatim from §12:
//   1  health
//   2  setup: create an account, add it to `acme`, register an agent, register a locally generated
//      ES256 public key, grant `tools:read` on `{base}/mcp/demo`
//   3  the agent exchanges a `private_key_jwt` assertion for a delegated token
//   3b the same request widened to `tools:write` is refused
//   4  `list_notes` succeeds; 4b `delete_note` is refused with `insufficient_scope`
//   5  the audit page shows account → grant → agent → token(jti) → tool and the chain verifies
import { createHmac } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { describeNetError } from "../lib/net.ts";

const ROOT = join(import.meta.dir, "..", "..");
const REPORT = join(ROOT, ".monaca", "reports", "skeleton.json");

/** The M0 org the walk-through lives in (contract §5.6 bootstrap). */
const ORG = "acme";
/** The M0 tenant (contract §5.6 bootstrap). */
const TENANT = "demo";
/** The client that may ask the management API for `monaca:admin` tokens (contract §5.7). */
const ADMIN_CLIENT_ID = "monaca-admin";
/** The local sign-in the browser flow uses (contract §2.2 bootstrap). */
const BOOTSTRAP_ADMIN = { email: "admin@demo.localhost", password: "monaca-dev-password" };

/** One entry per contract §12 row. `step` matches the contract's numbering. */
const ACCEPTANCE_STEPS: { step: string; title: string; assertion: string }[] = [
  {
    step: "1",
    title: "health",
    assertion: 'GET {base}/healthz → 200, status == "ok"',
  },
  {
    step: "2",
    title: "setup",
    assertion:
      "POST /v1/accounts, POST /v1/orgs/acme/members, POST /v1/orgs/acme/agents, " +
      "POST /v1/orgs/acme/agents/{id}/keys (locally generated ES256 public JWK), " +
      'POST /v1/orgs/acme/grants (scopes=["tools:read"], resource="{base}/mcp/demo")',
  },
  {
    step: "3",
    title: "token grant",
    assertion:
      "POST /t/demo/oauth2/token grant_type=client_credentials with a private_key_jwt assertion " +
      "→ 200; act.sub == agt_…, scope == [\"tools:read\"], exp - iat == 300, sub == acc_…",
  },
  {
    step: "3b",
    title: "over-request denied",
    assertion: 'same request with scope=tools:write → 400 {"error":"invalid_scope"}',
  },
  {
    step: "4",
    title: "allowed tool",
    assertion: "MCP tools/call list_notes with the token → success",
  },
  {
    step: "4b",
    title: "denied tool",
    assertion:
      'MCP tools/call delete_note → 403, WWW-Authenticate contains error="insufficient_scope" ' +
      'and scope="tools:write"',
  },
  {
    step: "5",
    title: "audit chain",
    assertion:
      "GET /v1/orgs/acme/audit?grant_id=grt_… shows account → grant → agent → token(jti) → tool; " +
      "GET /v1/orgs/acme/audit/verify → {\"valid\":true}",
  },
  {
    step: "6",
    title: "browser flow",
    assertion:
      "authorize → interaction → code → id_token(nonce,email) + refresh → rotation → replay refused",
  },
  {
    step: "7",
    title: "session & logout",
    assertion:
      "sign-in sets the monaca_session cookie; a silent prompt=none authorize reuses it; " +
      "GET/DELETE /v1/accounts/{id}/sessions manage it; " +
      "GET /t/demo/oauth2/end-session echoes state, clears the cookie and a later silent authorize is login_required",
  },
  {
    step: "8",
    title: "email verification",
    assertion:
      "sign-up → GET /internal/mail code → sign-up/verify → token; sign-in/code → code → verify → token; " +
      "password/forgot → password/reset → the old password is 401 and the new one signs in",
  },
  {
    step: "9",
    title: "two-step verification",
    assertion:
      "POST /t/demo/account/mfa/totp (session cookie) → secret + otpauth_url; verify a computed TOTP → enabled; " +
      "a new sign-in answers {\"mfa_required\":true}; a wrong code is 401 and the right one mints a token; " +
      "DELETE the credential → the next sign-in needs one factor again",
  },
  {
    step: "10",
    title: "account centre",
    assertion:
      "PATCH /t/demo/account changes the display name and GET echoes it; POST /account/password with a wrong " +
      "current password is 401, the right one is 204 and signs out the other sessions; the old password is " +
      "refused and the new one signs in; GET /account/sessions marks the caller current; DELETE one and " +
      "DELETE all others revoke them",
  },
  {
    step: "11",
    title: "MFA backup codes",
    assertion:
      "POST /t/demo/account/mfa/backup-codes (session cookie, authenticator enrolled) → ten grouped codes; " +
      "a sign-in challenge lists totp and backup_code; a wrong code is 401; a typed (uppercase, hyphenated) " +
      "code completes the flow and issues a token; the same code is refused on replay; GET reports the " +
      "remaining count; DELETE removes them and the next challenge offers totp only",
  },
  {
    step: "12",
    title: "passkeys",
    assertion:
      "POST /t/demo/account/passkeys/options → creation options (rp.localhost, a challenge); the registration " +
      "ceremony stores a pky_… key (201) and mfa.passkeys becomes 1; an assertion signs in without a password " +
      "and a stale assertion is 401; PATCH renames it; with TOTP enrolled the challenge lists totp and passkey " +
      "and POST /mfa/passkey completes it; DELETE removes the key and the next challenge offers totp only",
  },
  {
    step: "13",
    title: "username identifiers",
    assertion:
      "PATCH /t/demo/account {username} (session cookie) stores it lowercased and GET echoes it; a new sign-in " +
      "accepts the username case-insensitively and mints a token; an unknown identifier is 401; another account " +
      "claiming the same username (any case) is 409 MONACA_USERNAME_TAKEN; an invalid username is 400",
  },
];

interface StepResult {
  step: string;
  title: string;
  status: "pass" | "fail" | "skip" | "todo";
  ms?: number;
  detail?: string;
}

interface Report {
  base_url: string;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  stage: 1;
  ok: boolean;
  steps: StepResult[];
  error?: string;
}

/** Everything the walk-through discovered, so the report can name what it created. */
interface Walk {
  accountId: string;
  agentId: string;
  keyId: string;
  grantId: string;
  jti: string;
  scope: string;
}

function usage(): string {
  return [
    "usage: bun run e2e:skeleton --base-url <url>",
    "",
    "  --base-url <url>       the public origin to test (http://localhost:8080, the remote dev",
    "                         gateway, or the CI server). Required.",
    "  --admin-secret <s>     the seeded automation client's secret. Defaults to the dev value;",
    "                         set it to the tenant's real secret anywhere else.",
    "  --console-secret <s>   the console client's secret, for the browser-flow step. Defaults to",
    "                         the dev value.",
    "  --internal-secret <s>  the /internal/* shared secret, for reading the dev mail outbox.",
    "                         Defaults to $MONACA_INTERNAL_SECRET, then the dev value.",
    "  --report <path>        where to write the JSON report (default .monaca/reports/skeleton.json).",
    "  --json                 print only the report, not the human-readable lines.",
    "",
    "Steps 4 and 4b are reported as `skip` unless the origin mounts /mcp/demo (the gateway does;",
    "the bare server does not).",
  ].join("\n");
}

function parseArgs(argv: string[]): { baseUrl: string; report: string; json: boolean; adminSecret: string; consoleSecret: string; internalSecret: string } | { error: string } {
  let baseUrl: string | undefined;
  let report = REPORT;
  let json = false;
  let adminSecret = "dev-admin-client-secret";
  let consoleSecret = "dev-console-client-secret";
  let internalSecret = process.env.MONACA_INTERNAL_SECRET ?? "dev-internal-secret-change-me";
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--base-url") {
      baseUrl = argv[++i];
      if (baseUrl === undefined) return { error: "--base-url needs a value" };
    } else if (arg?.startsWith("--base-url=")) {
      baseUrl = arg.slice("--base-url=".length);
    } else if (arg === "--report") {
      const value = argv[++i];
      if (value === undefined) return { error: "--report needs a value" };
      report = value;
    } else if (arg?.startsWith("--report=")) {
      report = arg.slice("--report=".length);
    } else if (arg === "--admin-secret") {
      const value = argv[++i];
      if (value === undefined) return { error: "--admin-secret needs a value" };
      adminSecret = value;
    } else if (arg?.startsWith("--admin-secret=")) {
      adminSecret = arg.slice("--admin-secret=".length);
    } else if (arg === "--console-secret") {
      const value = argv[++i];
      if (value === undefined) return { error: "--console-secret needs a value" };
      consoleSecret = value;
    } else if (arg?.startsWith("--console-secret=")) {
      consoleSecret = arg.slice("--console-secret=".length);
    } else if (arg === "--internal-secret") {
      const value = argv[++i];
      if (value === undefined) return { error: "--internal-secret needs a value" };
      internalSecret = value;
    } else if (arg?.startsWith("--internal-secret=")) {
      internalSecret = arg.slice("--internal-secret=".length);
    } else if (arg === "--json") {
      json = true;
    } else if (arg === "--help" || arg === "-h") {
      return { error: "__help__" };
    } else {
      return { error: `unrecognised argument ${JSON.stringify(arg)}` };
    }
  }
  if (baseUrl === undefined || baseUrl.trim() === "") return { error: "--base-url is required" };
  return { baseUrl: baseUrl.trim(), report, json, adminSecret, consoleSecret, internalSecret };
}

/** Normalises the origin: no trailing slash, so `${base}/healthz` is well formed. */
function normaliseBaseUrl(raw: string): string | { invalid: string } {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { invalid: `${raw} is not an absolute URL (expected http://host[:port])` };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { invalid: `${parsed.protocol} is not supported; use http or https` };
  }
  return `${parsed.origin}${parsed.pathname.replace(/\/+$/, "")}`;
}

async function writeReport(path: string, report: Report): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(report, null, 2)}\n`, "utf8");
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

interface HttpResult {
  status: number;
  body: unknown;
  headers: Headers;
}

async function call(url: string, init?: RequestInit): Promise<HttpResult> {
  const response = await fetch(url, {
    ...init,
    headers: { accept: "application/json", ...(init?.headers ?? {}) },
    signal: AbortSignal.timeout(20_000),
  });
  const text = await response.text();
  let body: unknown = text;
  if (text.length > 0) {
    try {
      body = JSON.parse(text);
    } catch {
      // A non-JSON body is kept verbatim; the assertions report it.
    }
  }
  return { status: response.status, body, headers: response.headers };
}

/** A form-encoded token-endpoint call, optionally with HTTP Basic client authentication. */
async function tokenCall(
  base: string,
  params: Record<string, string>,
  basic?: string,
): Promise<HttpResult> {
  return call(`${base}/t/${TENANT}/oauth2/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(basic === undefined ? {} : { authorization: `Basic ${basic}` }),
    },
    body: new URLSearchParams(params).toString(),
  });
}

function managementHeaders(accessToken: string): Record<string, string> {
  return { authorization: `Bearer ${accessToken}`, "content-type": "application/json" };
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlJson(value: unknown): string {
  return base64Url(new TextEncoder().encode(JSON.stringify(value)));
}

/** Decodes a JWT payload without verifying it: the walk-through asserts on claims the server just minted. */
function jwtClaims(token: unknown): Record<string, unknown> | undefined {
  if (typeof token !== "string") return undefined;
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  try {
    const parsed: unknown = JSON.parse(atob(parts[1]!.replaceAll("-", "+").replaceAll("_", "/")));
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

function text(body: unknown, max = 160): string {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  const collapsed = raw.replace(/\s+/g, " ").trim();
  return collapsed.length <= max ? collapsed : `${collapsed.slice(0, max)}…`;
}

// ---------------------------------------------------------------------------
// the walk-through
// ---------------------------------------------------------------------------

/** A locally generated ES256 key pair: the private half never leaves this process (contract §5). */
async function generateAgentKey(): Promise<{
  publicJwk: Record<string, unknown>;
  sign: (input: string) => Promise<string>;
}> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const publicJwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as unknown as Record<string, unknown>;
  return {
    publicJwk,
    async sign(input: string): Promise<string> {
      const signature = new Uint8Array(
        await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new TextEncoder().encode(input)),
      );
      return base64Url(signature);
    },
  };
}

/** A `private_key_jwt` assertion naming the agent (contract §7.4). */
async function buildAssertion(
  agentId: string,
  base: string,
  sign: (input: string) => Promise<string>,
  kid: string,
): Promise<string> {
  const header = { alg: "ES256", typ: "JWT", kid };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: agentId,
    sub: agentId,
    aud: `${base}/t/${TENANT}/oauth2/token`,
    jti: crypto.randomUUID(),
    iat: now,
    exp: now + 120,
  };
  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(payload)}`;
  return `${signingInput}.${await sign(signingInput)}`;
}

/** An MCP `tools/call` request. */
async function mcpCall(base: string, name: string, args: Record<string, string>, token: string): Promise<HttpResult> {
  return call(`${base}/mcp/demo`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      // The MCP Streamable HTTP transport requires the client to accept both media types even
      // when the server answers with a plain JSON body (`enableJsonResponse`).
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: crypto.randomUUID(), method: "tools/call", params: { name, arguments: args } }),
  });
}

/** Step 2 — build everything the token step needs, through the management API. */
async function setup(
  base: string,
  adminToken: string,
  log: (line: string) => void,
): Promise<{
  ok: boolean;
  detail: string;
  walk?: Walk;
  /** The key pair that was registered: the token step must sign with this very private half. */
  agentKey?: Awaited<ReturnType<typeof generateAgentKey>>;
}> {
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const resource = `${base}/mcp/demo`;

  const account = await call(`${base}/v1/accounts`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      email: `agent-run-${runId}@demo.localhost`,
      display_name: "Agent Run",
      password: "correct-horse-battery-staple",
    }),
  });
  const accountId = (account.body as { id?: string })?.id;
  if (account.status !== 201 || accountId === undefined) {
    return { ok: false, detail: `POST /v1/accounts → ${account.status} ${text(account.body)}` };
  }

  const member = await call(`${base}/v1/orgs/${ORG}/members`, {
    method: "POST",
    headers,
    body: JSON.stringify({ account_id: accountId, role: "member" }),
  });
  if (member.status !== 201) {
    return { ok: false, detail: `POST /v1/orgs/${ORG}/members → ${member.status} ${text(member.body)}` };
  }

  const agent = await call(`${base}/v1/orgs/${ORG}/agents`, {
    method: "POST",
    headers,
    body: JSON.stringify({ name: `ci-bot-${runId}`, owner_account_id: accountId }),
  });
  const agentId = (agent.body as { id?: string })?.id;
  if (agent.status !== 201 || agentId === undefined) {
    return { ok: false, detail: `POST /v1/orgs/${ORG}/agents → ${agent.status} ${text(agent.body)}` };
  }

  const key = await generateAgentKey();
  const registered = await call(`${base}/v1/orgs/${ORG}/agents/${encodeURIComponent(agentId)}/keys`, {
    method: "POST",
    headers,
    body: JSON.stringify({ public_jwk: key.publicJwk, alg: "ES256", kid: "k1" }),
  });
  const keyId = (registered.body as { id?: string })?.id;
  if (registered.status !== 201 || keyId === undefined) {
    return { ok: false, detail: `POST …/agents/{id}/keys → ${registered.status} ${text(registered.body)}` };
  }
  log(`        account=${accountId} agent=${agentId} key=${keyId}`);

  const grant = await call(`${base}/v1/orgs/${ORG}/grants`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      agent_id: agentId,
      account_id: accountId,
      scopes: ["tools:read"],
      resource,
    }),
  });
  const grantBody = grant.body as { id?: string };
  if (grant.status !== 201 || grantBody.id === undefined) {
    return { ok: false, detail: `POST /v1/orgs/${ORG}/grants → ${grant.status} ${text(grant.body)}` };
  }

  return {
    ok: true,
    detail: `account ${accountId}, agent ${agentId}, key ${keyId}, grant ${grantBody.id} on ${resource}`,
    walk: { accountId, agentId, keyId, grantId: grantBody.id, jti: "", scope: "tools:read" },
    agentKey: key,
  };
}

/** Step 3 — the delegated token, and step 3b — the same request widened. */
async function tokenGrants(
  base: string,
  walk: Walk,
  sign: (input: string) => Promise<string>,
): Promise<{ step3: StepResult; step3b: StepResult; accessToken: string }> {
  const assertion = await buildAssertion(walk.agentId, base, sign, "k1");
  const details = JSON.stringify([{ type: "monaca_grant", grant_id: walk.grantId }]);

  const t = performance.now();
  const granted = await tokenCall(base, {
    grant_type: "client_credentials",
    client_id: walk.agentId,
    scope: "tools:read",
    resource: `${base}/mcp/demo`,
    authorization_details: details,
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: assertion,
  });
  const grantedMs = Math.round(performance.now() - t);

  const claims = jwtClaims((granted.body as { access_token?: unknown })?.access_token);
  const scope = claims?.scope;
  const act = claims?.act as { sub?: unknown } | undefined;
  const checks: [string, boolean][] = [
    ["200", granted.status === 200],
    [`sub == acc_…`, typeof claims?.sub === "string" && claims.sub.startsWith("acc_")],
    [`act.sub == ${walk.agentId}`, act?.sub === walk.agentId],
    ['scope == ["tools:read"]', Array.isArray(scope) && scope.join(" ") === "tools:read"],
    ["exp - iat == 300", typeof claims?.exp === "number" && typeof claims?.iat === "number" && claims.exp - claims.iat === 300],
  ];
  const ok = checks.every(([, passed]) => passed);
  walk.jti = typeof claims?.jti === "string" ? claims.jti : "";
  walk.scope = Array.isArray(scope) ? scope.join(" ") : "";

  const widened = await tokenCall(base, {
    grant_type: "client_credentials",
    client_id: walk.agentId,
    scope: "tools:write",
    resource: `${base}/mcp/demo`,
    authorization_details: details,
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: assertion,
  });
  const widenedBody = widened.body as { error?: unknown };

  return {
    step3: {
      step: "3",
      title: "token grant",
      status: ok ? "pass" : "fail",
      ms: grantedMs,
      detail: ok
        ? `200, act.sub=${String(act?.sub)}, scope=[${walk.scope}], jti=${walk.jti}`
        : checks
            .filter(([, passed]) => !passed)
            .map(([name]) => name)
            .concat(`— ${granted.status} ${text(granted.body)}`)
            .join(", "),
    },
    step3b: {
      step: "3b",
      title: "over-request denied",
      status: widened.status === 400 && widenedBody.error === "invalid_scope" ? "pass" : "fail",
      detail:
        widened.status === 400 && widenedBody.error === "invalid_scope"
          ? "400 invalid_scope"
          : `${widened.status} ${text(widened.body)}`,
    },
    accessToken: (granted.body as { access_token?: string })?.access_token ?? "",
  };
}

/** Steps 4 and 4b — the tool calls the guard must allow and refuse. */
async function toolCalls(
  base: string,
  token: string,
): Promise<{ step4: StepResult; step4b: StepResult }> {
  const probe = await mcpCall(base, "list_notes", {}, token);
  if (probe.status === 404) {
    // The bare server does not mount the demo MCP module; only the gateway does.
    const skipped: StepResult = {
      step: "",
      title: "",
      status: "skip",
      detail: `${base} does not mount /mcp/demo — run the walk-through against the gateway`,
    };
    return { step4: { ...skipped, step: "4", title: "allowed tool" }, step4b: { ...skipped, step: "4b", title: "denied tool" } };
  }

  const body = probe.body as { result?: { isError?: boolean; content?: { type: string; text: string }[] } } | undefined;
  const listed = probe.status === 200 && body?.result?.isError !== true && Array.isArray(body?.result?.content);
  const step4: StepResult = {
    step: "4",
    title: "allowed tool",
    status: listed ? "pass" : "fail",
    detail: listed ? `200, list_notes returned ${body?.result?.content?.length ?? 0} content block(s)` : `${probe.status} ${text(probe.body)}`,
  };

  const denied = await mcpCall(base, "delete_note", { id: "note_welcome" }, token);
  const challenge = denied.headers.get("www-authenticate") ?? "";
  const hasScope = /scope="tools:write"/.test(challenge);
  const hasError = /error="insufficient_scope"/.test(challenge);
  const step4b: StepResult = {
    step: "4b",
    title: "denied tool",
    status: denied.status === 403 && hasScope && hasError ? "pass" : "fail",
    detail:
      denied.status === 403 && hasScope && hasError
        ? `403, WWW-Authenticate: ${challenge}`
        : `${denied.status} ${text(denied.body)}${challenge === "" ? "" : ` / ${challenge}`}`,
  };
  return { step4, step4b };
}

/** Step 5 — the delegation chain on the audit page, and the chain's integrity. */
async function auditChain(base: string, adminToken: string, walk: Walk): Promise<StepResult> {
  const headers = managementHeaders(adminToken);
  // The chain spans events that name no grant at all (`agent.created`), so the page is read
  // unfiltered and the grant's own events are picked out of it. Filtering by `grant_id` would
  // only ever show `grant.created` and `agent.token.issued`.
  const page = await call(`${base}/v1/orgs/${ORG}/audit?limit=200`, { headers });
  const items = ((page.body as {
    items?: { action?: string; subject?: { id?: unknown }; actor_chain?: { id?: unknown }[]; jti?: unknown }[];
  })?.items ?? []) as {
    action: string;
    subject: { id?: unknown };
    actor_chain: { id?: unknown }[];
    jti: unknown;
  }[];

  const actions = new Set(items.map((item) => item.action));
  const jtiMatches = items.some((item) => item.jti === walk.jti && item.action === "agent.token.issued");
  const namesAgent = items.some((item) => item.action === "agent.created" && item.subject?.id === walk.agentId);
  const namesGrant = items.some((item) => item.action === "grant.created" && item.subject?.id === walk.grantId);
  const namesAccount = items.some(
    (item) => item.action === "agent.token.issued" && item.actor_chain.some((actor) => actor.id === walk.accountId),
  );

  const verify = await call(`${base}/v1/orgs/${ORG}/audit/verify`, { headers });
  const verified = (verify.body as { valid?: boolean })?.valid === true;

  const checks: [string, boolean][] = [
    ["audit 200", page.status === 200],
    ["account created the agent", namesAgent],
    ["grant names the agent's grant", namesGrant],
    ["agent.key.registered", actions.has("agent.key.registered")],
    ["agent.token.issued with the jti", jtiMatches],
    ["actor chain carries the account", namesAccount],
    ["verify.valid", verified],
  ];
  const ok = checks.every(([, passed]) => passed);
  return {
    step: "5",
    title: "audit chain",
    status: ok ? "pass" : "fail",
    detail: ok
      ? `${items.length} event(s); account → agent → grant → token(${walk.jti}) visible; verify.valid=true, head ${
          (verify.body as { head?: { seq?: number } })?.head?.seq ?? "?"
        }`
      : checks
          .filter(([, passed]) => !passed)
          .map(([name]) => name)
          .join(", "),
  };
}

/** The browser flow the console uses: authorize → interaction → sign-in → code → token → refresh. */
async function browserFlow(base: string, consoleSecret: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const verifier = `v-${runId}-${"x".repeat(32)}`;
  const challenge = base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));

  const authorize = await call(
    `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${runId}`,
      nonce: `n-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`,
    { redirect: "manual" },
  );
  const interaction = new URL(authorize.headers.get("location") ?? "", base).searchParams.get("interaction");
  if (authorize.status !== 302 || interaction === null) {
    return { step: "6", title: "browser flow", status: "fail", detail: `authorize → ${authorize.status} ${text(authorize.body)}` };
  }

  const signIn = await call(`${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: BOOTSTRAP_ADMIN.email, password: BOOTSTRAP_ADMIN.password }),
  });
  const redirectTo = (signIn.body as { redirect_to?: string })?.redirect_to;
  if (signIn.status !== 200 || redirectTo === undefined) {
    return { step: "6", title: "browser flow", status: "fail", detail: `sign-in → ${signIn.status} ${text(signIn.body)}` };
  }
  const code = new URL(redirectTo).searchParams.get("code") ?? "";

  const exchanged = await tokenCall(
    base,
    {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: "monaca-console",
      code_verifier: verifier,
    },
    btoa(`monaca-console:${consoleSecret}`),
  );
  const idToken = (exchanged.body as { id_token?: unknown })?.id_token;
  const refreshToken = (exchanged.body as { refresh_token?: unknown })?.refresh_token;
  const idClaims = jwtClaims(idToken);
  const checks: [string, boolean][] = [
    ["code exchanged", exchanged.status === 200],
    ["id_token nonce echoed", idClaims?.nonce === `n-${runId}`],
    ["id_token email", idClaims?.email === BOOTSTRAP_ADMIN.email],
    ["offline_access issued a refresh token", typeof refreshToken === "string"],
  ];
  const ok = checks.every(([, passed]) => passed);

  let rotated = false;
  if (ok && typeof refreshToken === "string") {
    const refreshed = await tokenCall(
      base,
      { grant_type: "refresh_token", refresh_token: refreshToken, client_id: "monaca-console" },
      btoa(`monaca-console:${consoleSecret}`),
    );
    rotated = refreshed.status === 200;
  }

  const replayed = await tokenCall(
    base,
    {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: "monaca-console",
      code_verifier: verifier,
    },
    btoa(`monaca-console:${consoleSecret}`),
  );

  return {
    step: "6",
    title: "browser flow",
    status: ok && rotated && replayed.status === 400 ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail:
      ok && rotated && replayed.status === 400
        ? "authorize → interaction → code → id_token(nonce,email) + refresh → rotation → replay refused"
        : `${checks
            .filter(([, passed]) => !passed)
            .map(([name]) => name)
            .join(", ")}; refresh rotated=${rotated}; replay=${replayed.status} ${text(replayed.body)}`,
  };
}

/**
 * Sessions and logout — the SSO cookie, the management session API and RP-initiated logout.
 *
 * Three independent browsers are simulated, because each check needs a live session: one is
 * revoked by the admin API, one is ended through `end-session`, and one is removed in bulk.
 */
async function sessionFlow(base: string, consoleSecret: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const checks: [string, boolean][] = [];
  let detail = "";

  const authorizeUrl = async (tag: string, prompt?: string): Promise<{ url: string; verifier: string; state: string }> => {
    const verifier = `s-${tag}-${runId}-${"y".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const state = `st-${tag}-${runId}`;
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
      ...(prompt === undefined ? {} : { prompt }),
    })}`;
    return { url, verifier, state };
  };

  /** One interactive sign-in: authorize → interaction → sign-in, returning the cookie and code. */
  const signIn = async (
    tag: string,
  ): Promise<{ cookie?: string; sessionId?: string; code?: string; idToken?: string; sub?: string } | undefined> => {
    const { url, verifier } = await authorizeUrl(tag);
    const authorize = await call(url, { redirect: "manual" });
    const interaction = new URL(authorize.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (authorize.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${authorize.status} ${text(authorize.body)}`;
      return undefined;
    }

    const response = await call(`${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: BOOTSTRAP_ADMIN.email, password: BOOTSTRAP_ADMIN.password }),
    });
    const redirectTo = (response.body as { redirect_to?: string })?.redirect_to;
    if (response.status !== 200 || redirectTo === undefined) {
      detail = `sign-in(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }

    // `fetch` never applies a cookie jar here, so the `Set-Cookie` is parsed by hand.
    const setCookie = response.headers.get("set-cookie") ?? "";
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(setCookie)?.[1];
    checks.push([`sign-in(${tag}) set the session cookie`, cookie !== undefined]);

    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    const exchanged = await tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
    const idToken = (exchanged.body as { id_token?: unknown })?.id_token as string | undefined;
    const sub = jwtClaims(idToken)?.sub as string | undefined;
    checks.push([`code(${tag}) exchanged`, exchanged.status === 200 && sub !== undefined]);
    return { cookie, sessionId: cookie, code, idToken, sub };
  };

  /** `prompt=none` with the cookie; returns the code when the SSO session was accepted. */
  const silent = async (cookie: string | undefined): Promise<{ status: number; error: string | null; code: string | null }> => {
    const { url } = await authorizeUrl("silent", "none");
    const response = await call(url, {
      redirect: "manual",
      headers: cookie === undefined ? {} : { cookie: `monaca_session=${cookie}` },
    });
    const params = new URL(response.headers.get("location") ?? "", base).searchParams;
    return { status: response.status, error: params.get("error"), code: params.get("code") };
  };

  const sessionsUrl = (accountId: string): string => `${base}/v1/accounts/${encodeURIComponent(accountId)}/sessions`;
  const listSessions = async (
    accountId: string,
  ): Promise<{ items: { id: string; uuid: string }[]; status: number }> => {
    const response = await call(sessionsUrl(accountId), { headers: { authorization: `Bearer ${adminToken}` } });
    const items = ((response.body as { items?: { id?: string }[] })?.items ?? []).map((item) => {
      const id = item.id ?? "";
      return { id, uuid: typeIdUuid(id) };
    });
    return { items, status: response.status };
  };

  try {
    // --- session A: the cookie and silent reuse ------------------------------------------------
    const first = await signIn("a");
    if (first === undefined || first.cookie === undefined || first.sub === undefined) {
      return { step: "7", title: "session & logout", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const listed = await listSessions(first.sub);
    const listedSession = listed.items.find((item) => item.uuid === first.cookie);
    checks.push(["GET sessions lists the cookie's session", listed.status === 200 && listedSession !== undefined]);

    const reused = await silent(first.cookie);
    checks.push(["prompt=none reuses the session", reused.status === 302 && reused.code !== null]);

    // --- admin revoke of one session ------------------------------------------------------------
    const revoked = await call(`${sessionsUrl(first.sub)}/${encodeURIComponent(listedSession?.id ?? "")}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${adminToken}` },
    });
    checks.push(["DELETE sessions/{sid} → 204", revoked.status === 204]);
    const afterRevoke = await listSessions(first.sub);
    checks.push(["the revoked session is gone", afterRevoke.status === 200 && !afterRevoke.items.some((item) => item.uuid === first.cookie)]);
    const stale = await silent(first.cookie);
    checks.push(["a revoked session cannot sign in silently", stale.status === 302 && stale.error === "login_required"]);

    // --- session B: RP-initiated logout --------------------------------------------------------
    const second = await signIn("b");
    if (second === undefined || second.cookie === undefined || second.idToken === undefined) {
      return { step: "7", title: "session & logout", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const logoutState = `logout-${runId}`;
    const endSession = await call(
      `${base}/t/${TENANT}/oauth2/end-session?${new URLSearchParams({
        id_token_hint: second.idToken,
        post_logout_redirect_uri: redirectUri,
        state: logoutState,
      })}`,
      { redirect: "manual", headers: { cookie: `monaca_session=${second.cookie}` } },
    );
    const endLocation = new URL(endSession.headers.get("location") ?? "", base);
    checks.push(["end-session → 302 to the registered target", endSession.status === 302 && endLocation.origin === new URL(redirectUri).origin]);
    checks.push(["end-session echoes state", endLocation.searchParams.get("state") === logoutState]);
    checks.push(["end-session clears the cookie", (endSession.headers.get("set-cookie") ?? "").includes("monaca_session=;")]);
    const afterLogout = await silent(second.cookie);
    checks.push(["end-session ended the SSO session", afterLogout.status === 302 && afterLogout.error === "login_required"]);

    // --- session C: revoke every session of an account ----------------------------------------
    const third = await signIn("c");
    if (third === undefined || third.cookie === undefined || third.sub === undefined) {
      return { step: "7", title: "session & logout", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const all = await call(sessionsUrl(third.sub), {
      method: "DELETE",
      headers: { authorization: `Bearer ${adminToken}` },
    });
    const replayed = await listSessions(third.sub);
    checks.push([
      "DELETE sessions revokes every live session",
      all.status === 200 && ((all.body as { revoked?: number })?.revoked ?? 0) >= 1,
    ]);
    checks.push(["no session is left after revoke-all", replayed.status === 200 && replayed.items.length === 0]);
    const bulkStale = await silent(third.cookie);
    checks.push(["revoke-all ends silent authentication", bulkStale.status === 302 && bulkStale.error === "login_required"]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "7",
    title: "session & logout",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: cookie → silent reuse → admin revoke → end-session → revoke-all`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * The email-verification flows: self-service registration, passwordless sign-in and password reset.
 *
 * The code is not guessed: it is read back from the dev outbox through `/internal/mail`, which is
 * the M0 stand-in for a mail relay. Every flow gets its own interaction, because sign-up, sign-in
 * and reset each consume one.
 */
async function emailFlow(base: string, consoleSecret: string, internalSecret: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const email = `signup-${runId}@example.test`;
  const password = `pw-${runId}-old-password`;
  const newPassword = `pw-${runId}-new-password`;
  const checks: [string, boolean][] = [];
  let detail = "";

  /** A fresh authorize → interaction, so each flow starts from a clean challenge. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `e-${tag}-${runId}-${"z".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** The newest dev mail for this address and purpose, or undefined when none arrived. */
  const mailCode = async (purpose: string): Promise<string | undefined> => {
    const query = new URLSearchParams({ tenant: TENANT, to: email, purpose });
    const response = await call(`${base}/internal/mail?${query}`, {
      headers: { "x-monaca-internal-secret": internalSecret },
    });
    const code = (response.body as { payload?: { code?: unknown } } | undefined)?.payload?.code;
    return response.status === 200 && typeof code === "string" ? code : undefined;
  };

  /** Redeem the code in `redirect_to` for a token, proving the whole flow completed. */
  const exchange = async (redirectTo: unknown, verifier: string): Promise<HttpResult> => {
    const code = typeof redirectTo === "string" ? new URL(redirectTo).searchParams.get("code") ?? "" : "";
    return tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
  };

  try {
    // --- sign-up: request → mail → verify → token ----------------------------------------------
    const signUp = await begin("signup");
    if (signUp === undefined) {
      return { step: "8", title: "email verification", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const signUpRequest = await call(`${base}/t/${TENANT}/interaction/${signUp.interaction}/sign-up`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email }),
    });
    checks.push([
      "sign-up requests a code",
      signUpRequest.status === 200 && (signUpRequest.body as { verification_required?: unknown })?.verification_required === true,
    ]);
    const signUpCode = await mailCode("sign_up");
    checks.push(["dev mail delivered a sign-up code", typeof signUpCode === "string" && /^\d{6}$/.test(signUpCode)]);

    const signUpVerify = await call(`${base}/t/${TENANT}/interaction/${signUp.interaction}/sign-up/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, code: signUpCode ?? "", password, display_name: "Email flow" }),
    });
    const signUpToken = await exchange((signUpVerify.body as { redirect_to?: unknown })?.redirect_to, signUp.verifier);
    const signUpClaims = jwtClaims((signUpToken.body as { id_token?: unknown })?.id_token);
    checks.push([
      "sign-up completed and issued a token",
      signUpVerify.status === 200 && signUpToken.status === 200 && signUpClaims?.email === email,
    ]);

    // --- passwordless sign-in: request → mail → verify → token ---------------------------------
    const codeSignIn = await begin("code");
    if (codeSignIn === undefined) {
      return { step: "8", title: "email verification", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const codeRequest = await call(`${base}/t/${TENANT}/interaction/${codeSignIn.interaction}/sign-in/code`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email }),
    });
    checks.push([
      "code sign-in requests a code",
      codeRequest.status === 200 && (codeRequest.body as { verification_required?: unknown })?.verification_required === true,
    ]);
    const signInCode = await mailCode("sign_in");
    checks.push(["dev mail delivered a sign-in code", typeof signInCode === "string" && /^\d{6}$/.test(signInCode)]);

    const codeVerify = await call(`${base}/t/${TENANT}/interaction/${codeSignIn.interaction}/sign-in/code/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, code: signInCode ?? "" }),
    });
    const codeToken = await exchange((codeVerify.body as { redirect_to?: unknown })?.redirect_to, codeSignIn.verifier);
    checks.push(["code sign-in issued a token", codeVerify.status === 200 && codeToken.status === 200]);

    // --- password reset: forgot → mail → reset → token -----------------------------------------
    const reset = await begin("reset");
    if (reset === undefined) {
      return { step: "8", title: "email verification", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const forgot = await call(`${base}/t/${TENANT}/interaction/${reset.interaction}/password/forgot`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email }),
    });
    checks.push([
      "password reset requests a code",
      forgot.status === 200 && (forgot.body as { verification_required?: unknown })?.verification_required === true,
    ]);
    const resetCode = await mailCode("password_reset");
    checks.push(["dev mail delivered a reset code", typeof resetCode === "string" && /^\d{6}$/.test(resetCode)]);

    const resetResponse = await call(`${base}/t/${TENANT}/interaction/${reset.interaction}/password/reset`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, code: resetCode ?? "", password: newPassword }),
    });
    const resetToken = await exchange((resetResponse.body as { redirect_to?: unknown })?.redirect_to, reset.verifier);
    checks.push(["password reset issued a token", resetResponse.status === 200 && resetToken.status === 200]);

    // --- the reset really changed the credential -----------------------------------------------
    const oldPassword = await begin("oldpw");
    if (oldPassword === undefined) {
      return { step: "8", title: "email verification", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const refused = await call(`${base}/t/${TENANT}/interaction/${oldPassword.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    checks.push(["the old password is refused", refused.status === 401]);

    const newPasswordFlow = await begin("newpw");
    if (newPasswordFlow === undefined) {
      return { step: "8", title: "email verification", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const accepted = await call(`${base}/t/${TENANT}/interaction/${newPasswordFlow.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: newPassword }),
    });
    const acceptedToken = await exchange((accepted.body as { redirect_to?: unknown })?.redirect_to, newPasswordFlow.verifier);
    checks.push(["the new password signs in", accepted.status === 200 && acceptedToken.status === 200]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "8",
    title: "email verification",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: sign-up → code sign-in → password reset → old password refused`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/** Decode the base32 secret an authenticator app stores (RFC 4648, no padding). */
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

/** RFC 6238, SHA-1, six digits, 30-second steps — the code an authenticator app would show now. */
function totpFromBase32(secret: string, at: number = Date.now()): string {
  const step = Math.floor(at / 1000 / 30);
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

/**
 * Step 9 — the authenticator (TOTP) factor.
 *
 * A dedicated account is created for the run: enrolling the second factor on the bootstrap admin
 * would make every later walk-through answer `mfa_required`. The code is computed locally with the
 * secret the setup endpoint returned, which is exactly what an authenticator app does.
 */
async function mfaFlow(base: string, adminToken: string, consoleSecret: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const email = `mfa-${runId}@demo.localhost`;
  const password = `pw-${runId}-mfa-account`;
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "9",
    title: "two-step verification",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `m-${tag}-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Password sign-in on a fresh interaction, together with any session cookie it set. */
  const signIn = async (
    tag: string,
  ): Promise<{ interaction: string; verifier: string; status: number; body: unknown; cookie?: string } | undefined> => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(response.headers.get("set-cookie") ?? "")?.[1];
    return { ...started, status: response.status, body: response.body, cookie };
  };

  /** Redeem the `redirect_to` a completed interaction returned for a token. */
  const exchange = async (redirectTo: unknown, verifier: string): Promise<HttpResult> => {
    const code = typeof redirectTo === "string" ? new URL(redirectTo).searchParams.get("code") ?? "" : "";
    return tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
  };

  try {
    // --- a dedicated account, already a member of acme ------------------------------------------
    const account = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "MFA flow", password }),
    });
    const accountId = (account.body as { id?: string })?.id;
    if (account.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${account.status} ${text(account.body)}`);
    }
    const member = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    checks.push(["the run's account joined acme", member.status === 201]);

    // --- first sign-in: one factor, so the flow completes and leaves the SSO cookie -------------
    const first = await signIn("first");
    if (first === undefined) return fail("");
    checks.push([
      "a fresh account signs in with one factor",
      first.status === 200 && (first.body as { redirect_to?: unknown })?.redirect_to !== undefined,
    ]);
    if (first.cookie === undefined) return fail("the first sign-in set no session cookie");
    const cookie = { cookie: `monaca_session=${first.cookie}` };

    // --- enrollment: secret + otpauth URL, confirmed with a locally computed code ---------------
    const enrollment = await call(`${base}/t/${TENANT}/account/mfa/totp`, { method: "POST", headers: cookie });
    const secret = (enrollment.body as { secret?: unknown })?.secret;
    checks.push([
      "the setup endpoint returns a base32 secret and an otpauth URL",
      enrollment.status === 200 &&
        typeof secret === "string" &&
        typeof (enrollment.body as { otpauth_url?: unknown })?.otpauth_url === "string",
    ]);
    if (typeof secret !== "string") return fail(`POST /account/mfa/totp → ${enrollment.status} ${text(enrollment.body)}`);

    const confirmed = await call(`${base}/t/${TENANT}/account/mfa/totp/verify`, {
      method: "POST",
      headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify({ code: totpFromBase32(secret) }),
    });
    checks.push([
      "a computed authenticator code enables the factor",
      confirmed.status === 200 && (confirmed.body as { enabled?: unknown })?.enabled === true,
    ]);

    const profile = await call(`${base}/t/${TENANT}/account`, { headers: cookie });
    checks.push([
      "GET /account reports totp enabled",
      profile.status === 200 && ((profile.body as { mfa?: { totp?: unknown } })?.mfa?.totp) === true,
    ]);

    // --- sign-in now pauses for the second factor -----------------------------------------------
    const challenged = await signIn("challenged");
    if (challenged === undefined) return fail("");
    checks.push([
      "a new sign-in answers mfa_required instead of a redirect",
      challenged.status === 200 &&
        (challenged.body as { mfa_required?: unknown })?.mfa_required === true &&
        (challenged.body as { redirect_to?: unknown })?.redirect_to === undefined,
    ]);

    const wrong = String((Number(totpFromBase32(secret)[0]) + 1) % 10) + totpFromBase32(secret).slice(1);
    const refused = await call(`${base}/t/${TENANT}/interaction/${challenged.interaction}/mfa/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: wrong }),
    });
    checks.push(["a wrong authenticator code is refused", refused.status === 401]);

    const verified = await call(`${base}/t/${TENANT}/interaction/${challenged.interaction}/mfa/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: totpFromBase32(secret) }),
    });
    const mfaToken = await exchange((verified.body as { redirect_to?: unknown })?.redirect_to, challenged.verifier);
    checks.push([
      "the correct code completes the flow and issues a token",
      verified.status === 200 && mfaToken.status === 200,
    ]);

    // --- removal: the account is back to one factor ---------------------------------------------
    const removed = await call(`${base}/t/${TENANT}/account/mfa/totp`, { method: "DELETE", headers: cookie });
    checks.push(["DELETE removes the authenticator", removed.status === 204]);

    const plain = await signIn("plain");
    if (plain === undefined) return fail("");
    const plainRedirect = (plain.body as { redirect_to?: unknown })?.redirect_to;
    const plainToken = await exchange(plainRedirect, plain.verifier);
    checks.push([
      "sign-in needs one factor again",
      plain.status === 200 && plainRedirect !== undefined && plainToken.status === 200,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "9",
    title: "two-step verification",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: enroll → challenge → wrong code refused → token → remove → one factor`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 10 — the account centre: profile, password and sessions.
 *
 * A dedicated account is created for the run, like step 9. Two browsers sign in (two cookies), so
 * the password change has another session to revoke and the sessions list has a `current` row to
 * mark. Revoking a session is checked by calling `GET /account` with that cookie afterwards.
 */
async function accountFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const email = `account-${runId}@demo.localhost`;
  const firstPassword = `pw-${runId}-account-original`;
  const secondPassword = `pw-${runId}-account-renamed`;
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "10",
    title: "account centre",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction. */
  const begin = async (tag: string): Promise<string | undefined> => {
    const verifier = `a-${tag}-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return encodeURIComponent(interaction);
  };

  /** Password sign-in on a fresh interaction; the response carries the SSO cookie. */
  const signIn = async (
    tag: string,
    password: string,
  ): Promise<{ status: number; body: unknown; cookie?: string } | undefined> => {
    const interaction = await begin(tag);
    if (interaction === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(response.headers.get("set-cookie") ?? "")?.[1];
    return { status: response.status, body: response.body, cookie };
  };

  const auth = (cookie: string): Record<string, string> => ({ cookie: `monaca_session=${cookie}` });
  const profile = (cookie: string): Promise<HttpResult> => call(`${base}/t/${TENANT}/account`, { headers: auth(cookie) });
  const sessionsOf = async (cookie: string): Promise<{ id: string; current: boolean }[]> => {
    const response = await call(`${base}/t/${TENANT}/account/sessions`, { headers: auth(cookie) });
    const items = (response.body as { items?: { id?: unknown; current?: unknown }[] })?.items ?? [];
    return items
      .filter((item): item is { id: string; current: boolean } => typeof item.id === "string")
      .map((item) => ({ id: item.id, current: item.current === true }));
  };

  try {
    // --- a dedicated account, already a member of acme ------------------------------------------
    const account = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Account centre", password: firstPassword }),
    });
    const accountId = (account.body as { id?: string })?.id;
    if (account.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${account.status} ${text(account.body)}`);
    }
    const member = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    checks.push(["the run's account joined acme", member.status === 201]);

    // --- two browsers, so a password change has something to revoke ------------------------------
    const first = await signIn("first", firstPassword);
    const second = await signIn("second", firstPassword);
    if (first?.cookie === undefined || second?.cookie === undefined) {
      return fail("the two sign-ins did not both set a session cookie");
    }
    const firstCookie = first.cookie;
    const secondCookie = second.cookie;

    // --- profile: PATCH changes the name, GET echoes it ------------------------------------------
    const renamed = await call(`${base}/t/${TENANT}/account`, {
      method: "PATCH",
      headers: { ...auth(firstCookie), "content-type": "application/json" },
      body: JSON.stringify({ display_name: "  Account centre renamed  " }),
    });
    checks.push([
      "PATCH /account stores the trimmed display name",
      renamed.status === 200 &&
        (renamed.body as { display_name?: unknown })?.display_name === "Account centre renamed",
    ]);
    const echoed = await profile(firstCookie);
    checks.push([
      "GET /account echoes the new name",
      echoed.status === 200 &&
        (echoed.body as { display_name?: unknown })?.display_name === "Account centre renamed",
    ]);

    // --- password: the current one is required, and the change ends the other sessions -----------
    const wrongCurrent = await call(`${base}/t/${TENANT}/account/password`, {
      method: "POST",
      headers: { ...auth(firstCookie), "content-type": "application/json" },
      body: JSON.stringify({ current_password: "not-the-password", new_password: secondPassword }),
    });
    checks.push(["a wrong current password is refused", wrongCurrent.status === 401]);

    const changed = await call(`${base}/t/${TENANT}/account/password`, {
      method: "POST",
      headers: { ...auth(firstCookie), "content-type": "application/json" },
      body: JSON.stringify({ current_password: firstPassword, new_password: secondPassword }),
    });
    checks.push(["the right current password changes it", changed.status === 204]);

    const stale = await signIn("stale", firstPassword);
    checks.push(["the old password no longer signs in", stale !== undefined && stale.status === 401]);

    const fresh = await signIn("fresh", secondPassword);
    const freshRedirect = (fresh?.body as { redirect_to?: unknown })?.redirect_to;
    checks.push([
      "the new password signs in",
      fresh !== undefined && fresh.status === 200 && freshRedirect !== undefined && fresh.cookie !== undefined,
    ]);
    if (fresh?.cookie === undefined) return fail("the new-password sign-in set no cookie");
    const freshCookie = fresh.cookie;

    checks.push(["the password change ended the other browser's session", (await profile(secondCookie)).status === 401]);

    // --- sessions: the caller is marked current, single and bulk revocation work -----------------
    const afterChange = await sessionsOf(firstCookie);
    checks.push([
      "GET /account/sessions lists the caller and marks exactly one current",
      afterChange.length === 2 && afterChange.filter((row) => row.current).length === 1,
    ]);
    const other = afterChange.find((row) => !row.current);
    if (other === undefined) return fail("no other session to revoke");
    const revokedOther = await call(`${base}/t/${TENANT}/account/sessions/${encodeURIComponent(other.id)}`, {
      method: "DELETE",
      headers: auth(firstCookie),
    });
    checks.push(["DELETE one session is 204", revokedOther.status === 204]);
    checks.push(["that browser is signed out", (await profile(freshCookie)).status === 401]);
    checks.push([
      "the list shrinks to the caller",
      (await sessionsOf(firstCookie)).filter((row) => !row.current).length === 0,
    ]);

    const third = await signIn("third", secondPassword);
    if (third?.cookie === undefined) return fail("the third sign-in set no cookie");
    checks.push([
      "DELETE all other sessions is 204",
      (
        await call(`${base}/t/${TENANT}/account/sessions`, { method: "DELETE", headers: auth(firstCookie) })
      ).status === 204,
    ]);
    checks.push(["the third browser is signed out", (await profile(third.cookie)).status === 401]);

    const remaining = await sessionsOf(firstCookie);
    const current = remaining.find((row) => row.current);
    if (current === undefined) return fail("the caller's session is missing from the list");
    const revokedSelf = await call(`${base}/t/${TENANT}/account/sessions/${encodeURIComponent(current.id)}`, {
      method: "DELETE",
      headers: auth(firstCookie),
    });
    checks.push(["a session may revoke itself", revokedSelf.status === 204]);
    checks.push(["the revoked cookie no longer authenticates", (await profile(firstCookie)).status === 401]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "10",
    title: "account centre",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: name → wrong current refused → password changed → old refused, new signs in → sessions listed and revoked`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 11 — MFA backup codes.
 *
 * A dedicated account enrolls an authenticator, generates a sheet of ten codes, then signs in with
 * one of them instead of the app. The same code is replayed on a fresh interaction to prove it is
 * single-use, and the remaining count is checked before and after removal. The typed code is sent in
 * uppercase with its display hyphen to exercise the server-side normalisation.
 */
async function backupCodeFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const email = `backup-${runId}@demo.localhost`;
  const password = `pw-${runId}-backup-account`;
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "11",
    title: "MFA backup codes",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction, with the PKCE verifier the exchange needs. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `b-${tag}-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Password sign-in on a fresh interaction, together with any session cookie it set. */
  const signIn = async (
    tag: string,
  ): Promise<{ interaction: string; verifier: string; status: number; body: unknown; cookie?: string } | undefined> => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(response.headers.get("set-cookie") ?? "")?.[1];
    return { ...started, status: response.status, body: response.body, cookie };
  };

  /** Redeem the `redirect_to` a completed interaction returned for a token. */
  const exchange = async (redirectTo: unknown, verifier: string): Promise<HttpResult> => {
    const code = typeof redirectTo === "string" ? new URL(redirectTo).searchParams.get("code") ?? "" : "";
    return tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
  };

  const factorsOf = (body: unknown): string[] => {
    const factors = (body as { factors?: unknown })?.factors;
    return Array.isArray(factors) ? factors.filter((value): value is string => typeof value === "string") : [];
  };

  try {
    // --- a dedicated account, already a member of acme ------------------------------------------
    const account = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Backup codes", password }),
    });
    const accountId = (account.body as { id?: string })?.id;
    if (account.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${account.status} ${text(account.body)}`);
    }
    const member = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    checks.push(["the run's account joined acme", member.status === 201]);

    // --- one-factor sign-in, then enroll the authenticator the codes stand behind ----------------
    const first = await signIn("first");
    if (first?.cookie === undefined) return fail("the first sign-in set no session cookie");
    const cookie = { cookie: `monaca_session=${first.cookie}` };

    const enrollment = await call(`${base}/t/${TENANT}/account/mfa/totp`, { method: "POST", headers: cookie });
    const secret = (enrollment.body as { secret?: unknown })?.secret;
    if (typeof secret !== "string") return fail(`POST /account/mfa/totp → ${enrollment.status} ${text(enrollment.body)}`);
    const confirmed = await call(`${base}/t/${TENANT}/account/mfa/totp/verify`, {
      method: "POST",
      headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify({ code: totpFromBase32(secret) }),
    });
    checks.push(["the authenticator is enrolled", confirmed.status === 200]);

    // --- generate the sheet: ten grouped codes, shown once --------------------------------------
    const sheet = await call(`${base}/t/${TENANT}/account/mfa/backup-codes`, { method: "POST", headers: cookie });
    const codes = (sheet.body as { codes?: unknown })?.codes;
    const codeList = Array.isArray(codes) ? codes.filter((code): code is string => typeof code === "string") : [];
    checks.push([
      "POST /account/mfa/backup-codes returns ten grouped codes",
      sheet.status === 200 &&
        codeList.length === 10 &&
        codeList.every((code) => /^[0-9a-z]{5}-[0-9a-z]{5}$/.test(code)),
    ]);
    if (codeList.length === 0) return fail(`POST /account/mfa/backup-codes → ${sheet.status} ${text(sheet.body)}`);

    const remaining = async (): Promise<number | undefined> => {
      const response = await call(`${base}/t/${TENANT}/account/mfa/backup-codes`, { headers: cookie });
      const value = (response.body as { remaining?: unknown })?.remaining;
      return typeof value === "number" ? value : undefined;
    };
    checks.push(["GET /account/mfa/backup-codes reports ten unused", (await remaining()) === 10]);

    // --- a sign-in challenge offers both factors ------------------------------------------------
    const challenged = await signIn("challenged");
    if (challenged === undefined) return fail("");
    const factors = factorsOf(challenged.body);
    checks.push([
      "a sign-in challenge lists totp and backup_code",
      challenged.status === 200 && factors.includes("totp") && factors.includes("backup_code"),
    ]);

    // --- a wrong code is refused; the typed form is normalised (uppercase + hyphen) -------------
    const canonical = codeList[0]!.replace("-", "");
    const wrong = `${canonical[0] === "0" ? "1" : "0"}${canonical.slice(1)}`;
    const refused = await call(`${base}/t/${TENANT}/interaction/${challenged.interaction}/mfa/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: wrong, factor: "backup_code" }),
    });
    checks.push(["a wrong backup code is refused", refused.status === 401]);

    const verified = await call(`${base}/t/${TENANT}/interaction/${challenged.interaction}/mfa/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: codeList[0]!.toUpperCase(), factor: "backup_code" }),
    });
    const token = await exchange((verified.body as { redirect_to?: unknown })?.redirect_to, challenged.verifier);
    checks.push([
      "a backup code completes the flow and issues a token",
      verified.status === 200 && token.status === 200,
    ]);

    // --- the code is single-use ------------------------------------------------------------------
    const replay = await signIn("replay");
    if (replay === undefined) return fail("");
    const reused = await call(`${base}/t/${TENANT}/interaction/${replay.interaction}/mfa/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: codeList[0]!, factor: "backup_code" }),
    });
    checks.push(["the same backup code cannot be reused", reused.status === 401]);
    checks.push(["the sheet now reports nine unused", (await remaining()) === 9]);

    // --- removal leaves only the authenticator --------------------------------------------------
    const removed = await call(`${base}/t/${TENANT}/account/mfa/backup-codes`, { method: "DELETE", headers: cookie });
    checks.push(["DELETE /account/mfa/backup-codes is 204", removed.status === 204]);
    checks.push(["no backup codes remain", (await remaining()) === 0]);

    const plain = await signIn("plain");
    checks.push([
      "the next challenge offers totp only",
      plain !== undefined && factorsOf(plain.body).join(",") === "totp",
    ]);
    checks.push([
      "the profile reports zero backup codes",
      ((await call(`${base}/t/${TENANT}/account`, { headers: cookie }).then((response) => response.body)) as {
        mfa?: { backup_codes?: unknown };
      })?.mfa?.backup_codes === 0,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "11",
    title: "MFA backup codes",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: generate ten → challenge offers both → wrong refused → code signs in → replay refused → remove`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

// ---------------------------------------------------------------------------
// Step 12: a software authenticator
// ---------------------------------------------------------------------------

/** Concatenate byte arrays; every ceremony below is a sequence of fixed-size slices. */
function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4);
  return new Uint8Array(Buffer.from(padded, "base64"));
}

/**
 * The CBOR heads the two WebAuthn structures use: integers as COSE map keys, byte strings and text
 * strings, and maps. A full encoder would be a dependency for four major types, so this writes the
 * three length forms that can actually appear here.
 */
function cborHead(major: number, argument: number): Uint8Array {
  if (argument < 24) return Uint8Array.of((major << 5) | argument);
  if (argument < 256) return Uint8Array.of((major << 5) | 24, argument);
  return Uint8Array.of((major << 5) | 25, (argument >>> 8) & 0xff, argument & 0xff);
}

function cborUint(value: number): Uint8Array {
  return cborHead(0, value);
}

/** CBOR major type 1 stores `-1 - value`, so `-7` is the argument `6`. */
function cborNegative(value: number): Uint8Array {
  return cborHead(1, -1 - value);
}

function cborBytes(bytes: Uint8Array): Uint8Array {
  return concatBytes(cborHead(2, bytes.length), bytes);
}

function cborText(text: string): Uint8Array {
  const bytes = new TextEncoder().encode(text);
  return concatBytes(cborHead(3, bytes.length), bytes);
}

function cborMap(entries: [Uint8Array, Uint8Array][]): Uint8Array {
  return concatBytes(cborHead(5, entries.length), ...entries.flatMap(([key, value]) => [key, value]));
}

function u32(value: number): Uint8Array {
  return Uint8Array.of((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.buffer as ArrayBuffer));
}

/** A P-256 key pair, a credential id and a counter: what one hardware authenticator would hold. */
interface SoftwareAuthenticator {
  credentialId: Uint8Array;
  /** The COSE `EC2` public key embedded in the attestation. */
  cose: Uint8Array;
  signCount: number;
  sign: (data: Uint8Array) => Promise<Uint8Array>;
}

async function createSoftwareAuthenticator(): Promise<SoftwareAuthenticator> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as { x: string; y: string };
  const cose = cborMap([
    [cborUint(1), cborUint(2)], // kty: EC2
    [cborUint(3), cborNegative(-7)], // alg: ES256
    [cborNegative(-1), cborUint(1)], // crv: P-256
    [cborNegative(-2), cborBytes(fromBase64Url(jwk.x))],
    [cborNegative(-3), cborBytes(fromBase64Url(jwk.y))],
  ]);
  return {
    credentialId: crypto.getRandomValues(new Uint8Array(16)),
    cose,
    signCount: 0,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      return new Uint8Array(
        await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, data.buffer as ArrayBuffer),
      );
    },
  };
}

interface CreationOptionsJSON {
  challenge: string;
  rp: { id: string };
  user: { id: string };
}

/** What `navigator.credentials.create()` would return, with `attestation: "none"`. */
async function buildRegistration(
  authenticator: SoftwareAuthenticator,
  options: CreationOptionsJSON,
  origin: string,
  name: string,
): Promise<Record<string, unknown>> {
  const clientData = new TextEncoder().encode(
    JSON.stringify({ type: "webauthn.create", challenge: options.challenge, origin, crossOrigin: false }),
  );
  const rpIdHash = await sha256(new TextEncoder().encode(options.rp.id));
  const idLength = Uint8Array.of(authenticator.credentialId.length >>> 8, authenticator.credentialId.length & 0xff);
  // UP | UV | AT, a fresh counter, an all-zero AAGUID, the id and the COSE key.
  const authData = concatBytes(
    rpIdHash,
    Uint8Array.of(0x45),
    u32(0),
    new Uint8Array(16),
    idLength,
    authenticator.credentialId,
    authenticator.cose,
  );
  const attestation = cborMap([
    [cborText("fmt"), cborText("none")],
    [cborText("attStmt"), cborMap([])],
    [cborText("authData"), cborBytes(authData)],
  ]);
  return {
    rawId: base64Url(authenticator.credentialId),
    name,
    response: {
      clientDataJSON: base64Url(clientData),
      attestationObject: base64Url(attestation),
      transports: ["internal"],
    },
  };
}

interface RequestOptionsJSON {
  challenge: string;
  rpId: string;
}

/** What `navigator.credentials.get()` would return, including the user handle. */
async function buildPasskeyAssertion(
  authenticator: SoftwareAuthenticator,
  options: RequestOptionsJSON,
  origin: string,
  userHandle: Uint8Array,
): Promise<Record<string, unknown>> {
  authenticator.signCount += 1;
  const clientData = new TextEncoder().encode(
    JSON.stringify({ type: "webauthn.get", challenge: options.challenge, origin, crossOrigin: false }),
  );
  const rpIdHash = await sha256(new TextEncoder().encode(options.rpId));
  // UP | UV; an assertion carries no attested credential data.
  const authData = concatBytes(rpIdHash, Uint8Array.of(0x05), u32(authenticator.signCount));
  const signature = await authenticator.sign(concatBytes(authData, await sha256(clientData)));
  return {
    rawId: base64Url(authenticator.credentialId),
    response: {
      clientDataJSON: base64Url(clientData),
      authenticatorData: base64Url(authData),
      signature: base64Url(signature),
      userHandle: base64Url(userHandle),
    },
  };
}

/**
 * Step 12 — passkeys, both as a primary factor and as the second factor.
 *
 * The software authenticator above produces exactly what a browser would: an ECDSA P-256 key,
 * CBOR COSE key and attestation, and signatures over `authData || SHA-256(clientDataJSON)`. The
 * relying party comes from the deployment, so the origin defaults to the CI value
 * (`MONACA_AUTH_UI_URL`) rather than the API origin the script talks to.
 */
async function passkeyFlow(base: string, adminToken: string, consoleSecret: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const email = `passkey-${runId}@demo.localhost`;
  const password = `pw-${runId}-passkey-account`;
  const headers = managementHeaders(adminToken);
  const origin = new URL(process.env.MONACA_AUTH_UI_URL ?? "http://localhost:5174").origin;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "12",
    title: "passkeys",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `p-${tag}-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Password sign-in on a fresh interaction, together with any session cookie it set. */
  const signIn = async (
    tag: string,
  ): Promise<{ interaction: string; verifier: string; status: number; body: unknown; cookie?: string } | undefined> => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(response.headers.get("set-cookie") ?? "")?.[1];
    return { ...started, status: response.status, body: response.body, cookie };
  };

  /** Redeem the `redirect_to` a completed interaction returned for a token. */
  const exchange = async (redirectTo: unknown, verifier: string): Promise<HttpResult> => {
    const code = typeof redirectTo === "string" ? new URL(redirectTo).searchParams.get("code") ?? "" : "";
    return tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
  };

  try {
    // --- a dedicated account, already a member of acme ------------------------------------------
    const account = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Passkey flow", password }),
    });
    const accountId = (account.body as { id?: string })?.id;
    if (account.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${account.status} ${text(account.body)}`);
    }
    // The WebAuthn user handle is the account UUID, which `user.id` in the options also carries.
    const userHandle = new Uint8Array(Buffer.from(typeIdUuid(accountId).replaceAll("-", ""), "hex"));
    const member = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    checks.push(["the run's account joined acme", member.status === 201]);

    // --- one-factor sign-in, so the session cookie can register the passkey -----------------------
    const first = await signIn("first");
    if (first?.cookie === undefined) return fail("the first sign-in set no session cookie");
    const cookie = { cookie: `monaca_session=${first.cookie}` };

    // --- registration: creation options, then the attestation ------------------------------------
    const authenticator = await createSoftwareAuthenticator();
    const options = await call(`${base}/t/${TENANT}/account/passkeys/options`, { method: "POST", headers: cookie });
    const creation = options.body as Partial<CreationOptionsJSON>;
    const rpId = creation.rp?.id;
    if (options.status !== 200 || typeof creation.challenge !== "string" || typeof rpId !== "string") {
      return fail(`POST /account/passkeys/options → ${options.status} ${text(options.body)}`);
    }
    checks.push([
      "the creation options carry the relying party and a challenge",
      rpId === new URL(origin).hostname && creation.user?.id === base64Url(userHandle),
    ]);

    const registered = await call(`${base}/t/${TENANT}/account/passkeys`, {
      method: "POST",
      headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify(await buildRegistration(authenticator, creation as CreationOptionsJSON, origin, "E2E key")),
    });
    const passkeyId = (registered.body as { id?: unknown })?.id;
    checks.push([
      "the registration ceremony stores a pky_… passkey",
      registered.status === 201 && typeof passkeyId === "string" && passkeyId.startsWith("pky_"),
    ]);
    if (typeof passkeyId !== "string") {
      return fail(`POST /account/passkeys → ${registered.status} ${text(registered.body)}`);
    }

    const list = async (): Promise<{ id?: unknown; name?: unknown; transports?: unknown }[]> => {
      const response = await call(`${base}/t/${TENANT}/account/passkeys`, { headers: cookie });
      const items = (response.body as { items?: unknown })?.items;
      return Array.isArray(items) ? (items as { id?: unknown; name?: unknown; transports?: unknown }[]) : [];
    };
    const items = await list();
    checks.push([
      "GET /account/passkeys lists it with its transport hint",
      items.length === 1 &&
        items[0]?.id === passkeyId &&
        Array.isArray(items[0]?.transports) &&
        (items[0]!.transports as string[]).includes("internal"),
    ]);
    const passkeyCount = async (): Promise<unknown> => {
      const response = await call(`${base}/t/${TENANT}/account`, { headers: cookie });
      return (response.body as { mfa?: { passkeys?: unknown } })?.mfa?.passkeys;
    };
    checks.push(["the profile reports one passkey", (await passkeyCount()) === 1]);

    // --- passwordless sign-in --------------------------------------------------------------------
    const passwordless = await begin("passwordless");
    if (passwordless === undefined) return fail("");
    const requestOptions = await call(`${base}/t/${TENANT}/interaction/${passwordless.interaction}/sign-in/passkey/options`, {
      method: "POST",
    });
    const request = requestOptions.body as Partial<RequestOptionsJSON>;
    if (requestOptions.status !== 200 || typeof request.challenge !== "string" || typeof request.rpId !== "string") {
      return fail(`POST /sign-in/passkey/options → ${requestOptions.status} ${text(requestOptions.body)}`);
    }
    checks.push(["the assertion options name the relying party", request.rpId === rpId]);

    const signedIn = await call(`${base}/t/${TENANT}/interaction/${passwordless.interaction}/sign-in/passkey`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(await buildPasskeyAssertion(authenticator, request as RequestOptionsJSON, origin, userHandle)),
    });
    const passkeyToken = await exchange((signedIn.body as { redirect_to?: unknown })?.redirect_to, passwordless.verifier);
    checks.push([
      "a passkey signs in without a password and issues a token",
      signedIn.status === 200 && passkeyToken.status === 200,
    ]);

    // --- a signature over an old challenge cannot be replayed -----------------------------------
    const replay = await begin("replay");
    if (replay === undefined) return fail("");
    const replayOptions = await call(`${base}/t/${TENANT}/interaction/${replay.interaction}/sign-in/passkey/options`, {
      method: "POST",
    });
    const stale = await buildPasskeyAssertion(authenticator, request as RequestOptionsJSON, origin, userHandle);
    const replayed = await call(`${base}/t/${TENANT}/interaction/${replay.interaction}/sign-in/passkey`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(stale),
    });
    checks.push([
      "an assertion over a stale challenge is 401",
      replayOptions.status === 200 && replayed.status === 401,
    ]);

    // --- the label can be changed ---------------------------------------------------------------
    const renamed = await call(`${base}/t/${TENANT}/account/passkeys/${passkeyId}`, {
      method: "PATCH",
      headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify({ name: "Renamed key" }),
    });
    checks.push([
      "PATCH renames the passkey",
      renamed.status === 200 && (renamed.body as { name?: unknown })?.name === "Renamed key",
    ]);

    // --- enroll TOTP, then prove the second factor with the passkey -------------------------------
    const enrollment = await call(`${base}/t/${TENANT}/account/mfa/totp`, { method: "POST", headers: cookie });
    const secret = (enrollment.body as { secret?: unknown })?.secret;
    if (typeof secret !== "string") return fail(`POST /account/mfa/totp → ${enrollment.status} ${text(enrollment.body)}`);
    const confirmed = await call(`${base}/t/${TENANT}/account/mfa/totp/verify`, {
      method: "POST",
      headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify({ code: totpFromBase32(secret) }),
    });
    checks.push(["the authenticator is enrolled alongside the passkey", confirmed.status === 200]);

    const challenged = await signIn("challenged");
    if (challenged === undefined) return fail("");
    const factors = Array.isArray((challenged.body as { factors?: unknown })?.factors)
      ? ((challenged.body as { factors: string[] }).factors)
      : [];
    checks.push([
      "a password sign-in offers totp and passkey",
      challenged.status === 200 &&
        (challenged.body as { mfa_required?: unknown })?.mfa_required === true &&
        factors.includes("totp") &&
        factors.includes("passkey"),
    ]);

    const mfaOptions = await call(`${base}/t/${TENANT}/interaction/${challenged.interaction}/mfa/passkey/options`, {
      method: "POST",
    });
    const mfaRequest = mfaOptions.body as Partial<RequestOptionsJSON & { allowCredentials?: { id?: unknown }[] }>;
    checks.push([
      "the second-factor options allow only this credential",
      mfaOptions.status === 200 &&
        typeof mfaRequest.challenge === "string" &&
        mfaRequest.allowCredentials?.length === 1 &&
        mfaRequest.allowCredentials[0]?.id === base64Url(authenticator.credentialId),
    ]);
    if (mfaOptions.status !== 200 || typeof mfaRequest.challenge !== "string" || typeof mfaRequest.rpId !== "string") {
      return fail(`POST /mfa/passkey/options → ${mfaOptions.status} ${text(mfaOptions.body)}`);
    }

    const mfa = await call(`${base}/t/${TENANT}/interaction/${challenged.interaction}/mfa/passkey`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(await buildPasskeyAssertion(authenticator, mfaRequest as RequestOptionsJSON, origin, userHandle)),
    });
    const mfaToken = await exchange((mfa.body as { redirect_to?: unknown })?.redirect_to, challenged.verifier);
    checks.push([
      "the passkey completes the second factor and issues a token",
      mfa.status === 200 && mfaToken.status === 200,
    ]);

    // --- removal returns the account to the authenticator app only -------------------------------
    const removed = await call(`${base}/t/${TENANT}/account/passkeys/${passkeyId}`, { method: "DELETE", headers: cookie });
    checks.push(["DELETE /account/passkeys/{id} is 204", removed.status === 204]);
    checks.push(["GET /account/passkeys is empty", (await list()).length === 0]);
    checks.push(["the profile reports zero passkeys", (await passkeyCount()) === 0]);

    const plain = await signIn("plain");
    if (plain === undefined) return fail("");
    checks.push([
      "the next challenge offers totp only",
      Array.isArray((plain.body as { factors?: unknown })?.factors) &&
        (plain.body as { factors: string[] }).factors.join(",") === "totp",
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "12",
    title: "passkeys",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: register → passwordless sign-in → replay refused → rename → MFA passkey → remove`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 13 — usernames as a second sign-in identifier (§6.1).
 *
 * The account centre claims a username, the sign-in endpoint accepts it (case-insensitively) in
 * place of the email, and a second account trying to claim the same name gets a 409.
 */
async function usernameFlow(base: string, adminToken: string, consoleSecret: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const headers = managementHeaders(adminToken);
  const username = `uname-${runId}`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "13",
    title: "username identifiers",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `u-${tag}-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Password sign-in on a fresh interaction, together with any session cookie it set. */
  const signIn = async (
    tag: string,
    identifier: string,
    password: string,
  ): Promise<{ interaction: string; verifier: string; status: number; body: unknown; cookie?: string } | undefined> => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier, password }),
    });
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(response.headers.get("set-cookie") ?? "")?.[1];
    return { ...started, status: response.status, body: response.body, cookie };
  };

  /** Redeem the `redirect_to` a completed interaction returned for a token. */
  const exchange = async (redirectTo: unknown, verifier: string): Promise<HttpResult> => {
    const code = typeof redirectTo === "string" ? new URL(redirectTo).searchParams.get("code") ?? "" : "";
    return tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
  };

  try {
    // --- account A claims a username -------------------------------------------------------------
    const emailA = `username-${runId}@demo.localhost`;
    const passwordA = `pw-${runId}-username-a`;
    const accountA = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: emailA, display_name: "Username A", password: passwordA }),
    });
    const accountAId = (accountA.body as { id?: string })?.id;
    if (accountA.status !== 201 || accountAId === undefined) {
      return fail(`POST /v1/accounts A → ${accountA.status} ${text(accountA.body)}`);
    }
    const memberA = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountAId, role: "member" }),
    });
    checks.push(["the first account joined acme", memberA.status === 201]);

    const first = await signIn("first", emailA, passwordA);
    if (first?.cookie === undefined) return fail("the first sign-in set no session cookie");
    const cookieA = { cookie: `monaca_session=${first.cookie}` };

    // A mixed-case claim is stored lowercased, matching the case-insensitive unique index.
    const claimed = await call(`${base}/t/${TENANT}/account`, {
      method: "PATCH",
      headers: { ...cookieA, "content-type": "application/json" },
      body: JSON.stringify({ username: `Uname-${runId}` }),
    });
    checks.push([
      "PATCH /account stores the username lowercased",
      claimed.status === 200 && (claimed.body as { username?: unknown })?.username === username,
    ]);
    const profile = await call(`${base}/t/${TENANT}/account`, { headers: cookieA });
    checks.push([
      "GET /account echoes the username",
      profile.status === 200 && (profile.body as { username?: unknown })?.username === username,
    ]);

    // --- the username signs in, case-insensitively ---------------------------------------------
    const byUsername = await signIn("username", username.toUpperCase(), passwordA);
    if (byUsername === undefined) return fail("");
    const usernameToken = await exchange(
      (byUsername.body as { redirect_to?: unknown })?.redirect_to,
      byUsername.verifier,
    );
    checks.push([
      "the username signs in case-insensitively and mints a token",
      byUsername.status === 200 && usernameToken.status === 200,
    ]);

    // The email remains a working identifier for the same account.
    const byEmail = await signIn("email", emailA, passwordA);
    checks.push(["the email still signs in", byEmail?.status === 200]);

    const unknown = await signIn("unknown", `nobody-${runId}`, passwordA);
    checks.push(["an unknown identifier is 401", unknown?.status === 401]);

    // --- account B cannot claim the same username -----------------------------------------------
    const emailB = `username-b-${runId}@demo.localhost`;
    const passwordB = `pw-${runId}-username-b`;
    const accountB = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: emailB, display_name: "Username B", password: passwordB }),
    });
    const accountBId = (accountB.body as { id?: string })?.id;
    if (accountB.status !== 201 || accountBId === undefined) {
      return fail(`POST /v1/accounts B → ${accountB.status} ${text(accountB.body)}`);
    }
    const memberB = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountBId, role: "member" }),
    });
    checks.push(["the second account joined acme", memberB.status === 201]);

    const second = await signIn("second", emailB, passwordB);
    if (second?.cookie === undefined) return fail("the second sign-in set no session cookie");
    const cookieB = { cookie: `monaca_session=${second.cookie}` };

    const taken = await call(`${base}/t/${TENANT}/account`, {
      method: "PATCH",
      headers: { ...cookieB, "content-type": "application/json" },
      body: JSON.stringify({ username: `UNAME-${runId}` }),
    });
    checks.push([
      "a username another account holds is 409 MONACA_USERNAME_TAKEN",
      taken.status === 409 &&
        (taken.body as { monaca_error_code?: unknown })?.monaca_error_code === "MONACA_USERNAME_TAKEN",
    ]);

    const invalid = await call(`${base}/t/${TENANT}/account`, {
      method: "PATCH",
      headers: { ...cookieB, "content-type": "application/json" },
      body: JSON.stringify({ username: "a!" }),
    });
    checks.push(["an invalid username is 400", invalid.status === 400]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "13",
    title: "username identifiers",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: claim → username sign-in → email still works → unknown 401 → conflict 409 → invalid 400`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

function typeIdUuid(id: string): string {
  const alphabet = "0123456789abcdefghjkmnpqrstvwxyz";
  const suffix = id.slice(id.indexOf("_") + 1);
  let value = 0n;
  for (const symbol of suffix) {
    value = (value << 5n) | BigInt(alphabet.indexOf(symbol));
  }
  const hex = (value & ((1n << 128n) - 1n)).toString(16).padStart(32, "0");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

async function main(): Promise<number> {
  const parsed = parseArgs(process.argv.slice(2));
  if ("error" in parsed) {
    if (parsed.error === "__help__") {
      console.log(usage());
      return 0;
    }
    process.stderr.write(`${parsed.error}\n\n${usage()}\n`);
    return 2;
  }

  const normalised = normaliseBaseUrl(parsed.baseUrl);
  if (typeof normalised !== "string") {
    process.stderr.write(`${normalised.invalid}\n`);
    return 2;
  }
  const base = normalised;
  const startedAt = new Date();
  const t0 = performance.now();
  const quiet = parsed.json;

  if (!quiet) {
    console.log(`monaca e2e walk-through — ${base}`);
  }

  const steps: StepResult[] = [];
  const report: Report = {
    base_url: base,
    started_at: startedAt.toISOString(),
    finished_at: "",
    duration_ms: 0,
    stage: 1,
    ok: false,
    steps,
  };
  const push = (result: StepResult): void => {
    steps.push(result);
    if (!quiet) {
      const label = result.status === "pass" ? "pass" : result.status.toUpperCase();
      console.log(`  ${label}  ${result.step.padEnd(3)} ${result.title}${result.ms === undefined ? "" : ` (${result.ms} ms)`}  ${result.detail}`);
    }
  };

  // --- 1. health -----------------------------------------------------------------------------
  let healthDetail: string | undefined;
  let healthOk = false;
  let healthMs = 0;
  try {
    const t = performance.now();
    const res = await fetch(`${base}/healthz`, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
    });
    healthMs = Math.round(performance.now() - t);
    const body = await res.text();
    if (!res.ok) {
      healthDetail = `HTTP ${res.status} ${res.statusText} — ${truncate(body)}`;
    } else {
      let parsedBody: unknown;
      try {
        parsedBody = JSON.parse(body);
      } catch {
        healthDetail = `200 but the body is not JSON — ${truncate(body)}`;
      }
      if (parsedBody !== undefined) {
        const status = (parsedBody as { status?: unknown }).status;
        if (status === "ok") {
          healthOk = true;
          healthDetail = `200 {"status":"ok"} in ${healthMs} ms`;
        } else {
          healthDetail = `200 but status is ${JSON.stringify(status)}, expected "ok"`;
        }
      }
    }
  } catch (err) {
    healthMs = 0;
    healthDetail = describeNetError(err);
  }

  push({
    step: "1",
    title: "health",
    status: healthOk ? "pass" : "fail",
    ms: healthMs,
    detail: healthDetail,
  });

  if (!healthOk) {
    // Nothing else can run; the remaining steps are reported as skipped rather than failed.
    for (const step of ACCEPTANCE_STEPS.slice(1)) {
      steps.push({ step: step.step, title: step.title, status: "todo", detail: step.assertion });
    }
    report.ok = false;
    report.error = `health failed: ${base}/healthz — ${healthDetail}`;
    report.duration_ms = Math.round(performance.now() - t0);
    report.finished_at = new Date().toISOString();
    await writeReport(parsed.report, report);

    process.stderr.write(
      `\ne2e walk-through: cannot reach ${base}/healthz (${healthDetail}).\n` +
        `  mode a: is \`bun run dev\` running?  mode b: check MONACA_REMOTE_URL.  CI: check the server log.\n` +
        `  report: ${parsed.report}\n`,
    );
    return 1;
  }

  // --- 0. a management token (step 2's credential) -------------------------------------------
  const admin = await tokenCall(base, { grant_type: "client_credentials", scope: "monaca:admin" }, btoa(`${ADMIN_CLIENT_ID}:${parsed.adminSecret}`));
  const adminToken = (admin.body as { access_token?: string })?.access_token;
  if (admin.status !== 200 || adminToken === undefined) {
    for (const step of ACCEPTANCE_STEPS.slice(1)) {
      steps.push({ step: step.step, title: step.title, status: "todo", detail: step.assertion });
    }
    report.ok = false;
    report.error = `no management token: ${admin.status} ${text(admin.body)}`;
    report.duration_ms = Math.round(performance.now() - t0);
    report.finished_at = new Date().toISOString();
    await writeReport(parsed.report, report);
    process.stderr.write(
      `\ne2e walk-through: the seeded ${ADMIN_CLIENT_ID} client did not yield a token (${admin.status} ${text(admin.body)}).\n` +
        `  pass its secret with --admin-secret.\n`,
    );
    return 1;
  }

  const setupResult = await setup(base, adminToken, (line) => {
    if (!quiet) console.log(line);
  });
  push({
    step: "2",
    title: "setup",
    status: setupResult.ok ? "pass" : "fail",
    detail: setupResult.detail,
  });

  if (setupResult.walk === undefined) {
    report.ok = false;
    report.error = setupResult.detail;
    report.duration_ms = Math.round(performance.now() - t0);
    report.finished_at = new Date().toISOString();
    await writeReport(parsed.report, report);
    return 1;
  }

  const walk = setupResult.walk;
  if (setupResult.agentKey === undefined) {
    report.ok = false;
    report.error = "the setup step returned no key pair";
    report.duration_ms = Math.round(performance.now() - t0);
    report.finished_at = new Date().toISOString();
    await writeReport(parsed.report, report);
    return 1;
  }
  const grants = await tokenGrants(base, walk, setupResult.agentKey.sign);
  push(grants.step3);
  push(grants.step3b);

  const tools = await toolCalls(base, grants.accessToken);
  push(tools.step4);
  push(tools.step4b);

  push(await auditChain(base, adminToken, walk));
  push(await browserFlow(base, parsed.consoleSecret));
  push(await sessionFlow(base, parsed.consoleSecret, adminToken));
  push(await emailFlow(base, parsed.consoleSecret, parsed.internalSecret));
  push(await mfaFlow(base, adminToken, parsed.consoleSecret));
  push(await accountFlow(base, adminToken));
  push(await backupCodeFlow(base, adminToken, parsed.consoleSecret));
  push(await passkeyFlow(base, adminToken, parsed.consoleSecret));
  push(await usernameFlow(base, adminToken, parsed.consoleSecret));

  const failures = steps.filter((step) => step.status === "fail");
  report.ok = failures.length === 0;
  report.duration_ms = Math.round(performance.now() - t0);
  report.finished_at = new Date().toISOString();
  await writeReport(parsed.report, report);

  if (quiet) console.log(JSON.stringify(report, null, 2));
  else {
    const skipped = steps.filter((step) => step.status === "skip").length;
    console.log(
      `\n${report.ok ? "walk-through ok" : "walk-through FAILED"} (${report.duration_ms} ms, ${steps.length} steps` +
        `${skipped === 0 ? "" : `, ${skipped} skipped`}) — report: ${parsed.report}`,
    );
  }
  return report.ok ? 0 : 1;
}

function truncate(text: string, max = 200): string {
  const collapsed = text.replace(/\s+/g, " ").trim();
  return collapsed.length <= max ? collapsed : `${collapsed.slice(0, max)}…`;
}

try {
  process.exit(await main());
} catch (err) {
  process.stderr.write(`e2e skeleton: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
