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
    "  --report <path>        where to write the JSON report (default .monaca/reports/skeleton.json).",
    "  --json                 print only the report, not the human-readable lines.",
    "",
    "Steps 4 and 4b are reported as `skip` unless the origin mounts /mcp/demo (the gateway does;",
    "the bare server does not).",
  ].join("\n");
}

function parseArgs(argv: string[]): { baseUrl: string; report: string; json: boolean; adminSecret: string; consoleSecret: string } | { error: string } {
  let baseUrl: string | undefined;
  let report = REPORT;
  let json = false;
  let adminSecret = "dev-admin-client-secret";
  let consoleSecret = "dev-console-client-secret";
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
    } else if (arg === "--json") {
      json = true;
    } else if (arg === "--help" || arg === "-h") {
      return { error: "__help__" };
    } else {
      return { error: `unrecognised argument ${JSON.stringify(arg)}` };
    }
  }
  if (baseUrl === undefined || baseUrl.trim() === "") return { error: "--base-url is required" };
  return { baseUrl: baseUrl.trim(), report, json, adminSecret, consoleSecret };
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
