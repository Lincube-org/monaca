import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createGateway, type Gateway } from "../src/index.ts";

/**
 * BFF integration against a stub of the Rust server: the whole login → session → API-rewrite
 * path runs against real HTTP, with the server's token endpoint, member list and `/v1` echo
 * standing in for `monaca-server`. The native verifier is out of the picture here (no `.node`
 * on this machine, and the BFF does not verify tokens — the server does, on `/v1`).
 */

const PUBLIC = "http://localhost:8080";
const CONSOLE = "http://localhost:5173";

interface Seen {
  method: string;
  path: string;
  search: string;
  authorization: string | null;
  body: string | null;
}

const seen: Seen[] = [];
let stub: ReturnType<typeof Bun.serve>;
let stubPort = 0;

function fakeJwt(payload: Record<string, unknown>): string {
  const encode = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "ES256", typ: "JWT" })}.${encode(payload)}.signature`;
}

beforeAll(() => {
  stub = Bun.serve({
    port: 0,
    fetch: async (request) => {
      const url = new URL(request.url);
      const entry: Seen = {
        method: request.method,
        path: url.pathname,
        search: url.search,
        authorization: request.headers.get("authorization"),
        body: request.method === "GET" || request.method === "HEAD" ? null : await request.text(),
      };
      seen.push(entry);

      if (url.pathname === "/t/demo/oauth2/token") {
        const params = new URLSearchParams(entry.body ?? "");
        const refresh = params.get("grant_type") === "refresh_token";
        return Response.json({
          access_token: refresh ? "at-refreshed" : "at-1",
          token_type: "Bearer",
          expires_in: refresh ? 900 : 900,
          refresh_token: "rt-1",
          id_token: fakeJwt({
            iss: "http://localhost:8080/t/demo",
            sub: "acc_00000000000000000000000001",
            aud: "monaca-console",
            tid: "ten_00000000000000000000000001",
            org: "org_00000000000000000000000001",
            email: "admin@demo.localhost",
            iat: 1767225600,
            exp: 1767226500,
          }),
          scope: "openid monaca:admin",
        });
      }
      if (url.pathname === "/v1/orgs/acme/members") {
        return Response.json({
          items: [
            { account_id: "acc_00000000000000000000000001", email: "admin@demo.localhost", role: "owner" },
            { account_id: "acc_someone_else", email: "other@demo.localhost", role: "member" },
          ],
          next: null,
        });
      }
      if (url.pathname.startsWith("/v1/")) {
        return Response.json({ ok: true, path: url.pathname, search: url.search });
      }
      return new Response("stub: not found", { status: 404 });
    },
  });
  stubPort = stub.port ?? 0;
});

afterAll(() => {
  stub.stop(true);
});

function makeGateway(): Gateway {
  return createGateway({
    env: {
      MONACA_SERVER_URL: `http://127.0.0.1:${stubPort}`,
      MONACA_PUBLIC_BASE_URL: PUBLIC,
      MONACA_CONSOLE_URL: CONSOLE,
      MONACA_LOG_LEVEL: "error",
    },
    jwksSync: false,
  });
}

/** Runs the full login: /bff/login → pre-created ticket → /bff/callback → session cookie. */
async function signIn(gateway: Gateway): Promise<{ cookie: string; sessionId: string }> {
  const login = await gateway.app.request(new Request(`${PUBLIC}/bff/login`));
  expect(login.status).toBe(302);
  const location = login.headers.get("location") ?? "";
  expect(location.startsWith(`${PUBLIC}/t/demo/oauth2/authorize?`)).toBe(true);

  const ticket = gateway.sessions.createTicket();
  const callback = await gateway.app.request(
    new Request(`${PUBLIC}/bff/callback?code=the-code&state=${encodeURIComponent(ticket.state)}`),
  );
  expect(callback.status).toBe(302);
  expect(callback.headers.get("location")).toBe(CONSOLE);
  const cookie = callback.headers.get("set-cookie") ?? "";
  expect(cookie.startsWith("monaca_session=")).toBe(true);
  expect(cookie).toContain("HttpOnly");
  expect(cookie).toContain("SameSite=Lax");
  expect(cookie).not.toContain("Secure"); // dev
  return { cookie, sessionId: cookie.split(";")[0]?.slice("monaca_session=".length) ?? "" };
}

describe("BFF login (contract §9)", () => {
  test("/bff/login redirects with PKCE, state, nonce and the management resource", async () => {
    const gateway = makeGateway();
    const res = await gateway.app.request(new Request(`${PUBLIC}/bff/login`));
    expect(res.status).toBe(302);
    const target = new URL(res.headers.get("location") ?? "");
    expect(target.origin + target.pathname).toBe(`${PUBLIC}/t/demo/oauth2/authorize`);
    const params = target.searchParams;
    expect(params.get("response_type")).toBe("code");
    expect(params.get("client_id")).toBe("monaca-console");
    expect(params.get("redirect_uri")).toBe(`${PUBLIC}/bff/callback`);
    expect(params.get("scope")).toContain("monaca:admin");
    expect(params.get("code_challenge_method")).toBe("S256");
    expect(params.get("code_challenge")).toMatch(/^[A-Za-z0-9-_]{43}$/);
    expect(params.get("state")).toBeTruthy();
    expect(params.get("nonce")).toBeTruthy();
    expect(params.get("resource")).toBe(`${PUBLIC}/v1`);
    expect(params.get("organization")).toBe("acme");
  });

  test("a bad state is refused 400 and leaves no session", async () => {
    const gateway = makeGateway();
    const res = await gateway.app.request(new Request(`${PUBLIC}/bff/callback?code=x&state=forged`));
    expect(res.status).toBe(400);
    expect((await res.json() as { monaca_error_code: string }).monaca_error_code).toBe("MONACA_LOGIN_STATE_INVALID");
    expect(gateway.sessions.size).toBe(0);
  });

  test("an authorize error redirects to the console without a session", async () => {
    const gateway = makeGateway();
    const res = await gateway.app.request(new Request(`${PUBLIC}/bff/callback?error=access_denied&state=x`));
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(CONSOLE);
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  test("a token-endpoint failure becomes 502", async () => {
    const gateway = makeGateway();
    const ticket = gateway.sessions.createTicket();
    // No stub route for a different tenant, so the exchange 404s.
    const broken = createGateway({
      env: {
        MONACA_SERVER_URL: `http://127.0.0.1:${stubPort}`,
        MONACA_PUBLIC_BASE_URL: PUBLIC,
        MONACA_CONSOLE_TENANT: "nope",
        MONACA_LOG_LEVEL: "error",
      },
      jwksSync: false,
    });
    void broken;
    const res = await gateway.app.request(
      new Request(`${PUBLIC}/bff/callback?code=c&state=${encodeURIComponent(ticket.state)}`),
    );
    // The demo tenant exists on the stub, so this succeeds; the 502 path is covered by the
    // tenant mismatch below.
    expect(res.status).toBe(302);

    const brokenTicket = broken.sessions.createTicket();
    const failed = await broken.app.request(
      new Request(`${PUBLIC}/bff/callback?code=c&state=${encodeURIComponent(brokenTicket.state)}`),
    );
    expect(failed.status).toBe(502);
    expect((await failed.json() as { monaca_error_code: string }).monaca_error_code).toBe("MONACA_TOKEN_EXCHANGE_FAILED");
  });
});

describe("BFF session and API rewrite", () => {
  test("sign-in creates a session; /bff/session and /bff/api/session both report it", async () => {
    const gateway = makeGateway();
    const { cookie } = await signIn(gateway);
    expect(gateway.sessions.size).toBe(1);

    for (const path of ["/bff/session", "/bff/api/session"]) {
      const res = await gateway.app.request(new Request(`${PUBLIC}${path}`, { headers: { cookie } }));
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({
        authenticated: true,
        account_id: "acc_00000000000000000000000001",
        email: "admin@demo.localhost",
        tenant: "demo",
        orgs: [{ slug: "acme", role: "owner" }],
        management: "none",
        roles: [],
        is_tenant_admin: false,
      });
    }

    const anonymous = await gateway.app.request(new Request(`${PUBLIC}/bff/session`));
    expect(await anonymous.json()).toEqual({
      authenticated: false,
      account_id: "",
      email: "",
      tenant: "demo",
      orgs: [],
      management: "none",
      roles: [],
      is_tenant_admin: false,
    });
  });

  test("/bff/api/* is rewritten to /v1/* with the session bearer", async () => {
    const gateway = makeGateway();
    const { cookie } = await signIn(gateway);
    seen.length = 0;

    const res = await gateway.app.request(
      new Request(`${PUBLIC}/bff/api/orgs/acme/agents?limit=50`, { headers: { cookie } }),
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, path: "/v1/orgs/acme/agents", search: "?limit=50" });

    const upstream = seen.at(-1);
    expect(upstream?.path).toBe("/v1/orgs/acme/agents");
    expect(upstream?.authorization).toBe("Bearer at-1");
    expect(upstream?.method).toBe("GET");
  });

  test("a POST body and content-type survive the rewrite", async () => {
    const gateway = makeGateway();
    const { cookie } = await signIn(gateway);
    seen.length = 0;

    const res = await gateway.app.request(
      new Request(`${PUBLIC}/bff/api/orgs/acme/members`, {
        method: "POST",
        headers: { cookie, "content-type": "application/json" },
        body: JSON.stringify({ account_id: "acc_x", role: "member" }),
      }),
    );
    expect(res.status).toBe(200);
    const upstream = seen.at(-1);
    expect(upstream?.method).toBe("POST");
    expect(JSON.parse(upstream?.body ?? "{}")).toEqual({ account_id: "acc_x", role: "member" });
  });

  test("no session → 401 problem+json; nothing reaches the server", async () => {
    const gateway = makeGateway();
    seen.length = 0;
    const res = await gateway.app.request(new Request(`${PUBLIC}/bff/api/orgs/acme/members`));
    expect(res.status).toBe(401);
    expect((await res.json() as { monaca_error_code: string }).monaca_error_code).toBe("MONACA_UNAUTHENTICATED");
    expect(seen).toHaveLength(0);
  });

  test("a token inside the 30 s refresh window is refreshed first", async () => {
    const gateway = makeGateway();
    const { cookie, sessionId } = await signIn(gateway);
    const session = gateway.sessions.get(sessionId);
    expect(session).toBeDefined();
    session!.tokens = { accessToken: "at-stale", refreshToken: "rt-1", expiresAt: Date.now() + 5_000 };
    seen.length = 0;

    const res = await gateway.app.request(new Request(`${PUBLIC}/bff/api/orgs/acme/agents`, { headers: { cookie } }));
    expect(res.status).toBe(200);
    const refresh = seen.find((entry) => entry.path === "/t/demo/oauth2/token");
    expect(refresh).toBeDefined();
    const form = new URLSearchParams(refresh?.body ?? "");
    expect(form.get("grant_type")).toBe("refresh_token");
    expect(form.get("refresh_token")).toBe("rt-1");
    expect(seen.at(-1)?.authorization).toBe("Bearer at-refreshed");
  });

  test("a session with no refresh token cannot slide past expiry → 401", async () => {
    const gateway = makeGateway();
    const { cookie, sessionId } = await signIn(gateway);
    gateway.sessions.get(sessionId)!.tokens = { accessToken: "at-stale", expiresAt: Date.now() - 1_000 };
    const res = await gateway.app.request(new Request(`${PUBLIC}/bff/api/orgs/acme/members`, { headers: { cookie } }));
    expect(res.status).toBe(401);
    expect((await res.json() as { monaca_error_code: string }).monaca_error_code).toBe("MONACA_UNAUTHENTICATED");
    // The dead session is gone.
    expect(gateway.sessions.get(sessionId)).toBeUndefined();
  });

  test("/bff/logout clears the session and the cookie", async () => {
    const gateway = makeGateway();
    const { cookie, sessionId } = await signIn(gateway);
    const res = await gateway.app.request(new Request(`${PUBLIC}/bff/logout`, { method: "POST", headers: { cookie } }));
    expect(res.status).toBe(204);
    expect(res.headers.get("set-cookie")).toContain("Max-Age=0");
    expect(gateway.sessions.get(sessionId)).toBeUndefined();

    const after = await gateway.app.request(new Request(`${PUBLIC}/bff/session`, { headers: { cookie } }));
    expect((await after.json() as { authenticated: boolean }).authenticated).toBe(false);
  });
});

describe("gateway surface", () => {
  test("/healthz answers the contract payload without a session", async () => {
    const gateway = makeGateway();
    const res = await gateway.app.request(new Request(`${PUBLIC}/healthz`));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok", service: "monaca-gateway" });
  });

  test("the demo module is mounted and its guard rejects unauthenticated MCP calls", async () => {
    // The module routes only exist after boot, which `listen()` performs (on an ephemeral port).
    const gateway = createGateway({
      env: {
        MONACA_SERVER_URL: `http://127.0.0.1:${stubPort}`,
        MONACA_PUBLIC_BASE_URL: PUBLIC,
        MONACA_GATEWAY_ADDR: "127.0.0.1:0",
        MONACA_LOG_LEVEL: "error",
      },
      jwksSync: false,
    });
    try {
      await gateway.listen();
      const res = await gateway.app.request(
        new Request(`${PUBLIC}/mcp/demo`, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_notes" } }),
        }),
      );
      // No native verifier on this machine: fail-closed, but authentication is checked first.
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toBe(
        'Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource/mcp/demo"',
      );
    } finally {
      await gateway.close();
    }
  });

  test("close() stops the kernel cleanly", async () => {
    const gateway = createGateway({
      env: { MONACA_GATEWAY_ADDR: "127.0.0.1:0", MONACA_LOG_LEVEL: "error" },
      jwksSync: false,
    });
    await gateway.listen();
    expect(gateway.kernel.state).toBe("running");
    await gateway.close();
    expect(gateway.kernel.state).toBe("stopped");
  });
});
