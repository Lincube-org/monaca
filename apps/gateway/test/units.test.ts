import { describe, expect, test } from "bun:test";
import { resolveGatewayConfig } from "../src/config.ts";
import { upstreamHeaders } from "../src/proxy.ts";
import { pkceChallenge, readCookie, clearSessionCookie, serializeSessionCookie, SessionStore } from "../src/sessions.ts";
import { encodeTypeIdSuffix, newTypedId, uuidv7 } from "../src/typed-id.ts";
import { buildToolAuditEvent } from "../src/audit.ts";
import type { ToolAuditRecord } from "@monaca/mcp";

describe("resolveGatewayConfig (contract §2.2)", () => {
  test("dev defaults", () => {
    const config = resolveGatewayConfig({});
    expect(config.env).toBe("dev");
    expect(config.hostname).toBe("127.0.0.1");
    expect(config.port).toBe(8080);
    expect(config.publicBaseUrl).toBe("http://localhost:8080");
    expect(config.serverUrl).toBe("http://127.0.0.1:8081");
    expect(config.sessionCookieName).toBe("monaca_session");
    expect(config.sessionSecureCookie).toBe(false);
    expect(config.devProxy).toBe(false);
    expect(config.mcpDemoMount).toBe("/mcp/demo");
    expect(config.mcpDemoResource).toBe("http://localhost:8080/mcp/demo");
    expect(config.mcpDemoOrg).toBe("acme");
    expect(config.bffDefaultOrg).toBe("acme");
    expect(config.sessionTtlSecs).toBe(28_800);
  });

  test("MONACA_ENV=prod switches to the __Host- cookie and Secure", () => {
    const config = resolveGatewayConfig({ MONACA_ENV: "prod" });
    expect(config.sessionCookieName).toBe("__Host-monaca_session");
    expect(config.sessionSecureCookie).toBe(true);
  });

  test("MONACA_GATEWAY_ADDR is parsed host:port; an empty string falls back", () => {
    expect(resolveGatewayConfig({ MONACA_GATEWAY_ADDR: "0.0.0.0:9090" })).toMatchObject({ hostname: "0.0.0.0", port: 9090 });
    expect(resolveGatewayConfig({ MONACA_GATEWAY_ADDR: "" }).port).toBe(8080);
    expect(() => resolveGatewayConfig({ MONACA_GATEWAY_ADDR: "127.0.0.1:not-a-port" })).toThrow(/MONACA_GATEWAY_ADDR/);
  });

  test("MONACA_ENV rejects unknown values; booleans and ints are validated", () => {
    expect(() => resolveGatewayConfig({ MONACA_ENV: "staging" })).toThrow(/MONACA_ENV/);
    expect(resolveGatewayConfig({ MONACA_DEV_PROXY: "1" }).devProxy).toBe(true);
    expect(() => resolveGatewayConfig({ MONACA_SESSION_TTL_SECS: "soon" })).toThrow(/integer/);
  });
});

describe("upstreamHeaders (gateway proxy)", () => {
  const request = (headers: Record<string, string>) =>
    new Request("http://localhost:8080/t/demo/account", { headers });

  test("drops the browser cookie and hop-by-hop headers by default", () => {
    const headers = upstreamHeaders(
      request({
        cookie: "monaca_session=abc",
        authorization: "Bearer token",
        connection: "keep-alive",
        host: "localhost:8080",
      }),
    );
    expect(headers.get("cookie")).toBeNull();
    expect(headers.get("authorization")).toBe("Bearer token");
    expect(headers.get("connection")).toBeNull();
    expect(headers.get("host")).toBeNull();
  });

  test("forwards the cookie when the dev proxy asks", () => {
    const headers = upstreamHeaders(request({ cookie: "monaca_session=abc" }), {
      forwardCookie: true,
    });
    expect(headers.get("cookie")).toBe("monaca_session=abc");
  });

  test("extra headers are set after the cookie rule", () => {
    const headers = upstreamHeaders(request({ cookie: "browser=1" }), {
      extraHeaders: { authorization: "Bearer gateway" },
    });
    expect(headers.get("cookie")).toBeNull();
    expect(headers.get("authorization")).toBe("Bearer gateway");
  });
});

describe("SessionStore", () => {
  test("tickets are single-use and unknown states are refused", () => {
    const store = new SessionStore(28_800);
    const ticket = store.createTicket();
    expect(store.consumeTicket(ticket.state)?.codeVerifier).toBe(ticket.codeVerifier);
    expect(store.consumeTicket(ticket.state)).toBeUndefined();
    expect(store.consumeTicket(null)).toBeUndefined();
    expect(store.consumeTicket("never-issued")).toBeUndefined();
  });

  test("sessions expire past their TTL; get() evicts, sweep() evicts without a reader", () => {
    const store = new SessionStore(0); // everything is born expired
    const session = store.createSession({
      tenant: "demo",
      accountId: "acc_1",
      email: "a@b.c",
      orgs: [],
      management: "full",
      roles: [],
      isTenantAdmin: true,
      tokens: { accessToken: "at", expiresAt: Date.now() + 60_000 },
    });
    expect(store.get(session.id)).toBeUndefined();
    expect(store.size).toBe(0);

    store.createSession({
      tenant: "demo",
      accountId: "acc_2",
      email: "d@e.f",
      orgs: [],
      management: "read",
      roles: [],
      isTenantAdmin: false,
      tokens: { accessToken: "at", expiresAt: Date.now() + 60_000 },
    });
    expect(store.size).toBe(1);
    store.sweep();
    expect(store.size).toBe(0);
  });

  test("PKCE S256 matches the RFC 7636 appendix B vector", () => {
    expect(pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });
});

describe("cookies (contract §9)", () => {
  test("session cookie attributes", () => {
    const cookie = serializeSessionCookie({ name: "monaca_session", value: "abc", maxAgeSecs: 28_800, secure: false });
    expect(cookie).toBe("monaca_session=abc; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800");
    const secure = serializeSessionCookie({ name: "__Host-monaca_session", value: "abc", maxAgeSecs: 1, secure: true });
    expect(secure).toContain("Secure");
    expect(secure).toContain("Max-Age=1");
  });

  test("clear and read", () => {
    expect(clearSessionCookie("monaca_session", false)).toBe("monaca_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    expect(readCookie("other=1; monaca_session=xyz; more=2", "monaca_session")).toBe("xyz");
    expect(readCookie(undefined, "monaca_session")).toBeUndefined();
    expect(readCookie("other=1", "monaca_session")).toBeUndefined();
  });
});

describe("typed ids (§5.2)", () => {
  test("uuidv7 has the version and variant bits set", () => {
    const uuid = uuidv7(1_767_225_600_000);
    expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  test("evt ids are 26 Crockford base32 symbols", () => {
    expect(newTypedId("evt")).toMatch(/^evt_[0-9abcdefghjkmnpqrstvwxyz]{26}$/);
  });

  test("non-UUID input is rejected", () => {
    expect(() => encodeTypeIdSuffix("not-a-uuid")).toThrow(/32-hex-digit/);
  });
});

describe("buildToolAuditEvent (§8.1)", () => {
  const token = {
    iss: "http://localhost:8080/t/demo",
    sub: "acc_00000000000000000000000001",
    aud: "http://localhost:8080/mcp/demo",
    tid: "ten_00000000000000000000000001",
    org: "org_00000000000000000000000001",
    scope: ["tools:read"],
    act: { sub: "agt_00000000000000000000000001" },
    grantId: "grt_00000000000000000000000001",
    jti: "01920000-0000-7000-8000-000000000001",
    iat: 1767225600,
    exp: 1767225900,
  };

  test("an allowed call becomes tool.invoked with the full actor chain", () => {
    const record: ToolAuditRecord = {
      action: "tool.invoked",
      decision: "allow",
      tool: "list_notes",
      requiredScopes: ["tools:read"],
      token,
    };
    const event = buildToolAuditEvent(record, 1_767_225_600_000);
    expect(event.id).toMatch(/^evt_[0-9abcdefghjkmnpqrstvwxyz]{26}$/);
    expect(event.at).toBe("2026-01-01T00:00:00.000Z");
    expect(event.action).toBe("tool.invoked");
    expect(event.actor_chain).toEqual([
      { type: "account", id: token.sub },
      { type: "agent", id: "agt_00000000000000000000000001" },
    ]);
    expect(event.subject).toEqual({ type: "tool", id: "list_notes" });
    expect(event.decision).toBe("allow");
    expect(event.grant_id).toBe(token.grantId);
    expect(event.jti).toBe(token.jti);
    expect(event.payload).toEqual({ scope: ["tools:read"], aud: token.aud, required_scopes: ["tools:read"] });
  });

  test("a denied call carries the reason; an undelegated token has no grant_id", () => {
    const { grantId: _grantId, act: _act, ...plain } = token;
    void _grantId;
    void _act;
    const event = buildToolAuditEvent(
      {
        action: "tool.denied",
        decision: "deny",
        tool: "delete_note",
        requiredScopes: ["tools:write"],
        reason: "insufficient_scope",
        token: plain,
      },
      1_767_225_600_000,
    );
    expect(event.actor_chain).toEqual([{ type: "account", id: token.sub }]);
    expect("grant_id" in event).toBe(false);
    expect(event.payload).toMatchObject({ reason: "insufficient_scope" });
  });
});
