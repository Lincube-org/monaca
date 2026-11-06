/**
 * The console BFF (contract §9).
 *
 * The browser never holds a token: it holds one opaque HttpOnly session cookie. The gateway
 * keeps the account's access/refresh tokens in memory, signs the user in through the
 * authorization-code + PKCE flow against the server's protocol endpoints, and rewrites
 * `/bff/api/*` to the server's `/v1/*` with the session's bearer attached — refreshing it
 * first when it expires within 30 s.
 *
 * Route order matters: `/bff/session` and `/bff/api/session` (the path the console's client
 * actually calls, `apps/console/src/api/client.ts`) are registered before the `/bff/api/*`
 * catch-all so the rewrite never turns them into `/v1/session`.
 */
import type { Context, Hono } from "hono";
import type { Logger } from "@monaca/kernel";
import { problemResponse } from "@monaca/mcp";
import { forward } from "./proxy.ts";
import type { GatewayConfig } from "./config.ts";
import {
  clearSessionCookie,
  readCookie,
  serializeSessionCookie,
  type BffOrg,
  type BffRole,
  type BffSession,
  type ManagementTier,
  type SessionStore,
} from "./sessions.ts";

/** Refresh the access token this long before it actually expires (§9). */
const REFRESH_WINDOW_MS = 30 * 1000;
const UPSTREAM_TIMEOUT_MS = 10 * 1000;

export interface BffDeps {
  readonly config: GatewayConfig;
  readonly sessions: SessionStore;
  readonly logger: Logger;
}

/** Thrown when a `/bff/api/*` request has no usable session; turned into a 401. */
class UnauthenticatedError extends Error {}

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

function base64UrlJson(segment: string | undefined): Record<string, unknown> | undefined {
  if (segment === undefined) return undefined;
  try {
    const parsed: unknown = JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

/** Decodes an id_token payload. The token came over a direct server hop; claims are read, not re-verified. */
function decodeIdToken(idToken: string | undefined): { accountId: string; email: string } | undefined {
  const claims = decodeJwtPayload(idToken);
  const accountId = claims?.sub;
  if (typeof accountId !== "string" || accountId === "") return undefined;
  const email = claims?.email;
  return { accountId, email: typeof email === "string" ? email : "" };
}

function decodeJwtPayload(token: string | undefined): Record<string, unknown> | undefined {
  if (token === undefined) return undefined;
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  return base64UrlJson(parts[1]);
}

/** One token-endpoint call; the console client authenticates with `client_secret_basic` (§5.7). */
async function tokenRequest(
  deps: BffDeps,
  params: Record<string, string>,
): Promise<{ ok: true; body: TokenResponse } | { ok: false; status: number; body: string }> {
  const { config } = deps;
  const basic = Buffer.from(`${config.consoleClientId}:${config.consoleClientSecret}`).toString("base64");
  try {
    const response = await fetch(new URL(`/t/${encodeURIComponent(config.tenant)}/oauth2/token`, config.serverUrl), {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${basic}`,
        accept: "application/json",
      },
      body: new URLSearchParams(params).toString(),
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });
    const text = await response.text();
    if (!response.ok) return { ok: false, status: response.status, body: text };
    return { ok: true, body: JSON.parse(text) as TokenResponse };
  } catch (error) {
    return { ok: false, status: 0, body: error instanceof Error ? error.message : String(error) };
  }
}

/**
 * The orgs the console shows. §6.2 has no "my orgs" endpoint, so the BFF looks the signed-in
 * account up in the tenant's default org's member list; a failed lookup degrades to an empty
 * list (the console renders "No organizations") rather than failing the sign-in.
 */
async function lookupOwnOrgs(deps: BffDeps, accessToken: string, accountId: string): Promise<BffOrg[]> {
  const { config } = deps;
  try {
    const response = await fetch(
      new URL(`/v1/orgs/${encodeURIComponent(config.bffDefaultOrg)}/members`, config.serverUrl),
      {
        headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
        signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
      },
    );
    if (!response.ok) {
      deps.logger.warn("bff: membership lookup failed", { status: response.status });
      return [];
    }
    const page = (await response.json()) as { items?: { account_id?: string; role?: string }[] };
    const mine = (page.items ?? []).find((item) => item.account_id === accountId);
    if (mine === undefined) return [];
    return [{ slug: config.bffDefaultOrg, role: mine.role ?? "member" }];
  } catch (error) {
    deps.logger.warn("bff: membership lookup error", { error: error instanceof Error ? error.message : String(error) });
    return [];
  }
}

interface MeResponse {
  management?: unknown;
  roles?: unknown;
  is_tenant_admin?: unknown;
}

/**
 * The signed-in account's current management tier and roles (§6.2 `/v1/me`).
 *
 * The console uses this to hide write controls a read-only operator cannot use. A failed lookup
 * falls back to the most restrictive tier: the server still rejects every mutation, so a stale
 * gateway must not pretend the caller can write.
 */
async function lookupMe(
  deps: BffDeps,
  accessToken: string,
): Promise<{ management: ManagementTier; roles: BffRole[]; isTenantAdmin: boolean }> {
  const { config } = deps;
  try {
    const response = await fetch(new URL("/v1/me", config.serverUrl), {
      headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });
    if (!response.ok) {
      deps.logger.warn("bff: /v1/me lookup failed", { status: response.status });
      return { management: "none", roles: [], isTenantAdmin: false };
    }
    const body = (await response.json()) as MeResponse;
    const management: ManagementTier =
      body.management === "read" || body.management === "write" || body.management === "full"
        ? body.management
        : "none";
    const roles = Array.isArray(body.roles)
      ? (body.roles as BffRole[]).filter(
          (role) =>
            typeof role === "object" &&
            role !== null &&
            typeof role.id === "string" &&
            typeof role.name === "string" &&
            Array.isArray(role.permissions),
        )
      : [];
    return { management, roles, isTenantAdmin: body.is_tenant_admin === true };
  } catch (error) {
    deps.logger.warn("bff: /v1/me lookup error", {
      error: error instanceof Error ? error.message : String(error),
    });
    return { management: "none", roles: [], isTenantAdmin: false };
  }
}

function currentSession(c: Context, deps: BffDeps): BffSession | undefined {
  const id = readCookie(c.req.header("cookie"), deps.config.sessionCookieName);
  return deps.sessions.get(id);
}

function redirect(location: string, setCookie?: string): Response {
  const headers: Record<string, string> = { location };
  if (setCookie !== undefined) headers["set-cookie"] = setCookie;
  return new Response(null, { status: 302, headers });
}

function problem(status: number, code: string, title: string, detail?: string): Response {
  return problemResponse({ code, status, title, detail });
}

/** Refreshes the access token when it expires inside the 30 s window; throws when the session is dead. */
async function ensureFreshToken(session: BffSession, deps: BffDeps): Promise<void> {
  if (session.tokens.expiresAt - Date.now() > REFRESH_WINDOW_MS) return;
  const { refreshToken } = session.tokens;
  // A session that cannot refresh is dead: drop it so the next request starts clean.
  if (refreshToken === undefined) {
    deps.sessions.destroy(session.id);
    throw new UnauthenticatedError("no refresh token");
  }

  const result = await tokenRequest(deps, {
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: deps.config.consoleClientId,
  });
  if (!result.ok) {
    deps.logger.warn("bff: token refresh rejected", { status: result.status });
    deps.sessions.destroy(session.id);
    throw new UnauthenticatedError("refresh rejected");
  }
  session.tokens = {
    accessToken: result.body.access_token,
    refreshToken: result.body.refresh_token ?? refreshToken,
    expiresAt: Date.now() + result.body.expires_in * 1000,
  };
}

export function registerBffRoutes(app: Hono, deps: BffDeps): void {
  const { config, sessions, logger } = deps;

  // --- sign-in --------------------------------------------------------------------------------

  app.get("/bff/login", () => {
    const ticket = sessions.createTicket();
    const params = new URLSearchParams({
      response_type: "code",
      client_id: config.consoleClientId,
      redirect_uri: config.consoleRedirectUri,
      scope: config.consoleScopes,
      state: ticket.state,
      nonce: ticket.nonce,
      code_challenge: ticket.codeChallenge,
      code_challenge_method: "S256",
      // The console manages one org; the Monaca extension pins it (§6.1).
      organization: config.bffDefaultOrg,
      // The BFF asks for a token whose audience is the management API (§6.2).
      resource: `${config.publicBaseUrl}/v1`,
    });
    logger.debug("bff: login redirect", { tenant: config.tenant });
    return redirect(`${config.publicBaseUrl}/t/${encodeURIComponent(config.tenant)}/oauth2/authorize?${params}`);
  });

  app.get("/bff/callback", async (c) => {
    const url = new URL(c.req.url);
    const error = url.searchParams.get("error");
    if (error !== null) {
      logger.warn("bff: authorize failed", { error });
      return redirect(config.consoleUrl);
    }

    const ticket = sessions.consumeTicket(url.searchParams.get("state"));
    const code = url.searchParams.get("code");
    if (ticket === undefined || code === null) {
      // An unknown state is a possible login-CSRF attempt; refuse without a session.
      return problem(400, "MONACA_LOGIN_STATE_INVALID", "Invalid login state", "Start the sign-in again from /bff/login.");
    }

    const exchanged = await tokenRequest(deps, {
      grant_type: "authorization_code",
      code,
      redirect_uri: config.consoleRedirectUri,
      client_id: config.consoleClientId,
      code_verifier: ticket.codeVerifier,
    });
    if (!exchanged.ok) {
      logger.warn("bff: code exchange rejected", { status: exchanged.status });
      return problem(502, "MONACA_TOKEN_EXCHANGE_FAILED", "Token exchange failed", "The server refused the authorization code.");
    }

    const identity = decodeIdToken(exchanged.body.id_token);
    if (identity === undefined) {
      logger.warn("bff: token response carried no usable id_token");
      return problem(502, "MONACA_TOKEN_EXCHANGE_FAILED", "Token exchange failed", "The server response carried no id_token.");
    }

    const orgs = await lookupOwnOrgs(deps, exchanged.body.access_token, identity.accountId);
    const me = await lookupMe(deps, exchanged.body.access_token);
    const session = sessions.createSession({
      tenant: config.tenant,
      accountId: identity.accountId,
      email: identity.email,
      orgs,
      management: me.management,
      roles: me.roles,
      isTenantAdmin: me.isTenantAdmin,
      tokens: {
        accessToken: exchanged.body.access_token,
        refreshToken: exchanged.body.refresh_token,
        expiresAt: Date.now() + exchanged.body.expires_in * 1000,
      },
    });

    logger.info("bff: session created", { account_id: session.accountId, orgs: orgs.map((o) => o.slug) });
    return redirect(
      config.consoleUrl,
      serializeSessionCookie({
        name: config.sessionCookieName,
        value: session.id,
        maxAgeSecs: config.sessionTtlSecs,
        secure: config.sessionSecureCookie,
      }),
    );
  });

  // --- sign-out -------------------------------------------------------------------------------

  app.post("/bff/logout", (c) => {
    const id = readCookie(c.req.header("cookie"), config.sessionCookieName);
    sessions.destroy(id);
    logger.debug("bff: logout", { had_session: id !== undefined });
    return new Response(null, {
      status: 204,
      headers: { "set-cookie": clearSessionCookie(config.sessionCookieName, config.sessionSecureCookie) },
    });
  });

  // --- session --------------------------------------------------------------------------------
  // The contract's path and the console client's actual path both land here (§9 vs.
  // apps/console/src/api/client.ts, which prefixes every call with /bff/api).

  const sessionPayload = (session: BffSession | undefined) => ({
    authenticated: session !== undefined,
    account_id: session?.accountId ?? "",
    email: session?.email ?? "",
    tenant: config.tenant,
    orgs: session?.orgs ?? [],
    management: session?.management ?? "none",
    roles: session?.roles ?? [],
    is_tenant_admin: session?.isTenantAdmin ?? false,
  });

  app.get("/bff/session", (c) => c.json(sessionPayload(currentSession(c, deps))));
  app.get("/bff/api/session", (c) => c.json(sessionPayload(currentSession(c, deps))));

  // --- management API rewrite ------------------------------------------------------------------

  app.all("/bff/api/*", async (c) => {
    let session: BffSession | undefined;
    try {
      session = currentSession(c, deps);
      if (session === undefined) throw new UnauthenticatedError("no session");
      await ensureFreshToken(session, deps);
    } catch (error) {
      if (error instanceof UnauthenticatedError) {
        return problem(401, "MONACA_UNAUTHENTICATED", "Not signed in", "The BFF session is missing or expired.");
      }
      throw error;
    }

    const rest = c.req.path.slice("/bff/api".length);
    const search = new URL(c.req.url).search;
    const upstream = new URL(`/v1${rest}${search}`, config.serverUrl);
    logger.debug("bff: api rewrite", { path: c.req.path, upstream: upstream.pathname });
    return forward(c.req.raw, upstream, { authorization: `Bearer ${session.tokens.accessToken}` });
  });
}
