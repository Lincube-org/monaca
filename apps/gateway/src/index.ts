/**
 * `@monaca/gateway` — the Hono-on-Bun gateway: module host, console BFF, JWKS sync, dev proxy
 * (contract §9, architecture §6).
 *
 * `createGateway()` is the library surface: it resolves configuration, wires the kernel (with
 * the demo MCP module mounted at `MONACA_MCP_DEMO_MOUNT`), registers the BFF and `/healthz`,
 * and returns a handle whose `listen()` boots the kernel, installs the native verifier after
 * the first JWKS sync, registers the dev proxy **last** (route order is part of the contract)
 * and serves on `MONACA_GATEWAY_ADDR`. `main.ts` is the thin runnable entry on top of it.
 *
 * Failure posture: before the first JWKS sync the kernel's verifier slot holds the kernel's
 * fail-closed "unavailable" verifier, so `/mcp/demo` answers 503 rather than letting anything
 * through unverified. A missing native binary (`MONACA_CORE_BINARY_MISSING`) keeps that
 * posture by design.
 */
import { Hono } from "hono";
import {
  createKernel,
  createLogger,
  parseLogLevel,
  type EnvLike,
  type Kernel,
  type Module,
} from "@monaca/kernel";
import { getConnInfo } from "hono/bun";
import { AUDIT_SINK_TOKEN, mcpDemoModule } from "@monaca/module-mcp-demo";
import type { ToolAuditSink } from "@monaca/mcp";
import { createHttpAuditSink } from "./audit.ts";
import { registerBffRoutes } from "./bff.ts";
import { resolveGatewayConfig, type GatewayConfig } from "./config.ts";
import { createJwksSyncer, loadNativeVerifier, type JwksSyncer } from "./jwks.ts";
import { forward } from "./proxy.ts";
import { SessionStore } from "./sessions.ts";

export interface GatewayOptions {
  /** Environment source; defaults to `process.env`. */
  readonly env?: EnvLike;
  /** Root Hono app; a fresh one is created when omitted. */
  readonly app?: Hono;
  /** Modules to host. Defaults to `[mcpDemoModule]`. */
  readonly modules?: readonly Module[];
  /** Audit sink override (tests); the default POSTs to the server's `/internal/audit`. */
  readonly auditSink?: ToolAuditSink;
  /** Set to `false` to skip the native verifier and the JWKS sync loop (tests). */
  readonly jwksSync?: boolean;
}

export interface Gateway {
  readonly app: Hono;
  readonly kernel: Kernel;
  readonly config: GatewayConfig;
  readonly sessions: SessionStore;
  /** Boots the kernel, installs the verifier, registers the dev proxy, and starts serving. */
  listen(): Promise<{ hostname: string; port: number }>;
  /** Stops the refresh timer, the sweeper, the server and the kernel, in that order. */
  close(): Promise<void>;
}

export function createGateway(options: GatewayOptions = {}): Gateway {
  const config = resolveGatewayConfig(options.env ?? process.env);
  const logger = createLogger({
    level: parseLogLevel(config.raw.get("MONACA_LOG_LEVEL")),
    format: config.raw.get("MONACA_LOG_FORMAT") === "json" ? "json" : "pretty",
    bindings: { service: "monaca-gateway" },
  });

  const app = options.app ?? new Hono();
  const kernel = createKernel({
    app,
    config: config.raw,
    logger,
    mountOverrides: { "mcp-demo": config.mcpDemoMount },
  });

  // The gateway is the side that knows the internal secret, so it owns the audit sink and
  // hands it to the module over the registry (§6.3, §9).
  kernel.registry.provide(AUDIT_SINK_TOKEN, options.auditSink ?? createHttpAuditSink({ config }));

  const sessions = new SessionStore(config.sessionTtlSecs);

  // Liveness first, then the BFF; module routes mount during boot; the dev proxy goes last.
  app.get("/healthz", (c) => c.json({ status: "ok", service: "monaca-gateway" }));
  registerBffRoutes(app, { config, sessions, logger });

  for (const module of options.modules ?? [mcpDemoModule]) kernel.register(module);

  let server: ReturnType<typeof Bun.serve> | undefined;
  let syncer: JwksSyncer | undefined;
  let listening = false;

  return {
    app,
    kernel,
    config,
    sessions,

    async listen(): Promise<{ hostname: string; port: number }> {
      if (listening) return { hostname: config.hostname, port: config.port };
      await kernel.boot();

      if (options.jwksSync !== false) {
        const native = await loadNativeVerifier(config.clockSkewSecs, logger);
        if (native !== undefined) {
          syncer = createJwksSyncer({
            serverUrl: config.serverUrl,
            tenant: config.mcpDemoTenant,
            internalSecret: config.internalSecret,
            issuer: `${config.publicBaseUrl}/t/${config.mcpDemoTenant}`,
            refreshSecs: config.jwksRefreshSecs,
            verifier: native,
            slot: kernel.verifier,
            logger,
          });
          // Best effort: a server that is not up yet leaves the guard fail-closed, and the
          // refresh loop keeps retrying until a sync succeeds.
          await syncer.syncOnce();
          syncer.start();
        }
      }

      if (config.devProxy) {
        // The dev proxy is registered last on purpose (§9): the module routes mounted by the
        // boot above — including `/.well-known/oauth-protected-resource/mcp/demo` — must win
        // over the prefix wildcards. `/internal/*` is never proxied: no prefix claims it.
        const target = new URL(config.serverUrl);
        for (const prefix of ["/t", "/v1", "/.well-known"]) {
          app.all(`${prefix}/*`, (c) => {
            const upstream = new URL(`${c.req.path}${new URL(c.req.url).search}`, target);
            // Append the peer this gateway saw. The server trusts the header only when the
            // immediate peer is in MONACA_TRUSTED_PROXY_CIDRS and reads the rightmost untrusted
            // hop, so a client-supplied prefix cannot choose its bucket.
            const peer = getConnInfo(c).remote.address;
            const forwarded = c.req.header("x-forwarded-for");
            const chain = [forwarded, peer].filter((value) => value !== undefined && value !== "").join(", ");
            return forward(c.req.raw, upstream, {
              // This is a transparent proxy for the browser's own session: `/t/*` sets and reads
              // `monaca_session`, so dropping the cookie would break every signed-in flow that
              // travels through the public origin.
              forwardCookie: true,
              extraHeaders: chain === "" ? undefined : { "x-forwarded-for": chain },
            });
          });
        }
        logger.info("dev proxy enabled", { prefixes: ["/t/*", "/v1/*", "/.well-known/*"], target: config.serverUrl });
      }

      sessions.startSweep();
      server = Bun.serve({ fetch: app.fetch, hostname: config.hostname, port: config.port });
      listening = true;
      logger.info("gateway listening", {
        url: `http://${config.hostname}:${config.port}`,
        env: config.env,
        modules: kernel.order.join(","),
      });
      return { hostname: config.hostname, port: config.port };
    },

    async close(): Promise<void> {
      syncer?.stop();
      syncer = undefined;
      sessions.stopSweep();
      server?.stop(true);
      server = undefined;
      listening = false;
      await kernel.stop();
      logger.info("gateway stopped");
    },
  };
}

export { resolveGatewayConfig, type GatewayConfig } from "./config.ts";
export { SessionStore } from "./sessions.ts";
export { buildToolAuditEvent, createHttpAuditSink, type AuditEvent } from "./audit.ts";
