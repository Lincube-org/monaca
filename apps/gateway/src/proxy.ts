/**
 * Upstream request forwarding, shared by the BFF `/bff/api/*` rewrite and the dev proxy.
 *
 * Bodies are streamed, never buffered: a management-API download or upload must not sit in
 * gateway memory. Hop-by-hop headers are dropped, and `host` is left to `fetch` (it derives it
 * from the upstream URL). An unreachable upstream becomes a 502 problem+json.
 */
import { problemResponse } from "@monaca/mcp";

const HOP_BY_HOP_HEADERS = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
] as const;

// `authorization` is deliberately **not** in that list, and it is deliberately not deleted below.
// The token endpoint authenticates clients with HTTP Basic (`client_secret_basic`, §6.1) and with
// `private_key_jwt`, so stripping it here would make every client-authenticated request fail the
// moment it travels through the public origin — which is where they all travel in dev. Browser
// credentials are what must not leak, and `cookie` is still deleted; the BFF's `/bff/api/*`
// rewrite sets its own bearer afterwards, so a header a browser sent cannot win there either.

/** Headers to send upstream: the request's own, minus hop-by-hop ones and browser credentials. */
export function upstreamHeaders(request: Request, extra?: Record<string, string>): Headers {
  const headers = new Headers(request.headers);
  for (const name of HOP_BY_HOP_HEADERS) headers.delete(name);
  headers.delete("cookie");
  for (const [name, value] of Object.entries(extra ?? {})) headers.set(name, value);
  return headers;
}

function hasBody(method: string): boolean {
  return method !== "GET" && method !== "HEAD";
}

/** Forwards `request` to `url` and relays the upstream response verbatim (streamed). */
export async function forward(request: Request, url: URL, extraHeaders?: Record<string, string>): Promise<Response> {
  let upstream: Response;
  try {
    upstream = await fetch(url, {
      method: request.method,
      headers: upstreamHeaders(request, extraHeaders),
      body: hasBody(request.method) ? request.body : undefined,
      redirect: "manual",
      // A streamed request body requires half-duplex mode (undici/Bun fetch semantics).
      duplex: "half",
    });
  } catch {
    // The upstream is unreachable (server not started, network cut): that is a bad gateway,
    // not an internal error, and it must not spray a raw stack trace into the log.
    return problemResponse({
      code: "MONACA_UPSTREAM_UNAVAILABLE",
      status: 502,
      title: "Upstream unavailable",
      detail: "The gateway could not reach the Monaca server.",
    });
  }
  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: upstream.headers,
  });
}
