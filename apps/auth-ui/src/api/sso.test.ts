import { afterEach, describe, expect, test } from "bun:test";

import { findSsoConnector, ssoSignInUrl } from "./sso";

/**
 * Enterprise SSO routing (docs/contracts/m0.md §6.1).
 *
 * The page's only job is to ask the tenant which connector owns an address's domain, so these tests
 * pin the lookup's contract: one connector for a match, nothing for a non-address, a failed lookup
 * or an empty list — never a throw that would keep the ordinary form from rendering.
 */

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function respond(body: unknown, status = 200): void {
  globalThis.fetch = (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    })) as unknown as typeof fetch;
}

describe("findSsoConnector", () => {
  test("returns the connector that owns the address's domain", async () => {
    let requested = "";
    globalThis.fetch = (async (input: string | URL | Request) => {
      requested = String(input);
      return new Response(
        JSON.stringify({ items: [{ connector_id: "okta", display_name: "Acme Okta" }] }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as unknown as typeof fetch;

    expect(await findSsoConnector("demo", "User@Acme.Example")).toEqual({
      connector_id: "okta",
      display_name: "Acme Okta",
    });
    expect(requested).toContain("/t/demo/sso-connectors?email=");
    expect(requested).toContain(encodeURIComponent("User@Acme.Example"));
  });

  test("does not call the server for something that is not an address", async () => {
    globalThis.fetch = (async () => {
      throw new Error("must not be called");
    }) as unknown as typeof fetch;
    expect(await findSsoConnector("demo", "just-a-username")).toBe(null);
  });

  test("a failed or empty lookup leaves the ordinary form in place", async () => {
    respond({ items: [] });
    expect(await findSsoConnector("demo", "user@demo.localhost")).toBe(null);

    respond({}, 500);
    expect(await findSsoConnector("demo", "user@demo.localhost")).toBe(null);

    globalThis.fetch = (async () => {
      throw new Error("offline");
    }) as unknown as typeof fetch;
    expect(await findSsoConnector("demo", "user@demo.localhost")).toBe(null);
  });
});

describe("ssoSignInUrl", () => {
  test("names the connector and the interaction", () => {
    expect(ssoSignInUrl("demo", "okta", "int_abc")).toBe(
      "/t/demo/sso/okta/authorize?interaction=int_abc",
    );
  });
});
