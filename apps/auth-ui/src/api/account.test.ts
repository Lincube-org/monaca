import { afterEach, describe, expect, test } from "bun:test";

import { AccountError, listAuthorizedApps, revokeAuthorizedApp } from "./account";

/**
 * The account centre's authorized-applications calls (docs/contracts/m0.md §6.1 consent).
 *
 * The page lists what the wire returns and withdraws by the application's public `client_id`;
 * these tests pin that path and method so a rename on either side shows up as a failing call.
 */

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

interface Call {
  url: string;
  init: RequestInit | undefined;
}

function respond(body: unknown, status = 200): { calls: Call[] } {
  const calls: Call[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(input), init });
    return new Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return { calls };
}

describe("listAuthorizedApps", () => {
  test("lists the account's approvals under the tenant's account base", async () => {
    const items = [
      {
        client_id: "acme-notes",
        name: "Acme Notes",
        scopes: ["openid", "profile"],
        granted_at: "2026-01-02T03:04:05Z",
        updated_at: "2026-01-02T03:04:05Z",
      },
    ];
    const { calls } = respond({ items, next: null });

    expect(await listAuthorizedApps("demo")).toEqual({ items, next: null });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("/t/demo/account/authorized-apps");
    expect(calls[0]?.init?.method).toBeUndefined();
    expect(calls[0]?.init?.credentials).toBe("same-origin");
  });
});

describe("revokeAuthorizedApp", () => {
  test("deletes the grant by client id and treats the empty 204 as done", async () => {
    const { calls } = respond(undefined, 204);

    expect(await revokeAuthorizedApp("demo", "acme/notes")).toBeUndefined();
    expect(calls[0]?.url).toBe("/t/demo/account/authorized-apps/acme%2Fnotes");
    expect(calls[0]?.init?.method).toBe("DELETE");
  });

  test("surfaces the server's detail when the grant is already gone", async () => {
    respond({ title: "Not Found", detail: "no approval for this application" }, 404);

    const failure = (await revokeAuthorizedApp("demo", "acme-notes").catch(
      (error: unknown) => error,
    )) as AccountError;
    expect(failure).toBeInstanceOf(AccountError);
    expect(failure.status).toBe(404);
    expect(failure.message).toBe("no approval for this application");
  });
});
