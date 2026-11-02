import { describe, expect, test } from "bun:test";

import { InteractionError, getInteraction, navigateTo, startSignUp } from "./interaction";

/**
 * `navigateTo` is the one place the sign-in page acts on a value it received from the network. The
 * contract says it always points at the console's BFF callback; these tests pin the refusal of
 * anything else, because a cross-origin redirect here is a login-CSRF vector.
 */
describe("navigateTo", () => {
  const original = globalThis.window;

  function withWindow(origin: string, assign: (url: string) => void): void {
    // A minimal stand-in for the browser globals the function reads.
    (globalThis as { window?: unknown }).window = { location: { origin, assign } };
  }

  test("accepts a same-origin absolute URL", () => {
    let visited: string | undefined;
    withWindow("http://localhost:5174", (url) => (visited = url));

    navigateTo("http://localhost:5174/bff/callback?code=abc&state=xyz");
    expect(visited).toBe("http://localhost:5174/bff/callback?code=abc&state=xyz");
  });

  test("accepts a root-relative URL, resolved against the current origin", () => {
    let visited: string | undefined;
    withWindow("http://localhost:5174", (url) => (visited = url));

    navigateTo("/bff/callback?error=access_denied");
    expect(visited).toBe("http://localhost:5174/bff/callback?error=access_denied");
  });

  test("refuses a different origin", () => {
    withWindow("http://localhost:5174", () => {
      throw new Error("must not navigate");
    });

    expect(() => navigateTo("https://evil.example/bff/callback?code=abc")).toThrow(InteractionError);
    expect(() => navigateTo("https://evil.example/bff/callback")).toThrow(/another origin/);
  });

  test("refuses a different port on the same host", () => {
    withWindow("http://localhost:5174", () => {
      throw new Error("must not navigate");
    });
    expect(() => navigateTo("http://localhost:8080/bff/callback")).toThrow(InteractionError);
  });

  test("refuses a malformed redirect", () => {
    withWindow("http://localhost:5174", () => {
      throw new Error("must not navigate");
    });
    expect(() => navigateTo("http://[")).toThrow(InteractionError);
  });

  globalThis.window = original;
});

describe("startSignUp", () => {
  /**
   * The one-step shape exists only when the tenant turned email verification off. The page decides
   * that from the public switches, so the request it builds is the load-bearing part: a password or
   * profile field left out here silently becomes a two-step registration.
   */
  test("posts the whole profile to /sign-up and passes the sign-in result through", async () => {
    const original = globalThis.fetch;
    let seen: { url: string; init?: RequestInit } | undefined;
    globalThis.fetch = ((url: string, init?: RequestInit) => {
      seen = { url, init };
      return Promise.resolve(
        new Response(
          JSON.stringify({ redirect_to: "http://localhost:5174/bff/callback?code=abc&state=xyz" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      );
    }) as unknown as typeof fetch;

    const body = {
      email: "new@demo.localhost",
      password: "a-long-enough-password",
      username: "NewPerson",
      display_name: "New Person",
      avatar_url: "https://cdn.example/avatar.png",
    };
    const result = await startSignUp("demo", "int_01h455vb4pex5vsknk084sn02q", body);

    expect(result).toEqual({
      redirect_to: "http://localhost:5174/bff/callback?code=abc&state=xyz",
    });
    expect(seen?.url).toBe("/t/demo/interaction/int_01h455vb4pex5vsknk084sn02q/sign-up");
    expect(seen?.init?.method).toBe("POST");
    expect(JSON.parse(String(seen?.init?.body))).toEqual(body);

    globalThis.fetch = original;
  });
});

describe("InteractionError codes", () => {
  /**
   * A 5xx must not be reported as a malformed request. In dev the gateway may simply not be running,
   * and a proxy answers with a 500 and an HTML body — telling the user their request was malformed
   * would send them looking in the wrong place.
   */
  test("a server error maps to unreachable, not to a malformed request", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.resolve(new Response("<html>proxy error</html>", { status: 502 }))) as unknown as typeof fetch;

    const failure = await getInteraction("demo", "int_01h455vb4pex5vsknk084sn02q").catch(
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(InteractionError);
    expect((failure as InteractionError).code).toBe("MONACA_UNREACHABLE");

    globalThis.fetch = original;
  });

  test("a documented 410 maps to expired", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.resolve(
        new Response(JSON.stringify({ title: "Expired", status: 410, monaca_error_code: "MONACA_INTERACTION_EXPIRED" }), {
          status: 410,
          headers: { "Content-Type": "application/problem+json" },
        }),
      )) as unknown as typeof fetch;

    const failure = await getInteraction("demo", "int_01h455vb4pex5vsknk084sn02q").catch(
      (error: unknown) => error,
    );
    expect((failure as InteractionError).code).toBe("MONACA_INTERACTION_EXPIRED");

    globalThis.fetch = original;
  });

  test("the monaca_error_code wins over the status", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (() =>
      Promise.resolve(
        new Response(JSON.stringify({ title: "Nope", monaca_error_code: "MONACA_INTERACTION_CONSUMED" }), {
          status: 400,
        }),
      )) as unknown as typeof fetch;

    const failure = await getInteraction("demo", "int_01h455vb4pex5vsknk084sn02q").catch(
      (error: unknown) => error,
    );
    expect((failure as InteractionError).code).toBe("MONACA_INTERACTION_CONSUMED");

    globalThis.fetch = original;
  });
});
