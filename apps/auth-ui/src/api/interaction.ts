/**
 * The interaction API (docs/contracts/m0.md §6.1).
 *
 * This is the Hydra-style handshake: the protocol engine has already decided *what* is being asked
 * for, and hands the browser a single-use `int_…` id that this page exchanges for a redirect. The
 * interaction id *is* the bearer of the request — high entropy and single use — so it travels in the
 * URL path and nowhere else. It is never put in a query string, never sent as a header, and never
 * logged.
 *
 * Requests are same-origin relative paths: the dev proxy forwards `/t/*` to the gateway, so the
 * browser only ever sees the origin it loaded from.
 */

/** One shape per documented error, so a page can branch without matching on strings. */
export type InteractionErrorCode =
  | "MONACA_INVALID_CREDENTIALS"
  | "MONACA_ACCOUNT_EXISTS"
  | "MONACA_WEAK_PASSWORD"
  | "MONACA_INVALID_VERIFICATION_CODE"
  | "MONACA_TOO_MANY_ATTEMPTS"
  | "MONACA_INTERACTION_NOT_FOUND"
  | "MONACA_INTERACTION_EXPIRED"
  | "MONACA_INTERACTION_CONSUMED"
  | "MONACA_INVALID_REQUEST"
  | "MONACA_UNREACHABLE";

export interface InteractionDetails {
  interaction_id: string;
  tenant: string;
  client: { client_id: string; name: string };
  scopes: string[];
  organization: string | null;
  /** Whether the flow must show the consent screen before a code is issued. */
  consent_required: boolean;
  /** Whether a cross-application session already authenticated this interaction. */
  signed_in: boolean;
  expires_at: string;
}

/**
 * The sign-in result is a union because a third-party client (or `prompt=consent`) pauses after
 * authentication: the server has not minted a code yet and waits for `submitConsent`.
 */
export type SignInResult = { redirect_to: string } | { consent_required: true };

/**
 * The answer to every code-request endpoint. It is deliberately the same whether or not an account
 * exists, so the page neither confirms nor denies an address (§6.1).
 */
export interface CodeRequestResult {
  verification_required: true;
  /** How long the code stays usable, in seconds. */
  expires_in: number;
}

export class InteractionError extends Error {
  readonly code: InteractionErrorCode;
  readonly status: number;
  readonly problem: { title?: string; detail?: string } | undefined;

  constructor(
    code: InteractionErrorCode,
    message: string,
    options: { status: number; problem?: { title?: string; detail?: string } },
  ) {
    super(message);
    this.name = "InteractionError";
    this.code = code;
    this.status = options.status;
    this.problem = options.problem;
  }
}

/**
 * Map an HTTP response to a code.
 *
 * The contract fixes both the status and the code for each failure, so both are matched and the
 * status is only a fallback — a server that returns the right status with a wrong code should still
 * produce the right message.
 *
 * A 5xx is mapped to "unreachable", not to "malformed request". In dev, a gateway that is not
 * running shows up as a proxy-generated 500 with an HTML body, and telling a user their request was
 * malformed when the real problem is that nothing is listening sends them looking in the wrong
 * place. A server error is never the client's request being wrong.
 */
function codeFor(status: number, monacaCode: string | undefined): InteractionErrorCode {
  switch (monacaCode) {
    case "MONACA_INVALID_CREDENTIALS":
    case "MONACA_ACCOUNT_EXISTS":
    case "MONACA_WEAK_PASSWORD":
    case "MONACA_INVALID_VERIFICATION_CODE":
    case "MONACA_TOO_MANY_ATTEMPTS":
    case "MONACA_INTERACTION_NOT_FOUND":
    case "MONACA_INTERACTION_EXPIRED":
    case "MONACA_INTERACTION_CONSUMED":
    case "MONACA_INVALID_REQUEST":
      return monacaCode;
    default:
      break;
  }
  switch (status) {
    case 400:
      return "MONACA_INVALID_REQUEST";
    case 401:
      return "MONACA_INVALID_CREDENTIALS";
    case 404:
      return "MONACA_INTERACTION_NOT_FOUND";
    case 410:
      return "MONACA_INTERACTION_EXPIRED";
    case 409:
      return "MONACA_INTERACTION_CONSUMED";
    case 429:
      return "MONACA_TOO_MANY_ATTEMPTS";
    default:
      // 5xx (including a dev proxy with nothing behind it) and anything else unexpected.
      return status >= 500 || status === 0 ? "MONACA_UNREACHABLE" : "MONACA_INVALID_REQUEST";
  }
}

async function parse<T>(response: Response): Promise<T> {
  const body: unknown = await response.json().catch(() => null);

  if (!response.ok) {
    const problem = (body ?? {}) as { title?: string; detail?: string; monaca_error_code?: string };
    const code = codeFor(response.status, problem.monaca_error_code);
    throw new InteractionError(code, problem.title ?? `Request failed with ${response.status}`, {
      status: response.status,
      problem,
    });
  }

  return body as T;
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        ...(init?.body === undefined ? {} : { "Content-Type": "application/json" }),
      },
    });
  } catch (cause) {
    throw new InteractionError("MONACA_UNREACHABLE", "the sign-in service could not be reached", {
      status: 0,
      problem: { detail: String(cause) },
    });
  }
  return parse<T>(response);
}

const base = (tenant: string, iid: string): string =>
  `/t/${encodeURIComponent(tenant)}/interaction/${encodeURIComponent(iid)}`;

export function getInteraction(tenant: string, iid: string): Promise<InteractionDetails> {
  return call<InteractionDetails>(base(tenant, iid));
}

export function submitSignIn(
  tenant: string,
  iid: string,
  credentials: { email: string; password: string },
): Promise<SignInResult> {
  return call<SignInResult>(`${base(tenant, iid)}/sign-in`, {
    method: "POST",
    body: JSON.stringify(credentials),
  });
}

/** Start self-service registration: mails a code for the address. */
export function startSignUp(tenant: string, iid: string, email: string): Promise<CodeRequestResult> {
  return call<CodeRequestResult>(`${base(tenant, iid)}/sign-up`, {
    method: "POST",
    body: JSON.stringify({ email }),
  });
}

/** Prove the address, create the account and finish the flow. */
export function verifySignUp(
  tenant: string,
  iid: string,
  body: { email: string; code: string; password: string; display_name?: string },
): Promise<SignInResult> {
  return call<SignInResult>(`${base(tenant, iid)}/sign-up/verify`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/** Request a passwordless sign-in code. */
export function requestSignInCode(tenant: string, iid: string, email: string): Promise<CodeRequestResult> {
  return call<CodeRequestResult>(`${base(tenant, iid)}/sign-in/code`, {
    method: "POST",
    body: JSON.stringify({ email }),
  });
}

/** Redeem the sign-in code. */
export function verifySignInCode(
  tenant: string,
  iid: string,
  body: { email: string; code: string },
): Promise<SignInResult> {
  return call<SignInResult>(`${base(tenant, iid)}/sign-in/code/verify`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/** Request a password-reset code. */
export function requestPasswordReset(
  tenant: string,
  iid: string,
  email: string,
): Promise<CodeRequestResult> {
  return call<CodeRequestResult>(`${base(tenant, iid)}/password/forgot`, {
    method: "POST",
    body: JSON.stringify({ email }),
  });
}

/** Redeem the reset code and set a new password. */
export function resetPassword(
  tenant: string,
  iid: string,
  body: { email: string; code: string; password: string },
): Promise<SignInResult> {
  return call<SignInResult>(`${base(tenant, iid)}/password/reset`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/**
 * The consent half of the handshake. `allow` mints the code and returns the redirect; `deny`
 * returns an `error=access_denied` redirect for the client.
 */
export function submitConsent(
  tenant: string,
  iid: string,
  decision: "allow" | "deny",
): Promise<{ redirect_to: string }> {
  return call<{ redirect_to: string }>(`${base(tenant, iid)}/consent`, {
    method: "POST",
    body: JSON.stringify({ decision }),
  });
}

export function abortInteraction(tenant: string, iid: string): Promise<{ redirect_to: string }> {
  return call<{ redirect_to: string }>(`${base(tenant, iid)}/abort`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

/**
 * Send the browser to `redirect_to` with a full-page navigation, as §6.1 requires.
 *
 * The target is validated before it is used. It always points at a console BFF callback, but an
 * unexpected redirect target is a login-CSRF vector, so an off-origin value is refused rather than
 * followed — a defensive check that costs one comparison and closes a real class of bug.
 */
export function navigateTo(redirectTo: string): void {
  let target: URL;
  try {
    target = new URL(redirectTo, window.location.origin);
  } catch {
    throw new InteractionError("MONACA_INVALID_REQUEST", "the sign-in service returned a malformed redirect", {
      status: 0,
    });
  }

  if (target.origin !== window.location.origin) {
    throw new InteractionError(
      "MONACA_INVALID_REQUEST",
      "the sign-in service returned a redirect to another origin, which was refused",
      { status: 0, problem: { title: "Refused a cross-origin redirect", detail: target.origin } },
    );
  }

  window.location.assign(target.toString());
}
