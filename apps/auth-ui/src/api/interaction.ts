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

import type { CeremonyJSON, RequestOptionsJSON } from "./webauthn";

/** One shape per documented error, so a page can branch without matching on strings. */
export type InteractionErrorCode =
  | "MONACA_INVALID_CREDENTIALS"
  | "MONACA_ACCOUNT_EXISTS"
  | "MONACA_USERNAME_TAKEN"
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
  /** The authorize request's `login_hint`, prefilled into the identifier field (OIDC Core §3.1.2.1). */
  login_hint: string | null;
  /** Whether the flow must show the consent screen before a code is issued. */
  consent_required: boolean;
  /** Whether a cross-application session already authenticated this interaction. */
  signed_in: boolean;
  /** Whether the primary factor passed and the account still owes an authenticator code. */
  mfa_required: boolean;
  /** Whether the tenant's mandatory policy requires setting up an authenticator before finishing. */
  mfa_enrollment_required: boolean;
  /** Which factors the second-factor step accepts: `totp`, `backup_code` and/or `passkey`. */
  mfa_factors: string[];
  expires_at: string;
}

/** The optional hosted-page look; `null` means the built-in style (§6.2). */
export interface Branding {
  display_name: string | null;
  logo_url: string | null;
  /** The logo used when the visitor's system is in dark mode; falls back to `logo_url`. */
  dark_logo_url: string | null;
  /** The favicon written into the document head; `null` keeps the built-in icon. */
  favicon_url: string | null;
  primary_color: string | null;
  terms_url: string | null;
  privacy_url: string | null;
  /** An address visitors can write to for help. */
  support_email: string | null;
  /** The tenant's own website, linked from the page footer. */
  website_url: string | null;
  /** CSS appended after the built-in stylesheet; `null` keeps the built-in look. */
  custom_css: string | null;
}

/** The tenant's hosted switches, read before the page decides which forms to offer (§6.1). */
export interface SignInExperience {
  /** Whether self-service registration is offered. */
  sign_up_enabled: boolean;
  /** Whether the password form is offered. */
  password_sign_in_enabled: boolean;
  /** Whether emailed codes and links are offered. */
  email_code_sign_in_enabled: boolean;
  /** Whether passwordless passkey sign-in is offered. */
  passkey_sign_in_enabled: boolean;
  /** Whether enterprise SSO connectors are reachable from this page. */
  single_sign_on_enabled: boolean;
  /** Whether second factors are used at all. */
  mfa_enabled: boolean;
  /** `user_controlled` | `mandatory`. */
  mfa_policy: "user_controlled" | "mandatory";
  /** Whether a browser may be remembered past the second factor. */
  mfa_trusted_devices_enabled: boolean;
  /** How long a remembered browser keeps its trust, in days. */
  mfa_trusted_device_ttl_days: number;
  /** The tenant's shortest accepted password, 8–64 characters. */
  password_min_length: number;
  /** How many character classes (lowercase, uppercase, digits, symbols) a password must use. */
  password_min_character_types: number;
  /** Whether a password may not contain the account's email local part or username. */
  password_reject_user_info: boolean;
  /** Whether a password may not repeat a character or follow a sequence four times. */
  password_reject_repetition_and_sequence: boolean;
  /** Lowercased words a password may not contain. */
  password_rejected_words: string[];
  /** Which identifiers a new account may be registered with; `email` is always present. */
  sign_up_identifiers: ("email" | "username")[];
  /** Whether the address is proven with an emailed code before the account exists. */
  sign_up_email_verification_required: boolean;
  /** Whether usernames keep their case; when false the server folds them to lowercase. */
  username_case_sensitive: boolean;
  /** The tenant's shortest accepted username. */
  username_min_length: number;
  /** The tenant's longest accepted username. */
  username_max_length: number;
  /** Which optional profile fields the sign-up form collects, in addition to the address. */
  sign_up_profile_fields: ("name" | "avatar")[];
  /** The optional hosted-page look. */
  branding: Branding;
}

/**
 * The sign-in result is a union because authentication can pause twice: a third-party client (or
 * `prompt=consent`) waits for `submitConsent`, and an account with an authenticator app waits for
 * `verifyMfa` before anything is minted (§6.1 `mfa`).
 */
export type SignInResult =
  | { redirect_to: string }
  | { consent_required: true }
  | { mfa_required: true; factors: string[] }
  | { mfa_enrollment_required: true; factors: string[] };

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
    case "MONACA_USERNAME_TAKEN":
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

/** The tenant's public sign-in switches — public because the page reads them before sign-in. */
export function getSignInExperience(
  tenant: string,
  clientId?: string | null,
): Promise<SignInExperience> {
  const query = clientId ? `?client_id=${encodeURIComponent(clientId)}` : "";
  return call<SignInExperience>(`/t/${encodeURIComponent(tenant)}/sign-in-experience${query}`);
}

/**
 * Submit the primary factor. `identifier` is the email address or the username; the server treats
 * both case-insensitively (§6.1).
 */
export function submitSignIn(
  tenant: string,
  iid: string,
  credentials: { identifier: string; password: string },
): Promise<SignInResult> {
  return call<SignInResult>(`${base(tenant, iid)}/sign-in`, {
    method: "POST",
    body: JSON.stringify(credentials),
  });
}

/**
 * What a sign-up collects on its first request.
 *
 * With email verification on, only `email` is read; the rest belongs to `sign-up/verify`. With it
 * off, the same request creates the account, so it carries the password and the profile fields the
 * tenant collects.
 */
export interface SignUpRequest {
  email: string;
  password?: string;
  username?: string;
  display_name?: string;
  avatar_url?: string;
}

/**
 * Start self-service registration.
 *
 * The answer follows the tenant's verification policy: a code request when the address must be
 * proven, the ordinary sign-in result when the account was created in this request.
 */
export function startSignUp(
  tenant: string,
  iid: string,
  body: SignUpRequest,
): Promise<CodeRequestResult | SignInResult> {
  return call<CodeRequestResult | SignInResult>(`${base(tenant, iid)}/sign-up`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/** Prove the address, create the account and finish the flow. */
export function verifySignUp(
  tenant: string,
  iid: string,
  body: {
    email: string;
    code: string;
    password: string;
    display_name?: string;
    username?: string;
    avatar_url?: string;
  },
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

/** Mail a one-time sign-in link instead of a six-digit code (§6.1 `sign-in/link`). */
export function requestSignInLink(
  tenant: string,
  iid: string,
  email: string,
): Promise<{ verification_required: true; expires_in: number }> {
  return call<{ verification_required: true; expires_in: number }>(
    `${base(tenant, iid)}/sign-in/link`,
    { method: "POST", body: JSON.stringify({ email }) },
  );
}

/** Prove the second factor with a six-digit authenticator code or a saved backup code. */
export function verifyMfa(
  tenant: string,
  iid: string,
  code: string,
  factor: "totp" | "backup_code" = "totp",
  rememberDevice = false,
): Promise<SignInResult> {
  return call<SignInResult>(`${base(tenant, iid)}/mfa/verify`, {
    method: "POST",
    body: JSON.stringify({ code, factor, remember_device: rememberDevice }),
  });
}

/** The setup data a mandatory policy's enrollment step shows. */
export interface MfaEnrollment {
  secret: string;
  otpauth_url: string;
  expires_in: number;
}

/** Start the enrollment a mandatory policy requires for this interaction. */
export function startMfaEnrollment(tenant: string, iid: string): Promise<MfaEnrollment> {
  return call<MfaEnrollment>(`${base(tenant, iid)}/mfa/enroll`, { method: "POST" });
}

/** Prove the freshly scanned authenticator and finish the sign-in. */
export function verifyMfaEnrollment(
  tenant: string,
  iid: string,
  code: string,
): Promise<SignInResult> {
  return call<SignInResult>(`${base(tenant, iid)}/mfa/enroll/verify`, {
    method: "POST",
    body: JSON.stringify({ code }),
  });
}

/**
 * Start a passwordless sign-in: the browser is offered every discoverable passkey it holds for this
 * site, and the resulting assertion names the account it belongs to.
 */
export function getPasskeySignInOptions(
  tenant: string,
  iid: string,
): Promise<RequestOptionsJSON> {
  return call<RequestOptionsJSON>(`${base(tenant, iid)}/sign-in/passkey/options`, {
    method: "POST",
  });
}

/** Complete the passwordless sign-in with the assertion the authenticator produced. */
export function verifyPasskeySignIn(
  tenant: string,
  iid: string,
  body: CeremonyJSON,
): Promise<SignInResult> {
  return call<SignInResult>(`${base(tenant, iid)}/sign-in/passkey`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/**
 * Offer the account's own passkeys as the second factor. The allow-list is server-side, so the
 * authenticator cannot answer the challenge with another account's credential.
 */
export function getMfaPasskeyOptions(
  tenant: string,
  iid: string,
): Promise<RequestOptionsJSON> {
  return call<RequestOptionsJSON>(`${base(tenant, iid)}/mfa/passkey/options`, {
    method: "POST",
  });
}

/** Prove the second factor with a passkey assertion. */
export function verifyMfaPasskey(
  tenant: string,
  iid: string,
  body: CeremonyJSON,
): Promise<SignInResult> {
  return call<SignInResult>(`${base(tenant, iid)}/mfa/passkey`, {
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
