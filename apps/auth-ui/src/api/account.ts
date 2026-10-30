/**
 * The signed-in account's own security API (docs/contracts/m0.md §6.1 `mfa`).
 *
 * These calls authenticate with the SSO session cookie the sign-in flow already set, so they need
 * no interaction id: the browser is asking about itself, at `/t/{tenant}/account`. A missing or
 * stale cookie is a `401` and the page sends the visitor back to sign in.
 */

export interface AccountProfile {
  id: string;
  email: string;
  display_name: string;
  mfa: { totp: boolean };
}

/** A pending authenticator secret, shown once to the setup page. */
export interface TotpEnrollment {
  secret: string;
  otpauth_url: string;
  expires_in: number;
}

export class AccountError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "AccountError";
    this.status = status;
  }
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
    throw new AccountError(0, String(cause));
  }

  if (!response.ok) {
    const problem = (await response.json().catch(() => null)) as {
      title?: string;
      detail?: string;
    } | null;
    throw new AccountError(
      response.status,
      problem?.detail ?? problem?.title ?? `Request failed with ${response.status}`,
    );
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

const base = (tenant: string): string => `/t/${encodeURIComponent(tenant)}/account`;

export function getAccount(tenant: string): Promise<AccountProfile> {
  return call<AccountProfile>(base(tenant));
}

/** Start an enrollment: the server mints a secret that the verify call confirms. */
export function beginTotp(tenant: string): Promise<TotpEnrollment> {
  return call<TotpEnrollment>(`${base(tenant)}/mfa/totp`, { method: "POST" });
}

export function verifyTotp(tenant: string, code: string): Promise<{ enabled: true }> {
  return call<{ enabled: true }>(`${base(tenant)}/mfa/totp/verify`, {
    method: "POST",
    body: JSON.stringify({ code }),
  });
}

export function disableTotp(tenant: string): Promise<void> {
  return call<void>(`${base(tenant)}/mfa/totp`, { method: "DELETE" });
}
