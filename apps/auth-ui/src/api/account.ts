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
  /** False for a passwordless account; the page hides the change-password form then. */
  has_password: boolean;
  /** `backup_codes` is how many unused recovery codes remain. */
  mfa: { totp: boolean; backup_codes: number };
}

/** A freshly generated sheet of recovery codes; the plaintext is shown only in this response. */
export interface BackupCodeSheet {
  codes: string[];
  remaining: number;
}

/** A pending authenticator secret, shown once to the setup page. */
export interface TotpEnrollment {
  secret: string;
  otpauth_url: string;
  expires_in: number;
}

/** One browser signed in to the account, as the account centre lists it. */
export interface AccountSession {
  id: string;
  current: boolean;
  client_id: string | null;
  issued_at: string;
  expires_at: string;
  last_seen_at: string;
  user_agent: string | null;
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

export function listBackupCodes(tenant: string): Promise<{ remaining: number }> {
  return call<{ remaining: number }>(`${base(tenant)}/mfa/backup-codes`);
}

/** Mint ten new single-use codes; this response is the only place the plaintext exists. */
export function generateBackupCodes(tenant: string): Promise<BackupCodeSheet> {
  return call<BackupCodeSheet>(`${base(tenant)}/mfa/backup-codes`, { method: "POST" });
}

export function disableBackupCodes(tenant: string): Promise<void> {
  return call<void>(`${base(tenant)}/mfa/backup-codes`, { method: "DELETE" });
}

/** Change the display name applications show; the server trims and bounds it. */
export function updateProfile(tenant: string, displayName: string): Promise<AccountProfile> {
  return call<AccountProfile>(base(tenant), {
    method: "PATCH",
    body: JSON.stringify({ display_name: displayName }),
  });
}

/** Replace the password; a wrong current password is a `401`. */
export function changePassword(
  tenant: string,
  currentPassword: string,
  newPassword: string,
): Promise<void> {
  return call<void>(`${base(tenant)}/password`, {
    method: "POST",
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
}

export function listSessions(tenant: string): Promise<{ items: AccountSession[]; next: null }> {
  return call<{ items: AccountSession[]; next: null }>(`${base(tenant)}/sessions`);
}

export function revokeSession(tenant: string, sessionId: string): Promise<void> {
  return call<void>(`${base(tenant)}/sessions/${encodeURIComponent(sessionId)}`, {
    method: "DELETE",
  });
}

/** Sign out every browser except this one. */
export function revokeOtherSessions(tenant: string): Promise<void> {
  return call<void>(`${base(tenant)}/sessions`, { method: "DELETE" });
}
