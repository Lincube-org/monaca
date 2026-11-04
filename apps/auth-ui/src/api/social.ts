/**
 * The tenant's public social connectors (docs/contracts/m0.md §6.1).
 *
 * The list is what the sign-in page renders as buttons; everything else about a connector
 * (URLs, the client secret) stays inside the tenant's configuration. Linking a provider from the
 * account centre is a browser navigation, so the page only needs the URL, not a JSON call.
 */

import { InteractionError, type SignInResult } from "./interaction";

export interface SocialConnector {
  connector_id: string;
  display_name: string;
  /** `generic` | `github` | `google`; the page uses it only for presentation. */
  provider?: "generic" | "github" | "google";
}

/** A pending "this provider identity wants to link to the account that owns the email" prompt. */
export interface SocialLinkDetails {
  connector_id: string;
  display_name: string;
  provider: "generic" | "github" | "google";
  email: string;
  expires_at: string;
}

/** Ask the server what a `social_link` token is about before showing the prompt. */
export async function getSocialLink(
  tenant: string,
  token: string,
): Promise<SocialLinkDetails> {
  const response = await fetch(
    `/t/${encodeURIComponent(tenant)}/social/link/${encodeURIComponent(token)}`,
    { credentials: "same-origin", headers: { Accept: "application/json" } },
  );
  if (!response.ok) {
    throw new InteractionError("MONACA_INVALID_REQUEST", "the link confirmation is no longer usable", {
      status: response.status,
    });
  }
  return (await response.json()) as SocialLinkDetails;
}

/** Confirm the link; the server answers with the same result shape a password sign-in uses. */
export async function confirmSocialLink(
  tenant: string,
  token: string,
): Promise<SignInResult> {
  const response = await fetch(
    `/t/${encodeURIComponent(tenant)}/social/link/${encodeURIComponent(token)}/confirm`,
    {
      method: "POST",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    },
  );
  const body = (await response.json().catch(() => null)) as
    | (SignInResult & { monaca_error_code?: string })
    | null;
  if (!response.ok) {
    throw new InteractionError("MONACA_INVALID_REQUEST", "the link could not be confirmed", {
      status: response.status,
      problem: {
        title: body?.monaca_error_code ?? "MONACA_INVALID_REQUEST",
      },
    });
  }
  return body as SignInResult;
}

export async function listSocialConnectors(
  tenant: string,
): Promise<SocialConnector[]> {
  let response: Response;
  try {
    response = await fetch(`/t/${encodeURIComponent(tenant)}/connectors`, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
  } catch {
    // A page without a backend is the stage-0 state, not an error worth showing: no buttons.
    return [];
  }
  if (!response.ok) return [];
  const body = (await response.json().catch(() => null)) as {
    items?: SocialConnector[];
  } | null;
  return body?.items ?? [];
}

/** Where the browser goes to sign in with a provider for this interaction. */
export function socialSignInUrl(
  tenant: string,
  connector: string,
  interaction: string,
): string {
  return `/t/${encodeURIComponent(tenant)}/connectors/${encodeURIComponent(connector)}/authorize?interaction=${encodeURIComponent(interaction)}`;
}

/** Where the browser goes to connect this provider while signed in. */
export function socialLinkUrl(tenant: string, connector: string): string {
  return `/t/${encodeURIComponent(tenant)}/account/social/${encodeURIComponent(connector)}/authorize`;
}
