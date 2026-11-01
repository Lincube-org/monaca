/**
 * Enterprise SSO routing (docs/contracts/m0.md §6.1).
 *
 * The sign-in page asks which connector owns an address's domain, so a federated visitor never
 * types a password this tenant cannot check. The lookup exposes a display name and an id — never
 * the provider's endpoints or the domains of connectors the address does not belong to.
 */

export interface SsoConnector {
  connector_id: string;
  display_name: string;
}

/** The connector that owns `email`'s domain, or `null` when the page should keep its own form. */
export async function findSsoConnector(
  tenant: string,
  email: string,
): Promise<SsoConnector | null> {
  if (!email.includes("@")) return null;

  let response: Response;
  try {
    response = await fetch(
      `/t/${encodeURIComponent(tenant)}/sso-connectors?email=${encodeURIComponent(email)}`,
      {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      },
    );
  } catch {
    // A page without a backend is the stage-0 state, not an error worth showing: no routing.
    return null;
  }
  if (!response.ok) return null;
  const body = (await response.json().catch(() => null)) as { items?: SsoConnector[] } | null;
  return body?.items?.[0] ?? null;
}

/** Where the browser goes to sign in with the connector that owns this address. */
export function ssoSignInUrl(
  tenant: string,
  connector: string,
  interaction: string,
): string {
  return `/t/${encodeURIComponent(tenant)}/sso/${encodeURIComponent(connector)}/authorize?interaction=${encodeURIComponent(interaction)}`;
}
