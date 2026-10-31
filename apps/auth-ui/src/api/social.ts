/**
 * The tenant's public social connectors (docs/contracts/m0.md §6.1).
 *
 * The list is what the sign-in page renders as buttons; everything else about a connector
 * (URLs, the client secret) stays inside the tenant's configuration. Linking a provider from the
 * account centre is a browser navigation, so the page only needs the URL, not a JSON call.
 */

export interface SocialConnector {
  connector_id: string;
  display_name: string;
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
