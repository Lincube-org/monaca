-- Enterprise SSO (OIDC federation) — docs/contracts/m0.md §5.6, §6.1, §6.2.
--
-- A tenant-level connector points at an identity provider's OIDC endpoints and owns one or more
-- email domains. A sign-in whose address is at one of those domains is routed to that provider;
-- the callback asserts the address, creates the account if needed and joins the interaction's org.
-- The secret is sealed (like every credential blob), so a database dump cannot impersonate the
-- tenant at the provider.

CREATE TABLE IF NOT EXISTS sso_connectors (
  id                uuid PRIMARY KEY,
  connector_id      text NOT NULL UNIQUE,   -- the slug the protocol and the page use, e.g. `okta`
  display_name      text NOT NULL,
  issuer            text NOT NULL,
  authorize_url     text NOT NULL,
  token_url         text NOT NULL,
  userinfo_url      text NOT NULL,
  client_id         text NOT NULL,
  client_secret_enc bytea NOT NULL,
  scopes            text[] NOT NULL DEFAULT '{}',
  email_domains     text[] NOT NULL DEFAULT '{}',
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sso_connectors_domains_idx
  ON sso_connectors USING gin (email_domains);

-- The `state` sent to the identity provider: single-use and bound to the interaction that started
-- the round-trip. Deliberately separate from `social_states`: an SSO callback belongs to exactly one
-- connector and one browser flow, and it is never a link request.
CREATE TABLE IF NOT EXISTS sso_states (
  id             uuid PRIMARY KEY,
  connector      text NOT NULL REFERENCES sso_connectors(connector_id) ON DELETE CASCADE,
  interaction_id text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  consumed_at    timestamptz
);
CREATE INDEX IF NOT EXISTS sso_states_expiry_idx
  ON sso_states (expires_at) WHERE consumed_at IS NULL;
