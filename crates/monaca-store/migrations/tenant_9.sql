-- Tenant schema, version 9 — social (OAuth2) connectors (§5.6, §6.1).
--
-- A connector is tenant configuration: where to send a visitor, how to exchange the returned code,
-- and where to read the provider's userinfo document. The client secret is sealed by the server
-- (like every credential blob), so a database dump cannot impersonate the tenant at the provider.
CREATE TABLE IF NOT EXISTS social_connectors (
  id                uuid PRIMARY KEY,
  connector_id      text NOT NULL UNIQUE,   -- the slug the protocol and the page use, e.g. `github`
  display_name      text NOT NULL,
  authorize_url     text NOT NULL,
  token_url         text NOT NULL,
  userinfo_url      text NOT NULL,
  client_id         text NOT NULL,
  client_secret_enc bytea NOT NULL,
  scopes            text[] NOT NULL DEFAULT '{}',
  created_at        timestamptz NOT NULL DEFAULT now()
);

-- One provider account maps to one Monaca account, and one account uses a connector at most once:
-- the two unique constraints are what make linking idempotent and a second account's claim a 409.
CREATE TABLE IF NOT EXISTS account_social_identities (
  id         uuid PRIMARY KEY,
  account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  connector  text NOT NULL REFERENCES social_connectors(connector_id) ON DELETE CASCADE,
  subject    text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (connector, subject),
  UNIQUE (account_id, connector)
);
CREATE INDEX IF NOT EXISTS account_social_identities_account_idx
  ON account_social_identities (account_id);

-- The `state` sent to the provider: single-use, binding the callback to an interaction (sign-in)
-- or to the signed-in account that asked to connect a provider (link).
CREATE TABLE IF NOT EXISTS social_states (
  id             uuid PRIMARY KEY,
  connector      text NOT NULL,
  purpose        text NOT NULL CHECK (purpose IN ('sign_in','link')),
  interaction_id text,
  account_id     uuid REFERENCES accounts(id) ON DELETE CASCADE,
  created_at     timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  consumed_at    timestamptz
);
CREATE INDEX IF NOT EXISTS social_states_expiry_idx
  ON social_states (expires_at) WHERE consumed_at IS NULL;
