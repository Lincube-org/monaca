-- Tenant schema, version 57 — inbound SAML LogoutRequest replay (§6.1).
--
-- LogoutRequest ids are one-time exactly like assertion ids: the first valid request inserts the
-- row and claims it with a conditional UPDATE; a replay finds no claimable row and is refused.
CREATE TABLE IF NOT EXISTS tenant.saml_logout_requests (
  request_id    text PRIMARY KEY,
  connector_id  text NOT NULL REFERENCES tenant.saml_connectors(connector_id) ON DELETE CASCADE,
  expires_at    timestamptz NOT NULL,
  consumed_at   timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS saml_logout_requests_expiry
  ON tenant.saml_logout_requests (expires_at);
