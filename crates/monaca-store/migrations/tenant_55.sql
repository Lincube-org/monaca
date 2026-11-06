-- Tenant schema, version 55 — SAML 2.0 connectors and their one-time state (§6.1, §6.2).
--
-- Metadata is the trust anchor and is stored verbatim; the entity id is derived from it at write
-- time so the read path never has to parse it twice. `email_domains` is the same routing key the
-- OIDC connectors use; the application refuses an overlap across the two tables.
CREATE TABLE IF NOT EXISTS tenant.saml_connectors (
  id               uuid PRIMARY KEY,
  connector_id     text NOT NULL UNIQUE,
  display_name     text NOT NULL,
  metadata_xml     text NOT NULL,
  entity_id        text NOT NULL,
  email_domains    text[] NOT NULL,
  email_attribute  text NOT NULL DEFAULT 'email',
  role_attribute   text,
  enabled          boolean NOT NULL DEFAULT true,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS saml_connectors_domains
  ON tenant.saml_connectors USING gin (email_domains);

-- RelayState is the primary key: one SP-initiated AuthnRequest, one completion. The conditional
-- UPDATE in the store is what makes it single-use; an expired or consumed row is refused.
CREATE TABLE IF NOT EXISTS tenant.saml_states (
  id                text PRIMARY KEY,
  connector_id      text NOT NULL REFERENCES tenant.saml_connectors(connector_id) ON DELETE CASCADE,
  interaction_id    text NOT NULL,
  request_id        text NOT NULL,
  idp_entity_id     text NOT NULL,
  acs_url           text NOT NULL,
  request_binding   text NOT NULL,
  response_binding  text NOT NULL,
  issued_at         text,
  expires_at        timestamptz NOT NULL,
  consumed_at       timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS saml_states_expiry ON tenant.saml_states (expires_at);

-- Assertion IDs are the replay key. The first login inserts the row with `consumed_at IS NULL`
-- and then claims it with a conditional UPDATE; a duplicate ID finds no claimable row.
CREATE TABLE IF NOT EXISTS tenant.saml_assertions (
  assertion_id   text PRIMARY KEY,
  connector_id   text NOT NULL REFERENCES tenant.saml_connectors(connector_id) ON DELETE CASCADE,
  expires_at     timestamptz NOT NULL,
  consumed_at    timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS saml_assertions_expiry ON tenant.saml_assertions (expires_at);
