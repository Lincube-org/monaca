-- Tenant schema, version 56 — SAML session bindings (§6.1).
--
-- A SAML sign-in is bound to the local session the verified assertion created. The tuple
-- (connector, NameID, SessionIndex) is what an IdP LogoutRequest names. Without that binding a
-- logout request could only mean "kill everything", which is not a targeted logout.
--
-- `session_indexes` is an array because one SAML Response may carry several AuthnStatements; an
-- empty array records that the IdP supplied none, which is a real state the logout contract has
-- to define.
CREATE TABLE IF NOT EXISTS tenant.saml_session_bindings (
  session_id       uuid NOT NULL REFERENCES tenant.sessions(id) ON DELETE CASCADE,
  connector_id     text NOT NULL REFERENCES tenant.saml_connectors(connector_id) ON DELETE CASCADE,
  name_id          text NOT NULL,
  name_id_format   text,
  session_indexes  text[] NOT NULL DEFAULT '{}',
  created_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (session_id, connector_id)
);
CREATE INDEX IF NOT EXISTS saml_session_bindings_lookup
  ON tenant.saml_session_bindings (connector_id, name_id);
