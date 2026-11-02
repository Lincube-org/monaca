-- Third-party consent grants — docs/contracts/m0.md §6.1 consent, §6.3.
--
-- The record that an account approved a client for a set of scopes. It is keyed by
-- (account, client) so approving again refreshes the scopes in place, and it is what lets a
-- returning user skip the consent screen while the application asks for nothing new. A revoke is
-- a delete: the next authorize request asks again.

CREATE TABLE IF NOT EXISTS consents (
  account_id  uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  client_id   uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  scopes      text[] NOT NULL DEFAULT '{}',
  granted_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, client_id)
);
CREATE INDEX IF NOT EXISTS consents_client_idx ON consents (client_id);
