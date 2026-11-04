-- Social provider presets, linking policy and the confirm-link handoff — §6.1, §6.2.
--
-- `provider` names the built-in endpoint/scope/field mapping (`github`, `google`) or `generic`
-- for a tenant-supplied OAuth2/OIDC connector. Existing connectors keep their behaviour: they
-- are marked `generic` and `auto_link_verified_email` below, while new rows default to the more
-- conservative `confirm_link`.
--
-- `enabled` lets an administrator keep a configured connector while hiding it from the public
-- list and refusing its round-trip. `email_at_link` records what the provider asserted when the
-- identity was connected, which is useful when the provider later stops returning the address.
-- Pending confirmations are their own table: the callback token that starts one is exchanged
-- once, and the row dies with the interaction that asked for it.
ALTER TABLE social_connectors
  ADD COLUMN IF NOT EXISTS provider text NOT NULL DEFAULT 'generic'
    CHECK (provider IN ('generic', 'github', 'google')),
  ADD COLUMN IF NOT EXISTS enabled boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS link_policy text NOT NULL DEFAULT 'auto_link_verified_email'
    CHECK (link_policy IN ('auto_link_verified_email', 'confirm_link', 'create_new_only'));

UPDATE social_connectors SET link_policy = 'auto_link_verified_email';
ALTER TABLE social_connectors ALTER COLUMN link_policy SET DEFAULT 'confirm_link';

ALTER TABLE account_social_identities
  ADD COLUMN IF NOT EXISTS email_at_link text;

ALTER TABLE social_states
  ADD COLUMN IF NOT EXISTS code_verifier_enc bytea,
  ADD COLUMN IF NOT EXISTS nonce text;

CREATE TABLE IF NOT EXISTS social_link_requests (
  id             uuid PRIMARY KEY,
  connector      text NOT NULL REFERENCES social_connectors(connector_id) ON DELETE CASCADE,
  subject        text NOT NULL,
  email          text NOT NULL,
  account_id     uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  interaction_id text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  consumed_at    timestamptz
);

CREATE INDEX IF NOT EXISTS social_link_requests_expiry_idx
  ON social_link_requests (expires_at) WHERE consumed_at IS NULL;
