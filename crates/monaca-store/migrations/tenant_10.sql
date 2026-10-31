-- Tenant schema, version 10 — remembered MFA devices (§5.6, §6.1).
--
-- A trusted browser substitutes for the second factor until it expires or the account revokes it.
-- Only the SHA-256 hex of the cookie value is stored: a database read must not yield a usable
-- token, exactly like the verification codes in version 4.
CREATE TABLE IF NOT EXISTS mfa_trusted_devices (
  id           uuid PRIMARY KEY,
  account_id   uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  token_hash   text NOT NULL,
  user_agent   text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS mfa_trusted_devices_token_idx
  ON mfa_trusted_devices (token_hash) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS mfa_trusted_devices_account_idx
  ON mfa_trusted_devices (account_id, created_at DESC) WHERE revoked_at IS NULL;
