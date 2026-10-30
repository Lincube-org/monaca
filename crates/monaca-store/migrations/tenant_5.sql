-- Tenant schema, version 5 — MFA backup codes (docs/contracts/m0.md §5.6, §6.1).
-- Additive: versions 1–4 have already run and their checksums must never change.

-- Single-use recovery codes for an account that has an authenticator app. Only the SHA-256 hex of
-- the canonical (hyphen-free, lowercase) code is stored: a database read must not hand out a usable
-- code. `used_at` makes consumption single-use even when two requests race, and the partial index
-- keeps the "how many remain" query to the live rows only.
CREATE TABLE IF NOT EXISTS backup_codes (
  id          uuid PRIMARY KEY,
  account_id  uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  code_hash   text NOT NULL,
  used_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS backup_codes_hash_idx
  ON backup_codes (account_id, code_hash);
CREATE INDEX IF NOT EXISTS backup_codes_live_idx
  ON backup_codes (account_id) WHERE used_at IS NULL;
