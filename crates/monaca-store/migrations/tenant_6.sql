-- Tenant schema, version 6 — WebAuthn passkeys (docs/contracts/m0.md §5.6, §6.1).
-- Additive: versions 1–5 have already run and their checksums must never change.

-- A passkey is one row of `credentials` with `kind = 'passkey'`. The existing columns already give
-- an account the row and the sealed payload (`secret_enc` holds the COSE public key, sealed like
-- every other credential blob); these columns add the WebAuthn pieces a ceremony needs.
--
-- `credential_id` is the raw id the browser reports as `rawId`, not its base64url form: the bytes
-- are what the authenticator will look up, and comparing bytes avoids two encodings of one id
-- becoming two rows.
-- `sign_count` is the last counter this server accepted. Authenticators that do not count report
-- zero forever, so zero means "no monotonicity to enforce" rather than a counter to compare.
-- `transports` remembers what the browser said about how the authenticator can be reached; it is
-- offered back in `allowCredentials` hints and has no security effect.
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS credential_id bytea;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS sign_count bigint NOT NULL DEFAULT 0;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS transports text[] NOT NULL DEFAULT '{}';
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS name text;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS aaguid uuid;

-- One credential id is one passkey, tenant-wide: an authenticator cannot be enrolled twice for
-- different accounts, and the assertion path looks a credential up by id alone.
CREATE UNIQUE INDEX IF NOT EXISTS credentials_passkey_id_idx
  ON credentials (credential_id) WHERE kind = 'passkey';
CREATE INDEX IF NOT EXISTS credentials_passkey_account_idx
  ON credentials (account_id, created_at DESC) WHERE kind = 'passkey';

-- A passkey row without the three WebAuthn fields is unusable and would fail in the assertion path
-- with a confusing error, so refuse it at write time.
ALTER TABLE credentials ADD CONSTRAINT credentials_passkey_fields
  CHECK (kind <> 'passkey' OR (credential_id IS NOT NULL AND sign_count >= 0));
