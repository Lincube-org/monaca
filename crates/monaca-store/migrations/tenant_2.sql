-- Tenant schema, version 2 — protocol completeness (docs/architecture.md §11 M1).
-- The migrator sets `SET LOCAL search_path = tenant`; nothing here is schema-qualified on purpose.
-- Everything is additive: version 1 already ran on existing tenant databases, so its checksum
-- must never change.

-- Third-party applications require a consent step (OAuth 2.1 / Logto parity).
ALTER TABLE clients ADD COLUMN IF NOT EXISTS is_third_party boolean NOT NULL DEFAULT false;

-- Refresh-token rotation: one family per authorization-code exchange, so reuse anywhere in the
-- chain revokes every descendant in one statement. `dpop_jkt` binds a refresh token to the DPoP
-- key that obtained it (RFC 9449 §5); `auth_time` is the original authentication instant that the
-- id_token must echo on refresh.
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS family_id uuid;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS dpop_jkt text;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS auth_time timestamptz NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS refresh_tokens_family_idx ON refresh_tokens (family_id)
  WHERE revoked_at IS NULL;

-- Authorization-code binding: `dpop_jkt` comes from the authorize request (RFC 9449 §10);
-- `auth_time` is the sign-in instant the id_token reports.
ALTER TABLE auth_codes ADD COLUMN IF NOT EXISTS dpop_jkt text;
ALTER TABLE auth_codes ADD COLUMN IF NOT EXISTS auth_time timestamptz NOT NULL DEFAULT now();

-- RFC 9126 pushed authorization requests. The `request_uri` is a bearer secret, so only its
-- SHA-256 is stored; `params` is the validated authorize request as JSON.
CREATE TABLE IF NOT EXISTS par_requests (
  id               uuid PRIMARY KEY,
  request_uri_hash text NOT NULL UNIQUE,
  client_id        uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  params           jsonb NOT NULL,
  expires_at       timestamptz NOT NULL,
  consumed_at      timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS par_requests_expiry_idx ON par_requests (expires_at)
  WHERE consumed_at IS NULL;

-- RFC 9449 replay protection: a DPoP proof's `jti` is single-use within its freshness window.
CREATE TABLE IF NOT EXISTS dpop_replays (
  jti        text PRIMARY KEY,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS dpop_replays_expiry_idx ON dpop_replays (expires_at);

-- RFC 7009 access-token revocation. Access tokens are self-contained JWTs, so a resource server
-- cannot see this table; the server-side endpoints (userinfo and introspection) consult it, and
-- resource servers rely on the short access-token TTL.
CREATE TABLE IF NOT EXISTS revoked_access_tokens (
  jti        uuid PRIMARY KEY,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS revoked_access_tokens_expiry_idx ON revoked_access_tokens (expires_at);
