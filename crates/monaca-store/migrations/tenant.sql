-- Per-tenant schema `tenant` — docs/contracts/m0.md §5.6.
-- The migrator sets `SET LOCAL search_path = tenant`; nothing here is schema-qualified on purpose.

CREATE TABLE IF NOT EXISTS organizations (
  id          uuid PRIMARY KEY,
  slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,30}$'),
  schema_name text NOT NULL UNIQUE,
  role_name   text NOT NULL UNIQUE,
  state       text NOT NULL CHECK (state IN ('active','archived')),
  is_default  boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS organizations_one_default_idx ON organizations (is_default) WHERE is_default;

CREATE TABLE IF NOT EXISTS agent_directory (
  agent_id   uuid PRIMARY KEY,
  org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS agent_directory_org_idx ON agent_directory (org_id);

CREATE TABLE IF NOT EXISTS accounts (
  id            uuid PRIMARY KEY,
  primary_email text NOT NULL,
  display_name  text NOT NULL,
  state         text NOT NULL CHECK (state IN ('active','disabled')),
  is_tenant_admin boolean NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS accounts_primary_email_idx ON accounts (lower(primary_email));

CREATE TABLE IF NOT EXISTS account_identifiers (
  id           uuid PRIMARY KEY,
  account_id   uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  -- Email and username identifiers are implemented. There is no phone identifier flow, so the
  -- check does not reserve `phone` (tenant_49 removes it from databases created before that).
  kind         text NOT NULL CHECK (kind IN ('email','username')),
  value        text NOT NULL,
  verified_at  timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (kind, value)
);

CREATE TABLE IF NOT EXISTS credentials (
  id            uuid PRIMARY KEY,
  account_id    uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  kind          text NOT NULL CHECK (kind IN ('password','passkey','totp')),
  secret_enc    bytea NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_used_at  timestamptz
);
CREATE INDEX IF NOT EXISTS credentials_account_idx ON credentials (account_id) WHERE kind = 'password';

CREATE TABLE IF NOT EXISTS sessions (
  id             uuid PRIMARY KEY,
  account_id     uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  issued_at      timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  revoked_at     timestamptz,
  user_agent     text,
  ip             inet
);
CREATE INDEX IF NOT EXISTS sessions_account_idx ON sessions (account_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS clients (
  id                uuid PRIMARY KEY,
  client_id         text NOT NULL UNIQUE,
  name              text NOT NULL,
  kind              text NOT NULL CHECK (kind IN ('public','confidential')),
  secret_hash       text,
  token_auth_method text NOT NULL CHECK (token_auth_method IN ('none','client_secret_basic','client_secret_post','private_key_jwt')),
  jwks              jsonb,
  scopes            text[] NOT NULL DEFAULT '{}',
  created_at        timestamptz NOT NULL DEFAULT now(),
  CHECK (kind = 'public' OR secret_hash IS NOT NULL OR token_auth_method = 'private_key_jwt')
);

CREATE TABLE IF NOT EXISTS redirect_uris (
  client_id     uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  redirect_uri  text NOT NULL,
  PRIMARY KEY (client_id, redirect_uri)
);

CREATE TABLE IF NOT EXISTS signing_keys (
  id          uuid PRIMARY KEY,
  alg         text NOT NULL DEFAULT 'ES256' CHECK (alg = 'ES256'),
  private_enc bytea NOT NULL,
  public_jwk  jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  retired_at  timestamptz,
  CHECK (retired_at IS NULL OR retired_at > created_at)
);
CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_active_idx ON signing_keys (alg) WHERE retired_at IS NULL;

CREATE TABLE IF NOT EXISTS auth_codes (
  id                uuid PRIMARY KEY,
  code_hash         text NOT NULL UNIQUE,
  client_id         uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  account_id        uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  org_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  redirect_uri      text NOT NULL,
  scope             text[] NOT NULL DEFAULT '{}',
  code_challenge    text NOT NULL,
  code_challenge_method text NOT NULL DEFAULT 'S256' CHECK (code_challenge_method = 'S256'),
  nonce             text,
  resource          text,
  session_id        uuid,
  expires_at        timestamptz NOT NULL,
  consumed_at       timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS auth_codes_expiry_idx ON auth_codes (expires_at) WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id           uuid PRIMARY KEY,
  token_hash   text NOT NULL UNIQUE,
  client_id    uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  account_id   uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scope        text[] NOT NULL DEFAULT '{}',
  resource     text,
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz,
  rotated_from uuid REFERENCES refresh_tokens(id),
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS refresh_tokens_account_idx ON refresh_tokens (account_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS audit_events (
  seq         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id          uuid NOT NULL UNIQUE,
  at          timestamptz NOT NULL,
  action      text NOT NULL,
  actor_chain jsonb NOT NULL,
  subject_type text NOT NULL,
  subject_id  uuid,
  -- The exact `subject.id` string (§8.1). A typed id can be recovered from `subject_id`, but a
  -- tool's subject id is a bare name with no uuid, and the canonical bytes hash it verbatim, so
  -- the chain cannot be re-verified without it.
  subject_ref text,
  decision    text NOT NULL CHECK (decision IN ('allow','deny','info')),
  grant_id    uuid,
  jti         uuid,
  payload     jsonb NOT NULL DEFAULT '{}'::jsonb,
  prev_hash   bytea NOT NULL,
  hash        bytea NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_at_idx ON audit_events (at DESC);
CREATE INDEX IF NOT EXISTS audit_events_action_idx ON audit_events (action, at DESC);

CREATE TABLE IF NOT EXISTS audit_chain_head (
  singleton  boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  seq        bigint NOT NULL,
  hash       bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO audit_chain_head (singleton, seq, hash)
VALUES (true, 0, decode(repeat('00', 32), 'hex'))
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS outbox (
  id             uuid PRIMARY KEY,
  topic          text NOT NULL,
  payload        jsonb NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  published_at   timestamptz,
  attempts       integer NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS outbox_unpublished_idx ON outbox (created_at) WHERE published_at IS NULL;
