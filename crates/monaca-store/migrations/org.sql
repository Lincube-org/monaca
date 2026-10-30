-- Per-organization schema template — docs/contracts/m0.md §5.7.
-- The migrator runs this with `SET LOCAL search_path = org_<oshort>` inside the provisioning
-- transaction, so no statement names the schema.

CREATE TABLE IF NOT EXISTS members (
  account_id  uuid NOT NULL,
  role        text NOT NULL CHECK (role IN ('owner','admin','member')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id)
);

CREATE TABLE IF NOT EXISTS agents (
  id               uuid PRIMARY KEY,
  name             text NOT NULL,
  description      text NOT NULL DEFAULT '',
  owner_account_id uuid NOT NULL,
  state            text NOT NULL CHECK (state IN ('active','disabled')),
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS agent_keys (
  id            uuid PRIMARY KEY,
  agent_id      uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  public_jwk    jsonb NOT NULL,
  alg           text NOT NULL DEFAULT 'ES256' CHECK (alg = 'ES256'),
  kid           text NOT NULL,
  fingerprint   text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  revoked_at    timestamptz,
  UNIQUE (agent_id, kid)
);
CREATE INDEX IF NOT EXISTS agent_keys_agent_idx ON agent_keys (agent_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS grants (
  id            uuid PRIMARY KEY,
  agent_id      uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  account_id    uuid NOT NULL,
  scopes        text[] NOT NULL,
  resource      text NOT NULL,
  constraints   jsonb NOT NULL DEFAULT '{}'::jsonb,
  expires_at    timestamptz,
  revoked_at    timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  created_by    uuid NOT NULL,
  CHECK (array_length(scopes, 1) > 0)
);
CREATE INDEX IF NOT EXISTS grants_agent_idx ON grants (agent_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS grants_account_idx ON grants (account_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS delegations (
  id            uuid PRIMARY KEY,
  parent_agent  uuid,
  child_agent   uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  grant_id      uuid NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
  scopes        text[] NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  CHECK (parent_agent IS DISTINCT FROM child_agent)
);

CREATE TABLE IF NOT EXISTS approvals (
  id           uuid PRIMARY KEY,
  grant_id     uuid NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
  requested_by text NOT NULL,
  state        text NOT NULL CHECK (state IN ('pending','approved','denied','expired')),
  decided_at   timestamptz,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS approvals_pending_idx ON approvals (created_at) WHERE state = 'pending';

CREATE TABLE IF NOT EXISTS audit_events (
  seq          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id           uuid NOT NULL UNIQUE,
  at           timestamptz NOT NULL,
  action       text NOT NULL,
  actor_chain  jsonb NOT NULL,
  subject_type text NOT NULL,
  subject_id   uuid,
  -- The exact `subject.id` string (§8.1); a tool subject has no uuid, and the digest covers it.
  subject_ref  text,
  decision     text NOT NULL CHECK (decision IN ('allow','deny','info')),
  grant_id     uuid,
  jti          uuid,
  payload      jsonb NOT NULL DEFAULT '{}'::jsonb,
  prev_hash    bytea NOT NULL,
  hash         bytea NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_at_idx ON audit_events (at DESC);
CREATE INDEX IF NOT EXISTS audit_events_grant_idx ON audit_events (grant_id) WHERE grant_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS audit_chain_head (
  singleton  boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  seq        bigint NOT NULL,
  hash       bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO audit_chain_head (singleton, seq, hash)
VALUES (true, 0, decode(repeat('00', 32), 'hex'))
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS policies (
  id         uuid PRIMARY KEY,
  cedar_text text NOT NULL,
  version    bigint NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (version)
);

CREATE TABLE IF NOT EXISTS mod_mcp_demo_notes (
  id         uuid PRIMARY KEY,
  title      text NOT NULL,
  body       text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid NOT NULL
);
