-- Control-plane schema — docs/contracts/m0.md §5.3.
-- Applied to MONACA_CONTROL_DATABASE_URL. Every statement is idempotent from the migrator's point
-- of view (the migration ledger decides whether it runs, not IF NOT EXISTS).

CREATE TABLE IF NOT EXISTS clusters (
  id             uuid PRIMARY KEY,
  name           text NOT NULL UNIQUE,
  admin_dsn_enc  bytea NOT NULL,
  app_dsn_enc    bytea NOT NULL,
  region         text NOT NULL DEFAULT 'local',
  capacity       integer NOT NULL DEFAULT 64,
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenants (
  id          uuid PRIMARY KEY,
  slug        text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,30}$'),
  short       text NOT NULL UNIQUE CHECK (short ~ '^[a-z0-9]{4,10}$'),
  cluster_id  uuid NOT NULL REFERENCES clusters(id),
  db_name     text NOT NULL UNIQUE,
  issuer      text NOT NULL UNIQUE,
  -- archived retains the database and can be reactivated by `tenant resume`.
  state       text NOT NULL CHECK (state IN ('provisioning','active','suspended','archived')),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tenants_state_idx ON tenants (state);

CREATE TABLE IF NOT EXISTS platform_admins (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id),
  account_id    uuid NOT NULL,
  email         text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, account_id)
);

CREATE TABLE IF NOT EXISTS migration_rollup (
  target        text NOT NULL,
  version       bigint NOT NULL,
  description   text NOT NULL,
  checksum      text NOT NULL,
  applied_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (target, version)
);
