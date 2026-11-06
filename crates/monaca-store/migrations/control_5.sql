-- Custom hostnames for tenants — docs/contracts/m0.md §5.8.
--
-- The binding lives in the control plane because a hostname maps to exactly one tenant and the
-- server asks this table before routing any request. `host` is stored lower-case without a port;
-- the UNIQUE constraint is the cross-tenant ownership lock. A row is never deleted: revocation and
-- failed DNS re-checks change `state`, so the tenant keeps its history and can recover.
CREATE TABLE IF NOT EXISTS tenant_domains (
  id                 uuid PRIMARY KEY,
  tenant_id          uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  host               text NOT NULL,
  state              text NOT NULL CHECK (state IN
                       ('pending','verified','active','degraded','revoked')),
  -- The value published at `_monaca-verify.<host>`: `monaca-verify-v1=<tenant_id>:<nonce>`.
  -- The nonce is one claim attempt bound to this tenant and this host. It stays readable for
  -- re-checks (the record is public anyway); a revoked binding rotates it before re-claiming.
  nonce              text NOT NULL,
  -- The serving state a failed re-check interrupted, so a successful re-check can restore it
  -- instead of guessing whether the tenant had activated the domain.
  last_good_state    text CHECK (last_good_state IN ('verified','active')),
  verified_at        timestamptz,
  last_checked_at    timestamptz,
  check_failures     integer NOT NULL DEFAULT 0,
  revoked_at         timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tenant_domains_host_key UNIQUE (host)
);
CREATE INDEX IF NOT EXISTS tenant_domains_tenant_idx ON tenant_domains (tenant_id);
CREATE INDEX IF NOT EXISTS tenant_domains_state_idx ON tenant_domains (state);
