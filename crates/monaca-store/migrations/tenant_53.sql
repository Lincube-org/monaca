-- Incremental usage counters and the account quota — §6.2.
--
-- `accounts_used` is the single source of truth for both the usage endpoint and quota
-- enforcement. It is incremented and decremented in the same transaction as the account row, so
-- the number equals `count(*)` without scanning the table. The one-time backfill below is the
-- only O(n) read, and it runs once per tenant database.
CREATE TABLE IF NOT EXISTS tenant.usage_counters (
  singleton     boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  accounts_used bigint NOT NULL DEFAULT 0 CHECK (accounts_used >= 0),
  max_accounts  bigint CHECK (max_accounts IS NULL OR max_accounts >= 0),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
INSERT INTO tenant.usage_counters (singleton, accounts_used, max_accounts)
SELECT true, (SELECT count(*) FROM tenant.accounts), NULL
ON CONFLICT (singleton) DO NOTHING;

-- One row per account per UTC day: active accounts = row count, logins = sum(logins). The primary
-- key is the only index the usage read needs; its range is bounded by today's active accounts.
CREATE TABLE IF NOT EXISTS tenant.usage_daily (
  day        date NOT NULL,
  account_id uuid NOT NULL REFERENCES tenant.accounts(id) ON DELETE CASCADE,
  logins     bigint NOT NULL DEFAULT 0 CHECK (logins >= 0),
  PRIMARY KEY (day, account_id)
);
