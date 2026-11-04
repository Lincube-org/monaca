-- Per-endpoint request gates — §6.2.
--
-- A NULL `client_id` is the tenant-wide layer for one endpoint class; a row with a client_id is
-- the stricter per-client layer keyed by the protocol client id. Both layers are evaluated, so
-- a client row cannot relax the tenant row. An absent row means the built-in default for that
-- endpoint, which keeps an existing tenant unthrottled until an administrator writes one.
CREATE TABLE IF NOT EXISTS rate_limits (
  id           uuid PRIMARY KEY,
  endpoint     text NOT NULL CHECK (endpoint IN ('authorize', 'token', 'userinfo', 'management')),
  client_id    text,
  limit_count  integer NOT NULL CHECK (limit_count > 0),
  window_secs  integer NOT NULL CHECK (window_secs > 0 AND window_secs <= 86400),
  updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS rate_limits_tenant_idx
  ON rate_limits (endpoint) WHERE client_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS rate_limits_client_idx
  ON rate_limits (client_id, endpoint) WHERE client_id IS NOT NULL;
