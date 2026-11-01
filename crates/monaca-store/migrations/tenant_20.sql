-- Tenant webhooks — docs/contracts/m0.md §6.2.
--
-- A webhook is an outbound subscription: the server posts the audit events whose action is in
-- `events` to `url`, signed with a tenant-specific secret. The secret is sealed like every other
-- credential blob, so a database dump cannot forge deliveries to the tenant's endpoint.
--
-- Deliveries are recorded after the last attempt, so the console can show whether the endpoint
-- accepted the event and what it answered. Rows are kept per tenant and pruned by the caller
-- through the list limit; there is no retention job in M1.

CREATE TABLE IF NOT EXISTS webhooks (
  id           uuid PRIMARY KEY,
  url          text NOT NULL,
  events       text[] NOT NULL DEFAULT '{}',
  secret_enc   bytea NOT NULL,
  enabled      boolean NOT NULL DEFAULT true,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS webhooks_enabled_idx ON webhooks (enabled);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id           uuid PRIMARY KEY,
  webhook_id   uuid NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event        text NOT NULL,
  status_code  integer,
  success      boolean NOT NULL,
  attempts     integer NOT NULL,
  error        text,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS webhook_deliveries_webhook_idx
  ON webhook_deliveries (webhook_id, created_at DESC);
