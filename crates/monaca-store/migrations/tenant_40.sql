-- The tenant's outbound mail connector — docs/contracts/m0.md §6.3.
--
-- The outbox is the queue, this row is the delivery route. A tenant configures one HTTP endpoint;
-- the server posts every unpublished `mail.verification` payload to it and marks the row published
-- on a 2xx. Templates stay in `email_templates`: the connector only transports the rendered copy,
-- so the server never becomes a mail transfer agent and a provider is swappable by configuration.
--
-- `secret_enc` is sealed with the tenant DEK like every credential blob. SMTP is deliberately not
-- a provider here: an implementation would need its own transport, retry and TLS policy, which is
-- a separate increment rather than a column value.
CREATE TABLE IF NOT EXISTS email_connector (
  singleton    boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  provider     text NOT NULL CHECK (provider = 'http'),
  endpoint     text NOT NULL CHECK (char_length(endpoint) BETWEEN 1 AND 2000),
  from_address text NOT NULL CHECK (char_length(from_address) BETWEEN 3 AND 320
                                    AND from_address ~ '@'),
  from_name    text CHECK (from_name IS NULL OR char_length(from_name) BETWEEN 1 AND 100),
  secret_enc   bytea,
  enabled      boolean NOT NULL DEFAULT true,
  updated_at   timestamptz NOT NULL DEFAULT now()
);
