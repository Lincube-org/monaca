-- Shared fixed-window counters for §6.2 request gates.
--
-- One row per bucket key, so the table is bounded by distinct
-- (endpoint, layer, subject) combinations rather than by time: the upsert resets the row when the
-- window elapses instead of inserting a new one. Every instance of the server updates the same
-- row, which makes the configured limit a deployment-wide limit instead of a per-process one.
CREATE TABLE IF NOT EXISTS rate_limit_counters (
  bucket_key   text PRIMARY KEY,
  window_start timestamptz NOT NULL,
  count        bigint NOT NULL
);
