-- Per-application CORS allowed origins — docs/contracts/m0.md §6.2, §6.1.
--
-- A browser application calls the tenant's protocol endpoints cross-origin, and the server may
-- only answer with CORS headers when the calling origin was registered by an administrator. Each
-- entry is a serialized origin — `scheme://host[:port]`, no path, no wildcard — so the runtime
-- comparison is exact and an unregistered path can never be admitted by a prefix match.
--
-- A preflight carries no client_id, so the effective gate is the union of every application's
-- list within the tenant; registering an origin on one application therefore admits it to read
-- the tenant's protocol responses, which is exactly what the browser needs to start a flow.

ALTER TABLE clients
  ADD COLUMN IF NOT EXISTS cors_allowed_origins text[] NOT NULL DEFAULT '{}'
    CHECK (cardinality(cors_allowed_origins) <= 32);
