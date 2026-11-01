-- Registered API resources and the scopes they define — docs/contracts/m0.md §6.2.
-- An authorize request that names a registered resource may only ask for its scopes.

CREATE TABLE IF NOT EXISTS api_resources (
  id         uuid PRIMARY KEY,
  name       text NOT NULL,
  identifier text NOT NULL UNIQUE,
  scopes     text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
