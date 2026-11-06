-- Tenant schema, version 54 — when a role last changed (§5.6, §6.2).
--
-- A role's permissions are what the management API and the scope-grant check read. Recording the
-- last update makes a permission change visible in the role object and gives the console a stable
-- ordering field without re-deriving it from the audit chain.
ALTER TABLE roles ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
