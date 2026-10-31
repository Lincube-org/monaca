-- Tenant schema, version 13 — RBAC roles and their account assignments (§5.6, §6.2).
--
-- A role is a named set of permission scopes; assigning it to an account is what makes the scopes
-- appear in that account's id_token. Deleting a role, or an account, removes the assignment.
CREATE TABLE IF NOT EXISTS roles (
  id          uuid PRIMARY KEY,
  name        text NOT NULL UNIQUE,
  description text NOT NULL DEFAULT '',
  permissions text[] NOT NULL DEFAULT '{}',
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS account_roles (
  account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  role_id    uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, role_id)
);
CREATE INDEX IF NOT EXISTS account_roles_role_idx ON account_roles (role_id);
