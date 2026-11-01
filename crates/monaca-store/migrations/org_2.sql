-- Per-organization roles — docs/contracts/m0.md §5.7, §6.2.
-- A role is a named set of scopes; a member may hold several of them. They are deliberately
-- separate from `members.role`, which is the membership rank (owner/admin/member), not a
-- permission grant.

CREATE TABLE IF NOT EXISTS roles (
  id          uuid PRIMARY KEY,
  name        text NOT NULL UNIQUE,
  description text NOT NULL DEFAULT '',
  scopes      text[] NOT NULL DEFAULT '{}',
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS member_roles (
  account_id uuid NOT NULL REFERENCES members(account_id) ON DELETE CASCADE,
  role_id    uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, role_id)
);
CREATE INDEX IF NOT EXISTS member_roles_role_idx ON member_roles (role_id);
