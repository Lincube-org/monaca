-- Organization invitations — docs/contracts/m0.md §5.6, §6.2.
-- An invitation names an email address and the role its account receives when it signs in to the
-- organization. There is no bearer token: acceptance is decided by the signed-in account's primary
-- email matching the row, so an invitation cannot be forwarded to a different account.

CREATE TABLE IF NOT EXISTS organization_invitations (
  id          uuid PRIMARY KEY,
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email       text NOT NULL CHECK (position('@' in email) > 1),
  role        text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  invited_by  uuid REFERENCES accounts(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  accepted_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS organization_invitations_pending_idx
  ON organization_invitations (org_id, email) WHERE accepted_at IS NULL;
CREATE INDEX IF NOT EXISTS organization_invitations_org_idx
  ON organization_invitations (org_id, created_at);
