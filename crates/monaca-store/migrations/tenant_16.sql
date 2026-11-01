-- Organization email domains and just-in-time membership — docs/contracts/m0.md §5.6, §6.2.
-- A sign-in whose account email domain is registered here joins that org with role `member`
-- instead of being refused, so an organization can admit its own domain without an invitation.

CREATE TABLE IF NOT EXISTS organization_email_domains (
  org_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  domain     text NOT NULL CHECK (domain ~ '^[a-z0-9][a-z0-9.-]*[a-z0-9]$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (domain)
);
CREATE INDEX IF NOT EXISTS organization_email_domains_org_idx ON organization_email_domains (org_id);
