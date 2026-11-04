-- Control-plane email-connector index — docs/contracts/m0.md §5.3.
--
-- The mailer joins this instead of opening every active tenant database just to discover that
-- `tenant.email_connector` is absent. Connector writes maintain the row; `monaca-server migrate`
-- reconciles it so connectors created before this migration become visible on the upgrade path.
CREATE TABLE IF NOT EXISTS tenant_email_connectors (
  tenant_id  uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  updated_at timestamptz NOT NULL DEFAULT now()
);
