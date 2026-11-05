-- Delivery-connector index — docs/contracts/m0.md §5.3.
--
-- control_2 created the index under its email-only name. The mailer now visits a tenant when any
-- channel has a connector, so the table is the delivery index rather than the email index. The
-- rows are unchanged: one row per tenant with at least one connector.
ALTER TABLE tenant_email_connectors RENAME TO tenant_delivery_connectors;
