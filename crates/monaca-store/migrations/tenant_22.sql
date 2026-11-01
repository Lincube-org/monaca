-- Tenant branding — docs/contracts/m0.md §6.1 sign-in experience, §6.2.
--
-- One row per tenant schema, seeded so a read never creates it. Every field is optional: an unset
-- value means the hosted page keeps its built-in look. The API clears a field with an empty string.

CREATE TABLE IF NOT EXISTS branding (
  singleton     boolean NOT NULL PRIMARY KEY DEFAULT true CHECK (singleton),
  display_name  text,
  logo_url      text,
  primary_color text,
  terms_url     text,
  privacy_url   text,
  updated_at    timestamptz NOT NULL DEFAULT now()
);

INSERT INTO branding (singleton) VALUES (true) ON CONFLICT DO NOTHING;
