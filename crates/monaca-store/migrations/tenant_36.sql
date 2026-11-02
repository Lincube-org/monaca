-- Per-purpose mail copy — docs/contracts/m0.md §6.3. A missing row means the built-in default;
-- the server renders the tenant's row, or the default, into every outbox `mail.verification`
-- payload, so an administrator can reword a code or notice without a deployment.
CREATE TABLE IF NOT EXISTS email_templates (
  purpose    text PRIMARY KEY CHECK (purpose IN
               ('sign_up','sign_in','password_reset','email_change','delete_account',
                'sign_in_link','email_changed','password_changed','account_deleted')),
  subject    text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 200),
  body       text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 10000),
  updated_at timestamptz NOT NULL DEFAULT now()
);
