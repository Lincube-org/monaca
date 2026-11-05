-- Delivery channels, multilingual templates and retry backoff — docs/contracts/m0.md §6.3/§6.5.
--
-- `email_connector` becomes `delivery_connector`, keyed by channel. A tenant has at most one
-- connector per channel. Existing rows are email rows, so the default keeps them working.
ALTER TABLE email_connector RENAME TO delivery_connector;
ALTER TABLE delivery_connector ADD COLUMN channel text NOT NULL DEFAULT 'email';

ALTER TABLE delivery_connector DROP CONSTRAINT IF EXISTS email_connector_pkey;
ALTER TABLE delivery_connector DROP CONSTRAINT IF EXISTS delivery_connector_pkey;
ALTER TABLE delivery_connector DROP COLUMN singleton;
ALTER TABLE delivery_connector ADD CONSTRAINT delivery_connector_pkey PRIMARY KEY (channel);

ALTER TABLE delivery_connector DROP CONSTRAINT IF EXISTS email_connector_provider_check;
ALTER TABLE delivery_connector DROP CONSTRAINT IF EXISTS delivery_connector_provider_check;
ALTER TABLE delivery_connector ADD CONSTRAINT delivery_connector_provider_check
  CHECK ((channel = 'email' AND provider IN ('http','smtp'))
      OR (channel = 'sms'   AND provider IN ('http','twilio')));

ALTER TABLE delivery_connector DROP CONSTRAINT IF EXISTS email_connector_from_address_check;
ALTER TABLE delivery_connector DROP CONSTRAINT IF EXISTS delivery_connector_from_address_check;
ALTER TABLE delivery_connector ADD CONSTRAINT delivery_connector_from_address_check
  CHECK (char_length(from_address) BETWEEN 1 AND 320);

ALTER TABLE delivery_connector ADD CONSTRAINT delivery_connector_channel_check
  CHECK (channel IN ('email','sms'));

-- SMS verification codes share the existing single-use code table. The purpose is separate from
-- the email purposes so a code minted for one channel cannot redeem the other.
ALTER TABLE verification_codes DROP CONSTRAINT IF EXISTS verification_codes_purpose_check;
ALTER TABLE verification_codes ADD CONSTRAINT verification_codes_purpose_check
  CHECK (purpose IN ('sign_up','sign_in','password_reset','email_change','delete_account',
                     'sign_in_link','sms_verification'));

-- Account-level language, used as the first step of the mail fallback chain. NULL means the
-- tenant default applies.
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS locale text
  CHECK (locale IS NULL OR char_length(locale) BETWEEN 2 AND 35);

-- A failure waits before the next attempt instead of being retried on the next 5 s tick.
ALTER TABLE outbox ADD COLUMN IF NOT EXISTS next_attempt_at timestamptz;
CREATE INDEX IF NOT EXISTS outbox_retry_idx
  ON outbox (next_attempt_at) WHERE published_at IS NULL;

-- Tenant customisations, now keyed by locale. Existing rows were English overrides.
ALTER TABLE email_templates RENAME TO message_template_overrides;
ALTER TABLE message_template_overrides ADD COLUMN locale text NOT NULL DEFAULT 'en';
ALTER TABLE message_template_overrides ADD COLUMN channel text NOT NULL DEFAULT 'email'
  CHECK (channel IN ('email','sms'));
ALTER TABLE message_template_overrides DROP CONSTRAINT IF EXISTS email_templates_pkey;
ALTER TABLE message_template_overrides DROP CONSTRAINT IF EXISTS message_template_overrides_pkey;
ALTER TABLE message_template_overrides
  ADD CONSTRAINT message_template_overrides_pkey PRIMARY KEY (purpose, locale);
ALTER TABLE message_template_overrides DROP CONSTRAINT IF EXISTS email_templates_purpose_check;
ALTER TABLE message_template_overrides DROP CONSTRAINT IF EXISTS message_template_overrides_purpose_check;
ALTER TABLE message_template_overrides ADD CONSTRAINT message_template_overrides_purpose_check
  CHECK (purpose IN ('sign_up','sign_in','password_reset','email_change','delete_account',
                     'sign_in_link','email_changed','password_changed','account_deleted',
                     'invitation','sms_verification'));

-- Built-in copy, seeded from the JSON resources in this crate by `apply_tenant`. A row removed
-- here is a deliberate "this locale has no copy": sending fails instead of falling through to a
-- placeholder. `monaca-server migrate` and the restore endpoint re-seed missing rows.
CREATE TABLE IF NOT EXISTS message_templates (
  purpose text NOT NULL CHECK (purpose IN
            ('sign_up','sign_in','password_reset','email_change','delete_account',
             'sign_in_link','email_changed','password_changed','account_deleted',
             'invitation','sms_verification')),
  locale  text NOT NULL CHECK (char_length(locale) BETWEEN 2 AND 35),
  channel text NOT NULL CHECK (channel IN ('email','sms')),
  subject text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 200),
  body    text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 10000),
  PRIMARY KEY (purpose, locale)
);
