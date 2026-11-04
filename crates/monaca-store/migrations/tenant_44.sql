-- Cap joins the CAPTCHA provider set — docs/contracts/m0.md §6.1.
--
-- Cap Standalone exposes a reCAPTCHA-compatible siteverify under the site key path:
-- `POST {base_url}/{site_key}/siteverify` with a JSON body (`secret`, `response`). The site key
-- and the sealed secret therefore stay in the columns tenant_37 added; this migration only makes
-- the provider name valid and stores the instance's public base URL, which also prefixes the
-- widget's `data-cap-api-endpoint`. The URL is tenant-supplied and never carries a secret.
ALTER TABLE sign_in_experience
  DROP CONSTRAINT IF EXISTS sign_in_experience_captcha_provider_check,
  ADD CONSTRAINT sign_in_experience_captcha_provider_check
    CHECK (captcha_provider IN ('turnstile', 'recaptcha', 'hcaptcha', 'cap')),
  ADD COLUMN IF NOT EXISTS captcha_cap_base_url text;
