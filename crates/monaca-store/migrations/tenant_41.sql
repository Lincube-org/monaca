-- hCaptcha joins the CAPTCHA provider set — docs/contracts/m0.md §6.1.
--
-- The provider is one tenant-wide value and all three providers share the same siteverify form
-- (`secret`, `response`) and the same `{"success": bool}` answer, so adding one is a constraint
-- change rather than a new table. The secret stays in `captcha_secret_enc`, sealed with the
-- tenant DEK. tenant_37 created the constraint inline, which Postgres named after the column.
ALTER TABLE sign_in_experience
  DROP CONSTRAINT IF EXISTS sign_in_experience_captcha_provider_check,
  ADD CONSTRAINT sign_in_experience_captcha_provider_check
    CHECK (captcha_provider IN ('turnstile', 'recaptcha', 'hcaptcha'));
