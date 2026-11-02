-- Registration policy and sign-up profile fields — docs/contracts/m0.md §6.1, §6.2.
ALTER TABLE sign_in_experience
  ADD COLUMN IF NOT EXISTS sign_up_identifiers text[] NOT NULL DEFAULT '{email}',
  ADD COLUMN IF NOT EXISTS sign_up_email_verification_required boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS username_case_sensitive boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS username_min_length integer NOT NULL DEFAULT 3,
  ADD COLUMN IF NOT EXISTS username_max_length integer NOT NULL DEFAULT 32,
  ADD COLUMN IF NOT EXISTS sign_up_profile_fields text[] NOT NULL DEFAULT '{name}';
