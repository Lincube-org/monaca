-- Username policy and display case — docs/contracts/m0.md §6.1.
--
-- ASCII letters and digits are always allowed; the tenant chooses which punctuation characters
-- may accompany them. Defaults reproduce the previous grammar (letters, digits, `_`, `-`), so an
-- existing tenant behaves exactly as before until it changes a switch.
--
-- `username_preserve_case` keeps the typed form in `account_identifiers.display_value` for
-- presentation while `value` stays lowercased for sign-in lookup and the unique index. It is
-- only meaningful while `username_case_sensitive` is false: a case-sensitive tenant already
-- stores and compares the typed form, so both switches on is a rejected configuration.
--
-- `username_reserved_words` is compared lowercased against the whole username, so `Admin` and
-- `admin` are both refused. Existing identifiers are never rewritten by this migration or by a
-- policy change; the rules apply to new usernames and username changes only.
ALTER TABLE sign_in_experience
  ADD COLUMN IF NOT EXISTS username_allowed_punctuation text[] NOT NULL DEFAULT ARRAY['_', '-'],
  ADD COLUMN IF NOT EXISTS username_allow_email_local_part boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS username_preserve_case boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS username_reserved_words text[] NOT NULL DEFAULT '{}';

ALTER TABLE sign_in_experience
  ADD CONSTRAINT sign_in_experience_username_punctuation_check
    CHECK (username_allowed_punctuation <@ ARRAY['_', '-', '.']),
  ADD CONSTRAINT sign_in_experience_username_reserved_count_check
    CHECK (cardinality(username_reserved_words) <= 100);

ALTER TABLE account_identifiers
  ADD COLUMN IF NOT EXISTS display_value text
    CHECK (display_value IS NULL OR char_length(display_value) BETWEEN 1 AND 32);
