-- Tenant language and custom sign-in copy — docs/contracts/m0.md §6.1 sign-in experience.
--
-- The built-in copy is English and lives in the hosted page; a tenant may translate any phrase and
-- choose the language visitors get by default. Overrides are keyed by the same dotted names the
-- page renders, so a key the page does not know is inert rather than a string it has to invent.
--
-- A language tag is stored lowercased so the primary key cannot hold two spellings of one tag. A
-- language with no rows is still meaningful: it is the tenant's default and means "built-in copy
-- with <html lang> set", which is what every tenant has before customising anything.

ALTER TABLE sign_in_experience
  ADD COLUMN IF NOT EXISTS language text NOT NULL DEFAULT 'en'
    CHECK (language ~ '^[a-z]{2,3}(-[a-z0-9]{1,8})*$' AND char_length(language) <= 35);

CREATE TABLE IF NOT EXISTS sign_in_phrases (
  language   text NOT NULL CHECK (language ~ '^[a-z]{2,3}(-[a-z0-9]{1,8})*$'
                                  AND char_length(language) <= 35),
  phrase_key text NOT NULL CHECK (phrase_key ~ '^[a-z][A-Za-z0-9]*(\.[a-z][A-Za-z0-9]*){1,3}$'
                                  AND char_length(phrase_key) BETWEEN 3 AND 100),
  value      text NOT NULL CHECK (char_length(value) BETWEEN 1 AND 500),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (language, phrase_key)
);
