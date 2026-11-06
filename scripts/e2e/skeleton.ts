// `bun run e2e:skeleton --base-url <url>` — the single acceptance script (contract §12, plan §13).
//
// Runs the whole M0 walk-through against any origin: localhost:8080 (the dev gateway), the deployed
// dev gateway, or the CI server started from the `server-*` artifact. Steps 4 and 4b need the demo
// MCP module, which only the gateway mounts — against the server alone they are reported as
// `skip`, which is the honest answer rather than a silent pass.
//
// The walk-through, verbatim from §12:
//   1  health
//   2  setup: create an account, add it to `acme`, register an agent, register a locally generated
//      ES256 public key, grant `tools:read` on `{base}/mcp/demo`
//   3  the agent exchanges a `private_key_jwt` assertion for a delegated token
//   3b the same request widened to `tools:write` is refused
//   4  `list_notes` succeeds; 4b `delete_note` is refused with `insufficient_scope`
//   5  the audit page shows account → grant → agent → token(jti) → tool and the chain verifies
import { createHmac } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { describeNetError } from "../lib/net.ts";
import { startSmsCapture } from "../sms-capture.ts";
import { startSmtpCapture } from "../smtp-capture.ts";
import { createMonacaClient } from "../../packages/sdk/src/index.ts";

const ROOT = join(import.meta.dir, "..", "..");
const REPORT = join(ROOT, ".monaca", "reports", "skeleton.json");

/** The M0 org the walk-through lives in (contract §5.6 bootstrap). */
const ORG = "acme";
/** The M0 tenant (contract §5.6 bootstrap). */
const TENANT = "demo";
/** The client that may ask the management API for `monaca:admin` tokens (contract §5.7). */
const ADMIN_CLIENT_ID = "monaca-admin";
/** The local sign-in the browser flow uses (contract §2.2 bootstrap). */
const BOOTSTRAP_ADMIN = { email: "admin@demo.localhost", password: "monaca-dev-password" };

/** One entry per contract §12 row. `step` matches the contract's numbering. */
const ACCEPTANCE_STEPS: { step: string; title: string; assertion: string }[] = [
  {
    step: "1",
    title: "health",
    assertion: 'GET {base}/healthz → 200, status == "ok"',
  },
  {
    step: "2",
    title: "setup",
    assertion:
      "POST /v1/accounts, POST /v1/orgs/acme/members, POST /v1/orgs/acme/agents, " +
      "POST /v1/orgs/acme/agents/{id}/keys (locally generated ES256 public JWK), " +
      'POST /v1/orgs/acme/grants (scopes=["tools:read"], resource="{base}/mcp/demo")',
  },
  {
    step: "3",
    title: "token grant",
    assertion:
      "POST /t/demo/oauth2/token grant_type=client_credentials with a private_key_jwt assertion " +
      "→ 200; act.sub == agt_…, scope == [\"tools:read\"], exp - iat == 300, sub == acc_…",
  },
  {
    step: "3b",
    title: "over-request denied",
    assertion: 'same request with scope=tools:write → 400 {"error":"invalid_scope"}',
  },
  {
    step: "4",
    title: "allowed tool",
    assertion: "MCP tools/call list_notes with the token → success",
  },
  {
    step: "4b",
    title: "denied tool",
    assertion:
      'MCP tools/call delete_note → 403, WWW-Authenticate contains error="insufficient_scope" ' +
      'and scope="tools:write"',
  },
  {
    step: "5",
    title: "audit chain",
    assertion:
      "GET /v1/orgs/acme/audit?grant_id=grt_… shows account → grant → agent → token(jti) → tool; " +
      "GET /v1/orgs/acme/audit/verify → {\"valid\":true}",
  },
  {
    step: "6",
    title: "browser flow",
    assertion:
      "authorize → interaction → code → id_token(nonce,email) + refresh → rotation → replay refused",
  },
  {
    step: "7",
    title: "session & logout",
    assertion:
      "sign-in sets the monaca_session cookie; a silent prompt=none authorize reuses it; " +
      "GET/DELETE /v1/accounts/{id}/sessions manage it; " +
      "GET /t/demo/oauth2/end-session echoes state, clears the cookie and a later silent authorize is login_required",
  },
  {
    step: "8",
    title: "email verification",
    assertion:
      "sign-up → GET /internal/mail code → sign-up/verify → token; sign-in/code → code → verify → token; " +
      "password/forgot → password/reset → the old password is 401 and the new one signs in",
  },
  {
    step: "9",
    title: "two-step verification",
    assertion:
      "POST /t/demo/account/mfa/totp (session cookie) → secret + otpauth_url; verify a computed TOTP → enabled; " +
      "a new sign-in answers {\"mfa_required\":true}; a wrong code is 401 and the right one mints a token; " +
      "DELETE the credential → the next sign-in needs one factor again",
  },
  {
    step: "10",
    title: "account centre",
    assertion:
      "PATCH /t/demo/account changes the display name and GET echoes it; POST /account/password with a wrong " +
      "current password is 401, the right one is 204 and signs out the other sessions; the old password is " +
      "refused and the new one signs in; GET /account/sessions marks the caller current; DELETE one and " +
      "DELETE all others revoke them",
  },
  {
    step: "11",
    title: "MFA backup codes",
    assertion:
      "POST /t/demo/account/mfa/backup-codes (session cookie, authenticator enrolled) → ten grouped codes; " +
      "a sign-in challenge lists totp and backup_code; a wrong code is 401; a typed (uppercase, hyphenated) " +
      "code completes the flow and issues a token; the same code is refused on replay; GET reports the " +
      "remaining count; DELETE removes them and the next challenge offers totp only",
  },
  {
    step: "12",
    title: "passkeys",
    assertion:
      "POST /t/demo/account/passkeys/options → creation options (rp.localhost, a challenge); the registration " +
      "ceremony stores a pky_… key (201) and mfa.passkeys becomes 1; an assertion signs in without a password " +
      "and a stale assertion is 401; PATCH renames it; with TOTP enrolled the challenge lists totp and passkey " +
      "and POST /mfa/passkey completes it; DELETE removes the key and the next challenge offers totp only",
  },
  {
    step: "13",
    title: "username identifiers",
    assertion:
      "PATCH /t/demo/account {username} (session cookie) stores it lowercased and GET echoes it; a new sign-in " +
      "accepts the username case-insensitively and mints a token; an unknown identifier is 401; another account " +
      "claiming the same username (any case) is 409 MONACA_USERNAME_TAKEN; an invalid username is 400",
  },
  {
    step: "14",
    title: "email change",
    assertion:
      "POST /t/demo/account/email (session cookie) answers verification_required and dev mail carries an " +
      "email_change code to the new address; a wrong code is 401; the right code moves the account and " +
      "GET /account echoes the new address; the old address no longer signs in while the new one mints a " +
      "token; another account's address is 409 MONACA_EMAIL_TAKEN and the current one is 400",
  },
  {
    step: "15",
    title: "social connectors",
    assertion:
      "POST /v1/connectors registers an OAuth2 provider (a duplicate slug is 409 MONACA_CONNECTOR_EXISTS) " +
      "and GET /v1/connectors lists it without the secret; the public list shows only the display name; the " +
      "account centre connects it (?linked=), GET /account lists it; the provider signs in without a password " +
      "and mints a token; a replayed callback is 400; another account connecting the same provider account is " +
      "refused (social_error=taken); a first social sign-in creates the account and issues a token; " +
      "DELETE /account/social/{connector} is 204 and the profile no longer lists it; DELETE /v1/connectors " +
      "is 204 and a missing one is 404",
  },
  {
    step: "16",
    title: "trusted browsers",
    assertion:
      "An account enrols an authenticator; a password sign-in answers mfa_required and " +
      "POST …/mfa/verify {remember_device:true} sets a monaca_mfa_device cookie and mints a token; " +
      "GET /account/mfa/devices lists the browser as current and GET /account counts it; the next sign-in " +
      "with that cookie skips the challenge and mints a token, while an unknown cookie still asks; " +
      "DELETE /account/mfa/devices/{device} is 204 and clears the caller's cookie; a sign-in with the " +
      "revoked cookie asks again and the list and profile count zero",
  },
  {
    step: "17",
    title: "account deletion",
    assertion:
      "An account owning an agent and a membership in acme requests deletion with its session cookie; " +
      "dev mail carries a delete_account code; a wrong code is 401; the right code is 204 and clears " +
      "monaca_session; the old session is 401, the old email no longer signs in, GET /v1/accounts/{id} " +
      "is 404, and the membership and the agent the account owned are gone",
  },
  {
    step: "18",
    title: "sign-in links",
    assertion:
      "POST /t/demo/interaction/{iid}/sign-in/link {email} answers verification_required regardless of " +
      "the address; dev mail carries a /sign-in/link/verify?token= URL; opening it is 302 to the client " +
      "with a code and the token exchange mints an id_token for the account; the same URL is 401 on " +
      "replay and a made-up token is 401",
  },
  {
    step: "19",
    title: "roles",
    assertion:
      "POST /v1/roles creates a role with permission scopes (a duplicate name is 409 MONACA_ROLE_EXISTS) " +
      "and GET lists it; assigning it to an account is 204 and the id_token carries it in `roles`; " +
      "assigning an unknown role is 404; unassigning is 204 and the next id_token has no roles claim; " +
      "DELETE /v1/roles is 204 and a missing one is 404",
  },
  {
    step: "20",
    title: "scope grants",
    assertion:
      "an account without a role requesting `openid tools:read` is refused at sign-in with " +
      "403 MONACA_INSUFFICIENT_SCOPE; after a role granting tools:read is assigned the same sign-in " +
      "completes and the access token carries tools:read; deleting the role is 204",
  },
  {
    step: "21",
    title: "login hint",
    assertion:
      "GET authorize with `login_hint` → GET interaction echoes it for the auth-ui to prefill; an " +
      "authorize without one reports null, and a hint naming an unknown address is echoed too (the " +
      "endpoint is not an address oracle); signing in with the hinted identifier mints a token",
  },
  {
    step: "22",
    title: "applications",
    assertion:
      "POST /v1/clients registers a public client (no secret, PKCE-only) and a confidential one " +
      "(a secret returned once); a duplicate client_id is 409 MONACA_CLIENT_EXISTS; each signs in " +
      "through authorize → interaction → code → token; rotating the confidential secret refuses the " +
      "old one and accepts the new one; PATCH renames it; GET /v1/clients lists both without secrets; " +
      "DELETE removes one and authorize refuses its client_id",
  },
  {
    step: "23",
    title: "user management",
    assertion:
      "GET /v1/accounts?query=… finds an account by a substring of its email; " +
      "PATCH /v1/accounts/{id} {state:disabled} suspends it — the password is 401, the previously " +
      "issued session cookie is 401, the previous access token is 401 on /v1 and userinfo, and the " +
      "refresh token is 400 invalid_grant — and {state:active} restores sign-in without resurrecting " +
      "the withdrawn token; an invalid state is 400 and an unknown account is 404",
  },
  {
    step: "24",
    title: "sign-in experience",
    assertion:
      "GET /t/demo/sign-in-experience is public and starts with every switch on; " +
      "PATCH /v1/sign-in-experience {sign_up_enabled:false,password_sign_in_enabled:false} answers 200 " +
      "and the public read follows; sign-up is 403 MONACA_SIGN_UP_DISABLED, the password is 403 " +
      "MONACA_PASSWORD_SIGN_IN_DISABLED, and email codes still work; disabling email codes refuses " +
      "them and keeps the password; disabling both is 400, an empty patch is 400, and re-enabling " +
      "restores every method",
  },
  {
    step: "25",
    title: "api resources",
    assertion:
      "POST /v1/resources registers an absolute http(s) identifier with its scopes (a duplicate is " +
      "409 MONACA_RESOURCE_EXISTS, a relative identifier is 400) and GET lists it; an authorize " +
      "naming the resource may only ask for its scopes, so a scope it does not define is " +
      "error=invalid_scope before the page opens; after PATCH adds the scope a role-granted sign-in " +
      "completes and the access token carries aud=the resource; DELETE is 204 and a missing one is 404",
  },
  {
    step: "26",
    title: "organizations",
    assertion:
      "POST /v1/orgs provisions an org and returns 201 with an org_ id (a duplicate slug is " +
      "409 MONACA_ORG_EXISTS, an invalid slug is 400); GET /v1/orgs lists it with its state, and " +
      "GET /v1/orgs/{org} resolves both the slug and the typed id; a member added to the new org is " +
      "listed there; PATCH {state:archived} is 200, the authorize naming that org redirects " +
      "error=invalid_request and its member list is 404, while GET by id still reports it; " +
      "{state:active} restores sign-in and membership, an invalid state is 400, and an unknown org is 404",
  },
  {
    step: "27",
    title: "org members",
    assertion:
      "PATCH /v1/orgs/{org}/members/{account} re-roles a member (200, and GET lists the new role) " +
      "while an invalid role is 400, an account that is not a member is 404 and repeating the " +
      "current role writes nothing; DELETE is 204 and the membership disappears from " +
      "GET /v1/orgs/{org}/members while the account itself survives (GET /v1/accounts/{id} is 200), " +
      "and deleting it again is 404",
  },
  {
    step: "28",
    title: "org email domains",
    assertion:
      "POST /v1/orgs/{org}/email-domains registers a domain (201; a duplicate is 409 " +
      "MONACA_DOMAIN_EXISTS, an invalid name is 400) and GET lists it; an account whose email is at " +
      "that domain signs in to an authorize naming the org and joins just in time (sign-in → code → " +
      "token with the org), while an account from another domain is 403 MONACA_INSUFFICIENT_SCOPE; " +
      "DELETE is 204, the list is empty, and deleting it again is 404",
  },
  {
    step: "29",
    title: "org roles",
    assertion:
      "POST /v1/orgs/{org}/roles defines a scoped role (201; a duplicate name is 409 " +
      "MONACA_ORG_ROLE_EXISTS, an invalid scope is 400) and GET lists it; PATCH replaces its scopes " +
      "and DELETE removes it; assigning it to a member is 204 and GET …/members/{account}/roles " +
      "lists it; a member asking for a scope only its org role grants signs in (200 → code → token), " +
      "the id_token carries org_roles and the access token carries the scope; before the assignment " +
      "the same request is 403 MONACA_INSUFFICIENT_SCOPE; unassigning is 204 and repeating it is 404",
  },
  {
    step: "30",
    title: "org invitations",
    assertion:
      "POST /v1/orgs/{org}/invitations invites an address with a role (201, lowercased; a live " +
      "duplicate is 409 MONACA_INVITATION_EXISTS, an invalid address is 400) and GET lists it; the " +
      "invited account signs in to an authorize naming the org and joins with the invited role " +
      "(sign-in → code → token with the org), after which the invitation is no longer listed; a " +
      "revoked invitation is gone from the list, and that account's sign-in is 403 " +
      "MONACA_INSUFFICIENT_SCOPE",
  },
  {
    step: "31",
    title: "enterprise SSO",
    assertion:
      "POST /v1/sso-connectors registers an OIDC provider with an email domain (201; a duplicate " +
      "slug is 409 MONACA_SSO_CONNECTOR_EXISTS, a claimed domain is 409 MONACA_SSO_DOMAIN_TAKEN, " +
      "a malformed domain or relative URL is 400) and GET /t/demo/sso-connectors?email= finds it; " +
      "an authorize naming the org starts sso/{connector}/authorize, the provider round-trip " +
      "creates the account and joins the org (302 → code → token with the org), while an asserted " +
      "address outside the connector's domains is 403 MONACA_SSO_DOMAIN_MISMATCH; DELETE is 204, " +
      "the lookup is empty, and deleting it again is 404",
  },
  {
    step: "32",
    title: "account security",
    assertion:
      "an account enrolls TOTP through its own session; GET /v1/accounts/{id}/security reports " +
      "mfa.totp=true, the recovery-code count and its (empty) passkey list; DELETE " +
      "/v1/accounts/{id}/mfa is 204 and the next GET reports mfa.totp=false, after which a fresh " +
      "sign-in completes without a second-factor challenge; an unknown passkey or account is 404",
  },
  {
    step: "33",
    title: "mandatory MFA",
    assertion:
      "PATCH /v1/sign-in-experience {mfa_enabled:true,mfa_policy:mandatory} is 200 (mfa_enabled=false " +
      "with a mandatory policy is 400); an account with no factor signs in and is answered " +
      "{mfa_enrollment_required:true}; POST …/mfa/enroll returns a secret and otpauth URL, " +
      "POST …/mfa/enroll/verify with a computed code finishes the flow, and the next sign-in is " +
      "challenged with mfa_required and factors=[totp]; restoring user_controlled succeeds",
  },
  {
    step: "34",
    title: "webhooks",
    assertion:
      "POST /v1/webhooks subscribes a local receiver to account.created and returns a signing key once; " +
      "creating an account posts a signed event the receiver verifies and the delivery log records; " +
      "enabled=false pauses deliveries, rotating the key changes the signature, and DELETE is 204",
  },
  {
    step: "35",
    title: "password policy",
    assertion:
      "PATCH /v1/sign-in-experience {password_min_length:12} is 200 and the public read follows (7 and 65 are 400); " +
      "an administrator's create and a self-service sign-up with a 9-character password are both 400 " +
      "MONACA_WEAK_PASSWORD, while a password at the new minimum completes; restoring 8 succeeds",
  },
  {
    step: "36",
    title: "branding",
    assertion:
      "PATCH /v1/sign-in-experience with a branding object (display name, logo, #rrggbb colour, terms and privacy links) " +
      "is 200 and the public read echoes it; a relative URL and a non-hex colour are 400; an empty string clears a field; " +
      "clearing every field restores the built-in look",
  },
  {
    step: "37",
    title: "account profile editing",
    assertion:
      "PATCH /v1/accounts/{id} {display_name,username} is 200 and GET echoes both; an empty patch or a blank display name " +
      "is 400; a username another account holds is 409 MONACA_USERNAME_TAKEN; a state-only patch still suspends and " +
      "reactivates",
  },
  {
    step: "38",
    title: "session lifetimes",
    assertion:
      "PATCH /v1/sign-in-experience {session_ttl_secs,refresh_token_ttl_secs} outside their ranges is 400; a one-hour " +
      "session and a two-hour refresh token are 200 and the public read follows; the next sign-in sets an SSO cookie " +
      "with Max-Age=3600 and its stored session expires at the same time; the code exchange mints a refresh token; " +
      "restoring the 30-day defaults succeeds",
  },
  {
    step: "39",
    title: "password complexity",
    assertion:
      "PATCH /v1/sign-in-experience {password_min_character_types:3} is 200 (0 and 5 are 400) and the public read " +
      "follows; an administrator's create and a self-service sign-up with a lowercase-only password are both 400 " +
      "MONACA_WEAK_PASSWORD, while a password using three character types completes; restoring 1 accepts the " +
      "lowercase-only password",
  },
  {
    step: "40",
    title: "custom CSS",
    assertion:
      "PATCH /v1/sign-in-experience {branding:{custom_css:…}} is 200 and the public read echoes the stylesheet; " +
      "a stylesheet over 20,000 characters is 400; an empty string clears it back to null",
  },
  {
    step: "41",
    title: "password rejections",
    assertion:
      "PATCH /v1/sign-in-experience toggles password_reject_user_info and password_reject_repetition_and_sequence " +
      "and the public read follows; with user-info on, an administrator's password containing the email local part " +
      "is 400 MONACA_WEAK_PASSWORD; with repetition on, four identical or four consecutive characters are 400; " +
      "clean passwords are 201 and the defaults are restored",
  },
  {
    step: "42",
    title: "password word list",
    assertion:
      "PATCH /v1/sign-in-experience {password_rejected_words:[\"monaca\",\"QWERTY\"]} is 200, lowercased, and the " +
      "public read follows; a word shorter than three characters and a list over 100 words are 400; a password " +
      "containing a listed word is 400 MONACA_WEAK_PASSWORD while a clean one is 201; an empty list restores none",
  },
  {
    step: "43",
    title: "application custom CSS",
    assertion:
      "PATCH /v1/clients/{client} {custom_css:…} is 200 and GET /t/{tenant}/sign-in-experience?client_id=… serves " +
      "that stylesheet; without client_id or for an unknown client_id the tenant's CSS is served; a stylesheet " +
      "over 20,000 characters is 400; an empty string clears it and the client-scoped read falls back",
  },
  {
    step: "44",
    title: "passkey sign-in switch",
    assertion:
      "PATCH /v1/sign-in-experience {passkey_sign_in_enabled:false} is 200 and the public read follows; an " +
      "interaction's POST …/sign-in/passkey/options is 403 MONACA_PASSKEY_SIGN_IN_DISABLED, while after switching " +
      "it back on the same endpoint returns discoverable-credential options with an empty allowCredentials",
  },
  {
    step: "45",
    title: "account avatar",
    assertion:
      "PATCH /v1/accounts/{id} {avatar_url:…} is 200 and the directory carries it, while a relative URL is 400; " +
      "the account centre's PATCH /t/{tenant}/account updates and clears it; an authorization code exchanged with " +
      "the profile scope mints an id_token whose picture is the avatar",
  },
  {
    step: "46",
    title: "trusted-device policy",
    assertion:
      "PATCH /v1/sign-in-experience sets mfa_trusted_devices_enabled and a 1–365-day " +
      "mfa_trusted_device_ttl_days (0 and 366 are 400) and the public read follows; a remembered browser's cookie " +
      "uses that Max-Age and its row expires that many days out; switching the policy off makes an existing device " +
      "cookie ask for MFA again and a new remember_device request is not remembered",
  },
  {
    step: "47",
    title: "enterprise SSO switch",
    assertion:
      "with a registered connector, GET /t/demo/sso-connectors?email= finds it; PATCH " +
      "{single_sign_on_enabled:false} is 200 and the public read follows, the lookup becomes empty, and both the " +
      "provider authorize and callback are 403 MONACA_SSO_DISABLED; switching it back on restores the lookup and a " +
      "302 provider redirect",
  },
  {
    step: "48",
    title: "branding extras",
    assertion:
      "PATCH /v1/sign-in-experience with dark_logo_url, favicon_url, support_email and website_url is 200 and the " +
      "public read echoes them; a relative logo URL and a malformed support email are 400; an empty string clears " +
      "only the named field, and clearing every branding field restores the built-in look",
  },
  {
    step: "49",
    title: "registration policy",
    assertion:
      "PATCH /v1/sign-in-experience validates sign_up_identifiers (email required, username optional), " +
      "sign_up_profile_fields (name, avatar), and username bounds (3–32, min ≤ max), and the public read follows; " +
      "with email verification off, POST …/sign-up {email,password,username,display_name,avatar_url} creates the " +
      "account and signs in, storing the username folded to lowercase and the profile fields; a username outside " +
      "the bounds, a relative avatar, a missing password, an identifier or profile field the policy does not offer " +
      "are 400; switching verification on makes the request step mail a code and refuse a password",
  },
  {
    step: "50",
    title: "consent and authorized apps",
    assertion:
      "a third-party authorize pauses at consent and approving it issues the code; " +
      "GET /t/{tenant}/account/authorized-apps lists the application and its scopes; a stored grant lets " +
      "prompt=none mint a code without the screen while prompt=consent asks again; " +
      "DELETE /t/{tenant}/account/authorized-apps/{client} is 204, removes the row, ends the account's refresh " +
      "tokens for that client, makes the next silent request answer consent_required, and a second delete is 404",
  },
  {
    step: "51",
    title: "email templates",
    assertion:
      "GET /v1/email-templates lists all nine purposes with their writable placeholders and the built-in copy; " +
      "PATCH one with a custom subject and body is 200 and a real sign-up then mails the rendered copy from " +
      "/internal/mail (tenant and code substituted, no literal placeholder); an unknown placeholder, an empty " +
      "subject and an unknown purpose are 400/400/404; DELETE restores the built-in copy with 204 and a second " +
      "DELETE is 204 too; email_template.updated and email_template.reset are on the tenant audit chain",
  },
  {
    step: "52",
    title: "CAPTCHA and lockout",
    assertion:
      "PATCH /v1/sign-in-experience stores provider=hcaptcha (200) and returns secret_set=true while never " +
      "echoing the secret; enabling it without a site key and a secret is 400, and so are an unknown provider, a " +
      "site key over 200 characters and a secret over 500; with on_sign_in=true a POST …/sign-in without " +
      "captcha_token is 400 MONACA_CAPTCHA_FAILED, a token the local siteverify mock rejects is the same, and a " +
      "token it accepts completes the sign-in, while the verify steps stay reachable without a token; one wrong " +
      "password then a correct sign-in clears the counter, and login_lockout_threshold=2 with a 60-second " +
      "duration makes two consecutive wrong passwords lock the identifier, the next attempt being 429 " +
      "MONACA_ACCOUNT_LOCKED audited as interaction.sign_in.failed with reason account_locked",
  },
  {
    step: "53",
    title: "application CORS",
    assertion:
      "POST/PATCH /v1/clients stores cors_allowed_origins (200) and canonicalizes https://App.Example.com:443/ " +
      "to https://app.example.com, while *, a path, a query, userinfo, an origin over 255 characters and a list " +
      "over 32 entries are 400; an OPTIONS /t/demo/oauth2/token preflight with Origin: https://app.example.com " +
      "answers 204 with that Access-Control-Allow-Origin, Access-Control-Allow-Credentials: true and " +
      "Access-Control-Allow-Methods, a GET …/jwks.json from the registered origin carries the allow-origin " +
      "header, an unregistered origin gets neither, and clearing the array removes the header",
  },
  {
    step: "54",
    title: "language and custom copy",
    assertion:
      "PATCH /v1/sign-in-copy {language:'de',phrases:{'signIn.title':'Anmelden'}} is 200 and GET /v1/sign-in-copy " +
      "lists de beside the default en; a bad tag, a single-segment key, a value over 500 characters and an empty " +
      "patch are 400; PATCH {language:'de',phrases:{}} removes the language, PATCH {default_language:'de'} keeps " +
      "the default listed, and each write is on the tenant audit chain as sign_in_copy.updated; " +
      "GET /t/demo/sign-in-copy returns the default, ?lang=de and Accept-Language: de both choose it, and an " +
      "unconfigured ?lang=fr falls back to the default (the hosted page itself is covered by the Playwright walk)",
  },
  {
    step: "55",
    title: "email delivery connector",
    assertion:
      "GET /v1/email-connector is configured:false before any route; PATCH stores an http endpoint, sender and " +
      "sealed secret, returns secret_set without echoing the secret, and rejects smtp, non-http endpoints, " +
      "embedded credentials and a malformed sender with 400; a real sign-up then arrives at a local mock " +
      "provider as one JSON message carrying the rendered copy, outbox id and bearer token; an empty secret " +
      "clears it, DELETE is 204 and the route reads unconfigured, and email_connector.updated/deleted are on " +
      "the tenant audit chain without the secret",
  },
  {
    step: "56",
    title: "username policy",
    assertion:
      "PATCH /v1/sign-in-experience validates username_allowed_punctuation (a unique subset of _, - and .), " +
      "username_reserved_words (3–64 characters, at most 100) and rejects username_preserve_case while " +
      "username_case_sensitive, all with 400; a username using a legacy hyphen is created, then the hyphen is " +
      "removed and that existing name still signs in while a new hyphenated name is 400; under the strict policy " +
      "a valid dotted name passes, an illegal character, an over-long name and the reserved word Admin are 400; " +
      "the email-local-part switch refuses the match and then allows it; and with display preservation on, the " +
      "typed case is returned while a lowercased name signs in and an upper-cased duplicate is 409 " +
      "MONACA_USERNAME_TAKEN",
  },
  {
    step: "57",
    title: "consent semantics",
    assertion:
      "a third-party client's first approval (remembered default) issues a code without a refresh token when " +
      "offline_access was not requested; a repeated request with the same scopes is silent; adding " +
      "offline_access to a prompt=none request answers consent_required, and its interactive screen names only " +
      "offline_access and its token exchange carries a refresh token; adding projects:read answers " +
      "consent_required and its screen names only the new scope, after which the full set is silent again; a " +
      "scope outside the client registration is invalid_scope; a partial approval issues a token carrying only " +
      "the allowed scopes and no refresh token when offline_access was refused, its remembered subset leaves " +
      "the refused scopes consent_required, a fresh password sign-in exposes only the scopes the remembered " +
      "approval does not cover, refusing every scope answers access_denied and consumes the interaction, and " +
      "an allowed scope outside the request is 400; a one-shot approval is listed with remember=false, does " +
      "not cover the next silent request, and withdrawal revokes its refresh token; a client holding both " +
      "kinds is listed once with kinds remember and one_shot, and withdrawal clears both and revokes the " +
      "remembered refresh token; consent.granted events record scopes, remember, mode and interaction id for " +
      "both silent and interactive decisions",
  },
  {
    step: "58",
    title: "Cap proof-of-work CAPTCHA",
    assertion:
      "PATCH /v1/sign-in-experience stores provider=cap with an instance base URL, site key and sealed secret " +
      "and returns secret_set=true without echoing the secret; enabling cap without a base URL and a relative, " +
      "credentialed or over-500-character base URL are 400; the server posts JSON (secret, response) to " +
      "{base}/{site_key}/siteverify exactly as Cap Standalone documents, a token the local mock rejects with " +
      "its real 4xx answer is 400 MONACA_CAPTCHA_FAILED, and a minted {site_key}:id:secret token completes the " +
      "sign-in; the same token replayed is 400 because siteverify consumes it once; two wrong passwords with " +
      "fresh tokens count, the next correct attempt is 429 MONACA_ACCOUNT_LOCKED and is audited as " +
      "interaction.sign_in.failed with reason account_locked",
  },
  {
    step: "59",
    title: "social providers and linking",
    assertion:
      "GitHub and Google connectors store provider, link policy and endpoints from the server presets; an authorize " +
      "redirect carries state, PKCE and (Google) a nonce; a malformed state is 400 and audited state_invalid; a valid " +
      "GitHub callback creates an account and signs it in, a repeat subject reuses that account, and " +
      "auto_link_verified_email attaches a verified email to an existing account while an unverified one is " +
      "403 MONACA_SOCIAL_UNLINKED; confirm_link parks on the hosted page, exposes the pending link, links on confirm " +
      "and rejects a replay; create_new_only refuses an existing email with 409 MONACA_SOCIAL_EMAIL_TAKEN and creates " +
      "when the address is free; a callback without the state cookie, with another browser's cookie or replayed " +
      "is 400; a Google callback verifies the RS256 id_token against the JWKS, refreshes an unknown kid, and rejects " +
      "alg=none, HS256 algorithm confusion, a forged signature, wrong aud/iss, expiry, an unknown kid and a " +
      "mismatched nonce as " +
      "502 MONACA_SOCIAL_PROVIDER_ERROR, while email_verified=false is 403 MONACA_SOCIAL_UNLINKED; disabling a " +
      "connector removes it from the public list and makes its authorize 404; social_sign_in.succeeded/failed and " +
      "social_identity.linked are on the tenant audit chain",
  },
  {
    step: "60",
    title: "revocation propagation",
    assertion:
      "two management tokens are minted for monaca-admin and both open /v1; POST /oauth2/revoke with " +
      "token_type_hint=access_token returns 200 and records the jti, the revoked token is then 401 " +
      "MONACA_UNAUTHORIZED on /v1 while the second token still answers 200, and revoking an unknown token " +
      "is 200 without disclosing anything",
  },
  {
    step: "61",
    title: "rate limits",
    assertion:
      "GET /v1/rate-limits reports the four built-in defaults; an unknown endpoint, a zero limit, a window " +
      "outside 1–86400 and an unknown client_id are 400; a per-client token row at 2 lets two client_credentials " +
      "requests through and answers the third 429 MONACA_TOO_MANY_ATTEMPTS with Retry-After; a tenant-wide " +
      "authorize row at 1 lets one authorize through and refuses the next with the same shape; items:[] restores " +
      "the defaults and a token request succeeds again",
  },
  {
    step: "62",
    title: "flow state survives a restart",
    assertion:
      "a second server process starts from the same binary and database; an authorize interaction created on " +
      "it answers GET /interaction/{iid} with signed_in=false after that process is killed and restarted; a " +
      "password sign-in completes (consent is honoured when the client asks), the code exchanges for a token " +
      "whose sub is the test account, a replay is 409 MONACA_INTERACTION_CONSUMED and an unknown id is 404; a " +
      "TOTP enrollment started before another restart verifies after it; a passkey registration challenge " +
      "issued before a third restart completes after it",
  },
  {
    step: "63",
    title: "rate limits are shared across instances",
    assertion:
      "a second server process is started on the same database; a per-client token row at 2 lets two " +
      "requests through the first process and the third request through the second process is 429 with " +
      "Retry-After, proving the counter is shared; clearing the configuration lets the second process mint " +
      "again",
  },
  {
    step: "64",
    title: "metrics and structured logs",
    assertion:
      "GET /metrics is 200 text/plain; it carries monaca_http_requests_total with a real tenant/endpoint/status " +
      "series, the latency histogram, a positive monaca_rate_limit_rejections_total from this run and a positive " +
      "monaca_revoked_token_rejections_total{surface=\"management\"} from this run; the body contains no internal " +
      "secret",
  },
  {
    step: "65",
    title: "generated SDK against the real server",
    assertion:
      "the committed @monaca/sdk client, generated from spec/openapi.json, calls the running server: " +
      "GET /healthz returns status ok, GET /v1/rate-limits returns the four defaults, and a typed PATCH " +
      "of the same path restores an empty item list",
  },
  {
    step: "66",
    title: "per-IP rate limits",
    assertion:
      "the returned per-IP default is used to send limit+1 token requests for a made-up tenant from one " +
      "X-Forwarded-For address: the first limit are 404 and the next is 429 with Retry-After and " +
      "MONACA_TOO_MANY_ATTEMPTS; a second address is not limited, and the exhausted address can still " +
      "reach authorize because the buckets are per endpoint",
  },
  {
    step: "67",
    title: "tenant lifecycle",
    assertion:
      "`tenant create` provisions a tenant, its org, an admin account and two clients; the admin client " +
      "mints a management token and the public client completes a password sign-in; a dry-run suspend " +
      "reports the transition without writing; suspend makes the same management token and the token " +
      "endpoint answer 403 MONACA_TENANT_SUSPENDED; resume restores both; archive answers " +
      "403 MONACA_TENANT_ARCHIVED and keeps the tenant database, and resume returns it to service",
  },
  {
    step: "68",
    title: "SMS verification",
    assertion:
      "without an SMS connector a code request is 503 MONACA_SMS_NOT_CONFIGURED; after a Twilio-shaped " +
      "connector is configured, a zh-CN request reaches the local capture as a form POST to " +
      "`/2010-04-01/Accounts/<sid>/Messages.json` with basic auth and a Chinese body containing the " +
      "code; an immediate resend is 429, a wrong code is 401, the right code verifies, and a code " +
      "left past its TTL is 401 MONACA_VERIFICATION_CODE_EXPIRED",
  },
  {
    step: "69",
    title: "SMTP delivery",
    assertion:
      "an `smtp://127.0.0.1` connector delivers a rendered password-reset mail to the local SMTP " +
      "capture: MAIL FROM and RCPT TO carry the configured addresses and the raw message carries the " +
      "Subject header and body with the code",
  },
  {
    step: "70",
    title: "template fallback and missing rejection",
    assertion:
      "the message-template list carries en and zh-cn copy for sms_verification; after the built-in " +
      "en sign_up row is removed a sign-up request fails 500 MONACA_TEMPLATE_MISSING naming `sign_up` " +
      "and `en`, the metric records it, and restoring the built-in row makes the same request succeed",
  },
  {
    step: "71",
    title: "administrative disposal",
    assertion:
      "DELETE /v1/accounts/{id}?dry_run=true reports the live sessions and refresh tokens and deletes " +
      "nothing; a delete without `confirm` or with another address is 400 MONACA_CONFIRMATION_REQUIRED; " +
      "`confirm=<email>` deletes the account, its access token is 401 on userinfo, its refresh token is " +
      "400 invalid_grant, the account is 404, and the tenant audit chain still holds account.deleted " +
      "with the operator as actor",
  },
  {
    step: "72",
    title: "session kick-out",
    assertion:
      "two console sign-ins appear as two `ses_…` sessions; DELETE one answers 204, exactly that browser's " +
      "access token is 401 on userinfo while the other still works, introspection reports the kicked " +
      "access and refresh tokens inactive, its refresh token is 400 invalid_grant, and DELETE all ends " +
      "the remaining browser and empties the list",
  },
  {
    step: "73",
    title: "tenant audit query",
    assertion:
      "a non-admin sign-in asking for `monaca:admin` receives a token without that scope and GET /v1/audit " +
      "is 403 MONACA_INSUFFICIENT_SCOPE; the operator's account events are found by subject, exact action, " +
      "action prefix and actor, a future time window is empty and a covering one is not, `limit=1` returns " +
      "one row plus `next` and `total`, a page request of 1,000,000 is clamped to 200, two reads leave the " +
      "head and total unchanged, and a malformed or inverted time window is 400 MONACA_INVALID_REQUEST",
  },
  {
    step: "74",
    title: "revocation watermark",
    assertion:
      "after a session kick the very next userinfo is 401 invalid_token, the very next renewal is 400 " +
      "invalid_grant and the very next introspection is active:false; after an account disable the same " +
      "three calls fail immediately, with no sleep between the write and the probe",
  },
  {
    step: "75",
    title: "tenant usage and quota",
    assertion:
      "GET /v1/usage reports the account counter, the UTC day and its active accounts and logins; " +
      "creating two accounts moves the total by two, one account's two sign-ins add one active account " +
      "and two logins; PATCH /v1/usage {max_accounts: current total} makes remaining 0 and the next " +
      "creation 403 MONACA_QUOTA_EXCEEDED; deleting one account decrements the total and frees one slot; " +
      "clearing the quota makes remaining null, and an empty or negative patch is 400",
  },
  {
    step: "76",
    title: "role access tiers",
    assertion:
      "a role's permissions grant management tiers: management:read opens GET, management:write adds " +
      "ordinary mutations, monaca:admin adds role administration; the tier is re-read from the account's " +
      "current roles so assigning or removing a role changes the next request without a new token, " +
      "issuance keeps monaca:admin only for a full account, and role.updated/assigned/unassigned are " +
      "written to the audit chain",
  },
  {
    step: "77",
    title: "me and tenant lifecycle",
    assertion:
      "GET /v1/me reports the account, its roles and the current management tier, and follows a role " +
      "removal on the same token; GET /v1/tenant reports the lifecycle record; the API refuses " +
      "suspension but archives and reactivates, /v1/me is 403 while archived while the lifecycle read " +
      "still answers, and both transitions are tenant-chain audit events with the tenant as subject",
  },
];

interface StepResult {
  step: string;
  title: string;
  status: "pass" | "fail" | "skip" | "todo";
  ms?: number;
  detail?: string;
}

interface Report {
  base_url: string;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  stage: 1;
  ok: boolean;
  steps: StepResult[];
  error?: string;
}

/** Everything the walk-through discovered, so the report can name what it created. */
interface Walk {
  accountId: string;
  agentId: string;
  keyId: string;
  grantId: string;
  jti: string;
  scope: string;
}

function usage(): string {
  return [
    "usage: bun run e2e:skeleton --base-url <url>",
    "",
    "  --base-url <url>       the public origin to test (http://localhost:8080, the remote dev",
    "                         gateway, or the CI server). Required.",
    "  --admin-secret <s>     the seeded automation client's secret. Defaults to the dev value;",
    "                         set it to the tenant's real secret anywhere else.",
    "  --console-secret <s>   the console client's secret, for the browser-flow step. Defaults to",
    "                         the dev value.",
    "  --internal-secret <s>  the /internal/* shared secret, for reading the dev mail outbox.",
    "                         Defaults to $MONACA_INTERNAL_SECRET, then the dev value.",
    "  --report <path>        where to write the JSON report (default .monaca/reports/skeleton.json).",
    "  --json                 print only the report, not the human-readable lines.",
    "",
    "Steps 4 and 4b are reported as `skip` unless the origin mounts /mcp/demo (the gateway does;",
    "the bare server does not).",
  ].join("\n");
}

function parseArgs(argv: string[]): { baseUrl: string; report: string; json: boolean; adminSecret: string; consoleSecret: string; internalSecret: string } | { error: string } {
  let baseUrl: string | undefined;
  let report = REPORT;
  let json = false;
  let adminSecret = "dev-admin-client-secret";
  let consoleSecret = "dev-console-client-secret";
  let internalSecret = process.env.MONACA_INTERNAL_SECRET ?? "dev-internal-secret-change-me";
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--base-url") {
      baseUrl = argv[++i];
      if (baseUrl === undefined) return { error: "--base-url needs a value" };
    } else if (arg?.startsWith("--base-url=")) {
      baseUrl = arg.slice("--base-url=".length);
    } else if (arg === "--report") {
      const value = argv[++i];
      if (value === undefined) return { error: "--report needs a value" };
      report = value;
    } else if (arg?.startsWith("--report=")) {
      report = arg.slice("--report=".length);
    } else if (arg === "--admin-secret") {
      const value = argv[++i];
      if (value === undefined) return { error: "--admin-secret needs a value" };
      adminSecret = value;
    } else if (arg?.startsWith("--admin-secret=")) {
      adminSecret = arg.slice("--admin-secret=".length);
    } else if (arg === "--console-secret") {
      const value = argv[++i];
      if (value === undefined) return { error: "--console-secret needs a value" };
      consoleSecret = value;
    } else if (arg?.startsWith("--console-secret=")) {
      consoleSecret = arg.slice("--console-secret=".length);
    } else if (arg === "--internal-secret") {
      const value = argv[++i];
      if (value === undefined) return { error: "--internal-secret needs a value" };
      internalSecret = value;
    } else if (arg?.startsWith("--internal-secret=")) {
      internalSecret = arg.slice("--internal-secret=".length);
    } else if (arg === "--json") {
      json = true;
    } else if (arg === "--help" || arg === "-h") {
      return { error: "__help__" };
    } else {
      return { error: `unrecognised argument ${JSON.stringify(arg)}` };
    }
  }
  if (baseUrl === undefined || baseUrl.trim() === "") return { error: "--base-url is required" };
  return { baseUrl: baseUrl.trim(), report, json, adminSecret, consoleSecret, internalSecret };
}

/** Normalises the origin: no trailing slash, so `${base}/healthz` is well formed. */
function normaliseBaseUrl(raw: string): string | { invalid: string } {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return { invalid: `${raw} is not an absolute URL (expected http://host[:port])` };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { invalid: `${parsed.protocol} is not supported; use http or https` };
  }
  return `${parsed.origin}${parsed.pathname.replace(/\/+$/, "")}`;
}

async function writeReport(path: string, report: Report): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(report, null, 2)}\n`, "utf8");
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

interface HttpResult {
  status: number;
  body: unknown;
  headers: Headers;
}

async function call(url: string, init?: RequestInit): Promise<HttpResult> {
  const response = await fetch(url, {
    ...init,
    headers: { accept: "application/json", ...(init?.headers ?? {}) },
    signal: AbortSignal.timeout(20_000),
  });
  const text = await response.text();
  let body: unknown = text;
  if (text.length > 0) {
    try {
      body = JSON.parse(text);
    } catch {
      // A non-JSON body is kept verbatim; the assertions report it.
    }
  }
  return { status: response.status, body, headers: response.headers };
}

/** A form-encoded token-endpoint call, optionally with HTTP Basic client authentication. */
async function tokenCall(
  base: string,
  params: Record<string, string>,
  basic?: string,
): Promise<HttpResult> {
  return call(`${base}/t/${TENANT}/oauth2/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(basic === undefined ? {} : { authorization: `Basic ${basic}` }),
    },
    body: new URLSearchParams(params).toString(),
  });
}

function managementHeaders(accessToken: string): Record<string, string> {
  return { authorization: `Bearer ${accessToken}`, "content-type": "application/json" };
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlJson(value: unknown): string {
  return base64Url(new TextEncoder().encode(JSON.stringify(value)));
}

/** Decodes a JWT payload without verifying it: the walk-through asserts on claims the server just minted. */
function jwtClaims(token: unknown): Record<string, unknown> | undefined {
  if (typeof token !== "string") return undefined;
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  try {
    const parsed: unknown = JSON.parse(atob(parts[1]!.replaceAll("-", "+").replaceAll("_", "/")));
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

/** A console sign-in's outcome: the browser cookie and the tokens the code exchange minted. */
interface ConsoleSignIn {
  cookie?: string;
  accessToken: string;
  refreshToken: string;
}

/**
 * Sign a password account in through the hosted page and exchange the code.
 *
 * Each call starts a new interaction, so two calls model two independent browsers even when they
 * name the same account. A failure is returned rather than thrown so the calling step can report
 * the exact leg that broke.
 */
async function consoleSignIn(
  base: string,
  email: string,
  password: string,
  consoleSecret: string,
  tag: string,
  scope = "openid profile email offline_access",
): Promise<{ session?: ConsoleSignIn; error?: string }> {
  const redirectUri = "http://localhost:5173/bff/callback";
  const verifier = `e-${tag}-${Date.now().toString(36)}-${"w".repeat(32)}`;
  const challenge = base64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
  );
  const authorize = await call(
    `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope,
      state: `st-${tag}`,
      nonce: `n-${tag}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
      resource: `${base}/v1`,
    })}`,
    { redirect: "manual" },
  );
  const interaction = new URL(authorize.headers.get("location") ?? "", base).searchParams.get("interaction");
  if (authorize.status !== 302 || interaction === null) {
    return { error: `authorize(${tag}) → ${authorize.status} ${text(authorize.body)}` };
  }
  const signIn = await call(`${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identifier: email, password }),
  });
  const redirectTo = (signIn.body as { redirect_to?: unknown })?.redirect_to;
  if (signIn.status !== 200 || typeof redirectTo !== "string") {
    return { error: `sign-in(${tag}) → ${signIn.status} ${text(signIn.body)}` };
  }
  const cookie = /monaca_session=([0-9a-f-]{36})/.exec(signIn.headers.get("set-cookie") ?? "")?.[1];
  const code = new URL(redirectTo).searchParams.get("code") ?? "";
  const token = await tokenCall(
    base,
    { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
    btoa(`monaca-console:${consoleSecret}`),
  );
  const accessToken = (token.body as { access_token?: unknown })?.access_token;
  const refreshToken = (token.body as { refresh_token?: unknown })?.refresh_token;
  if (token.status !== 200 || typeof accessToken !== "string" || typeof refreshToken !== "string") {
    return { error: `token(${tag}) → ${token.status} ${text(token.body)}` };
  }
  return { session: { cookie, accessToken, refreshToken } };
}

function text(body: unknown, max = 160): string {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  const collapsed = raw.replace(/\s+/g, " ").trim();
  return collapsed.length <= max ? collapsed : `${collapsed.slice(0, max)}…`;
}

// ---------------------------------------------------------------------------
// the walk-through
// ---------------------------------------------------------------------------

/** A locally generated ES256 key pair: the private half never leaves this process (contract §5). */
async function generateAgentKey(): Promise<{
  publicJwk: Record<string, unknown>;
  sign: (input: string) => Promise<string>;
}> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const publicJwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as unknown as Record<string, unknown>;
  return {
    publicJwk,
    async sign(input: string): Promise<string> {
      const signature = new Uint8Array(
        await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new TextEncoder().encode(input)),
      );
      return base64Url(signature);
    },
  };
}

/** A `private_key_jwt` assertion naming the agent (contract §7.4). */
async function buildAssertion(
  agentId: string,
  base: string,
  sign: (input: string) => Promise<string>,
  kid: string,
): Promise<string> {
  const header = { alg: "ES256", typ: "JWT", kid };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: agentId,
    sub: agentId,
    aud: `${base}/t/${TENANT}/oauth2/token`,
    jti: crypto.randomUUID(),
    iat: now,
    exp: now + 120,
  };
  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(payload)}`;
  return `${signingInput}.${await sign(signingInput)}`;
}

/** An MCP `tools/call` request. */
async function mcpCall(base: string, name: string, args: Record<string, string>, token: string): Promise<HttpResult> {
  return call(`${base}/mcp/demo`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      // The MCP Streamable HTTP transport requires the client to accept both media types even
      // when the server answers with a plain JSON body (`enableJsonResponse`).
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: crypto.randomUUID(), method: "tools/call", params: { name, arguments: args } }),
  });
}

/** Step 2 — build everything the token step needs, through the management API. */
async function setup(
  base: string,
  adminToken: string,
  log: (line: string) => void,
): Promise<{
  ok: boolean;
  detail: string;
  walk?: Walk;
  /** The key pair that was registered: the token step must sign with this very private half. */
  agentKey?: Awaited<ReturnType<typeof generateAgentKey>>;
}> {
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const resource = `${base}/mcp/demo`;

  const account = await call(`${base}/v1/accounts`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      email: `agent-run-${runId}@demo.localhost`,
      display_name: "Agent Run",
      password: "correct-horse-battery-staple",
    }),
  });
  const accountId = (account.body as { id?: string })?.id;
  if (account.status !== 201 || accountId === undefined) {
    return { ok: false, detail: `POST /v1/accounts → ${account.status} ${text(account.body)}` };
  }

  const member = await call(`${base}/v1/orgs/${ORG}/members`, {
    method: "POST",
    headers,
    body: JSON.stringify({ account_id: accountId, role: "member" }),
  });
  if (member.status !== 201) {
    return { ok: false, detail: `POST /v1/orgs/${ORG}/members → ${member.status} ${text(member.body)}` };
  }

  const agent = await call(`${base}/v1/orgs/${ORG}/agents`, {
    method: "POST",
    headers,
    body: JSON.stringify({ name: `ci-bot-${runId}`, owner_account_id: accountId }),
  });
  const agentId = (agent.body as { id?: string })?.id;
  if (agent.status !== 201 || agentId === undefined) {
    return { ok: false, detail: `POST /v1/orgs/${ORG}/agents → ${agent.status} ${text(agent.body)}` };
  }

  const key = await generateAgentKey();
  const registered = await call(`${base}/v1/orgs/${ORG}/agents/${encodeURIComponent(agentId)}/keys`, {
    method: "POST",
    headers,
    body: JSON.stringify({ public_jwk: key.publicJwk, alg: "ES256", kid: "k1" }),
  });
  const keyId = (registered.body as { id?: string })?.id;
  if (registered.status !== 201 || keyId === undefined) {
    return { ok: false, detail: `POST …/agents/{id}/keys → ${registered.status} ${text(registered.body)}` };
  }
  log(`        account=${accountId} agent=${agentId} key=${keyId}`);

  const grant = await call(`${base}/v1/orgs/${ORG}/grants`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      agent_id: agentId,
      account_id: accountId,
      scopes: ["tools:read"],
      resource,
    }),
  });
  const grantBody = grant.body as { id?: string };
  if (grant.status !== 201 || grantBody.id === undefined) {
    return { ok: false, detail: `POST /v1/orgs/${ORG}/grants → ${grant.status} ${text(grant.body)}` };
  }

  return {
    ok: true,
    detail: `account ${accountId}, agent ${agentId}, key ${keyId}, grant ${grantBody.id} on ${resource}`,
    walk: { accountId, agentId, keyId, grantId: grantBody.id, jti: "", scope: "tools:read" },
    agentKey: key,
  };
}

/** Step 3 — the delegated token, and step 3b — the same request widened. */
async function tokenGrants(
  base: string,
  walk: Walk,
  sign: (input: string) => Promise<string>,
): Promise<{ step3: StepResult; step3b: StepResult; accessToken: string }> {
  const assertion = await buildAssertion(walk.agentId, base, sign, "k1");
  const details = JSON.stringify([{ type: "monaca_grant", grant_id: walk.grantId }]);

  const t = performance.now();
  const granted = await tokenCall(base, {
    grant_type: "client_credentials",
    client_id: walk.agentId,
    scope: "tools:read",
    resource: `${base}/mcp/demo`,
    authorization_details: details,
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: assertion,
  });
  const grantedMs = Math.round(performance.now() - t);

  const claims = jwtClaims((granted.body as { access_token?: unknown })?.access_token);
  const scope = claims?.scope;
  const act = claims?.act as { sub?: unknown } | undefined;
  const checks: [string, boolean][] = [
    ["200", granted.status === 200],
    [`sub == acc_…`, typeof claims?.sub === "string" && claims.sub.startsWith("acc_")],
    [`act.sub == ${walk.agentId}`, act?.sub === walk.agentId],
    ['scope == ["tools:read"]', Array.isArray(scope) && scope.join(" ") === "tools:read"],
    ["exp - iat == 300", typeof claims?.exp === "number" && typeof claims?.iat === "number" && claims.exp - claims.iat === 300],
  ];
  const ok = checks.every(([, passed]) => passed);
  walk.jti = typeof claims?.jti === "string" ? claims.jti : "";
  walk.scope = Array.isArray(scope) ? scope.join(" ") : "";

  const widened = await tokenCall(base, {
    grant_type: "client_credentials",
    client_id: walk.agentId,
    scope: "tools:write",
    resource: `${base}/mcp/demo`,
    authorization_details: details,
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: assertion,
  });
  const widenedBody = widened.body as { error?: unknown };

  return {
    step3: {
      step: "3",
      title: "token grant",
      status: ok ? "pass" : "fail",
      ms: grantedMs,
      detail: ok
        ? `200, act.sub=${String(act?.sub)}, scope=[${walk.scope}], jti=${walk.jti}`
        : checks
            .filter(([, passed]) => !passed)
            .map(([name]) => name)
            .concat(`— ${granted.status} ${text(granted.body)}`)
            .join(", "),
    },
    step3b: {
      step: "3b",
      title: "over-request denied",
      status: widened.status === 400 && widenedBody.error === "invalid_scope" ? "pass" : "fail",
      detail:
        widened.status === 400 && widenedBody.error === "invalid_scope"
          ? "400 invalid_scope"
          : `${widened.status} ${text(widened.body)}`,
    },
    accessToken: (granted.body as { access_token?: string })?.access_token ?? "",
  };
}

/** Steps 4 and 4b — the tool calls the guard must allow and refuse. */
async function toolCalls(
  base: string,
  token: string,
): Promise<{ step4: StepResult; step4b: StepResult }> {
  const probe = await mcpCall(base, "list_notes", {}, token);
  if (probe.status === 404) {
    // The bare server does not mount the demo MCP module; only the gateway does.
    const skipped: StepResult = {
      step: "",
      title: "",
      status: "skip",
      detail: `${base} does not mount /mcp/demo — run the walk-through against the gateway`,
    };
    return { step4: { ...skipped, step: "4", title: "allowed tool" }, step4b: { ...skipped, step: "4b", title: "denied tool" } };
  }

  const body = probe.body as { result?: { isError?: boolean; content?: { type: string; text: string }[] } } | undefined;
  const listed = probe.status === 200 && body?.result?.isError !== true && Array.isArray(body?.result?.content);
  const step4: StepResult = {
    step: "4",
    title: "allowed tool",
    status: listed ? "pass" : "fail",
    detail: listed ? `200, list_notes returned ${body?.result?.content?.length ?? 0} content block(s)` : `${probe.status} ${text(probe.body)}`,
  };

  const denied = await mcpCall(base, "delete_note", { id: "note_welcome" }, token);
  const challenge = denied.headers.get("www-authenticate") ?? "";
  const hasScope = /scope="tools:write"/.test(challenge);
  const hasError = /error="insufficient_scope"/.test(challenge);
  const step4b: StepResult = {
    step: "4b",
    title: "denied tool",
    status: denied.status === 403 && hasScope && hasError ? "pass" : "fail",
    detail:
      denied.status === 403 && hasScope && hasError
        ? `403, WWW-Authenticate: ${challenge}`
        : `${denied.status} ${text(denied.body)}${challenge === "" ? "" : ` / ${challenge}`}`,
  };
  return { step4, step4b };
}

/** Step 5 — the delegation chain on the audit page, and the chain's integrity. */
async function auditChain(base: string, adminToken: string, walk: Walk): Promise<StepResult> {
  const headers = managementHeaders(adminToken);
  // The chain spans events that name no grant at all (`agent.created`), so the page is read
  // unfiltered and the grant's own events are picked out of it. Filtering by `grant_id` would
  // only ever show `grant.created` and `agent.token.issued`.
  const page = await call(`${base}/v1/orgs/${ORG}/audit?limit=200`, { headers });
  const items = ((page.body as {
    items?: { action?: string; subject?: { id?: unknown }; actor_chain?: { id?: unknown }[]; jti?: unknown }[];
  })?.items ?? []) as {
    action: string;
    subject: { id?: unknown };
    actor_chain: { id?: unknown }[];
    jti: unknown;
  }[];

  const actions = new Set(items.map((item) => item.action));
  const jtiMatches = items.some((item) => item.jti === walk.jti && item.action === "agent.token.issued");
  const namesAgent = items.some((item) => item.action === "agent.created" && item.subject?.id === walk.agentId);
  const namesGrant = items.some((item) => item.action === "grant.created" && item.subject?.id === walk.grantId);
  const namesAccount = items.some(
    (item) => item.action === "agent.token.issued" && item.actor_chain.some((actor) => actor.id === walk.accountId),
  );

  const verify = await call(`${base}/v1/orgs/${ORG}/audit/verify`, { headers });
  const verified = (verify.body as { valid?: boolean })?.valid === true;

  const checks: [string, boolean][] = [
    ["audit 200", page.status === 200],
    ["account created the agent", namesAgent],
    ["grant names the agent's grant", namesGrant],
    ["agent.key.registered", actions.has("agent.key.registered")],
    ["agent.token.issued with the jti", jtiMatches],
    ["actor chain carries the account", namesAccount],
    ["verify.valid", verified],
  ];
  const ok = checks.every(([, passed]) => passed);
  return {
    step: "5",
    title: "audit chain",
    status: ok ? "pass" : "fail",
    detail: ok
      ? `${items.length} event(s); account → agent → grant → token(${walk.jti}) visible; verify.valid=true, head ${
          (verify.body as { head?: { seq?: number } })?.head?.seq ?? "?"
        }`
      : checks
          .filter(([, passed]) => !passed)
          .map(([name]) => name)
          .join(", "),
  };
}

/** The browser flow the console uses: authorize → interaction → sign-in → code → token → refresh. */
async function browserFlow(base: string, consoleSecret: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const verifier = `v-${runId}-${"x".repeat(32)}`;
  const challenge = base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));

  const authorize = await call(
    `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${runId}`,
      nonce: `n-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`,
    { redirect: "manual" },
  );
  const interaction = new URL(authorize.headers.get("location") ?? "", base).searchParams.get("interaction");
  if (authorize.status !== 302 || interaction === null) {
    return { step: "6", title: "browser flow", status: "fail", detail: `authorize → ${authorize.status} ${text(authorize.body)}` };
  }

  const signIn = await call(`${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: BOOTSTRAP_ADMIN.email, password: BOOTSTRAP_ADMIN.password }),
  });
  const redirectTo = (signIn.body as { redirect_to?: string })?.redirect_to;
  if (signIn.status !== 200 || redirectTo === undefined) {
    return { step: "6", title: "browser flow", status: "fail", detail: `sign-in → ${signIn.status} ${text(signIn.body)}` };
  }
  const code = new URL(redirectTo).searchParams.get("code") ?? "";

  const exchanged = await tokenCall(
    base,
    {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: "monaca-console",
      code_verifier: verifier,
    },
    btoa(`monaca-console:${consoleSecret}`),
  );
  const idToken = (exchanged.body as { id_token?: unknown })?.id_token;
  const refreshToken = (exchanged.body as { refresh_token?: unknown })?.refresh_token;
  const idClaims = jwtClaims(idToken);
  const checks: [string, boolean][] = [
    ["code exchanged", exchanged.status === 200],
    ["id_token nonce echoed", idClaims?.nonce === `n-${runId}`],
    ["id_token email", idClaims?.email === BOOTSTRAP_ADMIN.email],
    ["offline_access issued a refresh token", typeof refreshToken === "string"],
  ];
  const ok = checks.every(([, passed]) => passed);

  let rotated = false;
  if (ok && typeof refreshToken === "string") {
    const refreshed = await tokenCall(
      base,
      { grant_type: "refresh_token", refresh_token: refreshToken, client_id: "monaca-console" },
      btoa(`monaca-console:${consoleSecret}`),
    );
    rotated = refreshed.status === 200;
  }

  const replayed = await tokenCall(
    base,
    {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: "monaca-console",
      code_verifier: verifier,
    },
    btoa(`monaca-console:${consoleSecret}`),
  );

  return {
    step: "6",
    title: "browser flow",
    status: ok && rotated && replayed.status === 400 ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail:
      ok && rotated && replayed.status === 400
        ? "authorize → interaction → code → id_token(nonce,email) + refresh → rotation → replay refused"
        : `${checks
            .filter(([, passed]) => !passed)
            .map(([name]) => name)
            .join(", ")}; refresh rotated=${rotated}; replay=${replayed.status} ${text(replayed.body)}`,
  };
}

/**
 * Sessions and logout — the SSO cookie, the management session API and RP-initiated logout.
 *
 * Three independent browsers are simulated, because each check needs a live session: one is
 * revoked by the admin API, one is ended through `end-session`, and one is removed in bulk.
 */
async function sessionFlow(base: string, consoleSecret: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const checks: [string, boolean][] = [];
  let detail = "";

  const authorizeUrl = async (tag: string, prompt?: string): Promise<{ url: string; verifier: string; state: string }> => {
    const verifier = `s-${tag}-${runId}-${"y".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const state = `st-${tag}-${runId}`;
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
      ...(prompt === undefined ? {} : { prompt }),
    })}`;
    return { url, verifier, state };
  };

  /** One interactive sign-in: authorize → interaction → sign-in, returning the cookie and code. */
  const signIn = async (
    tag: string,
  ): Promise<{ cookie?: string; sessionId?: string; code?: string; idToken?: string; sub?: string } | undefined> => {
    const { url, verifier } = await authorizeUrl(tag);
    const authorize = await call(url, { redirect: "manual" });
    const interaction = new URL(authorize.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (authorize.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${authorize.status} ${text(authorize.body)}`;
      return undefined;
    }

    const response = await call(`${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: BOOTSTRAP_ADMIN.email, password: BOOTSTRAP_ADMIN.password }),
    });
    const redirectTo = (response.body as { redirect_to?: string })?.redirect_to;
    if (response.status !== 200 || redirectTo === undefined) {
      detail = `sign-in(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }

    // `fetch` never applies a cookie jar here, so the `Set-Cookie` is parsed by hand.
    const setCookie = response.headers.get("set-cookie") ?? "";
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(setCookie)?.[1];
    checks.push([`sign-in(${tag}) set the session cookie`, cookie !== undefined]);

    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    const exchanged = await tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
    const idToken = (exchanged.body as { id_token?: unknown })?.id_token as string | undefined;
    const sub = jwtClaims(idToken)?.sub as string | undefined;
    checks.push([`code(${tag}) exchanged`, exchanged.status === 200 && sub !== undefined]);
    return { cookie, sessionId: cookie, code, idToken, sub };
  };

  /** `prompt=none` with the cookie; returns the code when the SSO session was accepted. */
  const silent = async (cookie: string | undefined): Promise<{ status: number; error: string | null; code: string | null }> => {
    const { url } = await authorizeUrl("silent", "none");
    const response = await call(url, {
      redirect: "manual",
      headers: cookie === undefined ? {} : { cookie: `monaca_session=${cookie}` },
    });
    const params = new URL(response.headers.get("location") ?? "", base).searchParams;
    return { status: response.status, error: params.get("error"), code: params.get("code") };
  };

  const sessionsUrl = (accountId: string): string => `${base}/v1/accounts/${encodeURIComponent(accountId)}/sessions`;
  const listSessions = async (
    accountId: string,
  ): Promise<{ items: { id: string; uuid: string }[]; status: number }> => {
    const response = await call(sessionsUrl(accountId), { headers: { authorization: `Bearer ${adminToken}` } });
    const items = ((response.body as { items?: { id?: string }[] })?.items ?? []).map((item) => {
      const id = item.id ?? "";
      return { id, uuid: typeIdUuid(id) };
    });
    return { items, status: response.status };
  };

  try {
    // --- session A: the cookie and silent reuse ------------------------------------------------
    const first = await signIn("a");
    if (first === undefined || first.cookie === undefined || first.sub === undefined) {
      return { step: "7", title: "session & logout", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const listed = await listSessions(first.sub);
    const listedSession = listed.items.find((item) => item.uuid === first.cookie);
    checks.push(["GET sessions lists the cookie's session", listed.status === 200 && listedSession !== undefined]);

    const reused = await silent(first.cookie);
    checks.push(["prompt=none reuses the session", reused.status === 302 && reused.code !== null]);

    // --- admin revoke of one session ------------------------------------------------------------
    const revoked = await call(`${sessionsUrl(first.sub)}/${encodeURIComponent(listedSession?.id ?? "")}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${adminToken}` },
    });
    checks.push(["DELETE sessions/{sid} → 204", revoked.status === 204]);
    const afterRevoke = await listSessions(first.sub);
    checks.push(["the revoked session is gone", afterRevoke.status === 200 && !afterRevoke.items.some((item) => item.uuid === first.cookie)]);
    const stale = await silent(first.cookie);
    checks.push(["a revoked session cannot sign in silently", stale.status === 302 && stale.error === "login_required"]);

    // --- session B: RP-initiated logout --------------------------------------------------------
    const second = await signIn("b");
    if (second === undefined || second.cookie === undefined || second.idToken === undefined) {
      return { step: "7", title: "session & logout", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const logoutState = `logout-${runId}`;
    const endSession = await call(
      `${base}/t/${TENANT}/oauth2/end-session?${new URLSearchParams({
        id_token_hint: second.idToken,
        post_logout_redirect_uri: redirectUri,
        state: logoutState,
      })}`,
      { redirect: "manual", headers: { cookie: `monaca_session=${second.cookie}` } },
    );
    const endLocation = new URL(endSession.headers.get("location") ?? "", base);
    checks.push(["end-session → 302 to the registered target", endSession.status === 302 && endLocation.origin === new URL(redirectUri).origin]);
    checks.push(["end-session echoes state", endLocation.searchParams.get("state") === logoutState]);
    checks.push(["end-session clears the cookie", (endSession.headers.get("set-cookie") ?? "").includes("monaca_session=;")]);
    const afterLogout = await silent(second.cookie);
    checks.push(["end-session ended the SSO session", afterLogout.status === 302 && afterLogout.error === "login_required"]);

    // --- session C: revoke every session of an account ----------------------------------------
    const third = await signIn("c");
    if (third === undefined || third.cookie === undefined || third.sub === undefined) {
      return { step: "7", title: "session & logout", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const all = await call(sessionsUrl(third.sub), {
      method: "DELETE",
      headers: { authorization: `Bearer ${adminToken}` },
    });
    const replayed = await listSessions(third.sub);
    checks.push([
      "DELETE sessions revokes every live session",
      all.status === 200 && ((all.body as { revoked?: number })?.revoked ?? 0) >= 1,
    ]);
    checks.push(["no session is left after revoke-all", replayed.status === 200 && replayed.items.length === 0]);
    const bulkStale = await silent(third.cookie);
    checks.push(["revoke-all ends silent authentication", bulkStale.status === 302 && bulkStale.error === "login_required"]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "7",
    title: "session & logout",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: cookie → silent reuse → admin revoke → end-session → revoke-all`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * The email-verification flows: self-service registration, passwordless sign-in and password reset.
 *
 * The code is not guessed: it is read back from the dev outbox through `/internal/mail`, which is
 * the M0 stand-in for a mail relay. Every flow gets its own interaction, because sign-up, sign-in
 * and reset each consume one.
 */
async function emailFlow(base: string, consoleSecret: string, internalSecret: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const email = `signup-${runId}@example.test`;
  const password = `pw-${runId}-old-password`;
  const newPassword = `pw-${runId}-new-password`;
  const checks: [string, boolean][] = [];
  let detail = "";

  /** A fresh authorize → interaction, so each flow starts from a clean challenge. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `e-${tag}-${runId}-${"z".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** The newest dev mail for this address and purpose, or undefined when none arrived. */
  const mailCode = async (purpose: string): Promise<string | undefined> => {
    const query = new URLSearchParams({ tenant: TENANT, to: email, purpose });
    const response = await call(`${base}/internal/mail?${query}`, {
      headers: { "x-monaca-internal-secret": internalSecret },
    });
    const code = (response.body as { payload?: { code?: unknown } } | undefined)?.payload?.code;
    return response.status === 200 && typeof code === "string" ? code : undefined;
  };

  /** Redeem the code in `redirect_to` for a token, proving the whole flow completed. */
  const exchange = async (redirectTo: unknown, verifier: string): Promise<HttpResult> => {
    const code = typeof redirectTo === "string" ? new URL(redirectTo).searchParams.get("code") ?? "" : "";
    return tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
  };

  try {
    // --- sign-up: request → mail → verify → token ----------------------------------------------
    const signUp = await begin("signup");
    if (signUp === undefined) {
      return { step: "8", title: "email verification", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const signUpRequest = await call(`${base}/t/${TENANT}/interaction/${signUp.interaction}/sign-up`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email }),
    });
    checks.push([
      "sign-up requests a code",
      signUpRequest.status === 200 && (signUpRequest.body as { verification_required?: unknown })?.verification_required === true,
    ]);
    const signUpCode = await mailCode("sign_up");
    checks.push(["dev mail delivered a sign-up code", typeof signUpCode === "string" && /^\d{6}$/.test(signUpCode)]);

    const signUpVerify = await call(`${base}/t/${TENANT}/interaction/${signUp.interaction}/sign-up/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, code: signUpCode ?? "", password, display_name: "Email flow" }),
    });
    const signUpToken = await exchange((signUpVerify.body as { redirect_to?: unknown })?.redirect_to, signUp.verifier);
    const signUpClaims = jwtClaims((signUpToken.body as { id_token?: unknown })?.id_token);
    checks.push([
      "sign-up completed and issued a token",
      signUpVerify.status === 200 && signUpToken.status === 200 && signUpClaims?.email === email,
    ]);

    // --- passwordless sign-in: request → mail → verify → token ---------------------------------
    const codeSignIn = await begin("code");
    if (codeSignIn === undefined) {
      return { step: "8", title: "email verification", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const codeRequest = await call(`${base}/t/${TENANT}/interaction/${codeSignIn.interaction}/sign-in/code`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email }),
    });
    checks.push([
      "code sign-in requests a code",
      codeRequest.status === 200 && (codeRequest.body as { verification_required?: unknown })?.verification_required === true,
    ]);
    const signInCode = await mailCode("sign_in");
    checks.push(["dev mail delivered a sign-in code", typeof signInCode === "string" && /^\d{6}$/.test(signInCode)]);

    const codeVerify = await call(`${base}/t/${TENANT}/interaction/${codeSignIn.interaction}/sign-in/code/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, code: signInCode ?? "" }),
    });
    const codeToken = await exchange((codeVerify.body as { redirect_to?: unknown })?.redirect_to, codeSignIn.verifier);
    checks.push(["code sign-in issued a token", codeVerify.status === 200 && codeToken.status === 200]);

    // --- password reset: forgot → mail → reset → token -----------------------------------------
    const reset = await begin("reset");
    if (reset === undefined) {
      return { step: "8", title: "email verification", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const forgot = await call(`${base}/t/${TENANT}/interaction/${reset.interaction}/password/forgot`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email }),
    });
    checks.push([
      "password reset requests a code",
      forgot.status === 200 && (forgot.body as { verification_required?: unknown })?.verification_required === true,
    ]);
    const resetCode = await mailCode("password_reset");
    checks.push(["dev mail delivered a reset code", typeof resetCode === "string" && /^\d{6}$/.test(resetCode)]);

    const resetResponse = await call(`${base}/t/${TENANT}/interaction/${reset.interaction}/password/reset`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, code: resetCode ?? "", password: newPassword }),
    });
    const resetToken = await exchange((resetResponse.body as { redirect_to?: unknown })?.redirect_to, reset.verifier);
    checks.push(["password reset issued a token", resetResponse.status === 200 && resetToken.status === 200]);

    // --- the reset really changed the credential -----------------------------------------------
    const oldPassword = await begin("oldpw");
    if (oldPassword === undefined) {
      return { step: "8", title: "email verification", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const refused = await call(`${base}/t/${TENANT}/interaction/${oldPassword.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    checks.push(["the old password is refused", refused.status === 401]);

    const newPasswordFlow = await begin("newpw");
    if (newPasswordFlow === undefined) {
      return { step: "8", title: "email verification", status: "fail", ms: Math.round(performance.now() - t), detail };
    }
    const accepted = await call(`${base}/t/${TENANT}/interaction/${newPasswordFlow.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password: newPassword }),
    });
    const acceptedToken = await exchange((accepted.body as { redirect_to?: unknown })?.redirect_to, newPasswordFlow.verifier);
    checks.push(["the new password signs in", accepted.status === 200 && acceptedToken.status === 200]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "8",
    title: "email verification",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: sign-up → code sign-in → password reset → old password refused`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/** Decode the base32 secret an authenticator app stores (RFC 4648, no padding). */
function base32Decode(input: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const symbol of input.replaceAll("=", "").toUpperCase()) {
    const index = alphabet.indexOf(symbol);
    if (index < 0) throw new Error(`invalid base32 symbol ${JSON.stringify(symbol)}`);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

/** RFC 6238, SHA-1, six digits, 30-second steps — the code an authenticator app would show now. */
function totpFromBase32(secret: string, at: number = Date.now()): string {
  const step = Math.floor(at / 1000 / 30);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const value =
    ((digest[offset]! & 0x7f) << 24) |
    (digest[offset + 1]! << 16) |
    (digest[offset + 2]! << 8) |
    digest[offset + 3]!;
  return String(value % 1_000_000).padStart(6, "0");
}

/**
 * Step 9 — the authenticator (TOTP) factor.
 *
 * A dedicated account is created for the run: enrolling the second factor on the bootstrap admin
 * would make every later walk-through answer `mfa_required`. The code is computed locally with the
 * secret the setup endpoint returned, which is exactly what an authenticator app does.
 */
async function mfaFlow(base: string, adminToken: string, consoleSecret: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const email = `mfa-${runId}@demo.localhost`;
  const password = `pw-${runId}-mfa-account`;
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "9",
    title: "two-step verification",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `m-${tag}-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Password sign-in on a fresh interaction, together with any session cookie it set. */
  const signIn = async (
    tag: string,
  ): Promise<{ interaction: string; verifier: string; status: number; body: unknown; cookie?: string } | undefined> => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(response.headers.get("set-cookie") ?? "")?.[1];
    return { ...started, status: response.status, body: response.body, cookie };
  };

  /** Redeem the `redirect_to` a completed interaction returned for a token. */
  const exchange = async (redirectTo: unknown, verifier: string): Promise<HttpResult> => {
    const code = typeof redirectTo === "string" ? new URL(redirectTo).searchParams.get("code") ?? "" : "";
    return tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
  };

  try {
    // --- a dedicated account, already a member of acme ------------------------------------------
    const account = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "MFA flow", password }),
    });
    const accountId = (account.body as { id?: string })?.id;
    if (account.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${account.status} ${text(account.body)}`);
    }
    const member = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    checks.push(["the run's account joined acme", member.status === 201]);

    // --- first sign-in: one factor, so the flow completes and leaves the SSO cookie -------------
    const first = await signIn("first");
    if (first === undefined) return fail("");
    checks.push([
      "a fresh account signs in with one factor",
      first.status === 200 && (first.body as { redirect_to?: unknown })?.redirect_to !== undefined,
    ]);
    if (first.cookie === undefined) return fail("the first sign-in set no session cookie");
    const cookie = { cookie: `monaca_session=${first.cookie}` };

    // --- enrollment: secret + otpauth URL, confirmed with a locally computed code ---------------
    const enrollment = await call(`${base}/t/${TENANT}/account/mfa/totp`, { method: "POST", headers: cookie });
    const secret = (enrollment.body as { secret?: unknown })?.secret;
    checks.push([
      "the setup endpoint returns a base32 secret and an otpauth URL",
      enrollment.status === 200 &&
        typeof secret === "string" &&
        typeof (enrollment.body as { otpauth_url?: unknown })?.otpauth_url === "string",
    ]);
    if (typeof secret !== "string") return fail(`POST /account/mfa/totp → ${enrollment.status} ${text(enrollment.body)}`);

    const confirmed = await call(`${base}/t/${TENANT}/account/mfa/totp/verify`, {
      method: "POST",
      headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify({ code: totpFromBase32(secret) }),
    });
    checks.push([
      "a computed authenticator code enables the factor",
      confirmed.status === 200 && (confirmed.body as { enabled?: unknown })?.enabled === true,
    ]);

    const profile = await call(`${base}/t/${TENANT}/account`, { headers: cookie });
    checks.push([
      "GET /account reports totp enabled",
      profile.status === 200 && ((profile.body as { mfa?: { totp?: unknown } })?.mfa?.totp) === true,
    ]);

    // --- sign-in now pauses for the second factor -----------------------------------------------
    const challenged = await signIn("challenged");
    if (challenged === undefined) return fail("");
    checks.push([
      "a new sign-in answers mfa_required instead of a redirect",
      challenged.status === 200 &&
        (challenged.body as { mfa_required?: unknown })?.mfa_required === true &&
        (challenged.body as { redirect_to?: unknown })?.redirect_to === undefined,
    ]);

    const wrong = String((Number(totpFromBase32(secret)[0]) + 1) % 10) + totpFromBase32(secret).slice(1);
    const refused = await call(`${base}/t/${TENANT}/interaction/${challenged.interaction}/mfa/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: wrong }),
    });
    checks.push(["a wrong authenticator code is refused", refused.status === 401]);

    const verified = await call(`${base}/t/${TENANT}/interaction/${challenged.interaction}/mfa/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: totpFromBase32(secret) }),
    });
    const mfaToken = await exchange((verified.body as { redirect_to?: unknown })?.redirect_to, challenged.verifier);
    checks.push([
      "the correct code completes the flow and issues a token",
      verified.status === 200 && mfaToken.status === 200,
    ]);

    // --- removal: the account is back to one factor ---------------------------------------------
    const removed = await call(`${base}/t/${TENANT}/account/mfa/totp`, { method: "DELETE", headers: cookie });
    checks.push(["DELETE removes the authenticator", removed.status === 204]);

    const plain = await signIn("plain");
    if (plain === undefined) return fail("");
    const plainRedirect = (plain.body as { redirect_to?: unknown })?.redirect_to;
    const plainToken = await exchange(plainRedirect, plain.verifier);
    checks.push([
      "sign-in needs one factor again",
      plain.status === 200 && plainRedirect !== undefined && plainToken.status === 200,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "9",
    title: "two-step verification",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: enroll → challenge → wrong code refused → token → remove → one factor`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 10 — the account centre: profile, password and sessions.
 *
 * A dedicated account is created for the run, like step 9. Two browsers sign in (two cookies), so
 * the password change has another session to revoke and the sessions list has a `current` row to
 * mark. Revoking a session is checked by calling `GET /account` with that cookie afterwards.
 */
async function accountFlow(
  base: string,
  adminToken: string,
  internalSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const email = `account-${runId}@demo.localhost`;
  const firstPassword = `pw-${runId}-account-original`;
  const secondPassword = `pw-${runId}-account-renamed`;
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "10",
    title: "account centre",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction. */
  const begin = async (tag: string): Promise<string | undefined> => {
    const verifier = `a-${tag}-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return encodeURIComponent(interaction);
  };

  /** Password sign-in on a fresh interaction; the response carries the SSO cookie. */
  const signIn = async (
    tag: string,
    password: string,
  ): Promise<{ status: number; body: unknown; cookie?: string } | undefined> => {
    const interaction = await begin(tag);
    if (interaction === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(response.headers.get("set-cookie") ?? "")?.[1];
    return { status: response.status, body: response.body, cookie };
  };

  const auth = (cookie: string): Record<string, string> => ({ cookie: `monaca_session=${cookie}` });
  const profile = (cookie: string): Promise<HttpResult> => call(`${base}/t/${TENANT}/account`, { headers: auth(cookie) });
  const sessionsOf = async (cookie: string): Promise<{ id: string; current: boolean }[]> => {
    const response = await call(`${base}/t/${TENANT}/account/sessions`, { headers: auth(cookie) });
    const items = (response.body as { items?: { id?: unknown; current?: unknown }[] })?.items ?? [];
    return items
      .filter((item): item is { id: string; current: boolean } => typeof item.id === "string")
      .map((item) => ({ id: item.id, current: item.current === true }));
  };

  try {
    // --- a dedicated account, already a member of acme ------------------------------------------
    const account = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Account centre", password: firstPassword }),
    });
    const accountId = (account.body as { id?: string })?.id;
    if (account.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${account.status} ${text(account.body)}`);
    }
    const member = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    checks.push(["the run's account joined acme", member.status === 201]);

    // --- two browsers, so a password change has something to revoke ------------------------------
    const first = await signIn("first", firstPassword);
    const second = await signIn("second", firstPassword);
    if (first?.cookie === undefined || second?.cookie === undefined) {
      return fail("the two sign-ins did not both set a session cookie");
    }
    const firstCookie = first.cookie;
    const secondCookie = second.cookie;

    // --- profile: PATCH changes the name, GET echoes it ------------------------------------------
    const renamed = await call(`${base}/t/${TENANT}/account`, {
      method: "PATCH",
      headers: { ...auth(firstCookie), "content-type": "application/json" },
      body: JSON.stringify({ display_name: "  Account centre renamed  " }),
    });
    checks.push([
      "PATCH /account stores the trimmed display name",
      renamed.status === 200 &&
        (renamed.body as { display_name?: unknown })?.display_name === "Account centre renamed",
    ]);
    const echoed = await profile(firstCookie);
    checks.push([
      "GET /account echoes the new name",
      echoed.status === 200 &&
        (echoed.body as { display_name?: unknown })?.display_name === "Account centre renamed",
    ]);

    // --- password: the current one is required, and the change ends the other sessions -----------
    const wrongCurrent = await call(`${base}/t/${TENANT}/account/password`, {
      method: "POST",
      headers: { ...auth(firstCookie), "content-type": "application/json" },
      body: JSON.stringify({ current_password: "not-the-password", new_password: secondPassword }),
    });
    checks.push(["a wrong current password is refused", wrongCurrent.status === 401]);

    const changed = await call(`${base}/t/${TENANT}/account/password`, {
      method: "POST",
      headers: { ...auth(firstCookie), "content-type": "application/json" },
      body: JSON.stringify({ current_password: firstPassword, new_password: secondPassword }),
    });
    checks.push(["the right current password changes it", changed.status === 204]);

    const passwordNotice = await call(
      `${base}/internal/mail?${new URLSearchParams({ tenant: TENANT, to: email, purpose: "password_changed" })}`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    checks.push(["the password change mails a notice", passwordNotice.status === 200]);

    const stale = await signIn("stale", firstPassword);
    checks.push(["the old password no longer signs in", stale !== undefined && stale.status === 401]);

    const fresh = await signIn("fresh", secondPassword);
    const freshRedirect = (fresh?.body as { redirect_to?: unknown })?.redirect_to;
    checks.push([
      "the new password signs in",
      fresh !== undefined && fresh.status === 200 && freshRedirect !== undefined && fresh.cookie !== undefined,
    ]);
    if (fresh?.cookie === undefined) return fail("the new-password sign-in set no cookie");
    const freshCookie = fresh.cookie;

    checks.push(["the password change ended the other browser's session", (await profile(secondCookie)).status === 401]);

    // --- sessions: the caller is marked current, single and bulk revocation work -----------------
    const afterChange = await sessionsOf(firstCookie);
    checks.push([
      "GET /account/sessions lists the caller and marks exactly one current",
      afterChange.length === 2 && afterChange.filter((row) => row.current).length === 1,
    ]);
    const other = afterChange.find((row) => !row.current);
    if (other === undefined) return fail("no other session to revoke");
    const revokedOther = await call(`${base}/t/${TENANT}/account/sessions/${encodeURIComponent(other.id)}`, {
      method: "DELETE",
      headers: auth(firstCookie),
    });
    checks.push(["DELETE one session is 204", revokedOther.status === 204]);
    checks.push(["that browser is signed out", (await profile(freshCookie)).status === 401]);
    checks.push([
      "the list shrinks to the caller",
      (await sessionsOf(firstCookie)).filter((row) => !row.current).length === 0,
    ]);

    const third = await signIn("third", secondPassword);
    if (third?.cookie === undefined) return fail("the third sign-in set no cookie");
    checks.push([
      "DELETE all other sessions is 204",
      (
        await call(`${base}/t/${TENANT}/account/sessions`, { method: "DELETE", headers: auth(firstCookie) })
      ).status === 204,
    ]);
    checks.push(["the third browser is signed out", (await profile(third.cookie)).status === 401]);

    const remaining = await sessionsOf(firstCookie);
    const current = remaining.find((row) => row.current);
    if (current === undefined) return fail("the caller's session is missing from the list");
    const revokedSelf = await call(`${base}/t/${TENANT}/account/sessions/${encodeURIComponent(current.id)}`, {
      method: "DELETE",
      headers: auth(firstCookie),
    });
    checks.push(["a session may revoke itself", revokedSelf.status === 204]);
    checks.push(["the revoked cookie no longer authenticates", (await profile(firstCookie)).status === 401]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "10",
    title: "account centre",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: name → wrong current refused → password changed → old refused, new signs in → sessions listed and revoked`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 11 — MFA backup codes.
 *
 * A dedicated account enrolls an authenticator, generates a sheet of ten codes, then signs in with
 * one of them instead of the app. The same code is replayed on a fresh interaction to prove it is
 * single-use, and the remaining count is checked before and after removal. The typed code is sent in
 * uppercase with its display hyphen to exercise the server-side normalisation.
 */
async function backupCodeFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const email = `backup-${runId}@demo.localhost`;
  const password = `pw-${runId}-backup-account`;
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "11",
    title: "MFA backup codes",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction, with the PKCE verifier the exchange needs. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `b-${tag}-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Password sign-in on a fresh interaction, together with any session cookie it set. */
  const signIn = async (
    tag: string,
  ): Promise<{ interaction: string; verifier: string; status: number; body: unknown; cookie?: string } | undefined> => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(response.headers.get("set-cookie") ?? "")?.[1];
    return { ...started, status: response.status, body: response.body, cookie };
  };

  /** Redeem the `redirect_to` a completed interaction returned for a token. */
  const exchange = async (redirectTo: unknown, verifier: string): Promise<HttpResult> => {
    const code = typeof redirectTo === "string" ? new URL(redirectTo).searchParams.get("code") ?? "" : "";
    return tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
  };

  const factorsOf = (body: unknown): string[] => {
    const factors = (body as { factors?: unknown })?.factors;
    return Array.isArray(factors) ? factors.filter((value): value is string => typeof value === "string") : [];
  };

  try {
    // --- a dedicated account, already a member of acme ------------------------------------------
    const account = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Backup codes", password }),
    });
    const accountId = (account.body as { id?: string })?.id;
    if (account.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${account.status} ${text(account.body)}`);
    }
    const member = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    checks.push(["the run's account joined acme", member.status === 201]);

    // --- one-factor sign-in, then enroll the authenticator the codes stand behind ----------------
    const first = await signIn("first");
    if (first?.cookie === undefined) return fail("the first sign-in set no session cookie");
    const cookie = { cookie: `monaca_session=${first.cookie}` };

    const enrollment = await call(`${base}/t/${TENANT}/account/mfa/totp`, { method: "POST", headers: cookie });
    const secret = (enrollment.body as { secret?: unknown })?.secret;
    if (typeof secret !== "string") return fail(`POST /account/mfa/totp → ${enrollment.status} ${text(enrollment.body)}`);
    const confirmed = await call(`${base}/t/${TENANT}/account/mfa/totp/verify`, {
      method: "POST",
      headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify({ code: totpFromBase32(secret) }),
    });
    checks.push(["the authenticator is enrolled", confirmed.status === 200]);

    // --- generate the sheet: ten grouped codes, shown once --------------------------------------
    const sheet = await call(`${base}/t/${TENANT}/account/mfa/backup-codes`, { method: "POST", headers: cookie });
    const codes = (sheet.body as { codes?: unknown })?.codes;
    const codeList = Array.isArray(codes) ? codes.filter((code): code is string => typeof code === "string") : [];
    checks.push([
      "POST /account/mfa/backup-codes returns ten grouped codes",
      sheet.status === 200 &&
        codeList.length === 10 &&
        codeList.every((code) => /^[0-9a-z]{5}-[0-9a-z]{5}$/.test(code)),
    ]);
    if (codeList.length === 0) return fail(`POST /account/mfa/backup-codes → ${sheet.status} ${text(sheet.body)}`);

    const remaining = async (): Promise<number | undefined> => {
      const response = await call(`${base}/t/${TENANT}/account/mfa/backup-codes`, { headers: cookie });
      const value = (response.body as { remaining?: unknown })?.remaining;
      return typeof value === "number" ? value : undefined;
    };
    checks.push(["GET /account/mfa/backup-codes reports ten unused", (await remaining()) === 10]);

    // --- a sign-in challenge offers both factors ------------------------------------------------
    const challenged = await signIn("challenged");
    if (challenged === undefined) return fail("");
    const factors = factorsOf(challenged.body);
    checks.push([
      "a sign-in challenge lists totp and backup_code",
      challenged.status === 200 && factors.includes("totp") && factors.includes("backup_code"),
    ]);

    // --- a wrong code is refused; the typed form is normalised (uppercase + hyphen) -------------
    const canonical = codeList[0]!.replace("-", "");
    const wrong = `${canonical[0] === "0" ? "1" : "0"}${canonical.slice(1)}`;
    const refused = await call(`${base}/t/${TENANT}/interaction/${challenged.interaction}/mfa/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: wrong, factor: "backup_code" }),
    });
    checks.push(["a wrong backup code is refused", refused.status === 401]);

    const verified = await call(`${base}/t/${TENANT}/interaction/${challenged.interaction}/mfa/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: codeList[0]!.toUpperCase(), factor: "backup_code" }),
    });
    const token = await exchange((verified.body as { redirect_to?: unknown })?.redirect_to, challenged.verifier);
    checks.push([
      "a backup code completes the flow and issues a token",
      verified.status === 200 && token.status === 200,
    ]);

    // --- the code is single-use ------------------------------------------------------------------
    const replay = await signIn("replay");
    if (replay === undefined) return fail("");
    const reused = await call(`${base}/t/${TENANT}/interaction/${replay.interaction}/mfa/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: codeList[0]!, factor: "backup_code" }),
    });
    checks.push(["the same backup code cannot be reused", reused.status === 401]);
    checks.push(["the sheet now reports nine unused", (await remaining()) === 9]);

    // --- removal leaves only the authenticator --------------------------------------------------
    const removed = await call(`${base}/t/${TENANT}/account/mfa/backup-codes`, { method: "DELETE", headers: cookie });
    checks.push(["DELETE /account/mfa/backup-codes is 204", removed.status === 204]);
    checks.push(["no backup codes remain", (await remaining()) === 0]);

    const plain = await signIn("plain");
    checks.push([
      "the next challenge offers totp only",
      plain !== undefined && factorsOf(plain.body).join(",") === "totp",
    ]);
    checks.push([
      "the profile reports zero backup codes",
      ((await call(`${base}/t/${TENANT}/account`, { headers: cookie }).then((response) => response.body)) as {
        mfa?: { backup_codes?: unknown };
      })?.mfa?.backup_codes === 0,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "11",
    title: "MFA backup codes",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: generate ten → challenge offers both → wrong refused → code signs in → replay refused → remove`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

// ---------------------------------------------------------------------------
// Step 12: a software authenticator
// ---------------------------------------------------------------------------

/** Concatenate byte arrays; every ceremony below is a sequence of fixed-size slices. */
function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (value.length % 4)) % 4);
  return new Uint8Array(Buffer.from(padded, "base64"));
}

/**
 * The CBOR heads the two WebAuthn structures use: integers as COSE map keys, byte strings and text
 * strings, and maps. A full encoder would be a dependency for four major types, so this writes the
 * three length forms that can actually appear here.
 */
function cborHead(major: number, argument: number): Uint8Array {
  if (argument < 24) return Uint8Array.of((major << 5) | argument);
  if (argument < 256) return Uint8Array.of((major << 5) | 24, argument);
  return Uint8Array.of((major << 5) | 25, (argument >>> 8) & 0xff, argument & 0xff);
}

function cborUint(value: number): Uint8Array {
  return cborHead(0, value);
}

/** CBOR major type 1 stores `-1 - value`, so `-7` is the argument `6`. */
function cborNegative(value: number): Uint8Array {
  return cborHead(1, -1 - value);
}

function cborBytes(bytes: Uint8Array): Uint8Array {
  return concatBytes(cborHead(2, bytes.length), bytes);
}

function cborText(text: string): Uint8Array {
  const bytes = new TextEncoder().encode(text);
  return concatBytes(cborHead(3, bytes.length), bytes);
}

function cborMap(entries: [Uint8Array, Uint8Array][]): Uint8Array {
  return concatBytes(cborHead(5, entries.length), ...entries.flatMap(([key, value]) => [key, value]));
}

function u32(value: number): Uint8Array {
  return Uint8Array.of((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.buffer as ArrayBuffer));
}

/** A P-256 key pair, a credential id and a counter: what one hardware authenticator would hold. */
interface SoftwareAuthenticator {
  credentialId: Uint8Array;
  /** The COSE `EC2` public key embedded in the attestation. */
  cose: Uint8Array;
  signCount: number;
  sign: (data: Uint8Array) => Promise<Uint8Array>;
}

async function createSoftwareAuthenticator(): Promise<SoftwareAuthenticator> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as { x: string; y: string };
  const cose = cborMap([
    [cborUint(1), cborUint(2)], // kty: EC2
    [cborUint(3), cborNegative(-7)], // alg: ES256
    [cborNegative(-1), cborUint(1)], // crv: P-256
    [cborNegative(-2), cborBytes(fromBase64Url(jwk.x))],
    [cborNegative(-3), cborBytes(fromBase64Url(jwk.y))],
  ]);
  return {
    credentialId: crypto.getRandomValues(new Uint8Array(16)),
    cose,
    signCount: 0,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      return new Uint8Array(
        await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, data.buffer as ArrayBuffer),
      );
    },
  };
}

interface CreationOptionsJSON {
  challenge: string;
  rp: { id: string };
  user: { id: string };
}

/** What `navigator.credentials.create()` would return, with `attestation: "none"`. */
async function buildRegistration(
  authenticator: SoftwareAuthenticator,
  options: CreationOptionsJSON,
  origin: string,
  name: string,
): Promise<Record<string, unknown>> {
  const clientData = new TextEncoder().encode(
    JSON.stringify({ type: "webauthn.create", challenge: options.challenge, origin, crossOrigin: false }),
  );
  const rpIdHash = await sha256(new TextEncoder().encode(options.rp.id));
  const idLength = Uint8Array.of(authenticator.credentialId.length >>> 8, authenticator.credentialId.length & 0xff);
  // UP | UV | AT, a fresh counter, an all-zero AAGUID, the id and the COSE key.
  const authData = concatBytes(
    rpIdHash,
    Uint8Array.of(0x45),
    u32(0),
    new Uint8Array(16),
    idLength,
    authenticator.credentialId,
    authenticator.cose,
  );
  const attestation = cborMap([
    [cborText("fmt"), cborText("none")],
    [cborText("attStmt"), cborMap([])],
    [cborText("authData"), cborBytes(authData)],
  ]);
  return {
    rawId: base64Url(authenticator.credentialId),
    name,
    response: {
      clientDataJSON: base64Url(clientData),
      attestationObject: base64Url(attestation),
      transports: ["internal"],
    },
  };
}

interface RequestOptionsJSON {
  challenge: string;
  rpId: string;
}

/** What `navigator.credentials.get()` would return, including the user handle. */
async function buildPasskeyAssertion(
  authenticator: SoftwareAuthenticator,
  options: RequestOptionsJSON,
  origin: string,
  userHandle: Uint8Array,
): Promise<Record<string, unknown>> {
  authenticator.signCount += 1;
  const clientData = new TextEncoder().encode(
    JSON.stringify({ type: "webauthn.get", challenge: options.challenge, origin, crossOrigin: false }),
  );
  const rpIdHash = await sha256(new TextEncoder().encode(options.rpId));
  // UP | UV; an assertion carries no attested credential data.
  const authData = concatBytes(rpIdHash, Uint8Array.of(0x05), u32(authenticator.signCount));
  const signature = await authenticator.sign(concatBytes(authData, await sha256(clientData)));
  return {
    rawId: base64Url(authenticator.credentialId),
    response: {
      clientDataJSON: base64Url(clientData),
      authenticatorData: base64Url(authData),
      signature: base64Url(signature),
      userHandle: base64Url(userHandle),
    },
  };
}

/**
 * Step 12 — passkeys, both as a primary factor and as the second factor.
 *
 * The software authenticator above produces exactly what a browser would: an ECDSA P-256 key,
 * CBOR COSE key and attestation, and signatures over `authData || SHA-256(clientDataJSON)`. The
 * relying party comes from the deployment, so the origin defaults to the CI value
 * (`MONACA_AUTH_UI_URL`) rather than the API origin the script talks to.
 */
async function passkeyFlow(base: string, adminToken: string, consoleSecret: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const email = `passkey-${runId}@demo.localhost`;
  const password = `pw-${runId}-passkey-account`;
  const headers = managementHeaders(adminToken);
  const origin = new URL(process.env.MONACA_AUTH_UI_URL ?? "http://localhost:5174").origin;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "12",
    title: "passkeys",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `p-${tag}-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Password sign-in on a fresh interaction, together with any session cookie it set. */
  const signIn = async (
    tag: string,
  ): Promise<{ interaction: string; verifier: string; status: number; body: unknown; cookie?: string } | undefined> => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(response.headers.get("set-cookie") ?? "")?.[1];
    return { ...started, status: response.status, body: response.body, cookie };
  };

  /** Redeem the `redirect_to` a completed interaction returned for a token. */
  const exchange = async (redirectTo: unknown, verifier: string): Promise<HttpResult> => {
    const code = typeof redirectTo === "string" ? new URL(redirectTo).searchParams.get("code") ?? "" : "";
    return tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
  };

  try {
    // --- a dedicated account, already a member of acme ------------------------------------------
    const account = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Passkey flow", password }),
    });
    const accountId = (account.body as { id?: string })?.id;
    if (account.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${account.status} ${text(account.body)}`);
    }
    // The WebAuthn user handle is the account UUID, which `user.id` in the options also carries.
    const userHandle = new Uint8Array(Buffer.from(typeIdUuid(accountId).replaceAll("-", ""), "hex"));
    const member = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    checks.push(["the run's account joined acme", member.status === 201]);

    // --- one-factor sign-in, so the session cookie can register the passkey -----------------------
    const first = await signIn("first");
    if (first?.cookie === undefined) return fail("the first sign-in set no session cookie");
    const cookie = { cookie: `monaca_session=${first.cookie}` };

    // --- registration: creation options, then the attestation ------------------------------------
    const authenticator = await createSoftwareAuthenticator();
    const options = await call(`${base}/t/${TENANT}/account/passkeys/options`, { method: "POST", headers: cookie });
    const creation = options.body as Partial<CreationOptionsJSON>;
    const rpId = creation.rp?.id;
    if (options.status !== 200 || typeof creation.challenge !== "string" || typeof rpId !== "string") {
      return fail(`POST /account/passkeys/options → ${options.status} ${text(options.body)}`);
    }
    checks.push([
      "the creation options carry the relying party and a challenge",
      rpId === new URL(origin).hostname && creation.user?.id === base64Url(userHandle),
    ]);

    const registered = await call(`${base}/t/${TENANT}/account/passkeys`, {
      method: "POST",
      headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify(await buildRegistration(authenticator, creation as CreationOptionsJSON, origin, "E2E key")),
    });
    const passkeyId = (registered.body as { id?: unknown })?.id;
    checks.push([
      "the registration ceremony stores a pky_… passkey",
      registered.status === 201 && typeof passkeyId === "string" && passkeyId.startsWith("pky_"),
    ]);
    if (typeof passkeyId !== "string") {
      return fail(`POST /account/passkeys → ${registered.status} ${text(registered.body)}`);
    }

    const list = async (): Promise<{ id?: unknown; name?: unknown; transports?: unknown }[]> => {
      const response = await call(`${base}/t/${TENANT}/account/passkeys`, { headers: cookie });
      const items = (response.body as { items?: unknown })?.items;
      return Array.isArray(items) ? (items as { id?: unknown; name?: unknown; transports?: unknown }[]) : [];
    };
    const items = await list();
    checks.push([
      "GET /account/passkeys lists it with its transport hint",
      items.length === 1 &&
        items[0]?.id === passkeyId &&
        Array.isArray(items[0]?.transports) &&
        (items[0]!.transports as string[]).includes("internal"),
    ]);
    const passkeyCount = async (): Promise<unknown> => {
      const response = await call(`${base}/t/${TENANT}/account`, { headers: cookie });
      return (response.body as { mfa?: { passkeys?: unknown } })?.mfa?.passkeys;
    };
    checks.push(["the profile reports one passkey", (await passkeyCount()) === 1]);

    // --- passwordless sign-in --------------------------------------------------------------------
    const passwordless = await begin("passwordless");
    if (passwordless === undefined) return fail("");
    const requestOptions = await call(`${base}/t/${TENANT}/interaction/${passwordless.interaction}/sign-in/passkey/options`, {
      method: "POST",
    });
    const request = requestOptions.body as Partial<RequestOptionsJSON>;
    if (requestOptions.status !== 200 || typeof request.challenge !== "string" || typeof request.rpId !== "string") {
      return fail(`POST /sign-in/passkey/options → ${requestOptions.status} ${text(requestOptions.body)}`);
    }
    checks.push(["the assertion options name the relying party", request.rpId === rpId]);

    const signedIn = await call(`${base}/t/${TENANT}/interaction/${passwordless.interaction}/sign-in/passkey`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(await buildPasskeyAssertion(authenticator, request as RequestOptionsJSON, origin, userHandle)),
    });
    const passkeyToken = await exchange((signedIn.body as { redirect_to?: unknown })?.redirect_to, passwordless.verifier);
    checks.push([
      "a passkey signs in without a password and issues a token",
      signedIn.status === 200 && passkeyToken.status === 200,
    ]);

    // --- a signature over an old challenge cannot be replayed -----------------------------------
    const replay = await begin("replay");
    if (replay === undefined) return fail("");
    const replayOptions = await call(`${base}/t/${TENANT}/interaction/${replay.interaction}/sign-in/passkey/options`, {
      method: "POST",
    });
    const stale = await buildPasskeyAssertion(authenticator, request as RequestOptionsJSON, origin, userHandle);
    const replayed = await call(`${base}/t/${TENANT}/interaction/${replay.interaction}/sign-in/passkey`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(stale),
    });
    checks.push([
      "an assertion over a stale challenge is 401",
      replayOptions.status === 200 && replayed.status === 401,
    ]);

    // --- the label can be changed ---------------------------------------------------------------
    const renamed = await call(`${base}/t/${TENANT}/account/passkeys/${passkeyId}`, {
      method: "PATCH",
      headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify({ name: "Renamed key" }),
    });
    checks.push([
      "PATCH renames the passkey",
      renamed.status === 200 && (renamed.body as { name?: unknown })?.name === "Renamed key",
    ]);

    // --- enroll TOTP, then prove the second factor with the passkey -------------------------------
    const enrollment = await call(`${base}/t/${TENANT}/account/mfa/totp`, { method: "POST", headers: cookie });
    const secret = (enrollment.body as { secret?: unknown })?.secret;
    if (typeof secret !== "string") return fail(`POST /account/mfa/totp → ${enrollment.status} ${text(enrollment.body)}`);
    const confirmed = await call(`${base}/t/${TENANT}/account/mfa/totp/verify`, {
      method: "POST",
      headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify({ code: totpFromBase32(secret) }),
    });
    checks.push(["the authenticator is enrolled alongside the passkey", confirmed.status === 200]);

    const challenged = await signIn("challenged");
    if (challenged === undefined) return fail("");
    const factors = Array.isArray((challenged.body as { factors?: unknown })?.factors)
      ? ((challenged.body as { factors: string[] }).factors)
      : [];
    checks.push([
      "a password sign-in offers totp and passkey",
      challenged.status === 200 &&
        (challenged.body as { mfa_required?: unknown })?.mfa_required === true &&
        factors.includes("totp") &&
        factors.includes("passkey"),
    ]);

    const mfaOptions = await call(`${base}/t/${TENANT}/interaction/${challenged.interaction}/mfa/passkey/options`, {
      method: "POST",
    });
    const mfaRequest = mfaOptions.body as Partial<RequestOptionsJSON & { allowCredentials?: { id?: unknown }[] }>;
    checks.push([
      "the second-factor options allow only this credential",
      mfaOptions.status === 200 &&
        typeof mfaRequest.challenge === "string" &&
        mfaRequest.allowCredentials?.length === 1 &&
        mfaRequest.allowCredentials[0]?.id === base64Url(authenticator.credentialId),
    ]);
    if (mfaOptions.status !== 200 || typeof mfaRequest.challenge !== "string" || typeof mfaRequest.rpId !== "string") {
      return fail(`POST /mfa/passkey/options → ${mfaOptions.status} ${text(mfaOptions.body)}`);
    }

    const mfa = await call(`${base}/t/${TENANT}/interaction/${challenged.interaction}/mfa/passkey`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(await buildPasskeyAssertion(authenticator, mfaRequest as RequestOptionsJSON, origin, userHandle)),
    });
    const mfaToken = await exchange((mfa.body as { redirect_to?: unknown })?.redirect_to, challenged.verifier);
    checks.push([
      "the passkey completes the second factor and issues a token",
      mfa.status === 200 && mfaToken.status === 200,
    ]);

    // --- removal returns the account to the authenticator app only -------------------------------
    const removed = await call(`${base}/t/${TENANT}/account/passkeys/${passkeyId}`, { method: "DELETE", headers: cookie });
    checks.push(["DELETE /account/passkeys/{id} is 204", removed.status === 204]);
    checks.push(["GET /account/passkeys is empty", (await list()).length === 0]);
    checks.push(["the profile reports zero passkeys", (await passkeyCount()) === 0]);

    const plain = await signIn("plain");
    if (plain === undefined) return fail("");
    checks.push([
      "the next challenge offers totp only",
      Array.isArray((plain.body as { factors?: unknown })?.factors) &&
        (plain.body as { factors: string[] }).factors.join(",") === "totp",
    ]);
  } catch (error) {
    // A thrown fetch means a request never got an answer; a step with only passing checks so far
    // must not be reported as green.
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "12",
    title: "passkeys",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: register → passwordless sign-in → replay refused → rename → MFA passkey → remove`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 13 — usernames as a second sign-in identifier (§6.1).
 *
 * The account centre claims a username, the sign-in endpoint accepts it (case-insensitively) in
 * place of the email, and a second account trying to claim the same name gets a 409.
 */
async function usernameFlow(base: string, adminToken: string, consoleSecret: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const headers = managementHeaders(adminToken);
  const username = `uname-${runId}`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "13",
    title: "username identifiers",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `u-${tag}-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Password sign-in on a fresh interaction, together with any session cookie it set. */
  const signIn = async (
    tag: string,
    identifier: string,
    password: string,
  ): Promise<{ interaction: string; verifier: string; status: number; body: unknown; cookie?: string } | undefined> => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier, password }),
    });
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(response.headers.get("set-cookie") ?? "")?.[1];
    return { ...started, status: response.status, body: response.body, cookie };
  };

  /** Redeem the `redirect_to` a completed interaction returned for a token. */
  const exchange = async (redirectTo: unknown, verifier: string): Promise<HttpResult> => {
    const code = typeof redirectTo === "string" ? new URL(redirectTo).searchParams.get("code") ?? "" : "";
    return tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
  };

  try {
    // --- account A claims a username -------------------------------------------------------------
    const emailA = `username-${runId}@demo.localhost`;
    const passwordA = `pw-${runId}-username-a`;
    const accountA = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: emailA, display_name: "Username A", password: passwordA }),
    });
    const accountAId = (accountA.body as { id?: string })?.id;
    if (accountA.status !== 201 || accountAId === undefined) {
      return fail(`POST /v1/accounts A → ${accountA.status} ${text(accountA.body)}`);
    }
    const memberA = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountAId, role: "member" }),
    });
    checks.push(["the first account joined acme", memberA.status === 201]);

    const first = await signIn("first", emailA, passwordA);
    if (first?.cookie === undefined) return fail("the first sign-in set no session cookie");
    const cookieA = { cookie: `monaca_session=${first.cookie}` };

    // A mixed-case claim is stored lowercased, matching the case-insensitive unique index.
    const claimed = await call(`${base}/t/${TENANT}/account`, {
      method: "PATCH",
      headers: { ...cookieA, "content-type": "application/json" },
      body: JSON.stringify({ username: `Uname-${runId}` }),
    });
    checks.push([
      "PATCH /account stores the username lowercased",
      claimed.status === 200 && (claimed.body as { username?: unknown })?.username === username,
    ]);
    const profile = await call(`${base}/t/${TENANT}/account`, { headers: cookieA });
    checks.push([
      "GET /account echoes the username",
      profile.status === 200 && (profile.body as { username?: unknown })?.username === username,
    ]);

    // --- the username signs in, case-insensitively ---------------------------------------------
    const byUsername = await signIn("username", username.toUpperCase(), passwordA);
    if (byUsername === undefined) return fail("");
    const usernameToken = await exchange(
      (byUsername.body as { redirect_to?: unknown })?.redirect_to,
      byUsername.verifier,
    );
    checks.push([
      "the username signs in case-insensitively and mints a token",
      byUsername.status === 200 && usernameToken.status === 200,
    ]);

    // The email remains a working identifier for the same account.
    const byEmail = await signIn("email", emailA, passwordA);
    checks.push(["the email still signs in", byEmail?.status === 200]);

    const unknown = await signIn("unknown", `nobody-${runId}`, passwordA);
    checks.push(["an unknown identifier is 401", unknown?.status === 401]);

    // --- account B cannot claim the same username -----------------------------------------------
    const emailB = `username-b-${runId}@demo.localhost`;
    const passwordB = `pw-${runId}-username-b`;
    const accountB = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: emailB, display_name: "Username B", password: passwordB }),
    });
    const accountBId = (accountB.body as { id?: string })?.id;
    if (accountB.status !== 201 || accountBId === undefined) {
      return fail(`POST /v1/accounts B → ${accountB.status} ${text(accountB.body)}`);
    }
    const memberB = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountBId, role: "member" }),
    });
    checks.push(["the second account joined acme", memberB.status === 201]);

    const second = await signIn("second", emailB, passwordB);
    if (second?.cookie === undefined) return fail("the second sign-in set no session cookie");
    const cookieB = { cookie: `monaca_session=${second.cookie}` };

    const taken = await call(`${base}/t/${TENANT}/account`, {
      method: "PATCH",
      headers: { ...cookieB, "content-type": "application/json" },
      body: JSON.stringify({ username: `UNAME-${runId}` }),
    });
    checks.push([
      "a username another account holds is 409 MONACA_USERNAME_TAKEN",
      taken.status === 409 &&
        (taken.body as { monaca_error_code?: unknown })?.monaca_error_code === "MONACA_USERNAME_TAKEN",
    ]);

    const invalid = await call(`${base}/t/${TENANT}/account`, {
      method: "PATCH",
      headers: { ...cookieB, "content-type": "application/json" },
      body: JSON.stringify({ username: "a!" }),
    });
    checks.push(["an invalid username is 400", invalid.status === 400]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "13",
    title: "username identifiers",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: claim → username sign-in → email still works → unknown 401 → conflict 409 → invalid 400`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 14 — changing the sign-in email from the account centre (§6.1).
 *
 * The signed-in account asks to move to a new address, the code is read back from the dev outbox,
 * and only a confirmed code moves the account: the old address stops signing in, the new one
 * starts, a second account holding the address is a 409, and asking for the current one is a 400.
 */
async function emailChangeFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
  internalSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const headers = managementHeaders(adminToken);
  const emailOld = `email-change-${runId}@demo.localhost`;
  const emailNew = `email-changed-${runId}@example.test`;
  const emailB = `email-change-b-${runId}@demo.localhost`;
  const password = `pw-${runId}-email-change`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "14",
    title: "email change",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `m-${tag}-${runId}-${"k".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Password sign-in on a fresh interaction, together with any session cookie it set. */
  const signIn = async (
    tag: string,
    identifier: string,
    value: string,
  ): Promise<{ interaction: string; verifier: string; status: number; body: unknown; cookie?: string } | undefined> => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier, password: value }),
    });
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(response.headers.get("set-cookie") ?? "")?.[1];
    return { ...started, status: response.status, body: response.body, cookie };
  };

  /** Redeem the `redirect_to` a completed interaction returned for a token. */
  const exchange = async (redirectTo: unknown, verifier: string): Promise<HttpResult> => {
    const code = typeof redirectTo === "string" ? new URL(redirectTo).searchParams.get("code") ?? "" : "";
    return tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
  };

  /** The newest dev mail for an address and purpose, or undefined when none arrived. */
  const mailCode = async (to: string, purpose: string): Promise<string | undefined> => {
    const query = new URLSearchParams({ tenant: TENANT, to, purpose });
    const response = await call(`${base}/internal/mail?${query}`, {
      headers: { "x-monaca-internal-secret": internalSecret },
    });
    const code = (response.body as { payload?: { code?: unknown } } | undefined)?.payload?.code;
    return response.status === 200 && typeof code === "string" ? code : undefined;
  };

  try {
    // --- two accounts with passwords, both in acme ----------------------------------------------
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: emailOld, display_name: "Email change A", password }),
    });
    const accountId = (created.body as { id?: string })?.id;
    if (created.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts A → ${created.status} ${text(created.body)}`);
    }
    const createdB = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: emailB, display_name: "Email change B", password }),
    });
    const accountBId = (createdB.body as { id?: string })?.id;
    if (createdB.status !== 201 || accountBId === undefined) {
      return fail(`POST /v1/accounts B → ${createdB.status} ${text(createdB.body)}`);
    }
    const memberA = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    const memberB = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountBId, role: "member" }),
    });
    checks.push([
      "both accounts joined acme",
      memberA.status === 201 && memberB.status === 201,
    ]);

    const first = await signIn("first", emailOld, password);
    if (first?.cookie === undefined) return fail("the account centre sign-in set no session cookie");
    const cookieA = { cookie: `monaca_session=${first.cookie}` };
    const cookieJson = { ...cookieA, "content-type": "application/json" };

    // --- request: the code goes to the new address, keyed by that address ------------------------
    const requested = await call(`${base}/t/${TENANT}/account/email`, {
      method: "POST",
      headers: cookieJson,
      body: JSON.stringify({ email: emailNew }),
    });
    checks.push([
      "POST /account/email requests a code for the new address",
      requested.status === 200 &&
        (requested.body as { verification_required?: unknown })?.verification_required === true,
    ]);

    const code = await mailCode(emailNew, "email_change");
    checks.push([
      "dev mail delivered an email_change code",
      typeof code === "string" && /^\d{6}$/.test(code),
    ]);

    // A wrong code is refused and the address stays where it was.
    const wrong = await call(`${base}/t/${TENANT}/account/email/verify`, {
      method: "POST",
      headers: cookieJson,
      body: JSON.stringify({ email: emailNew, code: code === "000000" ? "111111" : "000000" }),
    });
    checks.push(["a wrong code is 401", wrong.status === 401]);

    const confirmed = await call(`${base}/t/${TENANT}/account/email/verify`, {
      method: "POST",
      headers: cookieJson,
      body: JSON.stringify({ email: emailNew, code: code ?? "" }),
    });
    checks.push([
      "the right code moves the account and the profile shows the new address",
      confirmed.status === 200 && (confirmed.body as { email?: unknown })?.email === emailNew,
    ]);

    const changeNotice = await call(
      `${base}/internal/mail?${new URLSearchParams({ tenant: TENANT, to: emailOld, purpose: "email_changed" })}`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    checks.push(["the previous address is told about the change", changeNotice.status === 200]);

    const profile = await call(`${base}/t/${TENANT}/account`, { headers: cookieA });
    checks.push([
      "GET /account echoes the new address",
      profile.status === 200 && (profile.body as { email?: unknown })?.email === emailNew,
    ]);

    // --- the old address stops signing in, the new one starts -----------------------------------
    const byOld = await signIn("old", emailOld, password);
    checks.push(["the old email no longer signs in", byOld?.status === 401]);

    const byNew = await signIn("new", emailNew, password);
    if (byNew === undefined) return fail("");
    const newToken = await exchange((byNew.body as { redirect_to?: unknown })?.redirect_to, byNew.verifier);
    checks.push([
      "the new email signs in and mints a token",
      byNew.status === 200 && newToken.status === 200,
    ]);

    // --- an address another account holds, and the account's own address ------------------------
    const taken = await call(`${base}/t/${TENANT}/account/email`, {
      method: "POST",
      headers: cookieJson,
      body: JSON.stringify({ email: emailB }),
    });
    checks.push([
      "an address another account holds is 409 MONACA_EMAIL_TAKEN",
      taken.status === 409 &&
        (taken.body as { monaca_error_code?: unknown })?.monaca_error_code === "MONACA_EMAIL_TAKEN",
    ]);

    const same = await call(`${base}/t/${TENANT}/account/email`, {
      method: "POST",
      headers: cookieJson,
      body: JSON.stringify({ email: emailNew }),
    });
    checks.push(["the account's own address is 400", same.status === 400]);
  } catch (error) {
    // A thrown fetch means a request never got an answer; a step with only passing checks so far
    // must not be reported as green.
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "14",
    title: "email change",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: request → code → wrong code 401 → confirm → old email 401 → new email token → conflict 409 → same address 400`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 15 — social (OAuth2) connectors (§6.1).
 *
 * A registered connector points at the in-process mock provider; the account centre connects it,
 * the provider signs the account in without a password, a first social sign-in creates an account,
 * a second account cannot claim the same provider account, a replayed callback is refused, and
 * disconnecting and deleting the connector take effect.
 */
async function socialFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";
  const provider = startMockProvider();

  const fail = (why: string): StepResult => ({
    step: "15",
    title: "social connectors",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `s-${tag}-${runId}-${"x".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Password sign-in on a fresh interaction, together with any session cookie it set. */
  const signIn = async (
    tag: string,
    identifier: string,
    password: string,
  ): Promise<{ interaction: string; verifier: string; status: number; body: unknown; cookie?: string } | undefined> => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier, password }),
    });
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(response.headers.get("set-cookie") ?? "")?.[1];
    return { ...started, status: response.status, body: response.body, cookie };
  };

  /** Redeem the `redirect_to` a completed interaction returned for a token. */
  const exchange = async (redirectTo: string, verifier: string): Promise<HttpResult> => {
    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    return tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
  };

  /** The connector body; the identity the mock asserts is fixed in its authorize URL. */
  const connectorBody = (
    connectorId: string,
    displayName: string,
    identity: Record<string, string>,
  ): Record<string, unknown> => ({
    connector_id: connectorId,
    display_name: displayName,
    authorize_url: `${provider.url}/authorize?${new URLSearchParams(identity).toString()}`,
    token_url: `${provider.url}/token`,
    userinfo_url: `${provider.url}/userinfo`,
    client_id: `${connectorId}-client`,
    client_secret: `${connectorId}-secret`,
    scopes: ["profile", "email"],
  });

  /** Follow a provider round-trip that starts signed in (the link flow). */
  const linkProvider = async (
    cookie: { cookie?: string },
    connector: string,
  ): Promise<{ callbackUrl: string; callback: HttpResult; finalLocation: string } | undefined> => {
    const start = await call(`${base}/t/${TENANT}/account/social/${connector}/authorize`, {
      headers: cookie,
      redirect: "manual",
    });
    const startLocation = start.headers.get("location") ?? "";
    const stateCookie =
      /monaca_social_state=([0-9a-f-]{36})/.exec(start.headers.get("set-cookie") ?? "")?.[1] ??
      "";
    if (start.status !== 302 || startLocation === "" || stateCookie === "") {
      detail = `account link start → ${start.status} ${text(start.body)}`;
      return undefined;
    }
    const atProvider = await call(startLocation, { redirect: "manual" });
    const callbackUrl = atProvider.headers.get("location") ?? "";
    if (atProvider.status !== 302 || callbackUrl === "") {
      detail = `provider authorize → ${atProvider.status}`;
      return undefined;
    }
    const cookieHeader = [cookie.cookie, `monaca_social_state=${stateCookie}`]
      .filter((value): value is string => value !== undefined && value !== "")
      .join("; ");
    const callback = await call(callbackUrl, {
      headers: cookieHeader === "" ? {} : { cookie: cookieHeader },
      redirect: "manual",
    });
    return { callbackUrl, callback, finalLocation: callback.headers.get("location") ?? "" };
  };

  /** Follow a provider round-trip that starts from the sign-in page. */
  const socialSignIn = async (
    connector: string,
  ): Promise<{ verifier: string; callback: HttpResult; callbackUrl: string; redirectTo: string } | undefined> => {
    const started = await begin(`social-${connector}`);
    if (started === undefined) return undefined;
    const authorize = await call(
      `${base}/t/${TENANT}/connectors/${connector}/authorize?interaction=${started.interaction}`,
      { redirect: "manual" },
    );
    const startLocation = authorize.headers.get("location") ?? "";
    const stateCookie =
      /monaca_social_state=([0-9a-f-]{36})/.exec(
        authorize.headers.get("set-cookie") ?? "",
      )?.[1] ?? "";
    if (authorize.status !== 302 || startLocation === "" || stateCookie === "") {
      detail = `connector authorize → ${authorize.status} ${text(authorize.body)}`;
      return undefined;
    }
    const atProvider = await call(startLocation, { redirect: "manual" });
    const callbackUrl = atProvider.headers.get("location") ?? "";
    if (atProvider.status !== 302 || callbackUrl === "") {
      detail = `provider authorize → ${atProvider.status}`;
      return undefined;
    }
    const callback = await call(callbackUrl, {
      headers: { cookie: `monaca_social_state=${stateCookie}` },
      redirect: "manual",
    });
    return {
      verifier: started.verifier,
      callback,
      callbackUrl,
      redirectTo: callback.headers.get("location") ?? "",
    };
  };

  try {
    // --- register the connector and check the admin surface ------------------------------------
    const identityA = {
      sub: `social-${runId}`,
      email: `social-${runId}@demo.localhost`,
      verified: "1",
      name: "Social A",
    };
    const created = await call(`${base}/v1/connectors`, {
      method: "POST",
      headers,
      body: JSON.stringify(connectorBody("mock", "Mock Provider", identityA)),
    });
    checks.push(["POST /v1/connectors is 201", created.status === 201]);

    const duplicate = await call(`${base}/v1/connectors`, {
      method: "POST",
      headers,
      body: JSON.stringify(connectorBody("mock", "Mock Provider", identityA)),
    });
    checks.push([
      "a duplicate connector is 409 MONACA_CONNECTOR_EXISTS",
      duplicate.status === 409 &&
        (duplicate.body as { monaca_error_code?: unknown })?.monaca_error_code === "MONACA_CONNECTOR_EXISTS",
    ]);

    const listed = await call(`${base}/v1/connectors`, { headers });
    const listedItems = (listed.body as { items?: { connector_id?: unknown }[] })?.items ?? [];
    checks.push([
      "GET /v1/connectors lists the connector without its secret",
      listed.status === 200 &&
        listedItems.some((item) => item.connector_id === "mock") &&
        !JSON.stringify(listed.body).includes("mock-secret"),
    ]);

    const publicList = await call(`${base}/t/${TENANT}/connectors`);
    checks.push([
      "the public list exposes the display name only",
      publicList.status === 200 &&
        JSON.stringify(publicList.body).includes("Mock Provider") &&
        !JSON.stringify(publicList.body).includes("mock-secret"),
    ]);

    // --- account A connects the provider --------------------------------------------------------
    const passwordA = `pw-${runId}-social-a`;
    const createdA = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: identityA.email, display_name: "Social A", password: passwordA }),
    });
    const accountAId = (createdA.body as { id?: string })?.id;
    if (createdA.status !== 201 || accountAId === undefined) {
      return fail(`POST /v1/accounts A → ${createdA.status} ${text(createdA.body)}`);
    }
    const memberA = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountAId, role: "member" }),
    });
    const first = await signIn("first", identityA.email, passwordA);
    if (first?.cookie === undefined) return fail("the password sign-in set no session cookie");
    const cookieA = { cookie: `monaca_session=${first.cookie}` };
    checks.push(["the account joined acme and signed in", memberA.status === 201]);

    const linkA = await linkProvider(cookieA, "mock");
    if (linkA === undefined) return fail("");
    checks.push([
      "the account centre connects the provider and returns to the page",
      linkA.callback.status === 302 && linkA.finalLocation.includes("linked=mock"),
    ]);

    const profileA = await call(`${base}/t/${TENANT}/account`, { headers: cookieA });
    const socialA = (profileA.body as { social?: { connector?: unknown }[] })?.social ?? [];
    checks.push([
      "GET /account lists the connected provider",
      profileA.status === 200 && socialA.some((row) => row.connector === "mock"),
    ]);

    // --- the provider signs the account in, and a replay is refused -----------------------------
    const social = await socialSignIn("mock");
    if (social === undefined) return fail("");
    const token = await exchange(social.redirectTo, social.verifier);
    const claims = jwtClaims((token.body as { id_token?: unknown })?.id_token);
    checks.push([
      "the connected provider signs in without a password and mints a token",
      social.callback.status === 302 && token.status === 200 && claims?.email === identityA.email,
    ]);

    const replay = await call(social.callbackUrl, { redirect: "manual" });
    checks.push(["a replayed callback is 400", replay.status === 400]);

    // --- account B cannot claim the same provider account ----------------------------------------
    const emailB = `social-b-${runId}@demo.localhost`;
    const passwordB = `pw-${runId}-social-b`;
    const createdB = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: emailB, display_name: "Social B", password: passwordB }),
    });
    const accountBId = (createdB.body as { id?: string })?.id;
    if (createdB.status !== 201 || accountBId === undefined) {
      return fail(`POST /v1/accounts B → ${createdB.status} ${text(createdB.body)}`);
    }
    const memberB = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountBId, role: "member" }),
    });
    const second = await signIn("second", emailB, passwordB);
    if (second?.cookie === undefined) return fail("the second sign-in set no session cookie");
    const cookieB = { cookie: `monaca_session=${second.cookie}` };

    const linkB = await linkProvider(cookieB, "mock");
    if (linkB === undefined) return fail("");
    checks.push([
      "a provider account already connected to another user is refused",
      memberB.status === 201 &&
        linkB.callback.status === 302 &&
        linkB.finalLocation.includes("social_error=taken"),
    ]);

    // --- a first social sign-in creates the account and signs it in -----------------------------
    const identityNew = {
      sub: `social-new-${runId}`,
      email: `social-new-${runId}@example.test`,
      verified: "1",
      name: "Social New",
    };
    const createdNew = await call(`${base}/v1/connectors`, {
      method: "POST",
      headers,
      body: JSON.stringify(connectorBody("mock-new", "Mock Provider New", identityNew)),
    });
    checks.push(["a second connector is 201", createdNew.status === 201]);

    const firstSocial = await socialSignIn("mock-new");
    if (firstSocial === undefined) return fail("");
    const newToken = await exchange(firstSocial.redirectTo, firstSocial.verifier);
    const newClaims = jwtClaims((newToken.body as { id_token?: unknown })?.id_token);
    checks.push([
      "a first social sign-in creates an account and issues a token",
      firstSocial.callback.status === 302 &&
        newToken.status === 200 &&
        newClaims?.email === identityNew.email,
    ]);

    // --- disconnecting, and deleting the connector ----------------------------------------------
    const unlink = await call(`${base}/t/${TENANT}/account/social/mock`, {
      method: "DELETE",
      headers: cookieA,
    });
    checks.push(["DELETE /account/social/{connector} is 204", unlink.status === 204]);

    const afterUnlink = await call(`${base}/t/${TENANT}/account`, { headers: cookieA });
    checks.push([
      "the profile no longer lists the provider",
      afterUnlink.status === 200 && (afterUnlink.body as { social?: unknown[] })?.social?.length === 0,
    ]);

    const removed = await call(`${base}/v1/connectors/mock-new`, { method: "DELETE", headers });
    checks.push(["DELETE /v1/connectors/{connector} is 204", removed.status === 204]);

    const missing = await call(`${base}/v1/connectors/mock-new`, { method: "DELETE", headers });
    checks.push(["deleting a missing connector is 404", missing.status === 404]);

    const publicAfter = await call(`${base}/t/${TENANT}/connectors`);
    checks.push([
      "the deleted connector disappears from the public list",
      !JSON.stringify(publicAfter.body).includes("mock-new"),
    ]);
  } catch (error) {
    // A thrown fetch means a request never got an answer; a step with only passing checks so far
    // must not be reported as green.
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    provider.stop();
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "15",
    title: "social connectors",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: configure → connect → social sign-in → replay 400 → conflict → first sign-in creates → disconnect → delete`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 16 — remembered browsers (§6.1 `mfa`).
 *
 * The account enrols an authenticator, proves the second factor once with `remember_device`, and
 * receives a per-tenant cookie. The next sign-in with that cookie skips the challenge and mints a
 * token; a bogus cookie does not. The account centre lists the browser, revoking it clears the
 * cookie and makes the next sign-in ask again.
 */
async function trustedDeviceFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "16",
    title: "trusted browsers",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `t-${tag}-${runId}-${"w".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Password sign-in on a fresh interaction, with an optional extra cookie. */
  const signIn = async (
    tag: string,
    identifier: string,
    password: string,
    cookie?: string,
  ): Promise<{ interaction: string; verifier: string; status: number; body: unknown; cookie?: string } | undefined> => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(cookie === undefined ? {} : { cookie }),
      },
      body: JSON.stringify({ identifier, password }),
    });
    const session = /monaca_session=([0-9a-f-]{36})/.exec(response.headers.get("set-cookie") ?? "")?.[1];
    return { ...started, status: response.status, body: response.body, cookie: session };
  };

  /** Redeem the `redirect_to` a completed interaction returned for a token. */
  const exchange = async (redirectTo: unknown, verifier: string): Promise<HttpResult> => {
    const code = typeof redirectTo === "string" ? new URL(redirectTo).searchParams.get("code") ?? "" : "";
    return tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
  };

  try {
    // --- an account with an authenticator app ----------------------------------------------------
    const email = `trusted-${runId}@demo.localhost`;
    const password = `pw-${runId}-trusted`;
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Trusted browsers", password }),
    });
    const accountId = (created.body as { id?: string })?.id;
    if (created.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    const member = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    const first = await signIn("first", email, password);
    if (first?.cookie === undefined) return fail("the password sign-in set no session cookie");
    const sessionCookie = `monaca_session=${first.cookie}`;
    const accountHeaders = { cookie: sessionCookie };

    const enrollment = await call(`${base}/t/${TENANT}/account/mfa/totp`, {
      method: "POST",
      headers: accountHeaders,
    });
    const secret = (enrollment.body as { secret?: unknown })?.secret;
    if (member.status !== 201 || typeof secret !== "string") {
      return fail(`POST /account/mfa/totp → ${enrollment.status} ${text(enrollment.body)}`);
    }
    const confirmed = await call(`${base}/t/${TENANT}/account/mfa/totp/verify`, {
      method: "POST",
      headers: { ...accountHeaders, "content-type": "application/json" },
      body: JSON.stringify({ code: totpFromBase32(secret) }),
    });
    checks.push([
      "the account enrols an authenticator app",
      confirmed.status === 200 && ((await call(`${base}/t/${TENANT}/account`, { headers: accountHeaders })).body as { mfa?: { totp?: unknown } })?.mfa?.totp === true,
    ]);

    // --- prove the factor once and ask the server to remember this browser ----------------------
    const challenged = await signIn("challenge", email, password);
    if (challenged === undefined) return fail("");
    checks.push([
      "a password sign-in asks for the second factor",
      challenged.status === 200 &&
        (challenged.body as { mfa_required?: unknown })?.mfa_required === true,
    ]);

    const verified = await call(`${base}/t/${TENANT}/interaction/${challenged.interaction}/mfa/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        code: totpFromBase32(secret),
        factor: "totp",
        remember_device: true,
      }),
    });
    const deviceToken = /monaca_mfa_device=([0-9a-f]{64})/.exec(verified.headers.get("set-cookie") ?? "")?.[1];
    const verifiedToken = await exchange((verified.body as { redirect_to?: unknown })?.redirect_to, challenged.verifier);
    checks.push([
      "the code is accepted and the browser is remembered",
      verified.status === 200 && deviceToken !== undefined && verifiedToken.status === 200,
    ]);
    if (deviceToken === undefined) return fail("no monaca_mfa_device cookie was set");

    const deviceCookie = `monaca_mfa_device=${deviceToken}`;
    const listed = await call(`${base}/t/${TENANT}/account/mfa/devices`, {
      headers: { cookie: `${sessionCookie}; ${deviceCookie}` },
    });
    const devices = (listed.body as { items?: { id?: string; current?: boolean }[] })?.items ?? [];
    checks.push([
      "GET /account/mfa/devices lists this browser as current",
      listed.status === 200 && devices.length === 1 && devices[0]?.current === true,
    ]);
    const profile = await call(`${base}/t/${TENANT}/account`, { headers: { cookie: `${sessionCookie}; ${deviceCookie}` } });
    checks.push([
      "the profile counts one trusted browser",
      ((profile.body as { mfa?: { trusted_devices?: unknown } })?.mfa?.trusted_devices) === 1,
    ]);

    // --- the remembered browser skips the challenge; a bogus cookie does not --------------------
    const trusted = await signIn("trusted", email, password, deviceCookie);
    if (trusted === undefined) return fail("");
    const trustedToken = await exchange((trusted.body as { redirect_to?: unknown })?.redirect_to, trusted.verifier);
    checks.push([
      "a remembered browser skips the second factor and mints a token",
      trusted.status === 200 &&
        "redirect_to" in (trusted.body as object) &&
        trustedToken.status === 200,
    ]);

    const bogus = await signIn("bogus", email, password, `monaca_mfa_device=${"a".repeat(64)}`);
    checks.push([
      "an unknown device cookie still asks for the second factor",
      bogus?.status === 200 &&
        (bogus.body as { mfa_required?: unknown })?.mfa_required === true,
    ]);

    // --- revoking the browser clears the caller's cookie and ends the trust ---------------------
    const deviceId = devices[0]?.id;
    if (deviceId === undefined) return fail("the device list carried no id");
    const revoke = await call(`${base}/t/${TENANT}/account/mfa/devices/${encodeURIComponent(deviceId)}`, {
      method: "DELETE",
      headers: { cookie: `${sessionCookie}; ${deviceCookie}` },
    });
    checks.push([
      "DELETE clears the current browser's device cookie",
      revoke.status === 204 &&
        (revoke.headers.get("set-cookie") ?? "").includes("monaca_mfa_device="),
    ]);

    const after = await signIn("after", email, password, deviceCookie);
    checks.push([
      "a revoked browser is asked for the second factor again",
      after?.status === 200 &&
        (after.body as { mfa_required?: unknown })?.mfa_required === true,
    ]);

    const afterList = await call(`${base}/t/${TENANT}/account/mfa/devices`, {
      headers: { cookie: sessionCookie },
    });
    checks.push([
      "the device list is empty and the profile counts zero",
      afterList.status === 200 &&
        ((afterList.body as { items?: unknown[] })?.items?.length ?? 0) === 0 &&
        ((await call(`${base}/t/${TENANT}/account`, { headers: { cookie: sessionCookie } })).body as { mfa?: { trusted_devices?: unknown } })?.mfa?.trusted_devices === 0,
    ]);
  } catch (error) {
    // A thrown fetch means a request never got an answer; a step with only passing checks so far
    // must not be reported as green.
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "16",
    title: "trusted browsers",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: enrol → remember → skip MFA → bogus still asks → revoke clears → revoked asks again`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 17 — self-service account deletion (§6.1).
 *
 * Deletion is irreversible, so the account first proves its address with a `delete_account` code.
 * The confirm step removes the tenant row, its tokens and its org resources (membership, grants,
 * agents), clears both cookies, and leaves the audit chains intact.
 */
async function accountDeletionFlow(
  base: string,
  adminToken: string,
  internalSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const headers = managementHeaders(adminToken);
  const email = `deletion-${runId}@demo.localhost`;
  const password = `pw-${runId}-deletion`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "17",
    title: "account deletion",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `d-${tag}-${runId}-${"v".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Password sign-in on a fresh interaction, together with any session cookie it set. */
  const signIn = async (
    tag: string,
  ): Promise<{ interaction: string; verifier: string; status: number; body: unknown; cookie?: string } | undefined> => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: email, password }),
    });
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(response.headers.get("set-cookie") ?? "")?.[1];
    return { ...started, status: response.status, body: response.body, cookie };
  };

  try {
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Delete me", password }),
    });
    const accountId = (created.body as { id?: string })?.id;
    if (created.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    const member = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    const agentName = `deletion-agent-${runId}`;
    const agent = await call(`${base}/v1/orgs/${ORG}/agents`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: agentName, description: "", owner_account_id: accountId }),
    });
    checks.push([
      "the account joined acme and owns an agent",
      member.status === 201 && agent.status === 201,
    ]);

    const first = await signIn("first");
    if (first?.cookie === undefined) return fail("the sign-in set no session cookie");
    const cookie = { cookie: `monaca_session=${first.cookie}` };

    // --- request a code; nothing is deleted yet -------------------------------------------------
    const requested = await call(`${base}/t/${TENANT}/account/deletion`, {
      method: "POST",
      headers: cookie,
    });
    checks.push([
      "POST /account/deletion requests a delete_account code",
      requested.status === 200 &&
        (requested.body as { verification_required?: unknown })?.verification_required === true,
    ]);

    const mail = await call(
      `${base}/internal/mail?${new URLSearchParams({ tenant: TENANT, to: email, purpose: "delete_account" })}`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    const code = (mail.body as { payload?: { code?: unknown } })?.payload?.code;
    checks.push([
      "dev mail delivered a delete_account code",
      typeof code === "string" && /^\d{6}$/.test(code),
    ]);

    const wrong = await call(`${base}/t/${TENANT}/account/deletion/confirm`, {
      method: "POST",
      headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify({ code: code === "000000" ? "111111" : "000000" }),
    });
    checks.push(["a wrong code is 401", wrong.status === 401]);

    // --- the code deletes the account and clears both cookies ------------------------------------
    const confirmed = await call(`${base}/t/${TENANT}/account/deletion/confirm`, {
      method: "POST",
      headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify({ code: code ?? "" }),
    });
    checks.push([
      "the right code deletes the account and clears the cookie",
      confirmed.status === 204 &&
        (confirmed.headers.get("set-cookie") ?? "").includes("monaca_session="),
    ]);

    const deletionNotice = await call(
      `${base}/internal/mail?${new URLSearchParams({ tenant: TENANT, to: email, purpose: "account_deleted" })}`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    checks.push(["the deletion mails a notice", deletionNotice.status === 200]);

    const oldSession = await call(`${base}/t/${TENANT}/account`, { headers: cookie });
    checks.push(["the old session is no longer accepted", oldSession.status === 401]);

    const oldEmail = await signIn("old");
    checks.push(["the old email no longer signs in", oldEmail?.status === 401]);

    const fetched = await call(`${base}/v1/accounts/${accountId}`, { headers });
    checks.push(["GET /v1/accounts/{id} is 404", fetched.status === 404]);

    const members = (await call(`${base}/v1/orgs/${ORG}/members`, { headers })).body as {
      items?: { account_id?: unknown }[];
    };
    checks.push([
      "the org membership is gone",
      (members.items ?? []).every((row) => row.account_id !== accountId),
    ]);

    const agents = (await call(`${base}/v1/orgs/${ORG}/agents`, { headers })).body as {
      items?: { name?: unknown }[];
    };
    checks.push([
      "the agent the account owned is gone",
      (agents.items ?? []).every((row) => row.name !== agentName),
    ]);
  } catch (error) {
    // A thrown fetch means a request never got an answer; a step with only passing checks so far
    // must not be reported as green.
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "17",
    title: "account deletion",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: request → code → wrong 401 → confirm → session gone → sign-in gone → account/gone → membership/agent gone`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 18 — one-time sign-in links (§6.1).
 *
 * The code mode also mails a link: the response never says whether an account exists, the dev
 * outbox carries the URL, opening it signs the account in and mints a token, the same link is
 * refused on replay, and a made-up token is refused.
 */
async function signInLinkFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
  internalSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const headers = managementHeaders(adminToken);
  const email = `link-${runId}@demo.localhost`;
  const password = `pw-${runId}-link`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "18",
    title: "sign-in links",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `l-${tag}-${runId}-${"u".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Redeem the `redirect_to` a completed interaction returned for a token. */
  const exchange = async (redirectTo: unknown, verifier: string): Promise<HttpResult> => {
    const code = typeof redirectTo === "string" ? new URL(redirectTo).searchParams.get("code") ?? "" : "";
    return tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: verifier },
      basic,
    );
  };

  try {
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Link sign-in", password }),
    });
    const accountId = (created.body as { id?: string })?.id;
    if (created.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    const member = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    checks.push(["the account joined acme", member.status === 201]);

    const started = await begin("first");
    if (started === undefined) return fail("");
    const requested = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in/link`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email }),
    });
    checks.push([
      "POST …/sign-in/link answers verification_required",
      requested.status === 200 &&
        (requested.body as { verification_required?: unknown })?.verification_required === true,
    ]);

    const mail = await call(
      `${base}/internal/mail?${new URLSearchParams({ tenant: TENANT, to: email, purpose: "sign_in_link" })}`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    const url = (mail.body as { payload?: { url?: unknown } })?.payload?.url;
    checks.push([
      "dev mail carries the sign-in URL",
      typeof url === "string" && url.includes("/sign-in/link/verify?token="),
    ]);
    if (typeof url !== "string") return fail("the mail carried no URL");

    const clicked = await call(url, { redirect: "manual" });
    const redirectTo = clicked.headers.get("location") ?? "";
    checks.push([
      "opening the link redirects to the client with a code",
      clicked.status === 302 && redirectTo.includes("code="),
    ]);

    const token = await exchange(redirectTo, started.verifier);
    const claims = jwtClaims((token.body as { id_token?: unknown })?.id_token);
    checks.push([
      "the link mints a token for the account",
      token.status === 200 && claims?.email === email,
    ]);

    const replay = await call(url, { redirect: "manual" });
    checks.push(["a replayed link is 401", replay.status === 401]);

    const second = await begin("bad");
    if (second === undefined) return fail("");
    const bogus = await call(
      `${base}/t/${TENANT}/interaction/${second.interaction}/sign-in/link/verify?token=${"0".repeat(64)}`,
      { redirect: "manual" },
    );
    checks.push(["an unknown token is 401", bogus.status === 401]);
  } catch (error) {
    // A thrown fetch means a request never got an answer; a step with only passing checks so far
    // must not be reported as green.
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "18",
    title: "sign-in links",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: request → mail URL → open → token → replay 401 → unknown token 401`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 19 — RBAC roles (§6.2, §7.3).
 *
 * A role names permission scopes; assigning it to an account makes its name appear in that
 * account's id_token `roles` claim. Unassigning removes it, deleting the role removes every
 * assignment, and duplicate names or unknown roles are refused.
 */
async function roleFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const headers = managementHeaders(adminToken);
  const roleName = `role-${runId}`;
  const email = `role-${runId}@demo.localhost`;
  const password = `pw-${runId}-role`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "19",
    title: "roles",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `r-${tag}-${runId}-${"t".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Password sign-in, returning the token the flow minted. */
  const signInToken = async (tag: string): Promise<Record<string, unknown> | undefined> => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const signIn = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: email, password }),
    });
    const redirectTo = (signIn.body as { redirect_to?: unknown })?.redirect_to;
    if (signIn.status !== 200 || typeof redirectTo !== "string") {
      detail = `sign-in(${tag}) → ${signIn.status} ${text(signIn.body)}`;
      return undefined;
    }
    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    const token = await tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: started.verifier },
      basic,
    );
    const claims = jwtClaims((token.body as { id_token?: unknown })?.id_token);
    if (token.status !== 200 || claims === undefined) {
      detail = `token(${tag}) → ${token.status} ${text(token.body)}`;
      return undefined;
    }
    return claims;
  };

  try {
    // --- a role, its uniqueness and its permissions ----------------------------------------------
    const created = await call(`${base}/v1/roles`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: roleName, description: "e2e", permissions: ["tools:read"] }),
    });
    const roleId = (created.body as { id?: string })?.id;
    checks.push([
      "POST /v1/roles is 201 and echoes the permission",
      created.status === 201 &&
        roleId !== undefined &&
        Array.isArray((created.body as { permissions?: unknown })?.permissions) &&
        ((created.body as { permissions: string[] }).permissions).includes("tools:read"),
    ]);
    if (roleId === undefined) return fail("the role carried no id");

    const duplicate = await call(`${base}/v1/roles`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: roleName, permissions: [] }),
    });
    checks.push([
      "a duplicate role name is 409 MONACA_ROLE_EXISTS",
      duplicate.status === 409 &&
        (duplicate.body as { monaca_error_code?: unknown })?.monaca_error_code === "MONACA_ROLE_EXISTS",
    ]);

    const listed = await call(`${base}/v1/roles`, { headers });
    checks.push([
      "GET /v1/roles lists the role",
      listed.status === 200 && JSON.stringify(listed.body).includes(roleName),
    ]);

    // --- assigning it puts the name in the account and its id_token -----------------------------
    const createdAccount = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Role holder", password }),
    });
    const accountId = (createdAccount.body as { id?: string })?.id;
    if (createdAccount.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${createdAccount.status} ${text(createdAccount.body)}`);
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });

    const assigned = await call(`${base}/v1/accounts/${accountId}/roles/${roleId}`, {
      method: "POST",
      headers,
    });
    const fetched = await call(`${base}/v1/accounts/${accountId}`, { headers });
    checks.push([
      "POST /v1/accounts/{id}/roles/{role} is 204 and GET lists it",
      assigned.status === 204 && JSON.stringify(fetched.body).includes(roleName),
    ]);

    const claims = await signInToken("assigned");
    if (claims === undefined) return fail("");
    checks.push([
      "the id_token carries the role name",
      Array.isArray(claims.roles) && (claims.roles as string[]).includes(roleName),
    ]);

    const unknown = await call(`${base}/v1/accounts/${accountId}/roles/rol_01h455vb4pex5vsknk084sn02q`, {
      method: "POST",
      headers,
    });
    checks.push(["assigning an unknown role is 404", unknown.status === 404]);

    // --- unassigning removes it; re-signing in has no roles claim --------------------------------
    const unassigned = await call(`${base}/v1/accounts/${accountId}/roles/${roleId}`, {
      method: "DELETE",
      headers,
    });
    checks.push(["DELETE /v1/accounts/{id}/roles/{role} is 204", unassigned.status === 204]);

    const claimsAfter = await signInToken("unassigned");
    if (claimsAfter === undefined) return fail("");
    checks.push([
      "re-signing in carries no roles claim",
      claimsAfter.roles === undefined,
    ]);

    // --- deleting the role removes it (and any assignment left) ---------------------------------
    const removed = await call(`${base}/v1/roles/${roleId}`, { method: "DELETE", headers });
    checks.push(["DELETE /v1/roles/{role} is 204", removed.status === 204]);

    const missing = await call(`${base}/v1/roles/${roleId}`, { method: "DELETE", headers });
    checks.push(["deleting a missing role is 404", missing.status === 404]);
  } catch (error) {
    // A thrown fetch means a request never got an answer; a step with only passing checks so far
    // must not be reported as green.
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "19",
    title: "roles",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: create → duplicate 409 → assign → id_token roles → unknown 404 → unassign → no claim → delete → 404`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 20 — role permissions govern API scopes (§6.1 scope grants).
 *
 * `monaca-console` may request `tools:read`, but only an account whose roles grant it can sign in
 * for that scope: without a role the sign-in is `403 MONACA_INSUFFICIENT_SCOPE`, and with the role
 * the access token carries `tools:read`.
 */
async function scopeGrantFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const headers = managementHeaders(adminToken);
  const email = `scope-${runId}@demo.localhost`;
  const password = `pw-${runId}-scope`;
  const roleName = `scope-role-${runId}`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "20",
    title: "scope grants",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction asking for `tools:read` as well. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `g-${tag}-${runId}-${"s".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid tools:read",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  try {
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Scope holder", password }),
    });
    const accountId = (created.body as { id?: string })?.id;
    if (created.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });

    // --- without a role the sign-in is refused before anything is minted -------------------------
    const deniedFlow = await begin("denied");
    if (deniedFlow === undefined) return fail("");
    const denied = await call(`${base}/t/${TENANT}/interaction/${deniedFlow.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: email, password }),
    });
    checks.push([
      "a scope no role grants is 403 MONACA_INSUFFICIENT_SCOPE",
      denied.status === 403 &&
        (denied.body as { monaca_error_code?: unknown })?.monaca_error_code === "MONACA_INSUFFICIENT_SCOPE",
    ]);

    // --- a role with the permission lets the same request through --------------------------------
    const role = await call(`${base}/v1/roles`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: roleName, permissions: ["tools:read"] }),
    });
    const roleId = (role.body as { id?: string })?.id;
    const assigned = await call(`${base}/v1/accounts/${accountId}/roles/${roleId}`, {
      method: "POST",
      headers,
    });
    checks.push([
      "a role granting tools:read is assignable",
      role.status === 201 && assigned.status === 204,
    ]);

    const allowedFlow = await begin("allowed");
    if (allowedFlow === undefined) return fail("");
    const allowed = await call(`${base}/t/${TENANT}/interaction/${allowedFlow.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: email, password }),
    });
    const redirectTo = (allowed.body as { redirect_to?: unknown })?.redirect_to;
    checks.push([
      "the same sign-in now completes",
      allowed.status === 200 && typeof redirectTo === "string",
    ]);
    if (typeof redirectTo !== "string") return fail("the granted sign-in returned no redirect_to");

    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    const token = await tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: allowedFlow.verifier },
      basic,
    );
    const scope = jwtClaims((token.body as { access_token?: unknown })?.access_token)?.scope;
    checks.push([
      "the access token carries tools:read",
      token.status === 200 && Array.isArray(scope) && (scope as string[]).includes("tools:read"),
    ]);

    const removed = await call(`${base}/v1/roles/${roleId}`, { method: "DELETE", headers });
    checks.push(["the role is removable", removed.status === 204]);
  } catch (error) {
    // A thrown fetch means a request never got an answer; a step with only passing checks so far
    // must not be reported as green.
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "20",
    title: "scope grants",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: denied 403 → grant role → sign-in → token scope → delete role`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 21 — OIDC `login_hint` prefills the hosted sign-in page (OpenID Connect Core §3.1.2.1).
 *
 * The hint travels with the authorize request into the interaction details, so the page can put it
 * in the identifier field. It is only a hint: a request without one reports null, a hint naming an
 * address that has no account is echoed just the same (the endpoint is not an address oracle), and
 * the visitor may type another identifier. Signing in with the hinted address proves the flow
 * still completes.
 */
async function loginHintFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const headers = managementHeaders(adminToken);
  const email = `hint-${runId}@demo.localhost`;
  const password = `pw-${runId}-hint`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "21",
    title: "login hint",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction, optionally carrying `login_hint`. */
  const begin = async (hint?: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `h-${runId}-${"u".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const query = new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email",
      state: `st-hint-${runId}`,
      nonce: `n-hint-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    });
    if (hint !== undefined) query.set("login_hint", hint);
    const response = await call(`${base}/t/${TENANT}/oauth2/authorize?${query}`, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${hint ?? "none"}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  try {
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Hint holder", password }),
    });
    const accountId = (created.body as { id?: string })?.id;
    if (created.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });

    // --- the hint is carried into the interaction details, and stays optional --------------------
    const hinted = await begin(email);
    const without = await begin();
    if (hinted === undefined || without === undefined) return fail("");

    const hintedDetails = await call(`${base}/t/${TENANT}/interaction/${hinted.interaction}`);
    checks.push([
      "GET interaction echoes the login_hint for the page to prefill",
      hintedDetails.status === 200 &&
        (hintedDetails.body as { login_hint?: unknown })?.login_hint === email,
    ]);

    const plainDetails = await call(`${base}/t/${TENANT}/interaction/${without.interaction}`);
    checks.push([
      "an authorize without login_hint reports null",
      plainDetails.status === 200 && (plainDetails.body as { login_hint?: unknown })?.login_hint === null,
    ]);

    // --- a hint is not a lookup: an address with no account is echoed just the same --------------
    const unknownEmail = `nobody-${runId}@demo.localhost`;
    const unknown = await begin(unknownEmail);
    if (unknown === undefined) return fail("");
    const unknownDetails = await call(`${base}/t/${TENANT}/interaction/${unknown.interaction}`);
    checks.push([
      "a hint naming an unknown address is echoed without disclosing anything",
      unknownDetails.status === 200 &&
        (unknownDetails.body as { login_hint?: unknown })?.login_hint === unknownEmail,
    ]);

    // --- the prefilled identifier completes the flow like any other sign-in ----------------------
    const signIn = await call(`${base}/t/${TENANT}/interaction/${hinted.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: email, password }),
    });
    const redirectTo = (signIn.body as { redirect_to?: unknown })?.redirect_to;
    checks.push([
      "signing in with the hinted identifier completes",
      signIn.status === 200 && typeof redirectTo === "string",
    ]);
    if (typeof redirectTo !== "string") return fail("the hinted sign-in returned no redirect_to");

    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    const token = await tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: hinted.verifier },
      basic,
    );
    const claims = jwtClaims((token.body as { id_token?: unknown })?.id_token);
    checks.push([
      "the token exchange mints an id_token for that account",
      token.status === 200 && claims?.email === email,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "21",
    title: "login hint",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: hint echoed → absent null → unknown echoed → sign-in → id_token`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 22 — application management (§6.2).
 *
 * Creating a client is what lets an application use this tenant as its IdP. A public client signs
 * in with PKCE only; a confidential client holds a secret that rotation replaces; a deleted
 * application can no longer authorize.
 */
async function clientFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const headers = managementHeaders(adminToken);
  const email = `app-${runId}@demo.localhost`;
  const password = `pw-${runId}-app`;
  const publicClientId = `e2e-public-${runId}`;
  const confidentialClientId = `e2e-confidential-${runId}`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "22",
    title: "applications",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction for `clientId`, asking for openid profile email. */
  const begin = async (
    clientId: string,
    tag: string,
  ): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `a-${tag}-${runId}-${"v".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: "openid profile email",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${clientId}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Password sign-in on an interaction, returning the authorization code. */
  const codeFrom = async (started: { interaction: string; verifier: string }): Promise<string | undefined> => {
    const signIn = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: email, password }),
    });
    const redirectTo = (signIn.body as { redirect_to?: unknown })?.redirect_to;
    if (signIn.status !== 200 || typeof redirectTo !== "string") {
      detail = `sign-in → ${signIn.status} ${text(signIn.body)}`;
      return undefined;
    }
    return new URL(redirectTo).searchParams.get("code") ?? "";
  };

  const exchange = (
    clientId: string,
    verifier: string,
    code: string,
    basic?: string,
  ): Promise<HttpResult> =>
    tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier },
      basic,
    );

  try {
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "App Owner", password }),
    });
    const accountId = (created.body as { id?: unknown })?.id;
    if (created.status !== 201 || typeof accountId !== "string") {
      return fail(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });

    // --- a public application: no secret, PKCE only ----------------------------------------------
    const publicCreated = await call(`${base}/v1/clients`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        client_id: publicClientId,
        name: "E2E Public",
        kind: "public",
        redirect_uris: [redirectUri],
        scopes: ["openid", "profile", "email"],
      }),
    });
    const publicRowId = (publicCreated.body as { id?: unknown })?.id;
    const publicBody = publicCreated.body as {
      client_secret?: unknown;
      token_auth_method?: unknown;
      redirect_uris?: unknown;
    };
    checks.push([
      "POST /v1/clients creates a public client without a secret",
      publicCreated.status === 201 &&
        typeof publicRowId === "string" &&
        publicRowId.startsWith("cli_") &&
        publicBody.client_secret === undefined &&
        publicBody.token_auth_method === "none" &&
        JSON.stringify(publicBody.redirect_uris).includes(redirectUri),
    ]);
    if (typeof publicRowId !== "string") return fail("the public client carried no id");

    const duplicate = await call(`${base}/v1/clients`, {
      method: "POST",
      headers,
      body: JSON.stringify({ client_id: publicClientId, name: "Duplicate", kind: "public" }),
    });
    checks.push([
      "a duplicate client_id is 409 MONACA_CLIENT_EXISTS",
      duplicate.status === 409 &&
        (duplicate.body as { monaca_error_code?: unknown })?.monaca_error_code === "MONACA_CLIENT_EXISTS",
    ]);

    const fetched = await call(`${base}/v1/clients/${publicRowId}`, { headers });
    checks.push([
      "GET /v1/clients/{client} echoes the application",
      fetched.status === 200 && JSON.stringify(fetched.body).includes(publicClientId),
    ]);

    const publicFlow = await begin(publicClientId, "pub");
    if (publicFlow === undefined) return fail("");
    const publicCode = await codeFrom(publicFlow);
    if (publicCode === undefined) return fail("");
    const publicToken = await exchange(publicClientId, publicFlow.verifier, publicCode);
    const publicClaims = jwtClaims((publicToken.body as { id_token?: unknown })?.id_token);
    checks.push([
      "a public client exchanges the code without a secret",
      publicToken.status === 200 &&
        publicClaims?.aud === publicClientId &&
        publicClaims?.email === email,
    ]);

    // --- a confidential application: the secret is returned once and rotation replaces it --------
    const confidentialCreated = await call(`${base}/v1/clients`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        client_id: confidentialClientId,
        name: "E2E Confidential",
        kind: "confidential",
        redirect_uris: [redirectUri],
        post_logout_redirect_uris: [redirectUri],
        scopes: ["openid", "profile", "email"],
      }),
    });
    const confidentialRowId = (confidentialCreated.body as { id?: unknown })?.id;
    const confidentialSecret = (confidentialCreated.body as { client_secret?: unknown })?.client_secret;
    checks.push([
      "a confidential client is issued a secret once",
      confidentialCreated.status === 201 &&
        typeof confidentialRowId === "string" &&
        typeof confidentialSecret === "string" &&
        confidentialSecret.length > 0 &&
        (confidentialCreated.body as { token_auth_method?: unknown }).token_auth_method === "client_secret_basic",
    ]);
    if (typeof confidentialRowId !== "string" || typeof confidentialSecret !== "string") {
      return fail("the confidential client carried no secret");
    }

    const confidentialFetch = await call(`${base}/v1/clients/${confidentialRowId}`, { headers });
    checks.push([
      "the secret is never returned again",
      confidentialFetch.status === 200 &&
        JSON.stringify(confidentialFetch.body).includes("post_logout_redirect_uris") &&
        !JSON.stringify(confidentialFetch.body).includes(confidentialSecret),
    ]);

    const confidentialFlow = await begin(confidentialClientId, "conf");
    if (confidentialFlow === undefined) return fail("");
    const confidentialCode = await codeFrom(confidentialFlow);
    if (confidentialCode === undefined) return fail("");
    const confidentialToken = await exchange(
      confidentialClientId,
      confidentialFlow.verifier,
      confidentialCode,
      btoa(`${confidentialClientId}:${confidentialSecret}`),
    );
    checks.push([
      "a confidential client exchanges the code with client_secret_basic",
      confidentialToken.status === 200,
    ]);

    const rotated = await call(`${base}/v1/clients/${confidentialRowId}/secret`, {
      method: "POST",
      headers,
    });
    const rotatedSecret = (rotated.body as { client_secret?: unknown })?.client_secret;
    checks.push([
      "rotating the secret returns a new one",
      rotated.status === 200 && typeof rotatedSecret === "string" && rotatedSecret !== confidentialSecret,
    ]);
    if (typeof rotatedSecret !== "string") return fail("the rotation returned no secret");

    // Client authentication happens before the code is consumed, so the same code can be retried
    // once the stale secret is refused.
    const staleFlow = await begin(confidentialClientId, "stale");
    if (staleFlow === undefined) return fail("");
    const staleCode = await codeFrom(staleFlow);
    if (staleCode === undefined) return fail("");
    const staleToken = await exchange(
      confidentialClientId,
      staleFlow.verifier,
      staleCode,
      btoa(`${confidentialClientId}:${confidentialSecret}`),
    );
    checks.push([
      "the previous secret is refused",
      staleToken.status === 401 && (staleToken.body as { error?: unknown })?.error === "invalid_client",
    ]);

    const freshToken = await exchange(
      confidentialClientId,
      staleFlow.verifier,
      staleCode,
      btoa(`${confidentialClientId}:${rotatedSecret}`),
    );
    checks.push(["the new secret exchanges the same code", freshToken.status === 200]);

    const renamed = await call(`${base}/v1/clients/${confidentialRowId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ name: "Renamed App" }),
    });
    checks.push([
      "PATCH renames the application",
      renamed.status === 200 && (renamed.body as { name?: unknown })?.name === "Renamed App",
    ]);

    const listed = await call(`${base}/v1/clients`, { headers });
    const listedText = JSON.stringify(listed.body);
    checks.push([
      "GET /v1/clients lists both without secrets",
      listed.status === 200 &&
        listedText.includes(publicClientId) &&
        listedText.includes(confidentialClientId) &&
        !listedText.includes(rotatedSecret),
    ]);

    // --- deleting an application ends its ability to ask for codes -------------------------------
    const removed = await call(`${base}/v1/clients/${publicRowId}`, { method: "DELETE", headers });
    const afterDelete = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: publicClientId,
        redirect_uri: redirectUri,
        scope: "openid profile email",
        state: `st-gone-${runId}`,
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method: "S256",
      })}`,
      { redirect: "manual" },
    );
    checks.push([
      "DELETE removes the application and authorize refuses it",
      removed.status === 204 && afterDelete.status === 400 && afterDelete.headers.get("location") === null,
    ]);

    const missing = await call(`${base}/v1/clients/${publicRowId}`, { method: "DELETE", headers });
    checks.push(["deleting a missing application is 404", missing.status === 404]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "22",
    title: "applications",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: public → duplicate 409 → token → confidential secret → rotate → old refused → patch → list → delete → 404`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 23 — user management (§6.2).
 *
 * An administrator can search the tenant's accounts and suspend one. Suspension is immediate:
 * the password stops working, the session cookie and refresh token already issued are revoked,
 * and reactivation restores sign-in.
 */
async function userManagementFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const headers = managementHeaders(adminToken);
  const email = `managed-${runId}@demo.localhost`;
  const password = `pw-${runId}-managed`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "23",
    title: "user management",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction for the managed account's sign-in. */
  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `m-${tag}-${runId}-${"w".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email offline_access",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
      // The management audience is what makes the /v1 state and session checks observable; with
      // the default audience the token is refused for the wrong reason (audience mismatch).
      resource: `${base}/v1`,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Sign in and exchange the code, returning the cookie, access token and refresh token it issued. */
  const signIn = async (
    tag: string,
  ): Promise<{ cookie?: string; accessToken?: string; refreshToken?: string } | undefined> => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: email, password }),
    });
    const redirectTo = (response.body as { redirect_to?: unknown })?.redirect_to;
    if (response.status !== 200 || typeof redirectTo !== "string") {
      detail = `sign-in(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(response.headers.get("set-cookie") ?? "")?.[1];
    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    const token = await tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: "monaca-console", code_verifier: started.verifier },
      basic,
    );
    const accessToken = (token.body as { access_token?: unknown })?.access_token;
    const refreshToken = (token.body as { refresh_token?: unknown })?.refresh_token;
    if (token.status !== 200 || typeof refreshToken !== "string" || typeof accessToken !== "string") {
      detail = `token(${tag}) → ${token.status} ${text(token.body)}`;
      return undefined;
    }
    return { cookie, accessToken, refreshToken };
  };

  try {
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Managed User", password }),
    });
    const accountId = (created.body as { id?: unknown })?.id;
    if (created.status !== 201 || typeof accountId !== "string") {
      return fail(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });

    // --- the search filter finds the account and nothing outside the needle ---------------------
    const searched = await call(`${base}/v1/accounts?query=${encodeURIComponent(`managed-${runId}`)}`, {
      headers,
    });
    const items = (searched.body as { items?: { email?: unknown }[] })?.items ?? [];
    checks.push([
      "GET /v1/accounts?query=… finds the account",
      searched.status === 200 &&
        items.length >= 1 &&
        items.every((item) => String(item.email).includes(`managed-${runId}`)),
    ]);

    const live = await signIn("live");
    if (live === undefined || live.cookie === undefined) {
      return fail("the pre-suspension sign-in issued no session cookie");
    }

    // --- suspension stops the password, the live session and the refresh flow --------------------
    const suspended = await call(`${base}/v1/accounts/${accountId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ state: "disabled" }),
    });
    checks.push([
      "PATCH {state:disabled} suspends the account",
      suspended.status === 200 && (suspended.body as { state?: unknown })?.state === "disabled",
    ]);

    const denied = await begin("denied");
    if (denied === undefined) return fail("");
    const passwordAttempt = await call(`${base}/t/${TENANT}/interaction/${denied.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: email, password }),
    });
    checks.push([
      "the suspended account's password is refused",
      passwordAttempt.status === 401 &&
        (passwordAttempt.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_INVALID_CREDENTIALS",
    ]);

    const sessionProbe = await call(`${base}/t/${TENANT}/account`, {
      headers: { cookie: `monaca_session=${live.cookie}` },
    });
    checks.push([
      "the previous session cookie no longer works",
      sessionProbe.status === 401 &&
        (sessionProbe.body as { monaca_error_code?: unknown })?.monaca_error_code === "MONACA_UNAUTHORIZED",
    ]);

    const renewed = await tokenCall(
      base,
      { grant_type: "refresh_token", refresh_token: live.refreshToken ?? "" },
      basic,
    );
    checks.push([
      "the previous refresh token is refused",
      renewed.status === 400 && (renewed.body as { error?: unknown })?.error === "invalid_grant",
    ]);

    // --- the already-issued access token stops reaching /v1 and userinfo -------------------------
    const managementProbe = await call(`${base}/v1/accounts?limit=1`, {
      headers: managementHeaders(live.accessToken ?? ""),
    });
    checks.push([
      "the previous access token cannot call /v1 after suspension",
      managementProbe.status === 401 &&
        (managementProbe.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_UNAUTHORIZED" &&
        String((managementProbe.body as { detail?: unknown })?.detail ?? "").includes("disabled"),
    ]);

    const userinfoProbe = await call(`${base}/t/${TENANT}/oauth2/userinfo`, {
      headers: { authorization: `Bearer ${live.accessToken}` },
    });
    checks.push([
      "the previous access token is refused by userinfo",
      userinfoProbe.status === 401 && (userinfoProbe.body as { error?: unknown })?.error === "invalid_token",
    ]);

    // --- reactivation restores sign-in ---------------------------------------------------------
    const restored = await call(`${base}/v1/accounts/${accountId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ state: "active" }),
    });
    checks.push([
      "PATCH {state:active} reactivates the account",
      restored.status === 200 && (restored.body as { state?: unknown })?.state === "active",
    ]);

    const after = await signIn("after");
    checks.push(["the reactivated account signs in again", after !== undefined]);

    // The suspension revoked the old session, so its token stays dead even now that the account is
    // active again; reactivation must not resurrect what an operator withdrew.
    const resurrected = await call(`${base}/v1/accounts?limit=1`, {
      headers: managementHeaders(live.accessToken ?? ""),
    });
    checks.push([
      "reactivation does not resurrect the withdrawn token",
      resurrected.status === 401 &&
        (resurrected.body as { monaca_error_code?: unknown })?.monaca_error_code === "MONACA_UNAUTHORIZED",
    ]);

    // --- bad input -----------------------------------------------------------------------------
    const invalid = await call(`${base}/v1/accounts/${accountId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ state: "suspended" }),
    });
    checks.push(["an unknown state is 400", invalid.status === 400]);

    const unknown = await call(`${base}/v1/accounts/acc_01h455vb4pex5vsknk084sn02q`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ state: "disabled" }),
    });
    checks.push(["suspending an unknown account is 404", unknown.status === 404]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "23",
    title: "user management",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: search → suspend → password 401 → session 401 → /v1 401 → userinfo 401 → refresh invalid → reactivate → sign-in → withdrawn token stays 401 → 400 → 404`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 71 — administrative disposal (§6.2).
 *
 * Deleting an account is destructive, so the endpoint must first report what would go (`dry_run`)
 * and then demand the account's email back. The real effects are asserted from the outside: the
 * deleted account's access and refresh tokens must stop working, and the tenant audit chain must
 * still name the deletion after the account row is gone.
 */
async function administrativeDisposalFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
  internalSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const headers = managementHeaders(adminToken);
  const email = `dispose-${runId}@demo.localhost`;
  const password = `pw-${runId}-dispose`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "71",
    title: "administrative disposal",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });
  const errorCode = (body: unknown): unknown => (body as { monaca_error_code?: unknown })?.monaca_error_code;

  try {
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Disposable User", password }),
    });
    const accountId = (created.body as { id?: unknown })?.id;
    if (created.status !== 201 || typeof accountId !== "string") {
      return fail(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });

    const signedIn = await consoleSignIn(base, email, password, consoleSecret, "dispose");
    if (signedIn.session === undefined) return fail(signedIn.error ?? "sign-in failed");
    const live = signedIn.session;

    const dryRun = await call(`${base}/v1/accounts/${accountId}?dry_run=true`, {
      method: "DELETE",
      headers,
    });
    const dry = dryRun.body as {
      dry_run?: unknown;
      email?: unknown;
      sessions?: unknown;
      refresh_tokens?: unknown;
    };
    checks.push([
      "dry_run reports the account, sessions and refresh tokens",
      dryRun.status === 200 &&
        dry.dry_run === true &&
        dry.email === email &&
        Number(dry.sessions) >= 1 &&
        Number(dry.refresh_tokens) >= 1,
    ]);

    const afterDryRun = await call(`${base}/v1/accounts/${accountId}`, { headers });
    checks.push(["dry_run leaves the account in place", afterDryRun.status === 200]);

    const unconfirmed = await call(`${base}/v1/accounts/${accountId}`, { method: "DELETE", headers });
    checks.push([
      "deleting without confirm is 400 MONACA_CONFIRMATION_REQUIRED",
      unconfirmed.status === 400 && errorCode(unconfirmed.body) === "MONACA_CONFIRMATION_REQUIRED",
    ]);

    const mismatched = await call(
      `${base}/v1/accounts/${accountId}?confirm=${encodeURIComponent("someone-else@demo.localhost")}`,
      { method: "DELETE", headers },
    );
    checks.push([
      "a confirm naming another address is refused",
      mismatched.status === 400 && errorCode(mismatched.body) === "MONACA_CONFIRMATION_REQUIRED",
    ]);

    const deleted = await call(`${base}/v1/accounts/${accountId}?confirm=${encodeURIComponent(email)}`, {
      method: "DELETE",
      headers,
    });
    const result = deleted.body as {
      deleted?: unknown;
      sessions_revoked?: unknown;
      refresh_tokens_revoked?: unknown;
    };
    checks.push([
      "the confirmed delete removes the account and reports what it revoked",
      deleted.status === 200 &&
        result.deleted === true &&
        Number(result.sessions_revoked) >= 1 &&
        Number(result.refresh_tokens_revoked) >= 1,
    ]);

    const gone = await call(`${base}/v1/accounts/${accountId}`, { headers });
    checks.push(["the deleted account is 404", gone.status === 404]);

    const userinfo = await call(`${base}/t/${TENANT}/oauth2/userinfo`, {
      headers: { authorization: `Bearer ${live.accessToken}` },
    });
    checks.push([
      "the deleted account's access token is refused",
      userinfo.status === 401 && (userinfo.body as { error?: unknown })?.error === "invalid_token",
    ]);

    const renewed = await tokenCall(
      base,
      { grant_type: "refresh_token", refresh_token: live.refreshToken },
      basic,
    );
    checks.push([
      "the deleted account's refresh token is refused",
      renewed.status === 400 && (renewed.body as { error?: unknown })?.error === "invalid_grant",
    ]);

    // The account row is gone, but the audit chain is history and must keep the event.
    const audit = await call(
      `${base}/internal/audit?${new URLSearchParams({ tenant: TENANT, action: "account.deleted", limit: "200" })}`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    const events =
      (
        audit.body as
          | {
              items?: {
                payload?: { email?: unknown; self_service?: unknown };
                actor_chain?: unknown[];
              }[];
            }
          | undefined
      )?.items ?? [];
    const match = events.find((event) => event.payload?.email === email);
    checks.push([
      "the deletion survives in the tenant audit chain with its actor",
      audit.status === 200 &&
        match !== undefined &&
        match.payload?.self_service === false &&
        Array.isArray(match.actor_chain) &&
        match.actor_chain.length >= 1,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "71",
    title: "administrative disposal",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: dry-run counts → account kept → confirm required → mismatch refused → delete → 404 → access 401 → refresh invalid → audit survives`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 72 — session visibility and kick-out (§6.2).
 *
 * Two browsers sign into one account. Revoking one session must kill exactly that browser's
 * access token and renewal, leaving the other untouched; revoking all must end both and empty the
 * list. Introspection is the resource-server view, so it is asserted too.
 */
async function sessionKickFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const headers = managementHeaders(adminToken);
  const email = `kick-${runId}@demo.localhost`;
  const password = `pw-${runId}-kick`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "72",
    title: "session kick-out",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });
  const userinfo = (token: string): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/oauth2/userinfo`, {
      headers: { authorization: `Bearer ${token}` },
    });
  const introspect = (token: string, hint: "access_token" | "refresh_token"): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/oauth2/introspect`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${basic}`,
      },
      body: new URLSearchParams({ token, token_type_hint: hint }).toString(),
    });

  try {
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Kick Target", password }),
    });
    const accountId = (created.body as { id?: unknown })?.id;
    if (created.status !== 201 || typeof accountId !== "string") {
      return fail(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });

    const first = await consoleSignIn(base, email, password, consoleSecret, "kick-a");
    if (first.session === undefined) return fail(first.error ?? "the first sign-in failed");
    // Distinct insertion times let the session list order the two browsers deterministically.
    await new Promise((resolve) => setTimeout(resolve, 30));
    const second = await consoleSignIn(base, email, password, consoleSecret, "kick-b");
    if (second.session === undefined) return fail(second.error ?? "the second sign-in failed");

    const listed = await call(`${base}/v1/accounts/${accountId}/sessions`, { headers });
    const sessions =
      (listed.body as { items?: { id?: unknown }[] } | undefined)?.items ?? [];
    checks.push([
      "both browsers are visible on the account",
      listed.status === 200 &&
        sessions.length === 2 &&
        sessions.every((row) => String(row.id).startsWith("ses_")),
    ]);
    const target = sessions[0]?.id;
    if (typeof target !== "string") return fail(`session list → ${listed.status} ${text(listed.body)}`);

    const kicked = await call(`${base}/v1/accounts/${accountId}/sessions/${target}`, {
      method: "DELETE",
      headers,
    });
    checks.push(["deleting one session answers 204", kicked.status === 204]);

    const firstProbe = await userinfo(first.session.accessToken);
    const secondProbe = await userinfo(second.session.accessToken);
    checks.push([
      "the kick ends exactly one browser",
      (firstProbe.status === 401) !== (secondProbe.status === 401),
    ]);
    const dead = secondProbe.status === 401 ? second.session : first.session;
    const alive = secondProbe.status === 401 ? first.session : second.session;
    const aliveProbeInitial = secondProbe.status === 401 ? firstProbe : secondProbe;
    checks.push([
      "the untouched browser keeps working",
      aliveProbeInitial.status === 200 &&
        typeof (aliveProbeInitial.body as { sub?: unknown })?.sub === "string",
    ]);

    const deadIntrospection = await introspect(dead.accessToken, "access_token");
    checks.push([
      "introspection reports the kicked access token inactive",
      deadIntrospection.status === 200 &&
        (deadIntrospection.body as { active?: unknown })?.active === false,
    ]);

    const deadRenewal = await tokenCall(
      base,
      { grant_type: "refresh_token", refresh_token: dead.refreshToken },
      basic,
    );
    checks.push([
      "the kicked session's refresh token is refused",
      deadRenewal.status === 400 && (deadRenewal.body as { error?: unknown })?.error === "invalid_grant",
    ]);

    const deadRefreshIntrospection = await introspect(dead.refreshToken, "refresh_token");
    checks.push([
      "introspection reports the kicked refresh token inactive",
      deadRefreshIntrospection.status === 200 &&
        (deadRefreshIntrospection.body as { active?: unknown })?.active === false,
    ]);

    const aliveRefreshIntrospection = await introspect(alive.refreshToken, "refresh_token");
    checks.push([
      "the untouched refresh token is still active",
      aliveRefreshIntrospection.status === 200 &&
        (aliveRefreshIntrospection.body as { active?: unknown })?.active === true,
    ]);

    const revokedAll = await call(`${base}/v1/accounts/${accountId}/sessions`, {
      method: "DELETE",
      headers,
    });
    const counts = revokedAll.body as { revoked?: unknown; refresh_revoked?: unknown };
    checks.push([
      "revoke-all ends the remaining session and its renewal",
      revokedAll.status === 200 && Number(counts.revoked) >= 1 && Number(counts.refresh_revoked) >= 1,
    ]);

    const aliveProbe = await userinfo(alive.accessToken);
    checks.push([
      "the remaining access token is refused after revoke-all",
      aliveProbe.status === 401 && (aliveProbe.body as { error?: unknown })?.error === "invalid_token",
    ]);

    const aliveRenewal = await tokenCall(
      base,
      { grant_type: "refresh_token", refresh_token: alive.refreshToken },
      basic,
    );
    checks.push([
      "the remaining refresh token is refused after revoke-all",
      aliveRenewal.status === 400 && (aliveRenewal.body as { error?: unknown })?.error === "invalid_grant",
    ]);

    const remaining = await call(`${base}/v1/accounts/${accountId}/sessions`, { headers });
    checks.push([
      "no live session remains listed",
      remaining.status === 200 &&
        ((remaining.body as { items?: unknown[] } | undefined)?.items ?? []).length === 0,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "72",
    title: "session kick-out",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: two sessions listed → one kick 204 → exactly one browser dead → other alive → introspection inactive → renewal refused → revoke-all → both dead → list empty`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 73 — tenant audit queries (§6.2).
 *
 * The tenant chain carries the operator actions the org chain never sees. The list must filter
 * by action, prefix, actor, subject and time window, state its effective page size and filtered
 * total, cap a page at 200 rows, refuse a non-admin, and above all not append an event just
 * because someone read the audit.
 */
async function auditQueryFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const email = `audit-${runId}@demo.localhost`;
  const password = `pw-${runId}-audit`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "73",
    title: "tenant audit query",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });
  interface AuditPage {
    items?: {
      seq?: number;
      action?: unknown;
      subject?: { id?: unknown };
      actor_chain?: { id?: unknown }[];
    }[];
    next?: number | null;
    limit?: unknown;
    total?: unknown;
    head?: { seq?: unknown };
  }
  const audit = (query: Record<string, string>): Promise<HttpResult> =>
    call(`${base}/v1/audit?${new URLSearchParams(query)}`, { headers });
  const page = (body: unknown): AuditPage => (body as AuditPage | undefined) ?? {};
  const errorCode = (body: unknown): unknown =>
    (body as { monaca_error_code?: unknown })?.monaca_error_code;

  try {
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Audit Subject", password }),
    });
    const accountId = (created.body as { id?: unknown })?.id;
    if (created.status !== 201 || typeof accountId !== "string") {
      return fail(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });

    const signedIn = await consoleSignIn(
      base,
      email,
      password,
      consoleSecret,
      "audit",
      "openid offline_access monaca:admin",
    );
    if (signedIn.session === undefined) return fail(signedIn.error ?? "sign-in failed");

    // --- §6.2: a non-admin asking for monaca:admin does not receive it -----------------------
    const tokenScope = (jwtClaims(signedIn.session.accessToken)?.scope ?? []) as unknown;
    checks.push([
      "a non-admin's requested monaca:admin is dropped at issuance",
      Array.isArray(tokenScope) && !tokenScope.map(String).includes("monaca:admin"),
    ]);
    const forbidden = await call(`${base}/v1/audit?limit=1`, {
      headers: managementHeaders(signedIn.session.accessToken),
    });
    checks.push([
      "a non-admin cannot read the tenant audit chain",
      forbidden.status === 403 &&
        errorCode(forbidden.body) === "MONACA_INSUFFICIENT_SCOPE",
    ]);

    // --- an operator action on the tenant chain ------------------------------------------------
    const disabled = await call(`${base}/v1/accounts/${accountId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ state: "disabled" }),
    });
    if (disabled.status !== 200) {
      return fail(`PATCH disabled → ${disabled.status} ${text(disabled.body)}`);
    }

    const bySubject = page((await audit({ subject: accountId, limit: "10" })).body);
    const subjectItems = bySubject.items ?? [];
    checks.push([
      "the subject filter returns only that account's events",
      subjectItems.length >= 2 &&
        subjectItems.every((item) => item.subject?.id === accountId),
    ]);

    const exact = page((await audit({ action: "account.suspended", subject: accountId, limit: "10" })).body);
    checks.push([
      "the exact action filter finds the suspension",
      (exact.items ?? []).length >= 1 &&
        (exact.items ?? []).every((item) => item.action === "account.suspended"),
    ]);

    const prefix = page((await audit({ action_prefix: "account.", subject: accountId, limit: "10" })).body);
    const prefixItems = prefix.items ?? [];
    checks.push([
      "the action prefix matches every account.* event",
      prefixItems.length >= 2 &&
        prefixItems.every((item) => String(item.action).startsWith("account.")),
    ]);

    const actor = (jwtClaims(adminToken) as { sub?: unknown } | undefined)?.sub;
    const byActor = page(
      (await audit({ actor: typeof actor === "string" ? actor : "", subject: accountId, limit: "10" })).body,
    );
    checks.push([
      "the actor filter matches the operator's chain entry",
      typeof actor === "string" &&
        (byActor.items ?? []).length >= 1 &&
        (byActor.items ?? []).every((item) =>
          (item.actor_chain ?? []).some((entry) => entry.id === actor),
        ),
    ]);

    const now = Date.now();
    const past = new Date(now - 3_600_000).toISOString();
    const future = new Date(now + 3_600_000).toISOString();
    const far = new Date(now + 7_200_000).toISOString();
    const empty = page((await audit({ from: future, to: far, subject: accountId, limit: "10" })).body);
    checks.push([
      "a time window after the events is empty",
      Number(empty.total) === 0 && (empty.items ?? []).length === 0,
    ]);
    const covered = page((await audit({ from: past, to: far, subject: accountId, limit: "10" })).body);
    checks.push([
      "a covering time window returns the events",
      Number(covered.total) >= 2,
    ]);

    // --- pagination: effective page size, cursor and the hard cap ------------------------------
    const first = page((await audit({ subject: accountId, limit: "1" })).body);
    const firstNext = first.next;
    checks.push([
      "limit=1 returns one row and a cursor while total stays filtered",
      Number(first.limit) === 1 &&
        (first.items ?? []).length === 1 &&
        typeof firstNext === "number" &&
        Number(first.total) >= 2,
    ]);
    const second = page(
      (
        await audit({
          subject: accountId,
          limit: "1",
          before: String(firstNext),
        })
      ).body,
    );
    checks.push([
      "before returns the older page",
      (second.items ?? []).length >= 1 &&
        Number((second.items ?? [])[0]?.seq) < Number(firstNext),
    ]);
    const capped = page((await audit({ limit: "1000000" })).body);
    checks.push([
      "a page size above the cap is clamped to 200",
      Number(capped.limit) === 200 && (capped.items ?? []).length <= 200,
    ]);

    // --- reading must not write ----------------------------------------------------------------
    const readOnce = page((await audit({ subject: accountId, limit: "1" })).body);
    const readTwice = page((await audit({ subject: accountId, limit: "1" })).body);
    checks.push([
      "reading the audit chain appends no event",
      readOnce.head?.seq === readTwice.head?.seq && Number(readOnce.total) === Number(readTwice.total),
    ]);

    const badTime = await audit({ from: "not-rfc3339" });
    checks.push([
      "a malformed time bound is 400 MONACA_INVALID_REQUEST",
      badTime.status === 400 && errorCode(badTime.body) === "MONACA_INVALID_REQUEST",
    ]);
    const inverted = await audit({ from: far, to: future });
    checks.push([
      "from later than to is 400",
      inverted.status === 400 && errorCode(inverted.body) === "MONACA_INVALID_REQUEST",
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "73",
    title: "tenant audit query",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: scope drop → non-admin 403 → subject → action → prefix → actor → windows → cursor → cap 200 → reads write nothing → 400s`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 74 — revocation takes effect on the very next request (§6.2).
 *
 * Two watermarks are exercised without any sleep: a session revocation and an account disable.
 * The next `userinfo`, token renewal and introspection must all see the new state immediately.
 */
async function revocationImmediateFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "74",
    title: "revocation watermark",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });
  const userinfo = (token: string): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/oauth2/userinfo`, {
      headers: { authorization: `Bearer ${token}` },
    });
  const introspect = (token: string): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/oauth2/introspect`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${basic}`,
      },
      body: new URLSearchParams({ token, token_type_hint: "access_token" }).toString(),
    });
  const renew = (refreshToken: string): Promise<HttpResult> =>
    tokenCall(base, { grant_type: "refresh_token", refresh_token: refreshToken }, basic);

  const addAccount = async (tag: string): Promise<{ id: string; session: ConsoleSignIn } | undefined> => {
    const email = `${tag}-${runId}@demo.localhost`;
    const password = `pw-${runId}-${tag}`;
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: tag, password }),
    });
    const id = (created.body as { id?: unknown })?.id;
    if (created.status !== 201 || typeof id !== "string") {
      detail = `POST /v1/accounts(${tag}) → ${created.status} ${text(created.body)}`;
      return undefined;
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: id, role: "member" }),
    });
    const signedIn = await consoleSignIn(base, email, password, consoleSecret, tag);
    if (signedIn.session === undefined) {
      detail = signedIn.error ?? "sign-in failed";
      return undefined;
    }
    return { id, session: signedIn.session };
  };

  try {
    // --- watermark 1: the session is revoked, the next request must fail ----------------------
    const kicked = await addAccount("watermark-kick");
    if (kicked === undefined) return fail("");
    const before = await userinfo(kicked.session.accessToken);
    checks.push(["the session's token works before the kick", before.status === 200]);

    const sessions = await call(`${base}/v1/accounts/${kicked.id}/sessions`, { headers });
    const sessionId = ((sessions.body as { items?: { id?: unknown }[] } | undefined)?.items ?? [])[0]?.id;
    if (typeof sessionId !== "string") return fail(`session list → ${text(sessions.body)}`);
    const kick = await call(`${base}/v1/accounts/${kicked.id}/sessions/${sessionId}`, {
      method: "DELETE",
      headers,
    });
    checks.push(["the kick answers 204", kick.status === 204]);

    const afterKick = await userinfo(kicked.session.accessToken);
    checks.push([
      "the very next userinfo after the kick is 401",
      afterKick.status === 401 && (afterKick.body as { error?: unknown })?.error === "invalid_token",
    ]);
    const kickRenewal = await renew(kicked.session.refreshToken);
    checks.push([
      "the very next renewal after the kick is invalid_grant",
      kickRenewal.status === 400 && (kickRenewal.body as { error?: unknown })?.error === "invalid_grant",
    ]);
    const kickIntrospection = await introspect(kicked.session.accessToken);
    checks.push([
      "the very next introspection after the kick is inactive",
      kickIntrospection.status === 200 &&
        (kickIntrospection.body as { active?: unknown })?.active === false,
    ]);

    // --- watermark 2: the account is disabled, the next request must fail ----------------------
    const disabled = await addAccount("watermark-disable");
    if (disabled === undefined) return fail("");
    const beforeDisable = await userinfo(disabled.session.accessToken);
    checks.push(["the token works before the disable", beforeDisable.status === 200]);
    const patch = await call(`${base}/v1/accounts/${disabled.id}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ state: "disabled" }),
    });
    checks.push(["the disable answers 200", patch.status === 200]);

    const afterDisable = await userinfo(disabled.session.accessToken);
    checks.push([
      "the very next userinfo after the disable is 401",
      afterDisable.status === 401 && (afterDisable.body as { error?: unknown })?.error === "invalid_token",
    ]);
    const disableRenewal = await renew(disabled.session.refreshToken);
    checks.push([
      "the very next renewal after the disable is invalid_grant",
      disableRenewal.status === 400 &&
        (disableRenewal.body as { error?: unknown })?.error === "invalid_grant",
    ]);
    const disableIntrospection = await introspect(disabled.session.accessToken);
    checks.push([
      "the very next introspection after the disable is inactive",
      disableIntrospection.status === 200 &&
        (disableIntrospection.body as { active?: unknown })?.active === false,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "74",
    title: "revocation watermark",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: kick 204 → next userinfo 401 → next renewal invalid → next introspection inactive → disable → same three immediately`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 75 — tenant usage and quota (§6.2).
 *
 * The counts must move with the real account rows and real sign-ins, and the cap must reject the
 * next creation rather than warn. The two halves are read from one snapshot: `users.total` is the
 * incremental counter that the creation and deletion transactions maintain.
 */
async function usageQuotaFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const prefix = `usage-${runId}`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "75",
    title: "tenant usage and quota",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });
  interface Usage {
    users?: { total?: unknown; quota?: unknown; remaining?: unknown; enforcement?: unknown };
    daily?: { date?: unknown; active_accounts?: unknown; logins?: unknown; timezone?: unknown };
  }
  const usage = async (): Promise<Usage> =>
    ((await call(`${base}/v1/usage`, { headers })).body as Usage | undefined) ?? {};
  const setQuota = (value: unknown): Promise<HttpResult> =>
    call(`${base}/v1/usage`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ max_accounts: value }),
    });
  const listOurs = async (): Promise<unknown[]> =>
    ((await call(`${base}/v1/accounts?query=${encodeURIComponent(prefix)}&limit=200`, { headers }).then(
      (result) => result.body,
    )) as { items?: unknown[] } | undefined)?.items ?? [];

  const addAccount = async (tag: string): Promise<{ id: string; email: string; password: string } | undefined> => {
    const email = `${prefix}-${tag}@demo.localhost`;
    const password = "Usage-Quota-Pass-96";
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: `Usage ${tag}`, password }),
    });
    const id = (created.body as { id?: unknown })?.id;
    if (created.status !== 201 || typeof id !== "string") {
      detail = `POST /v1/accounts(${tag}) → ${created.status} ${text(created.body)}`;
      return undefined;
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: id, role: "member" }),
    });
    return { id, email, password };
  };

  try {
    // A previous run may have left a cap; clear it so the baseline is unlimited.
    const cleared = await setQuota(null);
    const before = (cleared.body as Usage | undefined) ?? {};
    checks.push([
      "clearing the quota returns an unlimited snapshot",
      cleared.status === 200 &&
        before.users?.quota === null &&
        before.users?.remaining === null &&
        before.users?.enforcement === "reject",
    ]);
    const baseTotal = Number(before.users?.total);

    const a = await addAccount("a");
    const b = await addAccount("b");
    if (a === undefined || b === undefined) return fail("");
    const afterCreate = await usage();
    checks.push([
      "two creations move the counter by exactly two",
      Number(afterCreate.users?.total) === baseTotal + 2,
    ]);
    checks.push([
      "the account list shows the same two real rows",
      (await listOurs()).length === 2,
    ]);

    const signInA1 = await consoleSignIn(base, a.email, a.password, consoleSecret, "usage-a1");
    if (signInA1.session === undefined) return fail(signInA1.error ?? "the first sign-in failed");
    const afterFirst = await usage();
    checks.push([
      "the first sign-in adds one active account and one login",
      Number(afterFirst.daily?.active_accounts) === Number(before.daily?.active_accounts) + 1 &&
        Number(afterFirst.daily?.logins) === Number(before.daily?.logins) + 1,
    ]);
    const signInA2 = await consoleSignIn(base, a.email, a.password, consoleSecret, "usage-a2");
    if (signInA2.session === undefined) return fail(signInA2.error ?? "the second sign-in failed");
    const afterSignIn = await usage();
    checks.push([
      "a repeated sign-in adds a login but no new active account",
      Number(afterSignIn.daily?.active_accounts) === Number(before.daily?.active_accounts) + 1 &&
        Number(afterSignIn.daily?.logins) === Number(before.daily?.logins) + 2,
    ]);
    checks.push([
      "the daily date is the current UTC day",
      afterSignIn.daily?.date === new Date().toISOString().slice(0, 10) &&
        afterSignIn.daily?.timezone === "UTC",
    ]);

    // The cap is the count that already exists, so the next creation is refused.
    const capped = await setQuota(Number(afterCreate.users?.total));
    checks.push([
      "setting the cap at the current total leaves no room",
      capped.status === 200 &&
        (capped.body as Usage).users?.remaining === 0 &&
        (capped.body as Usage).users?.quota === Number(afterCreate.users?.total),
    ]);
    const overQuota = await addAccount("c-over");
    if (overQuota === undefined) {
      // `addAccount` sets a generic detail; the expected refusal is the assertion itself.
      const refused = await call(`${base}/v1/accounts`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          email: `${prefix}-over@demo.localhost`,
          display_name: "Over",
          password: "Usage-Quota-Pass-96",
        }),
      });
      checks.push([
        "the creation past the cap is 403 MONACA_QUOTA_EXCEEDED",
        refused.status === 403 &&
          (refused.body as { monaca_error_code?: unknown })?.monaca_error_code ===
            "MONACA_QUOTA_EXCEEDED",
      ]);
    } else {
      return fail("a creation past the cap unexpectedly succeeded");
    }

    const deleted = await call(
      `${base}/v1/accounts/${b.id}?confirm=${encodeURIComponent(b.email)}`,
      { method: "DELETE", headers },
    );
    const afterDelete = await usage();
    checks.push([
      "deleting one account decrements the counter and frees a slot",
      deleted.status === 200 &&
        Number(afterDelete.users?.total) === baseTotal + 1 &&
        Number(afterDelete.users?.remaining) === 1,
    ]);
    checks.push(["the account list shows the remaining row", (await listOurs()).length === 1]);

    const c = await addAccount("c");
    const afterRefill = await usage();
    checks.push([
      "the freed slot accepts one more creation",
      c !== undefined && Number(afterRefill.users?.total) === baseTotal + 2,
    ]);
    checks.push(["the account list shows two rows again", (await listOurs()).length === 2]);

    const unlimited = await setQuota(null);
    checks.push([
      "clearing the cap restores an unlimited remaining",
      unlimited.status === 200 &&
        (unlimited.body as Usage).users?.quota === null &&
        (unlimited.body as Usage).users?.remaining === null,
    ]);

    const empty = await call(`${base}/v1/usage`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({}),
    });
    checks.push(["an empty usage patch is 400", empty.status === 400]);
    const negative = await setQuota(-1);
    checks.push(["a negative quota is 400", negative.status === 400]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "75",
    title: "tenant usage and quota",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: clear → +2 creations/list → +1 active/+2 logins → cap 0 room → 403 → delete frees a slot → refill → unlimited → 400s`
      : `${checks
          .filter(([, passed]) => !passed)
          .map(([name]) => name)
          .join(", ") || detail}`,
  };
}

/**
 * Step 24 — hosted sign-in switches (§6.1/§6.2).
 *
 * The tenant turns sign-up, password sign-in and emailed codes on or off; the public read is what
 * the auth-ui applies, and the protocol endpoints enforce the same values.
 */
async function signInExperienceFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "24",
    title: "sign-in experience",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction id for the bootstrap admin. */
  const begin = async (tag: string): Promise<string | undefined> => {
    const verifier = `x-${tag}-${runId}-${"y".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid profile email",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    const response = await call(url, { redirect: "manual" });
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return encodeURIComponent(interaction);
  };

  const passwordSignIn = (interaction: string): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/interaction/${interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        identifier: BOOTSTRAP_ADMIN.email,
        password: BOOTSTRAP_ADMIN.password,
      }),
    });

  const requestCode = (interaction: string, address: string): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/interaction/${interaction}/sign-in/code`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: address }),
    });

  const patch = (body: Record<string, unknown>): Promise<HttpResult> =>
    call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify(body),
    });

  const publicRead = async (): Promise<
    { sign_up_enabled?: unknown; password_sign_in_enabled?: unknown; email_code_sign_in_enabled?: unknown } | undefined
  > => {
    const response = await call(`${base}/t/${TENANT}/sign-in-experience`);
    return response.status === 200
      ? (response.body as {
          sign_up_enabled?: unknown;
          password_sign_in_enabled?: unknown;
          email_code_sign_in_enabled?: unknown;
        })
      : undefined;
  };

  try {
    const initial = await publicRead();
    checks.push([
      "the public switches start with every method on",
      initial !== undefined &&
        initial.sign_up_enabled === true &&
        initial.password_sign_in_enabled === true &&
        initial.email_code_sign_in_enabled === true,
    ]);

    // --- sign-up and password off; email codes stay the way in -----------------------------------
    const disabled = await patch({ sign_up_enabled: false, password_sign_in_enabled: false });
    checks.push([
      "PATCH disables sign-up and the password",
      disabled.status === 200 &&
        (disabled.body as { sign_up_enabled?: unknown })?.sign_up_enabled === false &&
        (disabled.body as { password_sign_in_enabled?: unknown })?.password_sign_in_enabled === false &&
        (disabled.body as { email_code_sign_in_enabled?: unknown })?.email_code_sign_in_enabled === true,
    ]);

    const afterDisable = await publicRead();
    checks.push([
      "the public read follows the patch",
      afterDisable?.sign_up_enabled === false &&
        afterDisable?.password_sign_in_enabled === false &&
        afterDisable?.email_code_sign_in_enabled === true,
    ]);

    const signUpInteraction = await begin("signup");
    if (signUpInteraction === undefined) return fail("");
    const signUp = await call(`${base}/t/${TENANT}/interaction/${signUpInteraction}/sign-up`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: `disabled-${runId}@demo.localhost` }),
    });
    checks.push([
      "sign-up is refused while disabled",
      signUp.status === 403 &&
        (signUp.body as { monaca_error_code?: unknown })?.monaca_error_code === "MONACA_SIGN_UP_DISABLED",
    ]);

    const passwordInteraction = await begin("password");
    if (passwordInteraction === undefined) return fail("");
    const password = await passwordSignIn(passwordInteraction);
    checks.push([
      "the password is refused while disabled",
      password.status === 403 &&
        (password.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_PASSWORD_SIGN_IN_DISABLED",
    ]);

    const codeInteraction = await begin("code");
    if (codeInteraction === undefined) return fail("");
    const code = await requestCode(codeInteraction, `codes-${runId}@demo.localhost`);
    checks.push([
      "email codes still work while the password is disabled",
      code.status === 200 &&
        (code.body as { verification_required?: unknown })?.verification_required === true,
    ]);

    // --- the other direction: codes off, password back on ----------------------------------------
    const swapped = await patch({ password_sign_in_enabled: true, email_code_sign_in_enabled: false });
    checks.push([
      "email codes can be disabled while the password stays on",
      swapped.status === 200 &&
        (swapped.body as { sign_up_enabled?: unknown })?.sign_up_enabled === false &&
        (swapped.body as { password_sign_in_enabled?: unknown })?.password_sign_in_enabled === true &&
        (swapped.body as { email_code_sign_in_enabled?: unknown })?.email_code_sign_in_enabled === false,
    ]);

    const refusedInteraction = await begin("codes-off");
    if (refusedInteraction === undefined) return fail("");
    const refusedCode = await requestCode(refusedInteraction, `codes-off-${runId}@demo.localhost`);
    checks.push([
      "email codes are refused while disabled",
      refusedCode.status === 403 &&
        (refusedCode.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_EMAIL_CODE_SIGN_IN_DISABLED",
    ]);

    const passwordAgainInteraction = await begin("password-on");
    if (passwordAgainInteraction === undefined) return fail("");
    const passwordAgain = await passwordSignIn(passwordAgainInteraction);
    checks.push([
      "the password works again",
      passwordAgain.status === 200 && typeof (passwordAgain.body as { redirect_to?: unknown })?.redirect_to === "string",
    ]);

    // --- invalid patches change nothing ---------------------------------------------------------
    const bothOff = await patch({ password_sign_in_enabled: false, email_code_sign_in_enabled: false });
    checks.push(["turning both first factors off is 400", bothOff.status === 400]);

    const empty = await patch({});
    checks.push(["an empty patch is 400", empty.status === 400]);

    const restored = await patch({
      sign_up_enabled: true,
      password_sign_in_enabled: true,
      email_code_sign_in_enabled: true,
    });
    checks.push([
      "every method can be restored",
      restored.status === 200 &&
        (restored.body as { sign_up_enabled?: unknown })?.sign_up_enabled === true &&
        (restored.body as { password_sign_in_enabled?: unknown })?.password_sign_in_enabled === true &&
        (restored.body as { email_code_sign_in_enabled?: unknown })?.email_code_sign_in_enabled === true,
    ]);

    const finalRead = await publicRead();
    checks.push([
      "the public read is all on again",
      finalRead?.sign_up_enabled === true &&
        finalRead?.password_sign_in_enabled === true &&
        finalRead?.email_code_sign_in_enabled === true,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "24",
    title: "sign-in experience",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: public on → disable sign-up/password → 403s → codes still on → swap → password on → 400s → restore → public on`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 52: a tenant's CAPTCHA provider gates sign-in, and repeated wrong passwords lock the
 * identifier.
 *
 * The provider's siteverify endpoint is replaced by a local mock through
 * `MONACA_CAPTCHA_SITEVERIFY_URL` (dev/CI only, ignored in production). That is the only way to
 * prove both a rejected and an accepted token without a real provider account: the mock answers
 * `{"success":true}` for the token this step calls valid and `false` for everything else, while
 * recording the form the server posted. The lockout half uses a throwaway account, never the
 * bootstrap admin, so locking it cannot disturb a later step.
 */
async function captchaFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const mockPort = Number(process.env.MONACA_CAPTCHA_MOCK_PORT ?? 38100);
  const email = `captcha-${runId}@demo.localhost`;
  const password = `pw-${runId}-captcha`;
  const siteKey = `captcha-site-${runId}`;
  const secret = `captcha-secret-${runId}`;
  const validToken = `e2e-captcha-valid-${runId}`;
  const invalidToken = `e2e-captcha-invalid-${runId}`;
  const calls: { secret: string; response: string }[] = [];
  let mock: ReturnType<typeof Bun.serve> | undefined;
  const fail = (why: string): StepResult => ({
    step: "52",
    title: "CAPTCHA and lockout",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why,
  });

  /** A fresh authorize → interaction id, as the browser would open. */
  const begin = async (tag: string): Promise<string | undefined> => {
    const verifier = `cap-${tag}-${runId}-${"z".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const response = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: "monaca-console",
        redirect_uri: "http://localhost:5173/bff/callback",
        scope: "openid profile email",
        state: `st-captcha-${tag}-${runId}`,
        nonce: `n-captcha-${tag}-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status}`;
      return undefined;
    }
    return encodeURIComponent(interaction);
  };

  const signIn = (interaction: string, body: Record<string, unknown>): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/interaction/${interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });

  const patch = (body: Record<string, unknown>): Promise<HttpResult> =>
    call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify(body),
    });

  try {
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "CAPTCHA flow", password }),
    });
    const accountId = (created.body as { id?: unknown } | undefined)?.id;
    if (created.status !== 201 || typeof accountId !== "string") {
      return fail(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });

    const [noCredentials, badProvider, longKey, longSecret] = await Promise.all([
      patch({ captcha: { enabled: true } }),
      patch({ captcha: { provider: "hcaptcha2" } }),
      patch({ captcha: { site_key: "k".repeat(201) } }),
      patch({ captcha: { secret: "s".repeat(501) } }),
    ]);
    checks.push([
      "enabling without credentials, an unknown provider, a 201-character key and a 501-character secret are 400",
      noCredentials.status === 400 &&
        badProvider.status === 400 &&
        longKey.status === 400 &&
        longSecret.status === 400,
    ]);

    mock = Bun.serve({
      port: mockPort,
      hostname: "127.0.0.1",
      async fetch(request) {
        if (request.method !== "POST" || new URL(request.url).pathname !== "/siteverify") {
          return new Response("not found", { status: 404 });
        }
        const form = await request.formData();
        const postedSecret = String(form.get("secret") ?? "");
        const response = String(form.get("response") ?? "");
        calls.push({ secret: postedSecret, response });
        return Response.json({ success: response === validToken });
      },
    });

    const configured = await patch({
      captcha: {
        enabled: true,
        provider: "hcaptcha",
        site_key: siteKey,
        secret,
        on_sign_in: true,
        on_sign_up: false,
        on_password_reset: false,
      },
      login_lockout_threshold: 2,
      login_lockout_duration_secs: 60,
    });
    const configuredJson = configured.body as
      | {
          captcha?: { enabled?: unknown; provider?: unknown; site_key?: unknown; secret_set?: unknown };
          login_lockout_threshold?: unknown;
        }
      | undefined;
    checks.push([
      "PATCH stores hCaptcha and reports secret_set without echoing the secret",
      configured.status === 200 &&
        configuredJson?.captcha?.enabled === true &&
        configuredJson?.captcha?.provider === "hcaptcha" &&
        configuredJson?.captcha?.site_key === siteKey &&
        configuredJson?.captcha?.secret_set === true &&
        configuredJson?.login_lockout_threshold === 2 &&
        !JSON.stringify(configuredJson).includes(secret),
    ]);

    const first = await begin("responses");
    if (first === undefined) return fail(detail);
    const noToken = await signIn(first, { identifier: email, password });
    checks.push([
      "sign-in without a token is 400 MONACA_CAPTCHA_FAILED",
      noToken.status === 400 &&
        (noToken.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_CAPTCHA_FAILED",
    ]);
    const rejected = await signIn(first, {
      identifier: email,
      password,
      captcha_token: invalidToken,
    });
    checks.push([
      "a token the provider rejects is the same 400",
      rejected.status === 400 &&
        (rejected.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_CAPTCHA_FAILED",
    ]);

    const verify = await call(
      `${base}/t/${TENANT}/interaction/${first}/sign-in/code/verify`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, code: "000000" }),
      },
    );
    checks.push([
      "the verify step is reachable and does not demand a challenge token",
      verify.status === 401 &&
        (verify.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_INVALID_VERIFICATION_CODE",
    ]);

    const accepted = await signIn(first, {
      identifier: email,
      password,
      captcha_token: validToken,
    });
    const providerCall = calls.find((entry) => entry.response === validToken);
    checks.push([
      "a token the provider accepts completes the sign-in",
      accepted.status === 200 &&
        providerCall?.secret === secret &&
        (accepted.body as { redirect_to?: unknown } | undefined)?.redirect_to !== undefined,
    ]);

    // One wrong password counts, then a correct one clears the counter (§6.1 lockout).
    const clear = await begin("clear");
    if (clear === undefined) return fail(detail);
    const counted = await signIn(clear, {
      identifier: email,
      password: `${password}-wrong`,
      captcha_token: validToken,
    });
    const cleared = await signIn(clear, {
      identifier: email,
      password,
      captcha_token: validToken,
    });
    checks.push([
      "a wrong password counts and a subsequent success clears the counter",
      counted.status === 401 &&
        (counted.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_INVALID_CREDENTIALS" &&
        cleared.status === 200,
    ]);

    // Two consecutive wrong passwords lock the identifier; the next attempt is refused.
    const lock = await begin("lock");
    if (lock === undefined) return fail(detail);
    const wrongOne = await signIn(lock, {
      identifier: email,
      password: `${password}-wrong`,
      captcha_token: validToken,
    });
    const wrongTwo = await signIn(lock, {
      identifier: email,
      password: `${password}-wrong`,
      captcha_token: validToken,
    });
    const locked = await signIn(lock, {
      identifier: email,
      password,
      captcha_token: validToken,
    });
    checks.push([
      "two wrong passwords lock the identifier, and the next attempt is 429 MONACA_ACCOUNT_LOCKED",
      wrongOne.status === 401 && wrongTwo.status === 401 &&
        locked.status === 429 &&
        (locked.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_ACCOUNT_LOCKED",
    ]);

    const audit = await call(
      `${base}/v1/orgs/${ORG}/audit?${new URLSearchParams({ action: "interaction.sign_in.failed", limit: "50" })}`,
      { headers },
    );
    const events =
      (
        audit.body as
          | { items?: { payload?: { email?: unknown; reason?: unknown } }[] }
          | undefined
      )?.items ?? [];
    checks.push([
      "the lock is audited as interaction.sign_in.failed with reason account_locked",
      audit.status === 200 &&
        events.some((event) => event.payload?.email === email && event.payload?.reason === "account_locked"),
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await patch({
      captcha: {
        enabled: false,
        provider: "turnstile",
        site_key: "",
        secret: "",
        on_sign_in: true,
        on_sign_up: true,
        on_password_reset: true,
      },
      login_lockout_threshold: 0,
      login_lockout_duration_secs: 900,
    });
    mock?.stop(true);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "52",
    title: "CAPTCHA and lockout",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: hCaptcha stored without its secret → missing/rejected/accepted token → verify reachable → wrong count cleared → two wrong lock and audit`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 58: Cap proof-of-work CAPTCHA.
 *
 * Cap Standalone documents `POST {instance}/{site_key}/siteverify` with a JSON body
 * (`secret`, `response`) and a single-use `{site_key}:{id}:{secret}` token; a rejected token is
 * a 4xx `{"success":false}`. `MONACA_CAPTCHA_SITEVERIFY_URL` replaces the instance base in dev/CI
 * only, so the server still composes the site-key path. The mock below follows that protocol
 * rather than the form-based shape the earlier providers use, and records each request so the
 * step can prove the path, content type, body and one-time consumption.
 */
async function capCaptchaFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const mockPort = Number(process.env.MONACA_CAPTCHA_MOCK_PORT ?? 38100);
  const email = `cap-captcha-${runId}@demo.localhost`;
  const password = `pw-${runId}-cap-captcha`;
  const siteKey = `cap-site-${runId}`;
  const secret = `cap-secret-${runId}`;
  const instanceBase = `http://127.0.0.1:${mockPort}`;
  const minted = new Set<string>();
  const consumed = new Set<string>();
  const calls: { path: string; secret: string; response: string; contentType: string }[] = [];
  let mock: ReturnType<typeof Bun.serve> | undefined;
  const fail = (why: string): StepResult => ({
    step: "58",
    title: "Cap proof-of-work CAPTCHA",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why,
  });

  const hex = (length: number): string =>
    Array.from({ length }, () => Math.floor(Math.random() * 16).toString(16)).join("");
  /** A token in Cap's real `{site_key}:{id}:{secret}` shape. */
  const mint = (): string => {
    const token = `${siteKey}:${hex(16)}:${hex(30)}`;
    minted.add(token);
    return token;
  };

  /** A fresh authorize → interaction id, as the browser would open. */
  const begin = async (tag: string): Promise<string | undefined> => {
    const verifier = `cap58-${tag}-${runId}-${"z".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const response = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: "monaca-console",
        redirect_uri: "http://localhost:5173/bff/callback",
        scope: "openid profile email",
        state: `st-cap58-${tag}-${runId}`,
        nonce: `n-cap58-${tag}-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status}`;
      return undefined;
    }
    return encodeURIComponent(interaction);
  };

  const signIn = (interaction: string, body: Record<string, unknown>): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/interaction/${interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });

  const patch = (body: Record<string, unknown>): Promise<HttpResult> =>
    call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify(body),
    });

  try {
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Cap CAPTCHA flow", password }),
    });
    const accountId = (created.body as { id?: unknown } | undefined)?.id;
    if (created.status !== 201 || typeof accountId !== "string") {
      return fail(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });

    const [noBase, relative, credentialed, longBase] = await Promise.all([
      patch({ captcha: { enabled: true, provider: "cap", site_key: siteKey, secret } }),
      patch({ captcha: { provider: "cap", base_url: "cap.example.com", site_key: siteKey, secret } }),
      patch({
        captcha: {
          provider: "cap",
          base_url: "https://user:pass@cap.example.com",
          site_key: siteKey,
          secret,
        },
      }),
      patch({
        captcha: {
          provider: "cap",
          base_url: `https://cap.example.com/${"x".repeat(500)}`,
          site_key: siteKey,
          secret,
        },
      }),
    ]);
    checks.push([
      "enabling cap without a base URL, and relative, credentialed or over-500-character base URLs, are 400",
      noBase.status === 400 &&
        relative.status === 400 &&
        credentialed.status === 400 &&
        longBase.status === 400,
    ]);

    mock = Bun.serve({
      port: mockPort,
      hostname: "127.0.0.1",
      async fetch(request) {
        const url = new URL(request.url);
        if (request.method !== "POST" || !url.pathname.endsWith(`/${siteKey}/siteverify`)) {
          return new Response("not found", { status: 404 });
        }
        let body: { secret?: unknown; response?: unknown };
        try {
          body = (await request.json()) as { secret?: unknown; response?: unknown };
        } catch {
          return Response.json(
            { success: false, error: "Missing required parameters" },
            { status: 400 },
          );
        }
        const postedSecret = typeof body.secret === "string" ? body.secret : "";
        const token = typeof body.response === "string" ? body.response : "";
        calls.push({
          path: url.pathname,
          secret: postedSecret,
          response: token,
          contentType: request.headers.get("content-type") ?? "",
        });
        if (token.split(":").length !== 3) {
          return Response.json(
            { success: false, error: "Missing required parameters" },
            { status: 400 },
          );
        }
        if (!token.startsWith(`${siteKey}:`)) {
          return Response.json(
            { success: false, error: "Invalid site key or secret" },
            { status: 404 },
          );
        }
        if (postedSecret !== secret) {
          return Response.json(
            { success: false, error: "Invalid site key or secret" },
            { status: 403 },
          );
        }
        if (consumed.has(token) || !minted.has(token)) {
          return Response.json({ success: false, error: "Token not found" }, { status: 404 });
        }
        consumed.add(token);
        return Response.json({ success: true });
      },
    });

    const configured = await patch({
      captcha: {
        enabled: true,
        provider: "cap",
        base_url: instanceBase,
        site_key: siteKey,
        secret,
        on_sign_in: true,
        on_sign_up: false,
        on_password_reset: false,
      },
      login_lockout_threshold: 2,
      login_lockout_duration_secs: 60,
    });
    const configuredJson = configured.body as
      | {
          captcha?: {
            enabled?: unknown;
            provider?: unknown;
            site_key?: unknown;
            base_url?: unknown;
            secret_set?: unknown;
          };
          login_lockout_threshold?: unknown;
        }
      | undefined;
    checks.push([
      "PATCH stores provider=cap with its base URL and reports secret_set without echoing the secret",
      configured.status === 200 &&
        configuredJson?.captcha?.enabled === true &&
        configuredJson?.captcha?.provider === "cap" &&
        configuredJson?.captcha?.site_key === siteKey &&
        configuredJson?.captcha?.base_url === instanceBase &&
        configuredJson?.captcha?.secret_set === true &&
        configuredJson?.login_lockout_threshold === 2 &&
        !JSON.stringify(configuredJson).includes(secret),
    ]);

    const first = await begin("responses");
    if (first === undefined) return fail(detail);
    const noToken = await signIn(first, { identifier: email, password });
    checks.push([
      "sign-in without a token is 400 MONACA_CAPTCHA_FAILED",
      noToken.status === 400 &&
        (noToken.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_CAPTCHA_FAILED",
    ]);

    const rejected = await signIn(first, {
      identifier: email,
      password,
      captcha_token: "e2e-cap-invalid",
    });
    const rejectedCall = calls.find((entry) => entry.response === "e2e-cap-invalid");
    checks.push([
      "the server posts JSON to the site-key path and a token the provider rejects is the same 400",
      rejected.status === 400 &&
        (rejected.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_CAPTCHA_FAILED" &&
        rejectedCall?.secret === secret &&
        rejectedCall?.contentType.includes("application/json") === true &&
        rejectedCall?.path.endsWith(`/${siteKey}/siteverify`) === true,
    ]);

    const validToken = mint();
    const accepted = await signIn(first, {
      identifier: email,
      password,
      captcha_token: validToken,
    });
    checks.push([
      "a token the provider accepts completes the sign-in",
      accepted.status === 200 &&
        (accepted.body as { redirect_to?: unknown } | undefined)?.redirect_to !== undefined &&
        consumed.has(validToken),
    ]);

    const replay = await begin("replay");
    if (replay === undefined) return fail(detail);
    const replayed = await signIn(replay, {
      identifier: email,
      password,
      captcha_token: validToken,
    });
    checks.push([
      "the same token replayed is refused because siteverify consumes it once",
      replayed.status === 400 &&
        (replayed.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_CAPTCHA_FAILED",
    ]);

    // Two wrong passwords count, then the next attempt is locked (§6.1 lockout).
    const lock = await begin("lock");
    if (lock === undefined) return fail(detail);
    const wrongOne = await signIn(lock, {
      identifier: email,
      password: `${password}-wrong`,
      captcha_token: mint(),
    });
    const wrongTwo = await signIn(lock, {
      identifier: email,
      password: `${password}-wrong`,
      captcha_token: mint(),
    });
    const locked = await signIn(lock, {
      identifier: email,
      password,
      captcha_token: mint(),
    });
    checks.push([
      "two wrong passwords lock the identifier, and the next attempt is 429 MONACA_ACCOUNT_LOCKED",
      wrongOne.status === 401 && wrongTwo.status === 401 &&
        locked.status === 429 &&
        (locked.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_ACCOUNT_LOCKED",
    ]);

    const audit = await call(
      `${base}/v1/orgs/${ORG}/audit?${new URLSearchParams({ action: "interaction.sign_in.failed", limit: "50" })}`,
      { headers },
    );
    const events =
      (
        audit.body as
          | { items?: { payload?: { email?: unknown; reason?: unknown } }[] }
          | undefined
      )?.items ?? [];
    checks.push([
      "the lock is audited as interaction.sign_in.failed with reason account_locked",
      audit.status === 200 &&
        events.some(
          (event) => event.payload?.email === email && event.payload?.reason === "account_locked",
        ),
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await patch({
      captcha: {
        enabled: false,
        provider: "turnstile",
        site_key: "",
        base_url: "",
        secret: "",
        on_sign_in: true,
        on_sign_up: true,
        on_password_reset: true,
      },
      login_lockout_threshold: 0,
      login_lockout_duration_secs: 900,
    });
    mock?.stop(true);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "58",
    title: "Cap proof-of-work CAPTCHA",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: base URL validation → JSON site-key siteverify → rejected and accepted tokens → one-time replay → lock and audit`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 59: built-in social providers and the three linking policies.
 *
 * The server's real GitHub/Google endpoints are replaced by a local mock through
 * `MONACA_SOCIAL_PROVIDER_BASE_URL` (dev/CI only). The mock implements GitHub's token → `/user` →
 * `/user/emails` chain (primary+verified only), Google's token → userinfo chain with an id_token
 * carrying the nonce, and verifies the PKCE S256 verifier the server sends. Every profile is keyed
 * by the authorization code the step fabricates after reading the real authorize redirect.
 */
async function socialProvidersFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
  internalSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const redirectUri = "http://localhost:5173/bff/callback";
  const checks: [string, boolean][] = [];
  let detail = "";
  let mock: ReturnType<typeof Bun.serve> | undefined;
  const mockPort = Number(process.env.MONACA_SOCIAL_MOCK_PORT ?? 38200);
  const mockBase = `http://127.0.0.1:${mockPort}`;
  const profiles = new Map<
    string,
    {
      provider: "github" | "google";
      subject: string;
      email: string;
      verified: boolean;
      name: string;
      challenge?: string;
      nonce?: string;
      keyId?: string;
      id_token?: string;
    }
  >();
  const consumed = new Set<string>();

  interface GoogleSigningKey {
    kid: string;
    privateKey: CryptoKey;
    publicJwk: Record<string, unknown>;
  }

  const makeGoogleKey = async (kid: string): Promise<GoogleSigningKey> => {
    const pair = (await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const publicJwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as Record<
      string,
      unknown
    >;
    return {
      kid,
      privateKey: pair.privateKey,
      publicJwk: { ...publicJwk, kid, alg: "RS256", use: "sig" },
    };
  };

  const googleKeys: GoogleSigningKey[] = [await makeGoogleKey("google-key-1")];
  // A key the JWKS never publishes: used for a forged signature and an unknown-kid token.
  const rogueKey = await makeGoogleKey("rogue-key");
  const signGoogleToken = async (
    key: GoogleSigningKey,
    headerKid: string,
    claims: Record<string, unknown>,
  ): Promise<string> => {
    const header = base64UrlJson({ alg: "RS256", kid: headerKid, typ: "JWT" });
    const payload = base64UrlJson(claims);
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        key.privateKey,
        new TextEncoder().encode(`${header}.${payload}`),
      ),
    );
    return `${header}.${payload}.${base64Url(signature)}`;
  };

  const fail = (why: string): StepResult => ({
    step: "59",
    title: "social providers and linking",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why,
  });

  /** A fresh authorize → interaction; the service verifier is the console's own PKCE. */
  const begin = async (
    tag: string,
  ): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `s59-${tag}-${runId}-${"x".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const response = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: "monaca-console",
        redirect_uri: redirectUri,
        scope: "openid profile email",
        state: `st-s59-${tag}-${runId}`,
        nonce: `n-s59-${tag}-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(response.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  const exchange = async (redirectTo: string, verifier: string): Promise<HttpResult> => {
    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    return tokenCall(
      base,
      {
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: "monaca-console",
        code_verifier: verifier,
      },
      basic,
    );
  };

  const createConnector = (
    id: string,
    provider: "github" | "google",
    policy: string,
  ): Promise<HttpResult> =>
    call(`${base}/v1/connectors`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        connector_id: id,
        provider,
        display_name: `${provider} ${policy}`,
        link_policy: policy,
        enabled: true,
        client_id: `${id}-client`,
        client_secret: `${id}-secret`,
      }),
    });

  const startFlow = async (
    connector: string,
    tag: string,
  ): Promise<
    | {
        interaction: string;
        verifier: string;
        location: string;
        params: URLSearchParams;
        cookie: string;
      }
    | undefined
  > => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const authorize = await call(
      `${base}/t/${TENANT}/connectors/${connector}/authorize?interaction=${started.interaction}`,
      { redirect: "manual" },
    );
    const location = authorize.headers.get("location") ?? "";
    const cookie =
      /monaca_social_state=([0-9a-f-]{36})/.exec(authorize.headers.get("set-cookie") ?? "")?.[1] ??
      "";
    if (authorize.status !== 302 || location === "" || cookie === "") {
      detail = `connector authorize → ${authorize.status} ${text(authorize.body)}`;
      return undefined;
    }
    return { ...started, location, params: new URL(location).searchParams, cookie };
  };

  const register = async (
    code: string,
    profile: {
      provider: "github" | "google";
      subject: string;
      email: string;
      verified: boolean;
      name: string;
      challenge?: string;
      nonce?: string;
      keyId?: string;
      id_token?: string;
    },
  ): Promise<void> => {
    profiles.set(code, profile);
  };

  const callback = (
    start: { location: string; cookie?: string },
    code: string,
  ): Promise<HttpResult> => {
    const params = new URL(start.location).searchParams;
    const state = params.get("state") ?? "";
    const redirect = params.get("redirect_uri") ?? "";
    if (state === "" || redirect === "") {
      throw new Error("the provider redirect carried no callback URL");
    }
    const headers: Record<string, string> = {};
    if (start.cookie !== undefined && start.cookie !== "") {
      headers.cookie = `monaca_social_state=${start.cookie}`;
    }
    return call(`${redirect}?${new URLSearchParams({ state, code })}`, {
      redirect: "manual",
      headers,
    });
  };

  const accountsFor = async (email: string): Promise<{ id?: string; count: number }> => {
    const response = await call(`${base}/v1/accounts?${new URLSearchParams({ query: email })}`, {
      headers,
    });
    const items = (response.body as { items?: { id?: string; email?: string }[] } | undefined)
      ?.items ?? [];
    const matched = items.filter((item) => item.email === email);
    return { id: matched[0]?.id, count: matched.length };
  };

  const auditEvents = async (action: string): Promise<Record<string, unknown>[]> => {
    const response = await call(
      `${base}/internal/audit?${new URLSearchParams({
        tenant: TENANT,
        action,
        limit: "100",
      })}`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    return (response.body as { items?: { payload?: Record<string, unknown> }[] } | undefined)
      ?.items?.map((item) => item.payload ?? {}) ?? [];
  };

  const existingEmail = `social59-existing-${runId}@demo.localhost`;
  const existingPassword = `pw-${runId}-social59`;
  const connectorIds = [
    `s59-gh-auto-${runId}`,
    `s59-gh-confirm-${runId}`,
    `s59-gh-new-${runId}`,
    `s59-gh-off-${runId}`,
    `s59-go-auto-${runId}`,
  ];

  try {
    // --- the mock's four provider endpoints -----------------------------------------------------
    mock = Bun.serve({
      port: mockPort,
      hostname: "127.0.0.1",
      async fetch(request) {
        const url = new URL(request.url);
        if (request.method === "POST" && url.pathname === "/mock/profile") {
          const body = (await request.json()) as {
            code?: string;
            profile?: {
              provider: "github" | "google";
              subject: string;
              email: string;
              verified: boolean;
              name: string;
              challenge?: string;
              nonce?: string;
            };
          };
          if (typeof body.code !== "string" || body.profile === undefined) {
            return new Response("bad profile", { status: 400 });
          }
          profiles.set(body.code, body.profile);
          return new Response(null, { status: 204 });
        }

        if (request.method === "POST" && /\/(github|google)\/token$/.test(url.pathname)) {
          const form = await request.formData();
          const code = String(form.get("code") ?? "");
          const profile = profiles.get(code);
          if (!profile) return Response.json({ error: "invalid_grant" }, { status: 400 });
          if (consumed.has(code)) return Response.json({ error: "invalid_grant" }, { status: 400 });
          const verifier = String(form.get("code_verifier") ?? "");
          if (profile.challenge !== undefined) {
            const digest = base64Url(
              new Uint8Array(
                await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
              ),
            );
            if (digest !== profile.challenge) {
              return Response.json({ error: "invalid_grant" }, { status: 400 });
            }
          }
          consumed.add(code);
          if (profile.provider === "google") {
            const clientId = String(form.get("client_id") ?? "");
            const now = Math.floor(Date.now() / 1000);
            const claims: Record<string, unknown> = {
              iss: "https://accounts.google.com",
              aud: clientId,
              sub: profile.subject,
              email: profile.email,
              email_verified: profile.verified,
              name: profile.name,
              nonce: profile.nonce ?? "",
              iat: now,
              exp: now + 3_600,
            };
            const key =
              googleKeys.find((candidate) => candidate.kid === profile.keyId) ??
              googleKeys[0];
            if (key === undefined) return new Response("no Google key", { status: 500 });
            const idToken =
              profile.id_token ?? (await signGoogleToken(key, key.kid, claims));
            return Response.json({
              access_token: `go-${code}`,
              id_token: idToken,
              token_type: "Bearer",
            });
          }
          return Response.json({ access_token: `gh-${code}`, token_type: "bearer" });
        }

        if (request.method === "GET" && url.pathname === "/google/jwks") {
          return Response.json({ keys: googleKeys.map((key) => key.publicJwk) });
        }

        const bearer = request.headers.get("authorization")?.replace(/^Bearer /i, "") ?? "";
        if (request.method === "GET" && url.pathname === "/github/userinfo") {
          const code = bearer.replace(/^gh-/, "");
          const profile = profiles.get(code);
          if (!profile) return new Response("not found", { status: 404 });
          return Response.json({
            id: Number(profile.subject),
            login: `gh-${profile.subject}`,
            name: profile.name,
          });
        }
        if (request.method === "GET" && url.pathname === "/github/emails") {
          const code = bearer.replace(/^gh-/, "");
          const profile = profiles.get(code);
          if (!profile) return new Response("not found", { status: 404 });
          return Response.json([
            { email: profile.email, primary: true, verified: profile.verified },
          ]);
        }
        if (request.method === "GET" && url.pathname === "/google/userinfo") {
          const code = bearer.replace(/^go-/, "");
          const profile = profiles.get(code);
          if (!profile) return new Response("not found", { status: 404 });
          return Response.json({
            sub: profile.subject,
            email: profile.email,
            email_verified: profile.verified,
            name: profile.name,
          });
        }
        return new Response("not found", { status: 404 });
      },
    });

    // --- an existing password account the social flows can meet --------------------------------
    const createdExisting = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        email: existingEmail,
        display_name: "Social existing",
        password: existingPassword,
      }),
    });
    const existingId = (createdExisting.body as { id?: string } | undefined)?.id;
    if (createdExisting.status !== 201 || existingId === undefined) {
      return fail(`POST /v1/accounts → ${createdExisting.status} ${text(createdExisting.body)}`);
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: existingId, role: "member" }),
    });

    const [ghAuto, ghConfirm, ghNew, ghOff, goAuto] = await Promise.all([
      createConnector(connectorIds[0]!, "github", "auto_link_verified_email"),
      createConnector(connectorIds[1]!, "github", "confirm_link"),
      createConnector(connectorIds[2]!, "github", "create_new_only"),
      createConnector(connectorIds[3]!, "github", "auto_link_verified_email"),
      createConnector(connectorIds[4]!, "google", "auto_link_verified_email"),
    ]);
    const autoJson = ghAuto.body as
      | { provider?: unknown; link_policy?: unknown; enabled?: unknown; authorize_url?: unknown }
      | undefined;
    checks.push([
      "built-in connectors store their provider, policy and server-owned endpoints without the secret",
      ghAuto.status === 201 &&
        autoJson?.provider === "github" &&
        autoJson?.link_policy === "auto_link_verified_email" &&
        autoJson?.enabled === true &&
        String(autoJson?.authorize_url ?? "") === `${mockBase}/github/authorize` &&
        !JSON.stringify(ghAuto.body).includes(`${connectorIds[0]}-secret`) &&
        ghConfirm.status === 201 &&
        ghNew.status === 201 &&
        ghOff.status === 201 &&
        goAuto.status === 201,
    ]);

    // --- start: state, PKCE and (Google) nonce ---------------------------------------------------
    const ghStart = await startFlow(connectorIds[0]!, "gh-start");
    if (ghStart === undefined) return fail(detail);
    checks.push([
      "the GitHub redirect carries state, S256 PKCE, the fixed scopes and the state cookie",
      ghStart.params.get("state") !== null &&
        ghStart.params.get("code_challenge") !== null &&
        ghStart.params.get("code_challenge_method") === "S256" &&
        ghStart.params.get("scope") === "read:user user:email" &&
        ghStart.cookie !== "",
    ]);

    const goStart = await startFlow(connectorIds[4]!, "go-start");
    if (goStart === undefined) return fail(detail);
    checks.push([
      "the Google redirect carries an OIDC nonce and S256 PKCE",
      goStart.params.get("nonce") !== null &&
        goStart.params.get("code_challenge") !== null &&
        goStart.params.get("code_challenge_method") === "S256",
    ]);

    const badState = await call(
      `${ghStart.params.get("redirect_uri")}?state=not-a-uuid&code=anything`,
      { redirect: "manual" },
    );
    checks.push([
      "a malformed state is 400 and audited as state_invalid",
      badState.status === 400 &&
        (badState.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_INVALID_REQUEST" &&
        (await auditEvents("social_sign_in.failed")).some(
          (payload) => payload.connector_id === connectorIds[0] && payload.reason === "state_invalid",
        ),
    ]);

    // --- a first GitHub sign-in creates the account; a repeat subject reuses it -----------------
    const newEmail = `social59-new-${runId}@example.test`;
    const newSubject = `${9100000 + Math.floor(Math.random() * 1000)}`;
    const newCode = `code-gh-new-${runId}`;
    await register(newCode, {
      provider: "github",
      subject: newSubject,
      email: newEmail,
      verified: true,
      name: "Social New",
      challenge: ghStart.params.get("code_challenge") ?? undefined,
    });
    const noCookieUrl = `${ghStart.params.get("redirect_uri")}?${new URLSearchParams({
      state: ghStart.params.get("state") ?? "",
      code: newCode,
    })}`;
    const noCookie = await call(noCookieUrl, { redirect: "manual" });
    checks.push([
      "a callback without the state cookie is 400 and audited state_invalid",
      noCookie.status === 400 &&
        (noCookie.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_INVALID_REQUEST" &&
        (await auditEvents("social_sign_in.failed")).some(
          (payload) => payload.connector_id === connectorIds[0] && payload.reason === "state_invalid",
        ),
    ]);

    const firstCallback = await callback(ghStart, newCode);
    const firstRedirect = firstCallback.headers.get("location") ?? "";
    if (firstCallback.status !== 302 || firstRedirect === "") {
      detail = `first social callback → ${firstCallback.status} ${text(firstCallback.body)}`;
    }
    const replayed = await callback(ghStart, newCode);
    checks.push([
      "replaying the same callback is 400 and audited state_invalid",
      replayed.status === 400 &&
        (await auditEvents("social_sign_in.failed")).some(
          (payload) => payload.connector_id === connectorIds[0] && payload.reason === "state_invalid",
        ),
    ]);
    const firstToken =
      firstCallback.status === 302 && firstRedirect !== ""
        ? await exchange(firstRedirect, ghStart.verifier)
        : undefined;
    const firstClaims = jwtClaims((firstToken?.body as { id_token?: unknown })?.id_token);
    const firstAccount = await accountsFor(newEmail);
    checks.push([
      "a first GitHub sign-in creates one account and signs it in",
      firstCallback.status === 302 &&
        new URL(firstRedirect).searchParams.get("code") !== null &&
        firstToken?.status === 200 &&
        firstClaims?.email === newEmail &&
        firstAccount.count === 1 &&
        firstAccount.id === firstClaims?.sub,
    ]);

    const repeatStart = await startFlow(connectorIds[0]!, "gh-repeat");
    if (repeatStart === undefined) return fail(detail);
    const repeatCode = `code-gh-repeat-${runId}`;
    await register(repeatCode, {
      provider: "github",
      subject: newSubject,
      email: newEmail,
      verified: true,
      name: "Social New",
      challenge: repeatStart.params.get("code_challenge") ?? undefined,
    });
    const mismatchedBrowser = await callback(
      { location: repeatStart.location, cookie: ghStart.cookie },
      repeatCode,
    );
    checks.push([
      "a callback carrying another browser's state cookie is 400",
      mismatchedBrowser.status === 400,
    ]);
    const repeatCallback = await callback(repeatStart, repeatCode);
    const repeatRedirect = repeatCallback.headers.get("location") ?? "";
    if (repeatCallback.status !== 302 || repeatRedirect === "") {
      detail = `repeat social callback → ${repeatCallback.status} ${text(repeatCallback.body)}`;
    }
    const repeatToken =
      repeatCallback.status === 302 && repeatRedirect !== ""
        ? await exchange(repeatRedirect, repeatStart.verifier)
        : undefined;
    const repeatClaims = jwtClaims((repeatToken?.body as { id_token?: unknown })?.id_token);
    checks.push([
      "the same provider subject signs into the same account",
      repeatCallback.status === 302 &&
        repeatToken?.status === 200 &&
        repeatClaims?.sub === firstClaims?.sub &&
        (await accountsFor(newEmail)).count === 1,
    ]);

    // --- auto_link_verified_email: verified matches, unverified is refused -----------------------
    const autoStart = await startFlow(connectorIds[0]!, "gh-auto-link");
    if (autoStart === undefined) return fail(detail);
    const autoCode = `code-gh-auto-${runId}`;
    await register(autoCode, {
      provider: "github",
      subject: `${9200000 + Math.floor(Math.random() * 1000)}`,
      email: existingEmail,
      verified: true,
      name: "Social Auto",
      challenge: autoStart.params.get("code_challenge") ?? undefined,
    });
    const autoCallback = await callback(autoStart, autoCode);
    const autoRedirect = autoCallback.headers.get("location") ?? "";
    if (autoCallback.status !== 302 || autoRedirect === "") {
      detail = `auto-link social callback → ${autoCallback.status} ${text(autoCallback.body)}`;
    }
    const autoToken =
      autoCallback.status === 302 && autoRedirect !== ""
        ? await exchange(autoRedirect, autoStart.verifier)
        : undefined;
    const autoClaims = jwtClaims((autoToken?.body as { id_token?: unknown })?.id_token);
    checks.push([
      "auto_link_verified_email attaches a verified address to the existing account",
      autoCallback.status === 302 &&
        autoToken?.status === 200 &&
        autoClaims?.sub === existingId &&
        (await accountsFor(existingEmail)).count === 1,
    ]);

    const unverifiedEmail = `social59-unverified-${runId}@example.test`;
    const unverifiedStart = await startFlow(connectorIds[0]!, "gh-unverified");
    if (unverifiedStart === undefined) return fail(detail);
    const unverifiedCode = `code-gh-unverified-${runId}`;
    await register(unverifiedCode, {
      provider: "github",
      subject: `${9300000 + Math.floor(Math.random() * 1000)}`,
      email: unverifiedEmail,
      verified: false,
      name: "Social Unverified",
      challenge: unverifiedStart.params.get("code_challenge") ?? undefined,
    });
    const unverifiedCallback = await callback(unverifiedStart, unverifiedCode);
    checks.push([
      "an unverified GitHub email is refused with MONACA_SOCIAL_UNLINKED and makes no account",
      unverifiedCallback.status === 403 &&
        (unverifiedCallback.body as { monaca_error_code?: unknown } | undefined)
          ?.monaca_error_code === "MONACA_SOCIAL_UNLINKED" &&
        (await accountsFor(unverifiedEmail)).count === 0 &&
        (await auditEvents("social_sign_in.failed")).some(
          (payload) =>
            payload.connector_id === connectorIds[0] && payload.reason === "unverified_email",
        ),
    ]);

    // --- confirm_link: a page prompt, then an explicit link --------------------------------------
    const confirmStart = await startFlow(connectorIds[1]!, "gh-confirm");
    if (confirmStart === undefined) return fail(detail);
    const confirmCode = `code-gh-confirm-${runId}`;
    await register(confirmCode, {
      provider: "github",
      subject: `${9400000 + Math.floor(Math.random() * 1000)}`,
      email: existingEmail,
      verified: true,
      name: "Social Confirm",
      challenge: confirmStart.params.get("code_challenge") ?? undefined,
    });
    const confirmCallback = await callback(confirmStart, confirmCode);
    const confirmLocation = confirmCallback.headers.get("location") ?? "";
    const linkToken = new URL(confirmLocation, base).searchParams.get("social_link");
    checks.push([
      "confirm_link parks on the hosted page instead of linking",
      confirmCallback.status === 302 &&
        linkToken !== null &&
        confirmLocation.includes("social_link="),
    ]);
    if (linkToken === null) return fail("the confirm_link callback carried no token");

    const details = await call(
      `${base}/t/${TENANT}/social/link/${encodeURIComponent(linkToken)}`,
    );
    checks.push([
      "the pending-link read exposes the provider and the asserted email",
      details.status === 200 &&
        (details.body as { email?: unknown } | undefined)?.email === existingEmail &&
        (details.body as { connector_id?: unknown } | undefined)?.connector_id ===
          connectorIds[1],
    ]);

    const confirmed = await call(
      `${base}/t/${TENANT}/social/link/${encodeURIComponent(linkToken)}/confirm`,
      { method: "POST" },
    );
    const confirmedRedirect = (confirmed.body as { redirect_to?: unknown } | undefined)
      ?.redirect_to;
    const confirmedToken =
      typeof confirmedRedirect === "string"
        ? await exchange(confirmedRedirect, confirmStart.verifier)
        : undefined;
    const confirmedClaims = jwtClaims(
      (confirmedToken?.body as { id_token?: unknown })?.id_token,
    );
    checks.push([
      "confirming links the identity and completes the sign-in with the existing account",
      confirmed.status === 200 &&
        typeof confirmedRedirect === "string" &&
        confirmedToken?.status === 200 &&
        confirmedClaims?.sub === existingId &&
        (await auditEvents("social_identity.linked")).some(
          (payload) => payload.connector_id === connectorIds[1],
        ),
    ]);

    const replayConfirm = await call(
      `${base}/t/${TENANT}/social/link/${encodeURIComponent(linkToken)}/confirm`,
      { method: "POST" },
    );
    checks.push([
      "a consumed link confirmation cannot be replayed",
      replayConfirm.status === 400,
    ]);

    // --- create_new_only: never links; refuses an address another account owns --------------------
    const newOnlyStart = await startFlow(connectorIds[2]!, "gh-new-only");
    if (newOnlyStart === undefined) return fail(detail);
    const newOnlyCode = `code-gh-new-only-${runId}`;
    await register(newOnlyCode, {
      provider: "github",
      subject: `${9500000 + Math.floor(Math.random() * 1000)}`,
      email: existingEmail,
      verified: true,
      name: "Social New Only",
      challenge: newOnlyStart.params.get("code_challenge") ?? undefined,
    });
    const newOnlyCallback = await callback(newOnlyStart, newOnlyCode);
    checks.push([
      "create_new_only refuses an address another account owns with MONACA_SOCIAL_EMAIL_TAKEN",
      newOnlyCallback.status === 409 &&
        (newOnlyCallback.body as { monaca_error_code?: unknown } | undefined)
          ?.monaca_error_code === "MONACA_SOCIAL_EMAIL_TAKEN" &&
        (await accountsFor(existingEmail)).count === 1 &&
        (await auditEvents("social_sign_in.failed")).some(
          (payload) =>
            payload.connector_id === connectorIds[2] && payload.reason === "link_conflict",
        ),
    ]);

    const freeEmail = `social59-newonly-${runId}@example.test`;
    const freeStart = await startFlow(connectorIds[2]!, "gh-new-only-free");
    if (freeStart === undefined) return fail(detail);
    const freeCode = `code-gh-new-only-free-${runId}`;
    await register(freeCode, {
      provider: "github",
      subject: `${9600000 + Math.floor(Math.random() * 1000)}`,
      email: freeEmail,
      verified: true,
      name: "Social New Free",
      challenge: freeStart.params.get("code_challenge") ?? undefined,
    });
    const freeCallback = await callback(freeStart, freeCode);
    const freeRedirect = freeCallback.headers.get("location") ?? "";
    if (freeCallback.status !== 302 || freeRedirect === "") {
      detail = `new-only social callback → ${freeCallback.status} ${text(freeCallback.body)}`;
    }
    const freeToken =
      freeCallback.status === 302 && freeRedirect !== ""
        ? await exchange(freeRedirect, freeStart.verifier)
        : undefined;
    checks.push([
      "create_new_only still creates an account when the address is free",
      freeCallback.status === 302 &&
        freeToken?.status === 200 &&
        (await accountsFor(freeEmail)).count === 1,
    ]);

    // --- Google: the id_token nonce is checked ---------------------------------------------------
    const googleEmail = `social59-google-${runId}@example.test`;
    const googleStart = await startFlow(connectorIds[4]!, "google-ok");
    if (googleStart === undefined) return fail(detail);
    const googleCode = `code-go-ok-${runId}`;
    await register(googleCode, {
      provider: "google",
      subject: `google-${runId}`,
      email: googleEmail,
      verified: true,
      name: "Social Google",
      challenge: googleStart.params.get("code_challenge") ?? undefined,
      nonce: googleStart.params.get("nonce") ?? undefined,
    });
    const googleCallback = await callback(googleStart, googleCode);
    const googleRedirect = googleCallback.headers.get("location") ?? "";
    if (googleCallback.status !== 302 || googleRedirect === "") {
      detail = `Google social callback → ${googleCallback.status} ${text(googleCallback.body)}`;
    }
    const googleToken =
      googleCallback.status === 302 && googleRedirect !== ""
        ? await exchange(googleRedirect, googleStart.verifier)
        : undefined;
    const googleClaims = jwtClaims((googleToken?.body as { id_token?: unknown })?.id_token);
    checks.push([
      "a Google sign-in whose id_token carries the state nonce succeeds",
      googleCallback.status === 302 &&
        googleToken?.status === 200 &&
        googleClaims?.email === googleEmail,
    ]);

    const wrongNonceStart = await startFlow(connectorIds[4]!, "google-bad-nonce");
    if (wrongNonceStart === undefined) return fail(detail);
    const wrongNonceCode = `code-go-bad-${runId}`;
    await register(wrongNonceCode, {
      provider: "google",
      subject: `google-bad-${runId}`,
      email: `social59-google-bad-${runId}@example.test`,
      verified: true,
      name: "Social Google Bad",
      challenge: wrongNonceStart.params.get("code_challenge") ?? undefined,
      nonce: "not-the-state-nonce",
    });
    const wrongNonceCallback = await callback(wrongNonceStart, wrongNonceCode);
    checks.push([
      "a mismatched id_token nonce is 502 MONACA_SOCIAL_PROVIDER_ERROR and audited provider_error",
      wrongNonceCallback.status === 502 &&
        (wrongNonceCallback.body as { monaca_error_code?: unknown } | undefined)
          ?.monaca_error_code === "MONACA_SOCIAL_PROVIDER_ERROR" &&
        (await auditEvents("social_sign_in.failed")).some(
          (payload) => payload.connector_id === connectorIds[4] && payload.reason === "provider_error",
        ),
    ]);

    // --- Google id_token signature and claim negatives ------------------------------------------
    const googleClientId = `${connectorIds[4]}-client`;
    const googleIdToken = (
      nonce: string,
      overrides: Record<string, unknown> = {},
      key = googleKeys[0]!,
      headerKid = key.kid,
    ): Promise<string> => {
      const now = Math.floor(Date.now() / 1000);
      return signGoogleToken(key, headerKid, {
        iss: "https://accounts.google.com",
        aud: googleClientId,
        sub: `google-neg-${runId}`,
        email: `social59-google-neg-${runId}@example.test`,
        email_verified: true,
        name: "Google Negative",
        nonce,
        iat: now,
        exp: now + 3_600,
        ...overrides,
      });
    };
    const googleRejected = async (
      tag: string,
      makeToken: (nonce: string) => Promise<string>,
      expected = 502,
    ): Promise<boolean> => {
      const start = await startFlow(connectorIds[4]!, tag);
      if (start === undefined) return false;
      const nonce = start.params.get("nonce") ?? "";
      const code = `code-${tag}-${runId}`;
      await register(code, {
        provider: "google",
        subject: `google-${tag}-${runId}`,
        email: `social59-${tag}-${runId}@example.test`,
        verified: true,
        name: "Google Negative",
        challenge: start.params.get("code_challenge") ?? undefined,
        nonce,
        id_token: await makeToken(nonce),
      });
      const response = await callback(start, code);
      return response.status === expected;
    };

    checks.push([
      "a Google id_token with alg=none is rejected",
      await googleRejected("go-none", (nonce) => {
        const header = base64UrlJson({ alg: "none", typ: "JWT" });
        return Promise.resolve(`${header}.${base64UrlJson({ nonce })}.`);
      }),
    ]);
    checks.push([
      "a Google id_token signed with HS256 is rejected (algorithm confusion)",
      await googleRejected("go-hs256", (nonce) => {
        const now = Math.floor(Date.now() / 1000);
        const header = base64UrlJson({ alg: "HS256", typ: "JWT", kid: googleKeys[0]!.kid });
        const payload = base64UrlJson({
          iss: "https://accounts.google.com",
          aud: googleClientId,
          sub: `google-go-hs256-${runId}`,
          email: `social59-go-hs256-${runId}@example.test`,
          email_verified: true,
          nonce,
          iat: now,
          exp: now + 3_600,
        });
        const signature = createHmac("sha256", "the-public-key-would-be-the-secret")
          .update(`${header}.${payload}`)
          .digest("base64url");
        return Promise.resolve(`${header}.${payload}.${signature}`);
      }),
    ]);
    checks.push([
      "a Google id_token with a forged signature is rejected",
      await googleRejected("go-forged", (nonce) =>
        googleIdToken(nonce, {}, rogueKey, googleKeys[0]!.kid),
      ),
    ]);
    checks.push([
      "a Google id_token with a wrong aud is rejected",
      await googleRejected("go-aud", (nonce) => googleIdToken(nonce, { aud: "another-client" })),
    ]);
    checks.push([
      "a Google id_token with a wrong iss is rejected",
      await googleRejected("go-iss", (nonce) => googleIdToken(nonce, { iss: "https://evil.example" })),
    ]);
    checks.push([
      "an expired Google id_token is rejected",
      await googleRejected("go-exp", (nonce) => {
        const now = Math.floor(Date.now() / 1000);
        // Past the verifier's 60 s expiry leeway, but `iat` stays inside the ten-minute window so
        // this check fails on `exp`, not on the age rule.
        return googleIdToken(nonce, { iat: now - 180, exp: now - 120 });
      }),
    ]);
    checks.push([
      "a Google id_token with an unknown kid is rejected",
      await googleRejected("go-kid", (nonce) => googleIdToken(nonce, {}, rogueKey, "rogue-kid")),
    ]);
    checks.push([
      "a Google id_token with a mismatched nonce is rejected",
      await googleRejected("go-nonce", (nonce) =>
        googleIdToken(nonce === "" ? "missing" : `${nonce}-other`),
      ),
    ]);
    checks.push([
      "an unverified Google email cannot auto-link",
      await googleRejected(
        "go-unverified",
        (nonce) =>
          googleIdToken(nonce, {
            email: `social59-google-unverified-${runId}@example.test`,
            email_verified: false,
          }),
        403,
      ),
    ]);

    // --- a new Google key appears after the cache was filled: unknown kid → refresh → success ---
    googleKeys.push(await makeGoogleKey("google-key-2"));
    const rotatedEmail = `social59-google-rotated-${runId}@example.test`;
    const rotatedStart = await startFlow(connectorIds[4]!, "google-rotated");
    if (rotatedStart === undefined) return fail(detail);
    const rotatedCode = `code-go-rotated-${runId}`;
    await register(rotatedCode, {
      provider: "google",
      subject: `google-rotated-${runId}`,
      email: rotatedEmail,
      verified: true,
      name: "Google Rotated",
      challenge: rotatedStart.params.get("code_challenge") ?? undefined,
      nonce: rotatedStart.params.get("nonce") ?? undefined,
      keyId: "google-key-2",
    });
    const rotatedCallback = await callback(rotatedStart, rotatedCode);
    const rotatedRedirect = rotatedCallback.headers.get("location") ?? "";
    const rotatedToken =
      rotatedCallback.status === 302 && rotatedRedirect !== ""
        ? await exchange(rotatedRedirect, rotatedStart.verifier)
        : undefined;
    checks.push([
      "a rotated Google kid is refreshed and signs in",
      rotatedCallback.status === 302 &&
        rotatedToken?.status === 200 &&
        (await accountsFor(rotatedEmail)).count === 1,
    ]);

    // --- disabling a connector -------------------------------------------------------------------
    const disabled = await call(`${base}/v1/connectors/${connectorIds[3]}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ enabled: false }),
    });
    const publicAfter = await call(`${base}/t/${TENANT}/connectors`);
    const publicItems =
      (publicAfter.body as { items?: { connector_id?: unknown }[] } | undefined)?.items ?? [];
    const disabledStart = await startFlow(connectorIds[3]!, "disabled");
    checks.push([
      "a disabled connector leaves the public list and its authorize is 404",
      disabled.status === 200 &&
        (disabled.body as { enabled?: unknown } | undefined)?.enabled === false &&
        !publicItems.some((item) => item.connector_id === connectorIds[3]) &&
        disabledStart === undefined &&
        (await auditEvents("connector.updated")).some(
          (payload) =>
            payload.connector_id === connectorIds[3] && payload.enabled === false,
        ),
    ]);

    // --- success audit ---------------------------------------------------------------------------
    const success = await auditEvents("social_sign_in.succeeded");
    checks.push([
      "social_sign_in.succeeded records the connector, new-account flag and confirmation",
      success.some(
        (payload) =>
          payload.connector_id === connectorIds[0] &&
          payload.new_account === true &&
          payload.email === newEmail,
      ) &&
        success.some(
          (payload) =>
            payload.connector_id === connectorIds[1] && payload.confirmed === true,
        ),
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    for (const id of connectorIds) {
      await call(`${base}/v1/connectors/${id}`, { method: "DELETE", headers }).catch(
        () => undefined,
      );
    }
    mock?.stop(true);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "59",
    title: "social providers and linking",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: presets → state/PKCE/nonce → GitHub account reuse → auto-link → unverified refusal → confirm link → new-only policy → Google nonce → disable → audit`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 60 — revocation reaches the management verifier (§6.2).
 *
 * `/oauth2/revoke` has always recorded the access token's `jti`; this step proves the `/v1`
 * verifier actually consults it. Two tokens are minted for the same automation client, one is
 * revoked, and only the other may still call `/v1`. An unknown token stays a RFC 7009 `200`.
 */
async function revocationFlow(base: string, adminSecret: string): Promise<StepResult> {
  const t = performance.now();
  const basic = btoa(`${ADMIN_CLIENT_ID}:${adminSecret}`);
  const checks: [string, boolean][] = [];
  let detail = "";

  const mint = (): Promise<HttpResult> =>
    tokenCall(base, { grant_type: "client_credentials", scope: "monaca:admin" }, basic);
  const management = (token: string): Promise<HttpResult> =>
    call(`${base}/v1/accounts?limit=1`, { headers: { authorization: `Bearer ${token}` } });
  const revoke = (token: string): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/oauth2/revoke`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${basic}`,
      },
      body: new URLSearchParams({ token, token_type_hint: "access_token" }).toString(),
    });

  try {
    const first = await mint();
    const second = await mint();
    const tokenA = (first.body as { access_token?: string } | undefined)?.access_token ?? "";
    const tokenB = (second.body as { access_token?: string } | undefined)?.access_token ?? "";
    checks.push([
      "two management tokens are minted for the same client",
      first.status === 200 && second.status === 200 && tokenA !== "" && tokenB !== "",
    ]);
    if (tokenA === "" || tokenB === "") {
      detail = `mint → ${first.status}/${second.status}`;
      return {
        step: "60",
        title: "revocation propagation",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail,
      };
    }

    const beforeA = await management(tokenA);
    const beforeB = await management(tokenB);
    checks.push([
      "both tokens open /v1",
      beforeA.status === 200 && beforeB.status === 200,
    ]);

    const revoked = await revoke(tokenA);
    checks.push(["POST /oauth2/revoke is 200", revoked.status === 200]);

    const afterA = await management(tokenA);
    const afterB = await management(tokenB);
    checks.push([
      "the revoked token is 401 MONACA_UNAUTHORIZED on /v1",
      afterA.status === 401 &&
        (afterA.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_UNAUTHORIZED",
    ]);
    checks.push([
      "the second token still opens /v1 after the revocation",
      afterB.status === 200,
    ]);

    const unknown = await revoke("not-a-real-token");
    checks.push([
      "revoking an unknown token is 200 and discloses nothing",
      unknown.status === 200,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "60",
    title: "revocation propagation",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: two tokens → both open /v1 → revoke A → A is 401 → B still 200 → unknown is 200`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 61 — configurable tenant/client/endpoint gates (§6.2).
 *
 * A limit that is only stored but never enforced would pass a "config saved" check. This step
 * trips both layers and requires the 429 + `Retry-After` answer, then clears the configuration and
 * proves the same request succeeds again.
 */
async function rateLimitFlow(
  base: string,
  adminToken: string,
  adminSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const headers = managementHeaders(adminToken);
  const basic = btoa(`${ADMIN_CLIENT_ID}:${adminSecret}`);
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const checks: [string, boolean][] = [];
  let detail = "";

  const patch = (items: unknown[]): Promise<HttpResult> =>
    call(`${base}/v1/rate-limits`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ items }),
    });
  const mint = (): Promise<HttpResult> =>
    tokenCall(base, { grant_type: "client_credentials", scope: "monaca:admin" }, basic);
  const authorize = async (tag: string): Promise<HttpResult> => {
    const verifier = `rl-${tag}-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: redirectUri,
      scope: "openid",
      state: `rl-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;
    return call(url, { redirect: "manual" });
  };
  const retryAfter = (result: HttpResult): number | undefined => {
    const raw = result.headers.get("retry-after");
    if (raw === null) return undefined;
    const value = Number(raw);
    return Number.isInteger(value) && value > 0 ? value : undefined;
  };
  const limited = (result: HttpResult): boolean =>
    result.status === 429 &&
    (result.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
      "MONACA_TOO_MANY_ATTEMPTS" &&
    retryAfter(result) !== undefined;

  try {
    const read = await call(`${base}/v1/rate-limits`, { headers });
    const defaults = (read.body as { defaults?: { endpoint?: string }[] } | undefined)?.defaults ?? [];
    checks.push([
      "GET /v1/rate-limits reports the four built-in defaults",
      read.status === 200 &&
        defaults.length === 4 &&
        ["authorize", "token", "userinfo", "management"].every((endpoint) =>
          defaults.some((item) => item.endpoint === endpoint),
        ) &&
        ((read.body as { items?: unknown[] } | undefined)?.items ?? []).length === 0,
    ]);

    const badEndpoint = await patch([{ endpoint: "bogus", limit: 5, window_secs: 60 }]);
    const badLimit = await patch([{ endpoint: "token", limit: 0, window_secs: 60 }]);
    const badWindow = await patch([{ endpoint: "token", limit: 5, window_secs: 86_401 }]);
    const badClient = await patch([
      { endpoint: "token", client_id: "no-such-client", limit: 5, window_secs: 60 },
    ]);
    checks.push([
      "invalid endpoint, limit, window and client are 400",
      badEndpoint.status === 400 &&
        badLimit.status === 400 &&
        badWindow.status === 400 &&
        badClient.status === 400,
    ]);

    const clientRow = await patch([
      { endpoint: "token", client_id: ADMIN_CLIENT_ID, limit: 2, window_secs: 60 },
    ]);
    checks.push([
      "a per-client token row is stored and echoed",
      clientRow.status === 200 &&
        ((clientRow.body as { items?: { client_id?: unknown; limit?: unknown }[] } | undefined)
          ?.items ?? []).some(
          (item) => item.client_id === ADMIN_CLIENT_ID && item.limit === 2,
        ),
    ]);

    const first = await mint();
    const second = await mint();
    const third = await mint();
    checks.push([
      "two token requests pass the per-client layer and the third is limited",
      first.status === 200 && second.status === 200 && limited(third),
    ]);
    checks.push([
      "the limit carries MONACA_TOO_MANY_ATTEMPTS and Retry-After",
      limited(third),
    ]);

    const live = await call(`${base}/v1/rate-limits`, { headers });
    const liveStatus =
      (live.body as {
        status?: { endpoint?: unknown; client_id?: unknown; count?: unknown; limited?: unknown }[];
      } | undefined)?.status ?? [];
    checks.push([
      "the live status names the token/client counter and reports it limited",
      live.status === 200 &&
        liveStatus.some(
          (item) =>
            item.endpoint === "token" &&
            item.client_id === ADMIN_CLIENT_ID &&
            typeof item.count === "number" &&
            item.count > 2 &&
            item.limited === true,
        ),
    ]);

    const tenantRow = await patch([{ endpoint: "authorize", limit: 1, window_secs: 60 }]);
    const firstAuthorize = await authorize("first");
    const secondAuthorize = await authorize("second");
    checks.push([
      "a tenant-wide authorize row is stored",
      tenantRow.status === 200 &&
        ((tenantRow.body as { items?: { client_id?: unknown }[] } | undefined)?.items ?? []).some(
          (item) => item.client_id === null,
        ),
    ]);
    checks.push([
      "one authorize passes the tenant layer and the next is limited",
      firstAuthorize.status === 302 && limited(secondAuthorize),
    ]);

    const cleared = await patch([]);
    const after = await mint();
    checks.push([
      "items:[] clears the overrides and a token request succeeds again",
      cleared.status === 200 &&
        ((cleared.body as { items?: unknown[] } | undefined)?.items ?? []).length === 0 &&
        after.status === 200,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "61",
    title: "rate limits",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: defaults → four 400s → client token limit 2 → third 429+Retry-After → tenant authorize limit 1 → second 429 → cleared`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 66 — the per-IP gate (§6.2).
 *
 * The tenant and client layers need a real tenant; this layer runs before the tenant lookup, so
 * the cheapest flooding target is a name that does not exist. The step reads the configured
 * per-IP limit from the management document instead of hard-coding it, exhausts one address and
 * proves that another address, and the same address on another endpoint, are unaffected.
 */
async function ipRateLimitFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  const runId = Date.now().toString(36);
  let detail = "";

  const retryAfter = (result: HttpResult): number | undefined => {
    const raw = result.headers.get("retry-after");
    if (raw === null) return undefined;
    const value = Number(raw);
    return Number.isInteger(value) && value > 0 ? value : undefined;
  };
  const limited = (result: HttpResult): boolean =>
    result.status === 429 &&
    (result.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
      "MONACA_TOO_MANY_ATTEMPTS" &&
    retryAfter(result) !== undefined;

  const missingTenant = `ip-limit-${runId}`;
  const token = (address: string): Promise<HttpResult> =>
    call(`${base}/t/${missingTenant}/oauth2/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "x-forwarded-for": address,
      },
      body: "grant_type=client_credentials",
    });
  const authorize = (address: string): Promise<HttpResult> =>
    call(`${base}/t/${missingTenant}/oauth2/authorize?client_id=no-such-client`, {
      headers: { "x-forwarded-for": address },
      redirect: "manual",
    });

  try {
    const read = await call(`${base}/v1/rate-limits`, { headers });
    const ip = (read.body as { ip?: { limit?: number; window_secs?: number; scope?: string } })
      ?.ip;
    const limit = ip?.limit ?? 0;
    checks.push([
      "GET /v1/rate-limits reports the per-IP layer and its limit",
      read.status === 200 && limit > 0 && ip?.window_secs === 60 && ip?.scope !== undefined,
    ]);
    if (limit <= 0) return { step: "66", title: "per-IP rate limits", status: "fail", ms: Math.round(performance.now() - t), detail: "the per-IP layer is disabled; enable MONACA_IP_RATE_LIMIT_PER_MINUTE" };

    const first = await token(`203.0.113.${Math.floor(Math.random() * 200) + 20}`);
    checks.push([
      "the first request from an address reaches the tenant lookup (404, not 429)",
      first.status === 404,
    ]);

    // The address is fresh. Send one more than the limit; the last request must be refused.
    const address = `198.51.100.${Math.floor(Math.random() * 200) + 20}`;
    let last: HttpResult | undefined;
    for (let i = 0; i <= limit; i++) last = await token(address);
    checks.push([
      "the address is limited after exactly the configured number of requests",
      last !== undefined && limited(last),
    ]);

    const other = await token(`192.0.2.${Math.floor(Math.random() * 200) + 20}`);
    checks.push([
      "a second address is not limited by the first address's bucket",
      other.status === 404,
    ]);
    checks.push([
      "the same address still reaches another endpoint (buckets are per endpoint)",
      (await authorize(address)).status === 404,
    ]);
    checks.push([
      "the 429 carries Retry-After between 1 and 60 seconds",
      retryAfter(last ?? other) !== undefined &&
        (retryAfter(last ?? other) ?? 0) >= 1 &&
        (retryAfter(last ?? other) ?? 0) <= 60,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "66",
    title: "per-IP rate limits",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: default read → first 404 → limit+1 429 → other address → other endpoint → Retry-After`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 67 — the tenant lifecycle entry point and the suspended gate (§5.4, §6.1).
 *
 * The CLI provisions a new tenant while the server is running; the same management token is then
 * used before and after suspend/resume/archive. A suspended tenant must answer the structured
 * `MONACA_TENANT_SUSPENDED`, not keep serving.
 */
async function tenantLifecycleFlow(base: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const slug = `life-${runId}`;
  const adminEmail = `admin@${slug}.localhost`;
  const adminPassword = `Life-${runId}-9xQ`;
  const adminSecret = `life-admin-${runId}`;
  const loginClient = "e2e-login";
  const redirectUri = "http://localhost:5173/bff/callback";
  const bin =
    process.env.MONACA_SERVER_BIN ??
    (process.platform === "win32"
      ? ".monaca/bin/monaca-server.exe"
      : ".monaca/bin/monaca-server");
  const checks: [string, boolean][] = [];
  let detail = "";

  const cli = async (args: string[]): Promise<{ code: number; stdout: string; stderr: string }> => {
    const proc = Bun.spawn([bin, ...args], {
      cwd: process.cwd(),
      env: { ...process.env },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, code] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    return { code, stdout, stderr };
  };

  const managementToken = (): Promise<HttpResult> =>
    call(`${base}/t/${slug}/oauth2/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${btoa(`monaca-admin:${adminSecret}`)}`,
      },
      body: "grant_type=client_credentials&scope=monaca:admin",
    });

  const signIn = async (): Promise<{ signIn: HttpResult; token: HttpResult }> => {
    const verifier = `life-${runId}-${"v".repeat(40)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const started = await call(
      `${base}/t/${slug}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: loginClient,
        redirect_uri: redirectUri,
        scope: "openid profile email",
        state: `life-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: `${base}/v1`,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(started.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    if (started.status !== 302 || interaction === null) {
      detail = `authorize answered ${started.status} ${text(started.body)}`;
      return { signIn: started, token: started };
    }
    const response = await call(
      `${base}/t/${slug}/interaction/${encodeURIComponent(interaction)}/sign-in`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identifier: adminEmail, password: adminPassword }),
      },
    );
    const redirectTo = (response.body as { redirect_to?: string })?.redirect_to ?? "";
    const token = await call(`${base}/t/${slug}/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: new URL(redirectTo, base).searchParams.get("code") ?? "",
        redirect_uri: redirectUri,
        client_id: loginClient,
        code_verifier: verifier,
      }).toString(),
    });
    return { signIn: response, token };
  };

  try {
    const created = await cli([
      "tenant",
      "create",
      "--slug",
      slug,
      "--admin-email",
      adminEmail,
      "--admin-password",
      adminPassword,
      "--admin-client-secret",
      adminSecret,
      "--login-client-id",
      loginClient,
      "--login-redirect-uri",
      redirectUri,
    ]);
    checks.push([
      "tenant create provisions the tenant and exits 0",
      created.code === 0 && created.stdout.includes(slug),
    ]);
    if (created.code !== 0) throw new Error(created.stderr || created.stdout);

    const minted = await managementToken();
    const bearer = (minted.body as { access_token?: string })?.access_token ?? "";
    checks.push([
      "the tenant's admin client mints a management token",
      minted.status === 200 && bearer !== "",
    ]);
    const before = await call(`${base}/v1/accounts?limit=1`, {
      headers: { authorization: `Bearer ${bearer}` },
    });
    checks.push(["the tenant answers /v1 before suspension", before.status === 200]);

    const first = await signIn();
    checks.push([
      "the tenant's public client completes a password sign-in",
      first.signIn.status === 200 && first.token.status === 200,
    ]);

    const userToken = (first.token.body as { access_token?: string })?.access_token ?? "";
    const me = (accessToken: string): Promise<HttpResult> =>
      call(`${base}/v1/me`, { headers: { authorization: `Bearer ${accessToken}` } });
    const demotedAudit = (): Promise<HttpResult> =>
      call(
        `${base}/v1/audit?${new URLSearchParams({
          action: "account.tenant_admin_demoted",
          limit: "5",
        })}`,
        { headers: { authorization: `Bearer ${bearer}` } },
      );

    const beforeMe = await me(userToken);
    checks.push([
      "the owner override makes /v1/me a tenant administrator",
      beforeMe.status === 200 &&
        (beforeMe.body as { is_tenant_admin?: boolean }).is_tenant_admin === true &&
        (beforeMe.body as { management?: string }).management === "full",
    ]);

    const dryDemote = await cli([
      "tenant",
      "demote-admin",
      "--slug",
      slug,
      "--email",
      adminEmail,
      "--dry-run",
    ]);
    checks.push([
      "tenant demote-admin --dry-run reports the change without writing the chain",
      dryDemote.code === 0 &&
        dryDemote.stdout.includes("would clear") &&
        ((await demotedAudit()).body as { items?: unknown[] }).items?.length === 0,
    ]);

    const demote = await cli([
      "tenant",
      "demote-admin",
      "--slug",
      slug,
      "--email",
      adminEmail,
    ]);
    const afterAudit = await demotedAudit();
    const afterMe = await me(userToken);
    const demoteItems =
      (afterAudit.body as {
        items?: {
          action?: string;
          actor_chain?: { type?: string }[];
          subject?: { type?: string; id?: string };
        }[];
      }).items ?? [];
    checks.push([
      "tenant demote-admin clears the override, writes one tenant-chain event and lowers /v1/me",
      demote.code === 0 &&
        demote.stdout.includes("cleared is_tenant_admin") &&
        afterAudit.status === 200 &&
        demoteItems.length === 1 &&
        demoteItems[0]?.action === "account.tenant_admin_demoted" &&
        demoteItems[0]?.actor_chain?.[0]?.type === "tenant" &&
        demoteItems[0]?.subject?.type === "account" &&
        afterMe.status === 200 &&
        (afterMe.body as { is_tenant_admin?: boolean }).is_tenant_admin === false &&
        (afterMe.body as { management?: string }).management === "none",
    ]);

    const again = await cli([
      "tenant",
      "demote-admin",
      "--slug",
      slug,
      "--email",
      adminEmail,
    ]);
    checks.push([
      "a second demote-admin writes nothing",
      again.code === 0 &&
        again.stdout.includes("already not a tenant administrator") &&
        ((await demotedAudit()).body as { items?: unknown[] }).items?.length === 1,
    ]);

    const dry = await cli(["tenant", "suspend", "--slug", slug, "--dry-run"]);
    checks.push([
      "tenant suspend --dry-run reports the transition without writing",
      dry.code === 0 && dry.stdout.includes("would apply"),
    ]);

    const suspended = await cli(["tenant", "suspend", "--slug", slug]);
    checks.push([
      "tenant suspend moves the tenant to suspended",
      suspended.code === 0 && suspended.stdout.includes("suspended"),
    ]);
    const refused = await call(`${base}/v1/accounts?limit=1`, {
      headers: { authorization: `Bearer ${bearer}` },
    });
    checks.push([
      "the same management token is refused with MONACA_TENANT_SUSPENDED",
      refused.status === 403 &&
        (refused.body as { monaca_error_code?: string })?.monaca_error_code ===
          "MONACA_TENANT_SUSPENDED",
    ]);
    const refusedToken = await managementToken();
    checks.push([
      "token issuance is refused while suspended",
      refusedToken.status === 403 &&
        (refusedToken.body as { monaca_error_code?: string })?.monaca_error_code ===
          "MONACA_TENANT_SUSPENDED",
    ]);

    const resumed = await cli(["tenant", "resume", "--slug", slug]);
    checks.push([
      "tenant resume restores service",
      resumed.code === 0 && resumed.stdout.includes("active"),
    ]);
    const afterResume = await call(`${base}/v1/accounts?limit=1`, {
      headers: { authorization: `Bearer ${bearer}` },
    });
    const secondSignIn = await signIn();
    checks.push([
      "the same management token and a fresh sign-in work after resume",
      afterResume.status === 200 &&
        secondSignIn.signIn.status === 200 &&
        secondSignIn.token.status === 200,
    ]);

    const archived = await cli(["tenant", "archive", "--slug", slug]);
    checks.push([
      "tenant archive retains the database and reports it",
      archived.code === 0 &&
        archived.stdout.includes("archive retained") &&
        archived.stdout.includes("resume"),
    ]);
    const refusedArchive = await call(`${base}/v1/accounts?limit=1`, {
      headers: { authorization: `Bearer ${bearer}` },
    });
    checks.push([
      "an archived tenant is refused with MONACA_TENANT_ARCHIVED",
      refusedArchive.status === 403 &&
        (refusedArchive.body as { monaca_error_code?: string })?.monaca_error_code ===
          "MONACA_TENANT_ARCHIVED",
    ]);
    const resumedArchive = await cli(["tenant", "resume", "--slug", slug]);
    const afterArchive = await call(`${base}/v1/accounts?limit=1`, {
      headers: { authorization: `Bearer ${bearer}` },
    });
    checks.push([
      "tenant resume returns an archived tenant to service",
      resumedArchive.code === 0 && afterArchive.status === 200,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "67",
    title: "tenant lifecycle",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: create → management token → sign-in → dry-run → suspend 403 → resume → archive 403 → resume`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 68 — SMS verification through the Twilio-shaped connector.
 *
 * The server's documented Twilio host is replaced with a local capture by the dev/CI-only
 * `MONACA_SMS_PROVIDER_BASE_URL`; the form body, basic auth and Messages path are the real
 * provider contract. The step also proves the fail-closed default (no connector → 503), the
 * shared per-address cooldown, wrong/right code handling and expiry.
 */
async function smsVerificationFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const capturePort = Number(process.env.MONACA_SMS_CAPTURE_PORT ?? 38300);
  const capture = startSmsCapture(capturePort);
  const sid = `AC${runId.replace(/[^a-z0-9]/gi, "").slice(0, 16)}`;
  const token = `token-${runId}`;
  const phone = `+1${String(Date.now()).slice(-10)}`;
  const expiredPhone = `+2${String(Date.now()).slice(-10)}`;
  const ttl = Number(process.env.MONACA_SMS_CODE_TTL_SECS ?? 600);

  try {
    const unconfigured = await call(`${base}/t/${TENANT}/verification/sms`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ phone, locale: "zh-CN" }),
    });
    checks.push([
      "an unconfigured tenant refuses the request with MONACA_SMS_NOT_CONFIGURED",
      unconfigured.status === 503 &&
        (unconfigured.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_SMS_NOT_CONFIGURED",
    ]);

    const configured = await call(`${base}/v1/sms-connector`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        provider: "twilio",
        endpoint: "https://api.twilio.com",
        from_address: "+15550000000",
        secret: `${sid}:${token}`,
        enabled: true,
      }),
    });
    checks.push([
      "PATCH stores the Twilio route and never echoes the secret",
      configured.status === 200 &&
        (configured.body as { provider?: unknown })?.provider === "twilio" &&
        (configured.body as { secret_set?: unknown })?.secret_set === true &&
        !JSON.stringify(configured.body).includes(token),
    ]);

    const sent = await call(`${base}/t/${TENANT}/verification/sms`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ phone, locale: "zh-CN" }),
    });
    checks.push([
      "a configured send answers verification_required",
      sent.status === 200 &&
        (sent.body as { verification_required?: unknown })?.verification_required === true,
    ]);

    const resend = await call(`${base}/t/${TENANT}/verification/sms`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ phone, locale: "zh-CN" }),
    });
    checks.push([
      "an immediate resend is refused by the shared per-address cooldown",
      resend.status === 429 &&
        (resend.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_TOO_MANY_ATTEMPTS",
    ]);

    const deadline = performance.now() + 20_000;
    const match = () =>
      capture.requests.find((entry) => {
        const form = new URLSearchParams(entry.body);
        return form.get("To") === phone;
      });
    while (match() === undefined && performance.now() < deadline) {
      await Bun.sleep(250);
    }
    const request = match();
    const form = request === undefined ? undefined : new URLSearchParams(request.body);
    const body = form?.get("Body") ?? "";
    const code = body.match(/\b\d{6}\b/)?.[0];
    checks.push([
      "the capture receives the documented Messages form with basic auth and Chinese copy",
      request !== undefined &&
        request.method === "POST" &&
        request.path === `/2010-04-01/Accounts/${sid}/Messages.json` &&
        request.authorization === `Basic ${btoa(`${sid}:${token}`)}` &&
        form?.get("From") === "+15550000000" &&
        typeof code === "string" &&
        body.includes("验证码") &&
        body.includes(code),
    ]);

    const wrongCode = code === "000000" ? "999999" : "000000";
    const wrong = await call(`${base}/t/${TENANT}/verification/sms/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ phone, code: wrongCode }),
    });
    checks.push([
      "a wrong code is 401 MONACA_INVALID_VERIFICATION_CODE",
      wrong.status === 401 &&
        (wrong.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_INVALID_VERIFICATION_CODE",
    ]);

    const right = await call(`${base}/t/${TENANT}/verification/sms/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ phone, code }),
    });
    checks.push([
      "the right code verifies",
      right.status === 200 && (right.body as { verified?: unknown })?.verified === true,
    ]);

    const expiring = await call(`${base}/t/${TENANT}/verification/sms`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ phone: expiredPhone, locale: "en" }),
    });
    if (expiring.status !== 200) {
      throw new Error(`the expiring-code request answered ${expiring.status}`);
    }
    await Bun.sleep((Math.min(ttl, 60) + 2) * 1000);
    const expired = await call(`${base}/t/${TENANT}/verification/sms/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ phone: expiredPhone, code: "000000" }),
    });
    checks.push([
      "a code past its TTL is 401 MONACA_VERIFICATION_CODE_EXPIRED",
      expired.status === 401 &&
        (expired.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_VERIFICATION_CODE_EXPIRED",
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    capture.stop();
    const removed = await call(`${base}/v1/sms-connector`, { method: "DELETE", headers });
    if (removed.status !== 204) detail = detail || `delete sms connector answered ${removed.status}`;
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "68",
    title: "SMS verification",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: unconfigured 503 → Twilio form → resend 429 → wrong 401 → verified → expired 401`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/** A fresh console interaction id for an email flow. */
async function consoleInteraction(base: string, tag: string): Promise<string | undefined> {
  const runId = Date.now().toString(36);
  const verifier = `${tag}-${runId}-${"z".repeat(32)}`;
  const challenge = base64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
  );
  const authorize = await call(
    `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: "monaca-console",
      redirect_uri: "http://localhost:5173/bff/callback",
      scope: "openid profile email",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`,
    { redirect: "manual" },
  );
  return (
    new URL(authorize.headers.get("location") ?? "", base).searchParams.get("interaction") ?? undefined
  );
}

/**
 * Step 69 — SMTP delivery to a local capture.
 *
 * The connector uses `smtp://127.0.0.1:2525` (the only plaintext form the server accepts) and the
 * capture records the wire message, so the envelope and the rendered MIME body are both proven
 * without a relay or an outbound network.
 */
async function smtpDeliveryFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";
  const port = Number(process.env.MONACA_SMTP_CAPTURE_PORT ?? 2525);
  const capture = startSmtpCapture(port);
  const email = `smtp-${runId}@demo.localhost`;
  const fail = (why: string): StepResult => ({
    step: "69",
    title: "SMTP delivery",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why,
  });

  try {
    const configured = await call(`${base}/v1/email-connector`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        provider: "smtp",
        endpoint: `smtp://127.0.0.1:${port}`,
        from_address: "no-reply@demo.localhost",
        from_name: "Monaca Demo",
        enabled: true,
      }),
    });
    checks.push([
      "PATCH accepts a loopback SMTP route",
      configured.status === 200 &&
        (configured.body as { provider?: unknown })?.provider === "smtp",
    ]);

    const interaction = await consoleInteraction(base, "smtp");
    if (interaction === undefined) return fail("authorize did not open an interaction");
    const requested = await call(
      `${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/password/forgot`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, locale: "en" }),
      },
    );
    checks.push([
      "a password-reset request queues a mail",
      requested.status === 200,
    ]);

    const deadline = performance.now() + 25_000;
    const find = () =>
      capture.messages.find((entry) => entry.to.some((to) => to.includes(email)));
    while (find() === undefined && performance.now() < deadline) {
      await Bun.sleep(250);
    }
    const message = find();
    const raw = message?.raw ?? "";
    const code = raw.match(/\b\d{6}\b/)?.[0];
    checks.push([
      "the local SMTP capture receives a message for the address",
      message !== undefined,
    ]);
    checks.push([
      "MAIL FROM and RCPT TO carry the configured addresses",
      (message?.from ?? "").includes("no-reply@demo.localhost") &&
        (message?.to ?? []).some((to) => to.includes(email)),
    ]);
    checks.push([
      "the raw message carries the rendered Subject header",
      raw.includes("Subject: Reset your demo password"),
    ]);
    checks.push([
      "the raw message is 7bit and carries the code",
      raw.includes("Content-Transfer-Encoding: 7bit") &&
        typeof code === "string" &&
        raw.includes(code),
    ]);
    if (
      !raw.includes("Subject: Reset your demo password") ||
      !raw.includes("Content-Transfer-Encoding: 7bit") ||
      typeof code !== "string" ||
      !raw.includes(code)
    ) {
      detail = `raw: ${raw.slice(0, 500)}`;
    }
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    capture.stop();
    const removed = await call(`${base}/v1/email-connector`, { method: "DELETE", headers });
    if (removed.status !== 204) detail = detail || `delete email connector answered ${removed.status}`;
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "69",
    title: "SMTP delivery",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: loopback SMTP route → reset queued → capture envelope → Subject/body code`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 70 — locale fallback and the explicit missing-template failure.
 *
 * The English row for `sign_up` is removed through the locale-aware API, a real sign-up request
 * must fail with `MONACA_TEMPLATE_MISSING` naming the purpose and locale (and increment the
 * metric), and restoring the built-in row makes the same request succeed.
 */
async function templateFallbackFlow(
  base: string,
  adminToken: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";
  const fail = (why: string): StepResult => ({
    step: "70",
    title: "template fallback and missing rejection",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why,
  });

  try {
    const listed = await call(`${base}/v1/message-templates?channel=sms`, { headers });
    const items =
      (listed.body as { items?: { purpose?: unknown; locale?: unknown; subject?: unknown; body?: unknown }[] })
        ?.items ?? [];
    const english = items.find((item) => item.purpose === "sms_verification" && item.locale === "en");
    const chinese = items.find((item) => item.purpose === "sms_verification" && item.locale === "zh-cn");
    checks.push([
      "the list carries en and zh-cn SMS copy",
      listed.status === 200 &&
        typeof english?.body === "string" &&
        english.body.includes("{{code}}") &&
        typeof chinese?.body === "string" &&
        chinese.body.includes("验证码"),
    ]);

    // Remove the override (if one exists) and then the seeded built-in row.
    const cleared = await call(`${base}/v1/message-templates/sign_up/en`, {
      method: "DELETE",
      headers,
    });
    const purged = await call(`${base}/v1/message-templates/sign_up/en?builtin=true`, {
      method: "DELETE",
      headers,
    });
    checks.push([
      "the generated en sign_up row can be explicitly removed",
      cleared.status === 204 && purged.status === 204,
    ]);

    const interaction = await consoleInteraction(base, "template");
    if (interaction === undefined) return fail("authorize did not open an interaction");
    const email = `missing-${runId}@demo.localhost`;
    const missing = await call(
      `${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-up`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, locale: "en" }),
      },
    );
    const problem = missing.body as
      | { monaca_error_code?: unknown; detail?: unknown }
      | undefined;
    checks.push([
      "a send with no template fails 500 MONACA_TEMPLATE_MISSING naming the key and locale",
      missing.status === 500 &&
        problem?.monaca_error_code === "MONACA_TEMPLATE_MISSING" &&
        typeof problem.detail === "string" &&
        problem.detail.includes("sign_up") &&
        problem.detail.includes("en"),
    ]);

    const metrics = await call(`${base}/metrics`);
    checks.push([
      "the missing-template rejection is counted",
      typeof metrics.body === "string" &&
        metrics.body.includes('monaca_template_missing_total{purpose="sign_up",locale="en"}'),
    ]);

    const restored = await call(`${base}/v1/message-templates/sign_up/en/restore`, {
      method: "POST",
      headers,
    });
    checks.push(["POST restore re-seeds the built-in row", restored.status === 204]);

    const retried = await call(
      `${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-up`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, locale: "en" }),
      },
    );
    checks.push([
      "the same request succeeds after the restore",
      retried.status === 200 &&
        (retried.body as { verification_required?: unknown })?.verification_required === true,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "70",
    title: "template fallback and missing rejection",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: en/zh list → purge en → 500 names sign_up/en → metric → restore → send`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 62 — the three short-lived flow states survive a server restart (§6.1).
 *
 * A second server process shares the database with the walk-through. An interaction, a pending
 * TOTP enrollment and a WebAuthn registration challenge are each started on one process and
 * finished on another; a replay after the restart must still be `409`, not a fresh flow.
 */
async function persistenceFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const headers = managementHeaders(adminToken);
  const runId = Date.now().toString(36);
  const email = `restart-${runId}@demo.localhost`;
  const password = `pw-${runId}-restart`;
  const redirectUri = "http://localhost:5173/bff/callback";
  const origin = new URL(process.env.MONACA_AUTH_UI_URL ?? "http://localhost:5174").origin;
  const serverBin =
    process.env.MONACA_SERVER_BIN ??
    join(ROOT, ".monaca", "bin", process.platform === "win32" ? "monaca-server.exe" : "monaca-server");
  const port = 8083;
  const second = `http://127.0.0.1:${port}`;
  const checks: [string, boolean][] = [];
  let detail = "";
  let proc: ReturnType<typeof Bun.spawn> | undefined;

  const skip = (why: string): StepResult => ({
    step: "62",
    title: "flow state survives a restart",
    status: "skip",
    ms: Math.round(performance.now() - t),
    detail: why,
  });
  if (!existsSync(serverBin)) {
    return skip(`no server binary at ${serverBin}; set MONACA_SERVER_BIN or run bun run fetch:native`);
  }
  if (
    process.env.MONACA_CONTROL_DATABASE_URL === undefined ||
    process.env.MONACA_ADMIN_DATABASE_URL === undefined
  ) {
    return skip("MONACA_CONTROL_DATABASE_URL / MONACA_ADMIN_DATABASE_URL are not in this environment");
  }

  const startServer = async (): Promise<boolean> => {
    proc = Bun.spawn([serverBin, "serve"], {
      cwd: ROOT,
      env: {
        ...process.env,
        MONACA_SERVER_ADDR: `127.0.0.1:${port}`,
        MONACA_SERVER_URL: second,
        MONACA_LOG_LEVEL: "warn",
      },
      stdout: "ignore",
      stderr: "ignore",
    });
    for (let i = 0; i < 120; i++) {
      try {
        const response = await fetch(`${second}/healthz`, { signal: AbortSignal.timeout(2_000) });
        if (response.ok) return true;
      } catch {
        // not listening yet
      }
      await Bun.sleep(250);
    }
    return false;
  };
  const stopServer = async (): Promise<void> => {
    if (proc === undefined) return;
    proc.kill();
    await proc.exited;
    proc = undefined;
    await Bun.sleep(250);
  };
  const restart = async (): Promise<boolean> => {
    await stopServer();
    return startServer();
  };
  const sessionCookie = (result: HttpResult): string | undefined =>
    /monaca_session=([0-9a-f-]{36})/.exec(result.headers.get("set-cookie") ?? "")?.[1];
  const cookieHeaders = (cookie: string | undefined): Record<string, string> =>
    cookie === undefined ? {} : { cookie: `monaca_session=${cookie}` };

  try {
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Restart flow", password }),
    });
    const accountId = (created.body as { id?: string } | undefined)?.id;
    if (created.status !== 201 || accountId === undefined) {
      detail = `POST /v1/accounts → ${created.status} ${text(created.body)}`;
      checks.push(["the test account is created", false]);
      throw new Error(detail);
    }
    const member = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    checks.push([
      "the test account is created and joined to acme",
      member.status === 201,
    ]);

    if (!(await startServer())) {
      checks.push(["the second server starts", false]);
      throw new Error(`second server did not answer ${second}/healthz`);
    }
    const verifier = `restart-${runId}-${"y".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const authorize = await call(
      `${second}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: "monaca-console",
        redirect_uri: redirectUri,
        scope: "openid profile email",
        state: `restart-${runId}`,
        nonce: `restart-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(authorize.headers.get("location") ?? "", second).searchParams.get(
      "interaction",
    );
    checks.push([
      "the second server creates an interaction",
      authorize.status === 302 && interaction !== null,
    ]);
    if (interaction === null) throw new Error(`authorize → ${authorize.status}`);
    const iid = encodeURIComponent(interaction);

    if (!(await restart())) {
      checks.push(["the second server restarts", false]);
      throw new Error(`second server did not answer ${second}/healthz after a restart`);
    }
    const details = await call(`${second}/t/${TENANT}/interaction/${iid}`);
    const detailBody = details.body as
      | { signed_in?: unknown; client?: { client_id?: unknown } }
      | undefined;
    checks.push([
      "the interaction survives the restart",
      details.status === 200 &&
        detailBody?.signed_in === false &&
        detailBody?.client?.client_id === "monaca-console",
    ]);

    const signIn = await call(`${second}/t/${TENANT}/interaction/${iid}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: email, password }),
    });
    const cookie = sessionCookie(signIn);
    checks.push(["password sign-in completes after the restart", signIn.status === 200]);
    let redirectTo = (signIn.body as { redirect_to?: string } | undefined)?.redirect_to;
    if (redirectTo === undefined) {
      const consent = await call(`${second}/t/${TENANT}/interaction/${iid}/consent`, {
        method: "POST",
        headers: { "content-type": "application/json", ...cookieHeaders(cookie) },
        body: JSON.stringify({ decision: "allow" }),
      });
      redirectTo = (consent.body as { redirect_to?: string } | undefined)?.redirect_to;
    }
    const code = new URL(redirectTo ?? "http://invalid", second).searchParams.get("code");
    const exchanged = await tokenCall(
      second,
      {
        grant_type: "authorization_code",
        code: code ?? "",
        redirect_uri: redirectUri,
        client_id: "monaca-console",
        code_verifier: verifier,
      },
      btoa(`monaca-console:${consoleSecret}`),
    );
    const claims = jwtClaims((exchanged.body as { id_token?: unknown } | undefined)?.id_token);
    checks.push([
      "the code minted after the restart exchanges for the test account",
      exchanged.status === 200 && claims?.sub === accountId,
    ]);

    const replay = await call(`${second}/t/${TENANT}/interaction/${iid}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: email, password }),
    });
    checks.push([
      "a consumed interaction is 409 after the restart",
      replay.status === 409 &&
        (replay.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_INTERACTION_CONSUMED",
    ]);
    const unknown = await call(
      `${second}/t/${TENANT}/interaction/int_00000000000000000000000000`,
    );
    checks.push([
      "an unknown interaction is 404",
      unknown.status === 404 &&
        (unknown.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_INTERACTION_NOT_FOUND",
    ]);

    // --- a pending TOTP enrollment survives another restart -------------------------------------
    const begin = await call(`${second}/t/${TENANT}/account/mfa/totp`, {
      method: "POST",
      headers: cookieHeaders(cookie),
    });
    const secret = (begin.body as { secret?: string } | undefined)?.secret;
    checks.push([
      "a TOTP enrollment starts",
      begin.status === 200 && typeof secret === "string" && secret.length > 0,
    ]);
    if (secret === undefined) throw new Error(`TOTP setup → ${begin.status}`);
    if (!(await restart())) {
      checks.push(["the second server restarts again", false]);
      throw new Error(`second server did not answer ${second}/healthz after the TOTP restart`);
    }
    const verified = await call(`${second}/t/${TENANT}/account/mfa/totp/verify`, {
      method: "POST",
      headers: { "content-type": "application/json", ...cookieHeaders(cookie) },
      body: JSON.stringify({ code: totpFromBase32(secret) }),
    });
    checks.push([
      "the pending TOTP enrollment verifies after the restart",
      verified.status === 200,
    ]);
    await call(`${second}/t/${TENANT}/account/mfa/totp`, {
      method: "DELETE",
      headers: cookieHeaders(cookie),
    });

    // --- a WebAuthn registration challenge survives a third restart ------------------------------
    const options = await call(`${second}/t/${TENANT}/account/passkeys/options`, {
      method: "POST",
      headers: cookieHeaders(cookie),
    });
    const creation = options.body as CreationOptionsJSON | undefined;
    checks.push([
      "passkey registration options are issued",
      options.status === 200 && creation?.challenge !== undefined && creation?.rp?.id !== undefined,
    ]);
    if (creation === undefined) throw new Error(`passkey options → ${options.status}`);
    if (!(await restart())) {
      checks.push(["the second server restarts for the passkey", false]);
      throw new Error(`second server did not answer ${second}/healthz after the passkey restart`);
    }
    const authenticator = await createSoftwareAuthenticator();
    const registered = await call(`${second}/t/${TENANT}/account/passkeys`, {
      method: "POST",
      headers: { "content-type": "application/json", ...cookieHeaders(cookie) },
      body: JSON.stringify(await buildRegistration(authenticator, creation, origin, "Restart key")),
    });
    const passkeyId = (registered.body as { id?: string } | undefined)?.id;
    checks.push([
      "the challenge survives the restart and the passkey registers",
      registered.status === 201 && passkeyId !== undefined,
    ]);
    if (passkeyId !== undefined) {
      await call(`${second}/t/${TENANT}/account/passkeys/${passkeyId}`, {
        method: "DELETE",
        headers: cookieHeaders(cookie),
      });
    }
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await stopServer();
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "62",
    title: "flow state survives a restart",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: interaction after restart → sign-in+consent+exchange → replay 409 → unknown 404 → TOTP across restart → passkey across restart`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 63 — the counter behind a gate is shared, not per process (§6.2).
 *
 * A per-instance counter would let the second server start a fresh budget. Two requests on the
 * first process and the third on the second must be the one that receives `429`.
 */
async function sharedRateLimitFlow(
  base: string,
  adminToken: string,
  adminSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const headers = managementHeaders(adminToken);
  const basic = btoa(`${ADMIN_CLIENT_ID}:${adminSecret}`);
  const serverBin =
    process.env.MONACA_SERVER_BIN ??
    join(ROOT, ".monaca", "bin", process.platform === "win32" ? "monaca-server.exe" : "monaca-server");
  const port = 8084;
  const second = `http://127.0.0.1:${port}`;
  const checks: [string, boolean][] = [];
  let detail = "";
  let proc: ReturnType<typeof Bun.spawn> | undefined;

  const skip = (why: string): StepResult => ({
    step: "63",
    title: "rate limits are shared across instances",
    status: "skip",
    ms: Math.round(performance.now() - t),
    detail: why,
  });
  if (!existsSync(serverBin)) {
    return skip(`no server binary at ${serverBin}; set MONACA_SERVER_BIN or run bun run fetch:native`);
  }
  if (
    process.env.MONACA_CONTROL_DATABASE_URL === undefined ||
    process.env.MONACA_ADMIN_DATABASE_URL === undefined
  ) {
    return skip("MONACA_CONTROL_DATABASE_URL / MONACA_ADMIN_DATABASE_URL are not in this environment");
  }

  const patch = (items: unknown[]): Promise<HttpResult> =>
    call(`${base}/v1/rate-limits`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ items }),
    });
  const mint = (target: string): Promise<HttpResult> =>
    tokenCall(target, { grant_type: "client_credentials", scope: "monaca:admin" }, basic);
  const limited = (result: HttpResult): boolean => {
    const raw = result.headers.get("retry-after");
    const retry = raw === null ? Number.NaN : Number(raw);
    return (
      result.status === 429 &&
      (result.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
        "MONACA_TOO_MANY_ATTEMPTS" &&
      Number.isInteger(retry) &&
      retry > 0
    );
  };

  try {
    proc = Bun.spawn([serverBin, "serve"], {
      cwd: ROOT,
      env: {
        ...process.env,
        MONACA_SERVER_ADDR: `127.0.0.1:${port}`,
        MONACA_SERVER_URL: second,
        MONACA_LOG_LEVEL: "warn",
      },
      stdout: "ignore",
      stderr: "ignore",
    });
    let started = false;
    for (let i = 0; i < 120; i++) {
      try {
        const response = await fetch(`${second}/healthz`, { signal: AbortSignal.timeout(2_000) });
        if (response.ok) {
          started = true;
          break;
        }
      } catch {
        // not listening yet
      }
      await Bun.sleep(250);
    }
    if (!started) throw new Error(`the second server did not answer ${second}/healthz`);

    const row = await patch([
      { endpoint: "token", client_id: ADMIN_CLIENT_ID, limit: 2, window_secs: 60 },
    ]);
    checks.push(["a per-client token row at 2 is stored", row.status === 200]);

    const first = await mint(base);
    const secondOnA = await mint(base);
    const thirdOnB = await mint(second);
    checks.push([
      "two requests pass on the first process",
      first.status === 200 && secondOnA.status === 200,
    ]);
    checks.push([
      "the third request on the second process is 429 with Retry-After",
      limited(thirdOnB),
    ]);

    const cleared = await patch([]);
    const afterOnB = await mint(second);
    checks.push([
      "clearing the configuration lets the second process mint again",
      cleared.status === 200 && afterOnB.status === 200,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    if (proc !== undefined) {
      proc.kill();
      await proc.exited;
    }
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "63",
    title: "rate limits are shared across instances",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: row stored → two pass on A → third on B is 429 → cleared → B mints`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 64 — the metrics endpoint answers "who is slow and who was limited" (§6.4).
 */
async function metricsFlow(base: string, internalSecret: string): Promise<StepResult> {
  const t = performance.now();
  const checks: [string, boolean][] = [];
  let detail = "";

  try {
    const response = await call(`${base}/metrics`, {
      headers: { accept: "text/plain" },
    });
    const body = typeof response.body === "string" ? response.body : "";
    const contentType = response.headers.get("content-type") ?? "";
    const total = (prefix: string): number => {
      let sum = 0;
      for (const line of body.split("\n")) {
        if (!line.startsWith(prefix)) continue;
        const value = Number(line.slice(line.lastIndexOf(" ") + 1));
        if (Number.isFinite(value)) sum += value;
      }
      return sum;
    };

    checks.push([
      "GET /metrics is 200 text/plain",
      response.status === 200 && contentType.startsWith("text/plain"),
    ]);
    checks.push([
      "request counters carry a real tenant, endpoint and status",
      body.includes("monaca_http_requests_total{") &&
        body.includes('endpoint="management"') &&
        body.includes('status="200"'),
    ]);
    checks.push([
      "the latency histogram is exposed with finite buckets",
      body.includes("monaca_http_request_duration_seconds_bucket") &&
        body.includes('le="+Inf"') &&
        body.includes("monaca_http_request_duration_seconds_count"),
    ]);
    checks.push([
      "this run's rate-limit rejections are visible",
      total("monaca_rate_limit_rejections_total{") > 0,
    ]);
    checks.push([
      "this run's revoked management token is visible",
      total('monaca_revoked_token_rejections_total{surface="management"}') > 0,
    ]);
    checks.push([
      "the scrape carries no internal secret",
      internalSecret === "" || !body.includes(internalSecret),
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "64",
    title: "metrics and structured logs",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: text/plain → request series → histogram → rate-limit rejections → revoked token → no secret`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 65 — the committed SDK, generated from the contract, against the real server (§6.5).
 */
async function sdkFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const checks: [string, boolean][] = [];
  let detail = "";
  const client = createMonacaClient({ baseUrl: base, token: adminToken });

  try {
    const health = await client.GET("/healthz");
    checks.push([
      "the generated client reads /healthz",
      health.response.status === 200 && health.data?.status === "ok",
    ]);

    const limits = await client.GET("/v1/rate-limits");
    checks.push([
      "the typed client reads the rate-limit document",
      limits.response.status === 200 &&
        limits.data?.defaults.length === 4 &&
        Array.isArray(limits.data?.items),
    ]);

    const cleared = await client.PATCH("/v1/rate-limits", { body: { items: [] } });
    checks.push([
      "the typed client writes the rate-limit document",
      cleared.response.status === 200 &&
        Array.isArray(cleared.data?.items) &&
        cleared.data.items.length === 0,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "65",
    title: "generated SDK against the real server",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: GET /healthz → GET /v1/rate-limits → PATCH /v1/rate-limits`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 25 — registered API resources (§6.2).
 *
 * A resource fixes the scope namespace of one API. An authorize request that names a registered
 * resource may only ask for the scopes it defines; after a role grants the scope the access token
 * carries the indicator as `aud`.
 */
async function apiResourceFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const headers = managementHeaders(adminToken);
  const email = `resource-${runId}@demo.localhost`;
  const password = `pw-${runId}-resource`;
  const clientId = `e2e-resource-${runId}`;
  const identifier = `https://api.example.com/${runId}`;
  const roleName = `resource-role-${runId}`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "25",
    title: "api resources",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** An authorize URL asking for `openid tools:write` against the resource. */
  const authorize = async (tag: string): Promise<{ url: string; verifier: string }> => {
    const verifier = `r-${tag}-${runId}-${"z".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: "openid tools:write",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
      resource: identifier,
    })}`;
    return { url, verifier };
  };

  try {
    // --- an account whose role grants the scope, and a public app that may ask for it -----------
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Resource holder", password }),
    });
    const accountId = (created.body as { id?: unknown })?.id;
    if (created.status !== 201 || typeof accountId !== "string") {
      return fail(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });

    const role = await call(`${base}/v1/roles`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: roleName, permissions: ["tools:write"] }),
    });
    const roleId = (role.body as { id?: unknown })?.id;
    if (role.status !== 201 || typeof roleId !== "string") {
      return fail(`POST /v1/roles → ${role.status} ${text(role.body)}`);
    }
    const assigned = await call(`${base}/v1/accounts/${accountId}/roles/${roleId}`, {
      method: "POST",
      headers,
    });
    if (assigned.status !== 204) {
      return fail(`assign role → ${assigned.status} ${text(assigned.body)}`);
    }

    const client = await call(`${base}/v1/clients`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        client_id: clientId,
        name: "E2E Resource App",
        kind: "public",
        redirect_uris: [redirectUri],
        scopes: ["openid", "tools:read", "tools:write"],
      }),
    });
    if (client.status !== 201) {
      return fail(`POST /v1/clients → ${client.status} ${text(client.body)}`);
    }

    // --- register the resource with only tools:read ----------------------------------------------
    const resource = await call(`${base}/v1/resources`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: "Example API", identifier, scopes: ["tools:read"] }),
    });
    const resourceId = (resource.body as { id?: unknown })?.id;
    checks.push([
      "POST /v1/resources registers the resource",
      resource.status === 201 &&
        typeof resourceId === "string" &&
        resourceId.startsWith("res_") &&
        JSON.stringify(resource.body).includes(identifier) &&
        JSON.stringify((resource.body as { scopes?: unknown })?.scopes).includes("tools:read"),
    ]);
    if (typeof resourceId !== "string") return fail("the resource carried no id");

    const duplicate = await call(`${base}/v1/resources`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: "Duplicate", identifier, scopes: [] }),
    });
    checks.push([
      "a duplicate identifier is 409 MONACA_RESOURCE_EXISTS",
      duplicate.status === 409 &&
        (duplicate.body as { monaca_error_code?: unknown })?.monaca_error_code === "MONACA_RESOURCE_EXISTS",
    ]);

    const relative = await call(`${base}/v1/resources`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: "Bad", identifier: "/api", scopes: [] }),
    });
    checks.push([
      "a relative identifier is 400",
      relative.status === 400,
    ]);

    const listed = await call(`${base}/v1/resources`, { headers });
    checks.push([
      "GET /v1/resources lists it",
      listed.status === 200 && JSON.stringify(listed.body).includes(identifier),
    ]);

    const fetched = await call(`${base}/v1/resources/${resourceId}`, { headers });
    checks.push([
      "GET /v1/resources/{id} echoes the scopes",
      fetched.status === 200 && JSON.stringify((fetched.body as { scopes?: unknown })?.scopes).includes("tools:read"),
    ]);

    // --- the resource's scope set gates authorize before the page opens ---------------------------
    const denied = await authorize("denied");
    const refused = await call(denied.url, { redirect: "manual" });
    const refusedParams = new URL(refused.headers.get("location") ?? "", base).searchParams;
    checks.push([
      "a scope the resource does not define is invalid_scope",
      refused.status === 302 &&
        refusedParams.get("error") === "invalid_scope" &&
        refusedParams.get("state") === `st-denied-${runId}`,
    ]);

    const patched = await call(`${base}/v1/resources/${resourceId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ scopes: ["tools:read", "tools:write"] }),
    });
    checks.push([
      "PATCH adds the scope",
      patched.status === 200 && JSON.stringify((patched.body as { scopes?: unknown })?.scopes).includes("tools:write"),
    ]);

    // --- the same request now signs in and the token carries the resource as aud ------------------
    const allowed = await authorize("allowed");
    const started = await call(allowed.url, { redirect: "manual" });
    const interaction = new URL(started.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (started.status !== 302 || interaction === null) {
      return fail(`authorize(allowed) → ${started.status} ${text(started.body)}`);
    }

    const signIn = await call(`${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: email, password }),
    });
    const redirectTo = (signIn.body as { redirect_to?: unknown })?.redirect_to;
    if (signIn.status !== 200 || typeof redirectTo !== "string") {
      return fail(`sign-in → ${signIn.status} ${text(signIn.body)}`);
    }

    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    const token = await tokenCall(base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: allowed.verifier,
    });
    const claims = jwtClaims((token.body as { access_token?: unknown })?.access_token);
    checks.push([
      "the access token carries the resource as aud and the granted scope",
      token.status === 200 &&
        claims !== undefined &&
        claims.aud === identifier &&
        Array.isArray(claims.scope) &&
        (claims.scope as string[]).includes("tools:write"),
    ]);

    // --- deletion ------------------------------------------------------------------------------
    const removed = await call(`${base}/v1/resources/${resourceId}`, { method: "DELETE", headers });
    checks.push(["DELETE /v1/resources/{id} is 204", removed.status === 204]);

    const missing = await call(`${base}/v1/resources/${resourceId}`, { headers });
    checks.push(["a deleted resource is 404", missing.status === 404]);

    const deleteMissing = await call(`${base}/v1/resources/${resourceId}`, { method: "DELETE", headers });
    checks.push(["deleting it again is 404", deleteMissing.status === 404]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "25",
    title: "api resources",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: create → duplicate 409 → relative 400 → list/get → invalid_scope → patch → sign-in → aud → delete → 404`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 26 — organizations (§5.5, §6.2).
 *
 * Creating an org runs the §5.5 provisioning transaction; archiving is the reversible substitute
 * for deleting it, so the slug must stop resolving for `authorize` and for the org's own
 * sub-resources while the row stays addressable by its typed id.
 */
async function organizationFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const slug = `team-${runId}`;
  const redirectUri = "http://localhost:5173/bff/callback";
  const headers = managementHeaders(adminToken);
  const email = `org-${runId}@demo.localhost`;
  const password = `pw-${runId}-org`;
  const clientId = `e2e-org-${runId}`;
  const stateValue = `st-org-${runId}`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "26",
    title: "organizations",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** An authorize URL naming the org, with a PKCE challenge. */
  const authorizeUrl = async (): Promise<string> => {
    const verifier = `o-${runId}-${"z".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    return `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: "openid",
      state: stateValue,
      nonce: `n-org-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: slug,
    })}`;
  };

  try {
    // --- provisioning ---------------------------------------------------------------------------
    const created = await call(`${base}/v1/orgs`, {
      method: "POST",
      headers,
      body: JSON.stringify({ slug }),
    });
    const orgId = (created.body as { id?: unknown })?.id;
    checks.push([
      "POST /v1/orgs provisions an org",
      created.status === 201 &&
        typeof orgId === "string" &&
        orgId.startsWith("org_") &&
        (created.body as { slug?: unknown })?.slug === slug &&
        (created.body as { state?: unknown })?.state === "active",
    ]);
    if (typeof orgId !== "string") return fail("the org carried no id");

    const duplicate = await call(`${base}/v1/orgs`, {
      method: "POST",
      headers,
      body: JSON.stringify({ slug }),
    });
    checks.push([
      "a duplicate slug is 409 MONACA_ORG_EXISTS",
      duplicate.status === 409 &&
        (duplicate.body as { monaca_error_code?: unknown })?.monaca_error_code === "MONACA_ORG_EXISTS",
    ]);

    const invalid = await call(`${base}/v1/orgs`, {
      method: "POST",
      headers,
      body: JSON.stringify({ slug: `Bad_${runId}` }),
    });
    checks.push(["an invalid slug is 400", invalid.status === 400]);

    // --- listing and both address forms ----------------------------------------------------------
    const listed = await call(`${base}/v1/orgs`, { headers });
    const items = (listed.body as { items?: { slug?: unknown; state?: unknown }[] })?.items;
    checks.push([
      "GET /v1/orgs lists it with its state",
      listed.status === 200 &&
        Array.isArray(items) &&
        items.some((item) => item.slug === slug && item.state === "active"),
    ]);

    const bySlug = await call(`${base}/v1/orgs/${slug}`, { headers });
    checks.push([
      "GET /v1/orgs/{slug} reports the active org",
      bySlug.status === 200 &&
        (bySlug.body as { id?: unknown })?.id === orgId &&
        (bySlug.body as { state?: unknown })?.state === "active",
    ]);

    const byId = await call(`${base}/v1/orgs/${orgId}`, { headers });
    checks.push([
      "GET /v1/orgs/{id} resolves the typed id",
      byId.status === 200 && (byId.body as { slug?: unknown })?.slug === slug,
    ]);

    // --- the new org is a real membership scope --------------------------------------------------
    const account = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Org holder", password }),
    });
    const accountId = (account.body as { id?: unknown })?.id;
    if (account.status !== 201 || typeof accountId !== "string") {
      return fail(`POST /v1/accounts → ${account.status} ${text(account.body)}`);
    }
    const added = await call(`${base}/v1/orgs/${slug}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    checks.push([
      "a member can join the new org",
      added.status === 201 && (added.body as { org?: unknown })?.org === orgId,
    ]);

    const members = await call(`${base}/v1/orgs/${slug}/members`, { headers });
    checks.push([
      "the new org lists its member",
      members.status === 200 && JSON.stringify(members.body).includes(email),
    ]);

    const client = await call(`${base}/v1/clients`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        client_id: clientId,
        name: "E2E Org App",
        kind: "public",
        redirect_uris: [redirectUri],
        scopes: ["openid"],
      }),
    });
    if (client.status !== 201) {
      return fail(`POST /v1/clients → ${client.status} ${text(client.body)}`);
    }

    // --- archiving hides the org from every operational lookup -----------------------------------
    const archived = await call(`${base}/v1/orgs/${slug}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ state: "archived" }),
    });
    checks.push([
      "PATCH archives it",
      archived.status === 200 && (archived.body as { state?: unknown })?.state === "archived",
    ]);

    const refused = await call(await authorizeUrl(), { redirect: "manual" });
    const refusedParams = new URL(refused.headers.get("location") ?? "", base).searchParams;
    checks.push([
      "authorize naming the archived org is invalid_request",
      refused.status === 302 &&
        refusedParams.get("error") === "invalid_request" &&
        refusedParams.get("state") === stateValue,
    ]);

    const membersGone = await call(`${base}/v1/orgs/${slug}/members`, { headers });
    checks.push(["its member list is 404 while archived", membersGone.status === 404]);

    const byIdArchived = await call(`${base}/v1/orgs/${orgId}`, { headers });
    checks.push([
      "GET by id still reports the archived org",
      byIdArchived.status === 200 && (byIdArchived.body as { state?: unknown })?.state === "archived",
    ]);

    // --- reactivating restores both -----------------------------------------------------------------
    const restored = await call(`${base}/v1/orgs/${orgId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ state: "active" }),
    });
    checks.push([
      "PATCH by id reactivates it",
      restored.status === 200 && (restored.body as { state?: unknown })?.state === "active",
    ]);

    const membersBack = await call(`${base}/v1/orgs/${slug}/members`, { headers });
    checks.push([
      "the member list works again",
      membersBack.status === 200 && JSON.stringify(membersBack.body).includes(email),
    ]);

    const authorizeBack = await call(await authorizeUrl(), { redirect: "manual" });
    const interaction = new URL(authorizeBack.headers.get("location") ?? "", base).searchParams.get("interaction");
    checks.push([
      "authorize opens the page again rather than refusing",
      authorizeBack.status === 302 && interaction !== null,
    ]);

    const badState = await call(`${base}/v1/orgs/${slug}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ state: "deleted" }),
    });
    checks.push(["an invalid state is 400", badState.status === 400]);

    const defaultOrg = await call(`${base}/v1/orgs/${ORG}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ state: "archived" }),
    });
    checks.push(["the tenant's default org cannot be archived", defaultOrg.status === 400]);

    const missing = await call(`${base}/v1/orgs/no-such-${runId}`, { headers });
    checks.push(["an unknown org is 404", missing.status === 404]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "26",
    title: "organizations",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: create → duplicate 409 → invalid 400 → list/get → member → archive → invalid_request → 404 → reactivate → 400 → 404`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 27 — org membership (§6.2).
 *
 * Membership has a single role per account; step 26 adds one to a new org, and this step covers
 * the rest of its lifecycle: re-rolling, refusing an account that is not a member, and removing the
 * membership without deleting the account.
 */
async function orgMemberFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const email = `member-${runId}@demo.localhost`;
  const password = `pw-${runId}-member`;
  const outsiderEmail = `outsider-${runId}@demo.localhost`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "27",
    title: "org members",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  try {
    // --- two accounts: one joins the org, the other must be refused ---------------------------------
    const member = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Org member", password }),
    });
    const memberId = (member.body as { id?: unknown })?.id;
    if (member.status !== 201 || typeof memberId !== "string") {
      return fail(`POST /v1/accounts → ${member.status} ${text(member.body)}`);
    }
    const outsider = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: outsiderEmail, display_name: "Org outsider", password }),
    });
    const outsiderId = (outsider.body as { id?: unknown })?.id;
    if (outsider.status !== 201 || typeof outsiderId !== "string") {
      return fail(`POST /v1/accounts (outsider) → ${outsider.status} ${text(outsider.body)}`);
    }

    const added = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: memberId, role: "member" }),
    });
    checks.push([
      "POST adds the member with role=member",
      added.status === 201 && (added.body as { role?: unknown })?.role === "member",
    ]);

    // --- re-roling -----------------------------------------------------------------------------------
    const promoted = await call(`${base}/v1/orgs/${ORG}/members/${memberId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ role: "admin" }),
    });
    checks.push([
      "PATCH re-roles it to admin",
      promoted.status === 200 && (promoted.body as { role?: unknown })?.role === "admin",
    ]);

    const listed = await call(`${base}/v1/orgs/${ORG}/members`, { headers });
    const items = (listed.body as { items?: { account_id?: unknown; role?: unknown }[] })?.items;
    checks.push([
      "GET lists the new role",
      listed.status === 200 &&
        Array.isArray(items) &&
        items.some((item) => item.account_id === memberId && item.role === "admin"),
    ]);

    const repeated = await call(`${base}/v1/orgs/${ORG}/members/${memberId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ role: "admin" }),
    });
    checks.push(["repeating the current role is still 200", repeated.status === 200]);

    const badRole = await call(`${base}/v1/orgs/${ORG}/members/${memberId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ role: "superuser" }),
    });
    checks.push(["an invalid role is 400", badRole.status === 400]);

    const notMember = await call(`${base}/v1/orgs/${ORG}/members/${outsiderId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ role: "member" }),
    });
    checks.push(["an account that is not a member is 404", notMember.status === 404]);

    // --- removal keeps the account ---------------------------------------------------------------------
    const removed = await call(`${base}/v1/orgs/${ORG}/members/${memberId}`, {
      method: "DELETE",
      headers,
    });
    checks.push(["DELETE the membership is 204", removed.status === 204]);

    const after = await call(`${base}/v1/orgs/${ORG}/members`, { headers });
    checks.push([
      "the membership is gone from the member list",
      after.status === 200 && !JSON.stringify(after.body).includes(email),
    ]);

    const accountStill = await call(`${base}/v1/accounts/${memberId}`, { headers });
    checks.push(["the account itself survives", accountStill.status === 200]);

    const removedAgain = await call(`${base}/v1/orgs/${ORG}/members/${memberId}`, {
      method: "DELETE",
      headers,
    });
    checks.push(["deleting it again is 404", removedAgain.status === 404]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "27",
    title: "org members",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: add → re-role → list → repeat → invalid 400 → outsider 404 → remove 204 → gone → account survives → 404`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 28 — organization email domains and just-in-time membership (§6.2).
 *
 * A domain registered to an org admits its own accounts: signing in to an authorize that names the
 * org joins the account as a `member` instead of answering 403, while an account from another
 * domain keeps the ordinary refusal.
 */
async function orgDomainFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const slug = `jit-${runId}`;
  const domain = `jit-${runId}.example.com`;
  const redirectUri = "http://localhost:5173/bff/callback";
  const headers = managementHeaders(adminToken);
  const clientId = `e2e-jit-${runId}`;
  const email = `user@${domain}`;
  const password = `pw-${runId}-jit`;
  const outsiderEmail = `jit-outsider-${runId}@demo.localhost`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "28",
    title: "org email domains",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** An authorize URL naming the org, with a PKCE challenge. */
  const authorize = async (tag: string): Promise<{ url: string; verifier: string }> => {
    const verifier = `d-${tag}-${runId}-${"z".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: "openid",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: slug,
    })}`;
    return { url, verifier };
  };

  try {
    const created = await call(`${base}/v1/orgs`, {
      method: "POST",
      headers,
      body: JSON.stringify({ slug }),
    });
    const orgId = (created.body as { id?: unknown })?.id;
    if (created.status !== 201 || typeof orgId !== "string") {
      return fail(`POST /v1/orgs → ${created.status} ${text(created.body)}`);
    }

    const registered = await call(`${base}/v1/orgs/${slug}/email-domains`, {
      method: "POST",
      headers,
      body: JSON.stringify({ domain: ` JIT-${runId}.Example.COM ` }),
    });
    checks.push([
      "POST registers the domain lowercased",
      registered.status === 201 && (registered.body as { domain?: unknown })?.domain === domain,
    ]);

    const duplicate = await call(`${base}/v1/orgs/${slug}/email-domains`, {
      method: "POST",
      headers,
      body: JSON.stringify({ domain }),
    });
    checks.push([
      "a duplicate domain is 409 MONACA_DOMAIN_EXISTS",
      duplicate.status === 409 &&
        (duplicate.body as { monaca_error_code?: unknown })?.monaca_error_code === "MONACA_DOMAIN_EXISTS",
    ]);

    const invalid = await call(`${base}/v1/orgs/${slug}/email-domains`, {
      method: "POST",
      headers,
      body: JSON.stringify({ domain: "not a domain" }),
    });
    checks.push(["an invalid domain is 400", invalid.status === 400]);

    const listed = await call(`${base}/v1/orgs/${slug}/email-domains`, { headers });
    checks.push([
      "GET lists the domain",
      listed.status === 200 && JSON.stringify(listed.body).includes(domain),
    ]);

    // --- a client and an account at that domain -----------------------------------------------
    const client = await call(`${base}/v1/clients`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        client_id: clientId,
        name: "E2E JIT App",
        kind: "public",
        redirect_uris: [redirectUri],
        scopes: ["openid"],
      }),
    });
    if (client.status !== 201) {
      return fail(`POST /v1/clients → ${client.status} ${text(client.body)}`);
    }

    const account = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Domain user", password }),
    });
    if (account.status !== 201) {
      return fail(`POST /v1/accounts → ${account.status} ${text(account.body)}`);
    }

    // --- the domain-matched account joins on sign-in -------------------------------------------
    const join = await authorize("join");
    const started = await call(join.url, { redirect: "manual" });
    const interaction = new URL(started.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (started.status !== 302 || interaction === null) {
      return fail(`authorize(join) → ${started.status} ${text(started.body)}`);
    }

    const signIn = await call(
      `${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identifier: email, password }),
      },
    );
    const redirectTo = (signIn.body as { redirect_to?: unknown })?.redirect_to;
    checks.push([
      "the domain-matched account signs in instead of being refused",
      signIn.status === 200 && typeof redirectTo === "string",
    ]);
    if (signIn.status !== 200 || typeof redirectTo !== "string") {
      return fail(`sign-in (JIT) → ${signIn.status} ${text(signIn.body)}`);
    }

    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    const token = await tokenCall(base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: join.verifier,
    });
    const claims = jwtClaims((token.body as { access_token?: unknown })?.access_token);
    checks.push([
      "the just-in-time token carries the org",
      token.status === 200 && claims !== undefined && claims.org === orgId,
    ]);

    const members = await call(`${base}/v1/orgs/${slug}/members`, { headers });
    checks.push([
      "the JIT membership is listed",
      members.status === 200 && JSON.stringify(members.body).includes(email),
    ]);

    // --- an account from another domain keeps the refusal ---------------------------------------
    const outsider = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: outsiderEmail, display_name: "Other domain", password }),
    });
    if (outsider.status !== 201) {
      return fail(`POST /v1/accounts (outsider) → ${outsider.status} ${text(outsider.body)}`);
    }
    const denied = await authorize("denied");
    const deniedStart = await call(denied.url, { redirect: "manual" });
    const deniedInteraction = new URL(deniedStart.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (deniedStart.status !== 302 || deniedInteraction === null) {
      return fail(`authorize(denied) → ${deniedStart.status} ${text(deniedStart.body)}`);
    }
    const deniedSignIn = await call(
      `${base}/t/${TENANT}/interaction/${encodeURIComponent(deniedInteraction)}/sign-in`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identifier: outsiderEmail, password }),
      },
    );
    checks.push([
      "an account from another domain is refused",
      deniedSignIn.status === 403 &&
        (deniedSignIn.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_INSUFFICIENT_SCOPE",
    ]);

    // --- removal stops future joins ---------------------------------------------------------------
    const removed = await call(`${base}/v1/orgs/${slug}/email-domains/${domain}`, {
      method: "DELETE",
      headers,
    });
    checks.push(["DELETE the domain is 204", removed.status === 204]);

    const after = await call(`${base}/v1/orgs/${slug}/email-domains`, { headers });
    const items = (after.body as { items?: unknown[] })?.items;
    checks.push([
      "the domain list is empty",
      after.status === 200 && Array.isArray(items) && items.length === 0,
    ]);

    const removedAgain = await call(`${base}/v1/orgs/${slug}/email-domains/${domain}`, {
      method: "DELETE",
      headers,
    });
    checks.push(["deleting it again is 404", removedAgain.status === 404]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "28",
    title: "org email domains",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: register → duplicate 409 → invalid 400 → list → JIT sign-in → token org → member → outsider 403 → remove 204 → empty → 404`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 29 — organization roles (§5.7, §6.2).
 *
 * An org role is a named scope set defined inside the org. Assigning one to a member lets that
 * member's sign-in request the role's scopes for that org only; the id_token lists the role and
 * the access token carries the scope. The membership rank is separate and grants nothing.
 */
async function orgRoleFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const slug = `roles-${runId}`;
  const roleName = `support-${runId}`;
  const redirectUri = "http://localhost:5173/bff/callback";
  const headers = managementHeaders(adminToken);
  const clientId = `e2e-roles-${runId}`;
  const email = `roles-${runId}@demo.localhost`;
  const password = `pw-${runId}-roles`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "29",
    title: "org roles",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** An authorize URL asking for `openid tools:read`, with a PKCE challenge. */
  const authorize = async (tag: string): Promise<{ url: string; verifier: string }> => {
    const verifier = `r-${tag}-${runId}-${"z".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: "openid tools:read",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: slug,
    })}`;
    return { url, verifier };
  };

  try {
    // --- the org, its member and an app that may ask for tools:read ------------------------------
    const created = await call(`${base}/v1/orgs`, {
      method: "POST",
      headers,
      body: JSON.stringify({ slug }),
    });
    const orgId = (created.body as { id?: unknown })?.id;
    if (created.status !== 201 || typeof orgId !== "string") {
      return fail(`POST /v1/orgs → ${created.status} ${text(created.body)}`);
    }

    const account = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Org role holder", password }),
    });
    const accountId = (account.body as { id?: unknown })?.id;
    if (account.status !== 201 || typeof accountId !== "string") {
      return fail(`POST /v1/accounts → ${account.status} ${text(account.body)}`);
    }
    const added = await call(`${base}/v1/orgs/${slug}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    if (added.status !== 201) {
      return fail(`add member → ${added.status} ${text(added.body)}`);
    }

    const client = await call(`${base}/v1/clients`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        client_id: clientId,
        name: "E2E Org Roles App",
        kind: "public",
        redirect_uris: [redirectUri],
        scopes: ["openid", "tools:read"],
      }),
    });
    if (client.status !== 201) {
      return fail(`POST /v1/clients → ${client.status} ${text(client.body)}`);
    }

    // --- the membership alone grants nothing: the same request is refused ------------------------
    const denied = await authorize("denied");
    const deniedStart = await call(denied.url, { redirect: "manual" });
    const deniedInteraction = new URL(deniedStart.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (deniedStart.status !== 302 || deniedInteraction === null) {
      return fail(`authorize(denied) → ${deniedStart.status} ${text(deniedStart.body)}`);
    }
    const deniedSignIn = await call(
      `${base}/t/${TENANT}/interaction/${encodeURIComponent(deniedInteraction)}/sign-in`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identifier: email, password }),
      },
    );
    checks.push([
      "a member without a role is refused tools:read",
      deniedSignIn.status === 403 &&
        (deniedSignIn.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_INSUFFICIENT_SCOPE",
    ]);

    // --- the role catalog ------------------------------------------------------------------------
    const role = await call(`${base}/v1/orgs/${slug}/roles`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: roleName, description: "", scopes: ["tools:read"] }),
    });
    const roleId = (role.body as { id?: unknown })?.id;
    checks.push([
      "POST /v1/orgs/{org}/roles defines the role",
      role.status === 201 &&
        typeof roleId === "string" &&
        roleId.startsWith("rol_") &&
        (role.body as { name?: unknown })?.name === roleName,
    ]);
    if (typeof roleId !== "string") return fail("the role carried no id");

    const duplicate = await call(`${base}/v1/orgs/${slug}/roles`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: roleName, scopes: ["tools:read"] }),
    });
    checks.push([
      "a duplicate role name is 409 MONACA_ORG_ROLE_EXISTS",
      duplicate.status === 409 &&
        (duplicate.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_ORG_ROLE_EXISTS",
    ]);

    const badScope = await call(`${base}/v1/orgs/${slug}/roles`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: `bad-${runId}`, scopes: ["Tools Read"] }),
    });
    checks.push(["an invalid scope is 400", badScope.status === 400]);

    const listed = await call(`${base}/v1/orgs/${slug}/roles`, { headers });
    checks.push([
      "GET lists the role with its scopes",
      listed.status === 200 && JSON.stringify(listed.body).includes(roleName),
    ]);

    const patched = await call(`${base}/v1/orgs/${slug}/roles/${roleId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ description: "Read-only support" }),
    });
    checks.push([
      "PATCH updates the description",
      patched.status === 200 &&
        (patched.body as { description?: unknown })?.description === "Read-only support",
    ]);

    // --- assignment ------------------------------------------------------------------------------
    const assigned = await call(`${base}/v1/orgs/${slug}/members/${accountId}/roles`, {
      method: "POST",
      headers,
      body: JSON.stringify({ role_id: roleId }),
    });
    checks.push(["assigning the role is 204", assigned.status === 204]);

    const memberRoles = await call(`${base}/v1/orgs/${slug}/members/${accountId}/roles`, { headers });
    checks.push([
      "GET member roles lists it",
      memberRoles.status === 200 && JSON.stringify(memberRoles.body).includes(roleName),
    ]);

    // --- the assigned role now grants the scope for this org --------------------------------------
    const allowed = await authorize("allowed");
    const started = await call(allowed.url, { redirect: "manual" });
    const interaction = new URL(started.headers.get("location") ?? "", base).searchParams.get("interaction");
    if (started.status !== 302 || interaction === null) {
      return fail(`authorize(allowed) → ${started.status} ${text(started.body)}`);
    }
    const signIn = await call(
      `${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identifier: email, password }),
      },
    );
    const redirectTo = (signIn.body as { redirect_to?: unknown })?.redirect_to;
    if (signIn.status !== 200 || typeof redirectTo !== "string") {
      return fail(`sign-in (role) → ${signIn.status} ${text(signIn.body)}`);
    }
    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    const token = await tokenCall(base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: allowed.verifier,
    });
    const accessClaims = jwtClaims((token.body as { access_token?: unknown })?.access_token);
    checks.push([
      "the access token carries the scope the org role granted",
      token.status === 200 &&
        accessClaims !== undefined &&
        accessClaims.org === orgId &&
        Array.isArray(accessClaims.scope) &&
        (accessClaims.scope as string[]).includes("tools:read"),
    ]);
    const idClaims = jwtClaims((token.body as { id_token?: unknown })?.id_token);
    checks.push([
      "the id_token carries org_roles",
      idClaims !== undefined &&
        Array.isArray(idClaims.org_roles) &&
        (idClaims.org_roles as string[]).includes(roleName),
    ]);

    // --- unassign and delete ---------------------------------------------------------------------
    const unassigned = await call(`${base}/v1/orgs/${slug}/members/${accountId}/roles/${roleId}`, {
      method: "DELETE",
      headers,
    });
    checks.push(["unassigning the role is 204", unassigned.status === 204]);

    const afterUnassign = await call(`${base}/v1/orgs/${slug}/members/${accountId}/roles`, { headers });
    checks.push([
      "the member role list is empty",
      afterUnassign.status === 200 && !JSON.stringify(afterUnassign.body).includes(roleName),
    ]);

    const unassignAgain = await call(`${base}/v1/orgs/${slug}/members/${accountId}/roles/${roleId}`, {
      method: "DELETE",
      headers,
    });
    checks.push(["unassigning it again is 404", unassignAgain.status === 404]);

    const removed = await call(`${base}/v1/orgs/${slug}/roles/${roleId}`, {
      method: "DELETE",
      headers,
    });
    checks.push(["DELETE the role is 204", removed.status === 204]);

    const rolesAfter = await call(`${base}/v1/orgs/${slug}/roles`, { headers });
    checks.push([
      "the role list no longer has it",
      rolesAfter.status === 200 && !JSON.stringify(rolesAfter.body).includes(roleName),
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "29",
    title: "org roles",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: define → duplicate 409 → invalid scope 400 → list → patch → assign → member roles → denied 403 → sign-in → scope → org_roles → unassign → 404 → delete`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 30 — organization invitations accepted at sign-in (§6.2).
 *
 * An invitation names one address and a role; there is no bearer token, so the invited account
 * joins by signing in to the org. A revoked invitation stops admitting that address immediately.
 */
async function orgInvitationFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const slug = `inv-${runId}`;
  const redirectUri = "http://localhost:5173/bff/callback";
  const headers = managementHeaders(adminToken);
  const clientId = `e2e-inv-${runId}`;
  const inviteeEmail = `invitee-${runId}@demo.localhost`;
  const revokedEmail = `revoked-${runId}@demo.localhost`;
  const password = `pw-${runId}-inv`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "30",
    title: "org invitations",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** An authorize URL naming the org, with a PKCE challenge. */
  const authorize = async (tag: string): Promise<{ url: string; verifier: string }> => {
    const verifier = `d-${tag}-${runId}-${"z".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: "openid",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: slug,
    })}`;
    return { url, verifier };
  };

  /** Opens an interaction for `email` and returns the sign-in response with its PKCE verifier. */
  const signIn = async (
    tag: string,
    email: string,
  ): Promise<{ status: number; body: unknown; verifier: string }> => {
    const request = await authorize(tag);
    const started = await call(request.url, { redirect: "manual" });
    const interaction = new URL(started.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    if (started.status !== 302 || interaction === null) {
      throw new Error(`authorize(${tag}) → ${started.status} ${text(started.body)}`);
    }
    const response = await call(
      `${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identifier: email, password }),
      },
    );
    return { ...response, verifier: request.verifier };
  };

  try {
    const created = await call(`${base}/v1/orgs`, {
      method: "POST",
      headers,
      body: JSON.stringify({ slug }),
    });
    const orgId = (created.body as { id?: unknown })?.id;
    if (created.status !== 201 || typeof orgId !== "string") {
      return fail(`POST /v1/orgs → ${created.status} ${text(created.body)}`);
    }

    const client = await call(`${base}/v1/clients`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        client_id: clientId,
        name: "E2E Invitation App",
        kind: "public",
        redirect_uris: [redirectUri],
        scopes: ["openid"],
      }),
    });
    if (client.status !== 201) {
      return fail(`POST /v1/clients → ${client.status} ${text(client.body)}`);
    }

    for (const email of [inviteeEmail, revokedEmail]) {
      const account = await call(`${base}/v1/accounts`, {
        method: "POST",
        headers,
        body: JSON.stringify({ email, display_name: "Invitee", password }),
      });
      if (account.status !== 201) {
        return fail(`POST /v1/accounts (${email}) → ${account.status} ${text(account.body)}`);
      }
    }

    // --- creating, validating and listing an invitation ----------------------------------------
    const invited = await call(`${base}/v1/orgs/${slug}/invitations`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: ` ${inviteeEmail.toUpperCase()} `, role: "admin", expires_in_days: 3 }),
    });
    const invitation = invited.body as { id?: unknown; email?: unknown; role?: unknown };
    checks.push([
      "POST returns the invitation lowercased and in the typed form",
      invited.status === 201 &&
        invitation.email === inviteeEmail &&
        invitation.role === "admin" &&
        typeof invitation.id === "string" &&
        invitation.id.startsWith("inv_"),
    ]);
    if (invited.status !== 201 || typeof invitation.id !== "string") {
      return fail(`POST /v1/orgs/${slug}/invitations → ${invited.status} ${text(invited.body)}`);
    }

    const duplicate = await call(`${base}/v1/orgs/${slug}/invitations`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: inviteeEmail }),
    });
    checks.push([
      "a live invitation for the same address is 409 MONACA_INVITATION_EXISTS",
      duplicate.status === 409 &&
        (duplicate.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_INVITATION_EXISTS",
    ]);

    const invalid = await call(`${base}/v1/orgs/${slug}/invitations`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: "not-an-email" }),
    });
    checks.push(["an invalid address is 400", invalid.status === 400]);

    const listed = await call(`${base}/v1/orgs/${slug}/invitations`, { headers });
    checks.push([
      "GET lists the pending invitation",
      listed.status === 200 && JSON.stringify(listed.body).includes(inviteeEmail),
    ]);

    // --- the invited account joins on sign-in with the invited role -----------------------------
    const joined = await signIn("join", inviteeEmail);
    const redirectTo = (joined.body as { redirect_to?: unknown })?.redirect_to;
    checks.push([
      "the invited account signs in",
      joined.status === 200 && typeof redirectTo === "string",
    ]);
    if (joined.status !== 200 || typeof redirectTo !== "string") {
      return fail(`sign-in (invited) → ${joined.status} ${text(joined.body)}`);
    }

    const verifier = joined.verifier;
    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    const token = await tokenCall(base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: verifier,
    });
    const claims = jwtClaims((token.body as { access_token?: unknown })?.access_token);
    checks.push([
      "the accepted invitation's token carries the org",
      token.status === 200 && claims !== undefined && claims.org === orgId,
    ]);

    const members = await call(`${base}/v1/orgs/${slug}/members`, { headers });
    const items = (members.body as { items?: { email?: string; role?: string }[] })?.items;
    const joinedMember = Array.isArray(items)
      ? items.find((item) => item.email === inviteeEmail)
      : undefined;
    checks.push([
      "the join uses the invited role, not the default",
      members.status === 200 && joinedMember?.role === "admin",
    ]);

    const afterAccept = await call(`${base}/v1/orgs/${slug}/invitations`, { headers });
    checks.push([
      "accepted invitations are no longer listed",
      afterAccept.status === 200 && !JSON.stringify(afterAccept.body).includes(inviteeEmail),
    ]);

    // --- a revoked invitation stops admitting its address ---------------------------------------
    const pending = await call(`${base}/v1/orgs/${slug}/invitations`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: revokedEmail }),
    });
    const pendingId = (pending.body as { id?: unknown })?.id;
    if (pending.status !== 201 || typeof pendingId !== "string") {
      return fail(`POST /v1/orgs/${slug}/invitations (revoked) → ${pending.status} ${text(pending.body)}`);
    }

    const revoked = await call(`${base}/v1/orgs/${slug}/invitations/${pendingId}`, {
      method: "DELETE",
      headers,
    });
    checks.push(["DELETE the invitation is 204", revoked.status === 204]);

    const afterRevoke = await call(`${base}/v1/orgs/${slug}/invitations`, { headers });
    checks.push([
      "the revoked invitation is no longer listed",
      afterRevoke.status === 200 && !JSON.stringify(afterRevoke.body).includes(revokedEmail),
    ]);

    const revokedAgain = await call(`${base}/v1/orgs/${slug}/invitations/${pendingId}`, {
      method: "DELETE",
      headers,
    });
    checks.push(["revoking it again is 404", revokedAgain.status === 404]);

    const refused = await signIn("revoked", revokedEmail);
    checks.push([
      "a revoked invitation is refused",
      refused.status === 403 &&
        (refused.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_INSUFFICIENT_SCOPE",
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "30",
    title: "org invitations",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: invite → duplicate 409 → invalid 400 → list → sign-in → token org → admin role → hidden → revoke 204 → hidden → 404 → refused`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 31 — enterprise SSO (OIDC federation) (§6.1).
 *
 * A tenant-level connector owns an email domain; the sign-in page routes that address to the
 * provider, and the callback asserts it. The provider itself is the same single-account mock the
 * social step uses, so the round-trip is a real authorization code exchange.
 */
async function ssoFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const slug = `sso-${runId}`;
  const redirectUri = "http://localhost:5173/bff/callback";
  const headers = managementHeaders(adminToken);
  const clientId = `e2e-sso-${runId}`;
  const connectorId = `okta-${runId}`;
  const mismatchConnectorId = `other-${runId}`;
  const domain = `sso-${runId}.example.com`;
  const ownedDomain = `owned-${runId}.example.com`;
  const email = `user@${domain}`;
  const intruderEmail = `intruder@${domain}`;
  const checks: [string, boolean][] = [];
  let detail = "";
  const provider = startMockProvider();

  const fail = (why: string): StepResult => ({
    step: "31",
    title: "enterprise SSO",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** An authorize URL naming the org, with a PKCE challenge. */
  const authorize = async (tag: string): Promise<{ url: string; verifier: string }> => {
    const verifier = `d-${tag}-${runId}-${"z".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const url = `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: "openid",
      state: `st-${tag}-${runId}`,
      nonce: `n-${tag}-${runId}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: slug,
    })}`;
    return { url, verifier };
  };

  /** Open an interaction, then run the connector round-trip and return its final response. */
  const roundTrip = async (
    tag: string,
    connector: string,
  ): Promise<{ status: number; body: unknown; location: string | null; verifier: string }> => {
    const request = await authorize(tag);
    const started = await call(request.url, { redirect: "manual" });
    const interaction = new URL(started.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    if (started.status !== 302 || interaction === null) {
      throw new Error(`authorize(${tag}) → ${started.status} ${text(started.body)}`);
    }
    const ssoStart = await call(
      `${base}/t/${TENANT}/sso/${connector}/authorize?interaction=${encodeURIComponent(interaction)}`,
      { redirect: "manual" },
    );
    if (ssoStart.status !== 302) {
      throw new Error(`sso authorize(${connector}) → ${ssoStart.status} ${text(ssoStart.body)}`);
    }
    const atProvider = await call(new URL(ssoStart.headers.get("location") ?? "", base).toString(), {
      redirect: "manual",
    });
    if (atProvider.status !== 302) {
      throw new Error(`provider authorize → ${atProvider.status} ${text(atProvider.body)}`);
    }
    const callback = await call(atProvider.headers.get("location") ?? "", { redirect: "manual" });
    return {
      status: callback.status,
      body: callback.body,
      location: callback.headers.get("location"),
      verifier: request.verifier,
    };
  };

  try {
    const created = await call(`${base}/v1/orgs`, {
      method: "POST",
      headers,
      body: JSON.stringify({ slug }),
    });
    const orgId = (created.body as { id?: unknown })?.id;
    if (created.status !== 201 || typeof orgId !== "string") {
      return fail(`POST /v1/orgs → ${created.status} ${text(created.body)}`);
    }

    const client = await call(`${base}/v1/clients`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        client_id: clientId,
        name: "E2E SSO App",
        kind: "public",
        redirect_uris: [redirectUri],
        scopes: ["openid"],
      }),
    });
    if (client.status !== 201) {
      return fail(`POST /v1/clients → ${client.status} ${text(client.body)}`);
    }

    // --- registering the connector -------------------------------------------------------------
    const body = {
      display_name: "Acme Okta",
      issuer: "https://acme.okta.example",
      authorize_url: `${provider.url}/authorize?sub=sub-${runId}&email=${encodeURIComponent(email)}&verified=1&name=SSO+User`,
      token_url: `${provider.url}/token`,
      userinfo_url: `${provider.url}/userinfo`,
      client_id: "okta-client",
      client_secret: `secret-${runId}`,
      scopes: [],
      email_domains: [` ${domain.toUpperCase()} `],
    };
    const registered = await call(`${base}/v1/sso-connectors`, {
      method: "POST",
      headers,
      body: JSON.stringify({ connector_id: connectorId, ...body }),
    });
    const sso = registered.body as { email_domains?: unknown; client_secret?: unknown; scopes?: unknown };
    checks.push([
      "POST registers the connector with normalised domains and default scopes",
      registered.status === 201 &&
        Array.isArray(sso.email_domains) &&
        sso.email_domains.includes(domain) &&
        Array.isArray(sso.scopes) &&
        sso.scopes.join(" ") === "openid profile email" &&
        sso.client_secret === undefined,
    ]);

    const duplicate = await call(`${base}/v1/sso-connectors`, {
      method: "POST",
      headers,
      body: JSON.stringify({ connector_id: connectorId, ...body }),
    });
    checks.push([
      "a duplicate slug is 409 MONACA_SSO_CONNECTOR_EXISTS",
      duplicate.status === 409 &&
        (duplicate.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_SSO_CONNECTOR_EXISTS",
    ]);

    const claimed = await call(`${base}/v1/sso-connectors`, {
      method: "POST",
      headers,
      body: JSON.stringify({ connector_id: mismatchConnectorId, ...body }),
    });
    checks.push([
      "a domain another connector owns is 409 MONACA_SSO_DOMAIN_TAKEN",
      claimed.status === 409 &&
        (claimed.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_SSO_DOMAIN_TAKEN",
    ]);

    const invalidDomain = await call(`${base}/v1/sso-connectors`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        connector_id: `bad-${runId}`,
        ...body,
        email_domains: ["not a domain"],
      }),
    });
    checks.push(["a malformed domain is 400", invalidDomain.status === 400]);

    const relative = await call(`${base}/v1/sso-connectors`, {
      method: "POST",
      headers,
      body: JSON.stringify({ connector_id: `bad-${runId}`, ...body, issuer: "not-a-url" }),
    });
    checks.push(["a relative issuer is 400", relative.status === 400]);

    // --- the public domain lookup --------------------------------------------------------------
    const lookup = await call(
      `${base}/t/${TENANT}/sso-connectors?email=${encodeURIComponent(` User@${domain.toUpperCase()} `)}`,
    );
    checks.push([
      "GET ?email finds the connector that owns the domain",
      lookup.status === 200 && JSON.stringify(lookup.body).includes(connectorId),
    ]);
    const unknown = await call(
      `${base}/t/${TENANT}/sso-connectors?email=${encodeURIComponent(`user@nobody-${runId}.example.com`)}`,
    );
    checks.push([
      "a domain no connector owns returns no connector",
      unknown.status === 200 && (unknown.body as { items?: unknown[] })?.items?.length === 0,
    ]);

    // --- the federated sign-in ----------------------------------------------------------------
    const finished = await roundTrip("sso", connectorId);
    const redirectTo = finished.location;
    checks.push([
      "the provider round-trip signs in",
      finished.status === 302 && typeof redirectTo === "string",
    ]);
    if (finished.status !== 302 || typeof redirectTo !== "string") {
      return fail(`sso round-trip → ${finished.status} ${text(finished.body)}`);
    }

    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    const verifier = finished.verifier;
    const token = await tokenCall(base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: verifier,
    });
    const claims = jwtClaims((token.body as { access_token?: unknown })?.access_token);
    checks.push([
      "the federated token carries the org",
      token.status === 200 && claims !== undefined && claims.org === orgId,
    ]);

    const members = await call(`${base}/v1/orgs/${slug}/members`, { headers });
    checks.push([
      "the first SSO sign-in created the account and joined the org",
      members.status === 200 && JSON.stringify(members.body).includes(email),
    ]);

    // --- an address outside the connector's domains is refused ----------------------------------
    const mismatch = await call(`${base}/v1/sso-connectors`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        connector_id: mismatchConnectorId,
        ...body,
        authorize_url: `${provider.url}/authorize?sub=mismatch-${runId}&email=${encodeURIComponent(intruderEmail)}&verified=1`,
        email_domains: [ownedDomain],
      }),
    });
    checks.push(["the second connector registers", mismatch.status === 201]);
    const refused = await roundTrip("mismatch", mismatchConnectorId);
    checks.push([
      "an asserted address outside the connector's domains is 403 MONACA_SSO_DOMAIN_MISMATCH",
      refused.status === 403 &&
        (refused.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_SSO_DOMAIN_MISMATCH",
    ]);

    // --- removal --------------------------------------------------------------------------------
    for (const connector of [connectorId, mismatchConnectorId]) {
      const removed = await call(`${base}/v1/sso-connectors/${connector}`, {
        method: "DELETE",
        headers,
      });
      checks.push([`DELETE ${connector} is 204`, removed.status === 204]);
    }
    const after = await call(
      `${base}/t/${TENANT}/sso-connectors?email=${encodeURIComponent(email)}`,
    );
    checks.push([
      "the removed connector no longer routes its domain",
      after.status === 200 && (after.body as { items?: unknown[] })?.items?.length === 0,
    ]);
    const removedAgain = await call(`${base}/v1/sso-connectors/${connectorId}`, {
      method: "DELETE",
      headers,
    });
    checks.push(["deleting it again is 404", removedAgain.status === 404]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    provider.stop();
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "31",
    title: "enterprise SSO",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: register → duplicate 409 → domain 409 → invalid 400 → lookup → SSO sign-in → token org → member → mismatch 403 → delete 204 → lookup empty → 404`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 32 — administrator account-security management (§6.2).
 *
 * An account enrolls TOTP through its own session; the administrator then reads the enrolled
 * factors, resets the authenticator, and the next sign-in is single-factor again. Passkeys are
 * separate credentials and are only removed one at a time.
 */
async function accountSecurityFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const email = `security-${runId}@demo.localhost`;
  const password = `pw-${runId}-security`;
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "32",
    title: "account security",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  const auth = (cookie: string): Record<string, string> => ({ cookie: `monaca_session=${cookie}` });

  /** A fresh authorize → interaction → password sign-in; the response carries the SSO cookie. */
  const signIn = async (
    tag: string,
  ): Promise<{ status: number; body: unknown; cookie?: string } | undefined> => {
    const verifier = `s-${tag}-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const started = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: "monaca-console",
        redirect_uri: redirectUri,
        scope: "openid profile email",
        state: `st-${tag}-${runId}`,
        nonce: `n-${tag}-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(started.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    if (started.status !== 302 || interaction === null) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(
      response.headers.get("set-cookie") ?? "",
    )?.[1];
    return { status: response.status, body: response.body, cookie };
  };

  try {
    const account = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Security", password }),
    });
    const accountId = (account.body as { id?: string })?.id;
    if (account.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${account.status} ${text(account.body)}`);
    }
    const member = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    checks.push(["the run's account joined acme", member.status === 201]);

    // --- enroll TOTP through the account's own session ----------------------------------------
    const first = await signIn("enroll");
    if (first?.cookie === undefined) return fail("the first sign-in did not set a session cookie");
    const enrollment = await call(`${base}/t/${TENANT}/account/mfa/totp`, {
      method: "POST",
      headers: auth(first.cookie),
    });
    const secret = (enrollment.body as { secret?: unknown })?.secret;
    if (enrollment.status !== 200 || typeof secret !== "string") {
      return fail(`POST /account/mfa/totp → ${enrollment.status} ${text(enrollment.body)}`);
    }
    const confirmed = await call(`${base}/t/${TENANT}/account/mfa/totp/verify`, {
      method: "POST",
      headers: { ...auth(first.cookie), "content-type": "application/json" },
      body: JSON.stringify({ code: totpFromBase32(secret) }),
    });
    checks.push(["the account confirms its authenticator", confirmed.status === 200]);

    // --- the administrator reads the enrolled factors ------------------------------------------
    const security = await call(`${base}/v1/accounts/${accountId}/security`, { headers });
    const mfa = (security.body as { mfa?: { totp?: unknown; backup_codes?: unknown } })?.mfa;
    const passkeys = (security.body as { passkeys?: unknown[] })?.passkeys;
    checks.push([
      "GET security reports the authenticator and its metadata",
      security.status === 200 &&
        mfa?.totp === true &&
        mfa.backup_codes === 0 &&
        Array.isArray(passkeys) &&
        passkeys.length === 0,
    ]);

    // --- reset, and the next sign-in is single-factor again ------------------------------------
    const reset = await call(`${base}/v1/accounts/${accountId}/mfa`, {
      method: "DELETE",
      headers,
    });
    checks.push(["DELETE the account MFA is 204", reset.status === 204]);

    const after = await call(`${base}/v1/accounts/${accountId}/security`, { headers });
    checks.push([
      "the reset removed the authenticator",
      after.status === 200 && (after.body as { mfa?: { totp?: unknown } })?.mfa?.totp === false,
    ]);

    const second = await signIn("after-reset");
    checks.push([
      "a fresh sign-in no longer challenges for a second factor",
      second?.status === 200 && typeof (second.body as { redirect_to?: unknown })?.redirect_to === "string",
    ]);

    // --- the levers are scoped ----------------------------------------------------------------
    const missingPasskey = await call(
      `${base}/v1/accounts/${accountId}/passkeys/pky_01h455vb4pex5vsknk084sn02q`,
      { method: "DELETE", headers },
    );
    checks.push(["a passkey the account does not have is 404", missingPasskey.status === 404]);

    const unknownAccount = await call(
      `${base}/v1/accounts/acc_01h455vb4pex5vsknk084sn02q/security`,
      { headers },
    );
    checks.push(["an unknown account is 404", unknownAccount.status === 404]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "32",
    title: "account security",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: member → enroll → security read → reset 204 → no authenticator → sign-in single-factor → passkey 404 → unknown account 404`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 33 — a mandatory MFA policy and the enrollment it demands (§6.1 `mfa`).
 *
 * The tenant turns MFA on with the mandatory policy; an account with no factor is stopped on a
 * setup step, proves its new authenticator, finishes the sign-in, and is challenged normally the
 * next time. The policy is restored in `finally`, so a failure cannot change later runs.
 */
async function mandatoryMfaFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const email = `mandatory-${runId}@demo.localhost`;
  const password = `pw-${runId}-mandatory`;
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "33",
    title: "mandatory MFA",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  /** A fresh authorize → interaction → password sign-in. */
  const beginSignIn = async (
    tag: string,
  ): Promise<{ interaction: string; verifier: string; status: number; body: unknown } | undefined> => {
    const verifier = `m-${tag}-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const started = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: "monaca-console",
        redirect_uri: redirectUri,
        scope: "openid profile email",
        state: `st-${tag}-${runId}`,
        nonce: `n-${tag}-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(started.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    if (started.status !== 302 || interaction === null) return undefined;
    const signedIn = await call(
      `${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password }),
      },
    );
    return {
      interaction,
      verifier,
      status: signedIn.status,
      body: signedIn.body,
    };
  };

  try {
    const enabled = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ mfa_enabled: true, mfa_policy: "mandatory" }),
    });
    checks.push([
      "PATCH enables a mandatory policy",
      enabled.status === 200 &&
        (enabled.body as { mfa_enabled?: unknown })?.mfa_enabled === true &&
        (enabled.body as { mfa_policy?: unknown })?.mfa_policy === "mandatory",
    ]);

    const impossible = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ mfa_enabled: false, mfa_policy: "mandatory" }),
    });
    checks.push(["MFA cannot be off while the policy is mandatory", impossible.status === 400]);

    const account = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Mandatory", password }),
    });
    const accountId = (account.body as { id?: string })?.id;
    if (account.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${account.status} ${text(account.body)}`);
    }
    const member = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    checks.push(["the run's account joined acme", member.status === 201]);

    // --- the sign-in stops on enrollment ------------------------------------------------------
    const start = await beginSignIn("enroll");
    if (start === undefined) return fail("authorize did not open an interaction");
    checks.push([
      "an account with no factor is asked to enroll",
      start.status === 200 &&
        (start.body as { mfa_enrollment_required?: unknown })?.mfa_enrollment_required === true,
    ]);

    const enrollment = await call(
      `${base}/t/${TENANT}/interaction/${encodeURIComponent(start.interaction)}/mfa/enroll`,
      { method: "POST" },
    );
    const secret = (enrollment.body as { secret?: unknown })?.secret;
    checks.push([
      "the enrollment returns a secret and an otpauth URL",
      enrollment.status === 200 &&
        typeof secret === "string" &&
        typeof (enrollment.body as { otpauth_url?: unknown })?.otpauth_url === "string",
    ]);
    if (enrollment.status !== 200 || typeof secret !== "string") {
      return fail(`mfa/enroll → ${enrollment.status} ${text(enrollment.body)}`);
    }

    const confirmed = await call(
      `${base}/t/${TENANT}/interaction/${encodeURIComponent(start.interaction)}/mfa/enroll/verify`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code: totpFromBase32(secret) }),
      },
    );
    const redirectTo = (confirmed.body as { redirect_to?: unknown })?.redirect_to;
    checks.push([
      "a confirmed enrollment finishes the sign-in",
      confirmed.status === 200 && typeof redirectTo === "string",
    ]);
    if (confirmed.status !== 200 || typeof redirectTo !== "string") {
      return fail(`mfa/enroll/verify → ${confirmed.status} ${text(confirmed.body)}`);
    }
    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    const token = await tokenCall(
      base,
      {
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: "monaca-console",
        code_verifier: start.verifier,
      },
      btoa(`monaca-console:${consoleSecret}`),
    );
    if (token.status !== 200) {
      return fail(`token exchange → ${token.status} ${text(token.body)}`);
    }
    checks.push(["the token exchange succeeds", true]);

    // --- the next sign-in challenges the new factor -------------------------------------------
    const again = await beginSignIn("challenge");
    if (again === undefined) return fail("the second authorize did not open an interaction");
    const factors = (again.body as { factors?: unknown })?.factors;
    checks.push([
      "the next sign-in requires the new factor",
      again.status === 200 &&
        (again.body as { mfa_required?: unknown })?.mfa_required === true &&
        Array.isArray(factors) &&
        factors.includes("totp"),
    ]);
    const verified = await call(
      `${base}/t/${TENANT}/interaction/${encodeURIComponent(again.interaction)}/mfa/verify`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code: totpFromBase32(secret) }),
      },
    );
    checks.push([
      "the newly enrolled factor completes the challenge",
      verified.status === 200 &&
        typeof (verified.body as { redirect_to?: unknown })?.redirect_to === "string",
    ]);

    const restored = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ mfa_policy: "user_controlled" }),
    });
    checks.push([
      "the policy is restored to user_controlled",
      restored.status === 200 &&
        (restored.body as { mfa_policy?: unknown })?.mfa_policy === "user_controlled",
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ mfa_policy: "user_controlled" }),
    }).catch(() => undefined);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "33",
    title: "mandatory MFA",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: enable → invalid pair 400 → no factor enroll → secret → verify → token → next challenge → verify → restore`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 34: a tenant subscribes an endpoint, the server signs and posts a matching event, and the
 * delivery log records what the endpoint answered.
 *
 * The receiver is a real local HTTP server — the point is the signature over the exact bytes, so a
 * recorded body must verify rather than merely parse.
 */
async function webhookFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";
  let webhookId = "";

  interface Received {
    body: string;
    signature: string;
    event: string;
  }
  const received: Received[] = [];
  const receiver = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(request) {
      if (new URL(request.url).pathname !== "/hook") {
        return new Response("not found", { status: 404 });
      }
      received.push({
        body: await request.text(),
        signature: request.headers.get("x-monaca-signature") ?? "",
        event: request.headers.get("x-monaca-event") ?? "",
      });
      return new Response("ok", { status: 200 });
    },
  });
  const url = `http://127.0.0.1:${receiver.port}/hook`;

  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  const waitFor = async (count: number, timeoutMs = 5_000): Promise<Received | undefined> => {
    const deadline = performance.now() + timeoutMs;
    while (received.length < count && performance.now() < deadline) await sleep(50);
    return received[count - 1];
  };

  const sign = (secret: string, body: string): string =>
    `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;

  const makeAccount = async (tag: string) => {
    const email = `hook-${tag}-${runId}@demo.localhost`;
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Webhook Receiver", password: `pw-${runId}` }),
    });
    return { status: created.status, body: created.body, email };
  };

  try {
    const relative = await call(`${base}/v1/webhooks`, {
      method: "POST",
      headers,
      body: JSON.stringify({ url: "/hook", events: ["account.created"] }),
    });
    checks.push(["a relative endpoint is 400", relative.status === 400]);

    const unknown = await call(`${base}/v1/webhooks`, {
      method: "POST",
      headers,
      body: JSON.stringify({ url, events: ["account.no_such_action"] }),
    });
    checks.push(["an event outside the catalog is 400", unknown.status === 400]);

    const created = await call(`${base}/v1/webhooks`, {
      method: "POST",
      headers,
      body: JSON.stringify({ url, events: ["account.created"] }),
    });
    const secret = (created.body as { secret?: unknown })?.secret;
    const id = (created.body as { id?: unknown })?.id;
    checks.push([
      "creating a webhook returns 201 with a signing key",
      created.status === 201 &&
        typeof secret === "string" &&
        secret.startsWith("whsec_") &&
        typeof id === "string" &&
        id.startsWith("whk_"),
    ]);
    if (created.status !== 201 || typeof secret !== "string" || typeof id !== "string") {
      return failWebhook(`POST /v1/webhooks → ${created.status} ${text(created.body)}`);
    }
    webhookId = id;

    const list = await call(`${base}/v1/webhooks`, { headers });
    const items = (list.body as { items?: unknown[] })?.items ?? [];
    const row = items.find((item) => (item as { id?: unknown }).id === webhookId);
    checks.push([
      "the list names the hook without the signing key",
      list.status === 200 && row !== undefined && !("secret" in (row as object)),
    ]);

    const first = await makeAccount("first");
    checks.push(["the triggering account was created", first.status === 201]);
    const delivery = await waitFor(1);
    let verified = false;
    let shaped = false;
    if (delivery) {
      verified = delivery.signature === sign(secret, delivery.body);
      const payload = JSON.parse(delivery.body) as {
        hook_id?: unknown;
        event?: unknown;
        data?: { subject?: { type?: unknown; id?: unknown }; payload?: { email?: unknown } };
      };
      shaped =
        payload.hook_id === webhookId &&
        payload.event === "account.created" &&
        delivery.event === "account.created" &&
        payload.data?.subject?.type === "account" &&
        payload.data?.subject?.id === (first.body as { id?: unknown })?.id &&
        payload.data?.payload?.email === first.email;
    }
    checks.push(["the delivery carries a valid sha256 HMAC", verified]);
    checks.push(["the body names the hook, event and subject", shaped]);

    let deliveryRow: {
      event?: unknown;
      success?: unknown;
      status_code?: unknown;
      attempts?: unknown;
    } = {};
    const deadline = performance.now() + 5_000;
    while (performance.now() < deadline) {
      const listed = await call(`${base}/v1/webhooks/${webhookId}/deliveries`, { headers });
      const rows = (listed.body as { items?: unknown[] })?.items ?? [];
      deliveryRow = (rows[0] as typeof deliveryRow) ?? {};
      if (deliveryRow.event === "account.created") break;
      await sleep(100);
    }
    checks.push([
      "the delivery log records the 200 answer",
      deliveryRow.event === "account.created" &&
        deliveryRow.success === true &&
        deliveryRow.status_code === 200 &&
        typeof deliveryRow.attempts === "number" &&
        deliveryRow.attempts >= 1,
    ]);

    const paused = await call(`${base}/v1/webhooks/${webhookId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ enabled: false }),
    });
    checks.push([
      "PATCH pauses the subscription",
      paused.status === 200 && (paused.body as { enabled?: unknown })?.enabled === false,
    ]);
    const before = received.length;
    const skipped = await makeAccount("paused");
    checks.push(["a second account was created while paused", skipped.status === 201]);
    await sleep(400);
    checks.push(["a paused hook receives nothing", received.length === before]);

    const rotated = await call(`${base}/v1/webhooks/${webhookId}/secret`, {
      method: "POST",
      headers,
    });
    const newSecret = (rotated.body as { secret?: unknown })?.secret;
    checks.push([
      "rotating the key returns a different signing key",
      rotated.status === 200 && typeof newSecret === "string" && newSecret !== secret,
    ]);
    if (rotated.status !== 200 || typeof newSecret !== "string") {
      return failWebhook(`webhook/secret → ${rotated.status} ${text(rotated.body)}`);
    }

    const resumed = await call(`${base}/v1/webhooks/${webhookId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ enabled: true }),
    });
    checks.push([
      "PATCH resumes the subscription",
      resumed.status === 200 && (resumed.body as { enabled?: unknown })?.enabled === true,
    ]);
    const third = await makeAccount("rotated");
    checks.push(["a third account was created after rotation", third.status === 201]);
    const rotatedDelivery = await waitFor(before + 1);
    checks.push([
      "the resumed delivery verifies with the new key",
      rotatedDelivery !== undefined && rotatedDelivery.signature === sign(newSecret, rotatedDelivery.body),
    ]);

    const removed = await call(`${base}/v1/webhooks/${webhookId}`, { method: "DELETE", headers });
    checks.push(["DELETE is 204", removed.status === 204]);
    webhookId = "";
    const gone = await call(`${base}/v1/webhooks`, { headers });
    const remaining = (gone.body as { items?: { id?: unknown }[] })?.items ?? [];
    checks.push([
      "the list no longer names it",
      gone.status === 200 && remaining.every((item) => item.id !== id),
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    if (webhookId !== "") {
      await call(`${base}/v1/webhooks/${webhookId}`, { method: "DELETE", headers }).catch(
        () => undefined,
      );
    }
    receiver.stop(true);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "34",
    title: "webhooks",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: validation → create + secret → signed delivery → log → pause → rotate → resume → delete`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };

  function failWebhook(why: string): StepResult {
    return { step: "34", title: "webhooks", status: "fail", ms: Math.round(performance.now() - t), detail: why };
  }
}

/**
 * Step 35: the tenant's minimum password length is enforced wherever a password is set.
 *
 * The administrator path and the self-service path share `check_password` server-side, so both are
 * exercised here: one proves the management API did not bypass the policy, the other proves the
 * hosted sign-up does not either.
 */
async function passwordPolicyFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
  internalSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const headers = managementHeaders(adminToken);
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const email = `policy-${runId}@demo.localhost`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const begin = async (): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `p-${runId}-${"z".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const started = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: "monaca-console",
        redirect_uri: redirectUri,
        scope: "openid profile email",
        state: `st-policy-${runId}`,
        nonce: `n-policy-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(started.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    if (started.status !== 302 || interaction === null) return undefined;
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  try {
    const tooShort = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ password_min_length: 7 }),
    });
    checks.push(["a minimum below 8 is 400", tooShort.status === 400]);

    const tooLong = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ password_min_length: 65 }),
    });
    checks.push(["a minimum above 64 is 400", tooLong.status === 400]);

    const raised = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ password_min_length: 12 }),
    });
    checks.push([
      "PATCH raises the minimum to 12",
      raised.status === 200 &&
        (raised.body as { password_min_length?: unknown })?.password_min_length === 12,
    ]);

    const publicRead = await call(`${base}/t/${TENANT}/sign-in-experience`);
    checks.push([
      "the public read carries the minimum",
      publicRead.status === 200 &&
        (publicRead.body as { password_min_length?: unknown })?.password_min_length === 12,
    ]);

    const weakAdmin = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        email: `policy-admin-weak-${runId}@demo.localhost`,
        display_name: "Weak",
        password: "short7c",
      }),
    });
    checks.push(["an administrator cannot create a weak password", weakAdmin.status === 400]);

    const strongAdmin = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        email: `policy-admin-ok-${runId}@demo.localhost`,
        display_name: "Strong",
        password: `pw-${runId}-admin-ok`,
      }),
    });
    checks.push(["an administrator's password at the minimum succeeds", strongAdmin.status === 201]);

    const interaction = await begin();
    if (interaction === undefined) return failPolicy("authorize did not open an interaction");
    const requested = await call(
      `${base}/t/${TENANT}/interaction/${interaction.interaction}/sign-up`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email }),
      },
    );
    checks.push([
      "sign-up requests a code",
      requested.status === 200 &&
        (requested.body as { verification_required?: unknown })?.verification_required === true,
    ]);
    const mail = await call(
      `${base}/internal/mail?${new URLSearchParams({ tenant: TENANT, to: email, purpose: "sign_up" })}`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    const code = (mail.body as { payload?: { code?: unknown } } | undefined)?.payload?.code;
    if (mail.status !== 200 || typeof code !== "string") {
      return failPolicy(`internal/mail → ${mail.status} ${text(mail.body)}`);
    }
    checks.push(["the dev outbox carries the sign-up code", true]);

    const weakSignUp = await call(
      `${base}/t/${TENANT}/interaction/${interaction.interaction}/sign-up/verify`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, code, password: "short7c" }),
      },
    );
    checks.push(["self-service sign-up refuses a weak password", weakSignUp.status === 400]);

    const strongSignUp = await call(
      `${base}/t/${TENANT}/interaction/${interaction.interaction}/sign-up/verify`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, code, password: `pw-${runId}-signup` }),
      },
    );
    const redirectTo = (strongSignUp.body as { redirect_to?: unknown })?.redirect_to;
    checks.push([
      "a password at the minimum completes sign-up",
      strongSignUp.status === 200 && typeof redirectTo === "string",
    ]);
    if (strongSignUp.status === 200 && typeof redirectTo === "string") {
      const token = await tokenCall(
        base,
        {
          grant_type: "authorization_code",
          code: new URL(redirectTo).searchParams.get("code") ?? "",
          redirect_uri: redirectUri,
          client_id: "monaca-console",
          code_verifier: interaction.verifier,
        },
        basic,
      );
      checks.push(["the sign-up token exchange succeeds", token.status === 200]);
    } else {
      checks.push(["the sign-up token exchange succeeds", false]);
    }

    const restored = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ password_min_length: 8 }),
    });
    checks.push([
      "the minimum is restored to 8",
      restored.status === 200 &&
        (restored.body as { password_min_length?: unknown })?.password_min_length === 8,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ password_min_length: 8 }),
    }).catch(() => undefined);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "35",
    title: "password policy",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: range 400s → raise 12 → public read → admin weak 400 → admin ok → sign-up weak 400 → sign-up ok → token → restore`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };

  function failPolicy(why: string): StepResult {
    return {
      step: "35",
      title: "password policy",
      status: "fail",
      ms: Math.round(performance.now() - t),
      detail: why,
    };
  }
}

/**
 * Step 36: a tenant can brand the hosted page, and the public read carries the same values.
 *
 * An empty string is the documented way to clear a field, so the flow exercises both directions
 * rather than only writing values the UI happens to offer.
 */
async function brandingFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const branding = {
    display_name: "Acme Identity",
    logo_url: "https://cdn.example/logo.png",
    primary_color: "#0f6cbd",
    terms_url: "https://acme.example/terms",
    privacy_url: "https://acme.example/privacy",
  };

  const current = (body: unknown): Record<string, unknown> =>
    (body as { branding?: Record<string, unknown> } | undefined)?.branding ?? {};

  try {
    const longName = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ branding: { display_name: "x".repeat(65) } }),
    });
    checks.push(["a display name over 64 characters is 400", longName.status === 400]);

    const relativeLogo = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ branding: { logo_url: "logo.png" } }),
    });
    checks.push(["a relative logo URL is 400", relativeLogo.status === 400]);

    const badColor = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ branding: { primary_color: "blue" } }),
    });
    checks.push(["a non-hex colour is 400", badColor.status === 400]);

    const written = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ branding }),
    });
    checks.push([
      "PATCH writes the five branding fields",
      written.status === 200 &&
        Object.entries(branding).every(([key, value]) => current(written.body)[key] === value),
    ]);

    const publicRead = await call(`${base}/t/${TENANT}/sign-in-experience`);
    checks.push([
      "the public read echoes the branding",
      publicRead.status === 200 &&
        Object.entries(branding).every(([key, value]) => current(publicRead.body)[key] === value),
    ]);

    const cleared = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ branding: { logo_url: "" } }),
    });
    checks.push([
      "an empty string clears only the named field",
      cleared.status === 200 &&
        current(cleared.body).logo_url === null &&
        current(cleared.body).display_name === branding.display_name,
    ]);

    const reset = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        branding: {
          display_name: "",
          logo_url: "",
          primary_color: "",
          terms_url: "",
          privacy_url: "",
        },
      }),
    });
    checks.push([
      "clearing every field restores the built-in look",
      reset.status === 200 &&
        Object.values(current(reset.body)).every((value) => value === null),
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        branding: {
          display_name: "",
          logo_url: "",
          primary_color: "",
          terms_url: "",
          privacy_url: "",
        },
      }),
    }).catch(() => undefined);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "36",
    title: "branding",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: 400s → write five fields → public echo → clear one → clear all`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/** Step 48: a tenant can carry a dark-mode logo, favicon and contact links. */
async function brandingExtrasFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const branding = {
    display_name: "Acme Identity",
    logo_url: "https://cdn.example/logo.png",
    dark_logo_url: "https://cdn.example/logo-dark.png",
    favicon_url: "https://cdn.example/favicon.ico",
    primary_color: "#0f6cbd",
    terms_url: "https://acme.example/terms",
    privacy_url: "https://acme.example/privacy",
    support_email: "help@acme.example",
    website_url: "https://acme.example",
  };
  const cleared = Object.fromEntries(Object.keys(branding).map((key) => [key, ""]));

  const current = (body: unknown): Record<string, unknown> =>
    (body as { branding?: Record<string, unknown> } | undefined)?.branding ?? {};

  try {
    const relativeDark = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ branding: { dark_logo_url: "logo-dark.png" } }),
    });
    checks.push(["a relative dark-logo URL is 400", relativeDark.status === 400]);

    const relativeFavicon = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ branding: { favicon_url: "favicon.ico" } }),
    });
    checks.push(["a relative favicon URL is 400", relativeFavicon.status === 400]);

    const badEmail = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ branding: { support_email: "not-an-address" } }),
    });
    checks.push(["a malformed support email is 400", badEmail.status === 400]);

    const written = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ branding }),
    });
    checks.push([
      "PATCH writes the four extra branding fields",
      written.status === 200 &&
        Object.entries(branding).every(([key, value]) => current(written.body)[key] === value),
    ]);

    const publicRead = await call(`${base}/t/${TENANT}/sign-in-experience`);
    checks.push([
      "the public read echoes them",
      publicRead.status === 200 &&
        Object.entries(branding).every(([key, value]) => current(publicRead.body)[key] === value),
    ]);

    const clearedOne = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ branding: { support_email: "" } }),
    });
    checks.push([
      "an empty string clears only the named field",
      clearedOne.status === 200 &&
        current(clearedOne.body).support_email === null &&
        current(clearedOne.body).website_url === branding.website_url &&
        current(clearedOne.body).dark_logo_url === branding.dark_logo_url,
    ]);

    const reset = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ branding: cleared }),
    });
    checks.push([
      "clearing every field restores the built-in look",
      reset.status === 200 && Object.values(current(reset.body)).every((value) => value === null),
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ branding: cleared }),
    }).catch(() => undefined);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "48",
    title: "branding extras",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: URL/email 400s → write nine fields → public echo → clear one → clear all`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 49: the tenant chooses who can register, what proves the address, and what sign-up collects.
 *
 * Two shapes come out of the same endpoint: with verification on, `sign-up` only mails a code and
 * the password belongs to `sign-up/verify`; with it off, one request creates the account. The
 * profile fields and username bounds are read from the tenant's policy at both entrances, so a
 * direct sign-up that ignores them is refused rather than silently narrowed.
 */
async function registrationPolicyFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const headers = managementHeaders(adminToken);
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const checks: [string, boolean][] = [];
  let detail = "";

  const policy = {
    sign_up_identifiers: ["email", "username"],
    sign_up_email_verification_required: false,
    username_case_sensitive: false,
    username_min_length: 4,
    username_max_length: 16,
    sign_up_profile_fields: ["name", "avatar"],
  };
  const defaults = {
    sign_up_identifiers: ["email"],
    sign_up_email_verification_required: true,
    username_case_sensitive: false,
    username_min_length: 3,
    username_max_length: 32,
    sign_up_profile_fields: ["name"],
  };
  const patch = (body: unknown): Promise<HttpResult> =>
    call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify(body),
    });
  const sameList = (value: unknown, expected: string[]): boolean =>
    Array.isArray(value) &&
    value.length === expected.length &&
    expected.every((item, index) => value[index] === item);

  const begin = async (tag: string): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `r-${runId}-${tag}-${"z".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const started = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: "monaca-console",
        redirect_uri: redirectUri,
        scope: "openid profile email",
        state: `st-registration-${tag}-${runId}`,
        nonce: `n-registration-${tag}-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(started.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    if (started.status !== 302 || interaction === null) return undefined;
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  const signUp = (
    target: { interaction: string },
    body: Record<string, unknown>,
  ): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/interaction/${target.interaction}/sign-up`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });

  const owner = `registration-${runId}@demo.localhost`;
  const password = `pw-${runId}-registration`;
  const username = `Reg-${runId}`;

  try {
    checks.push([
      "an empty identifier list is 400",
      (await patch({ sign_up_identifiers: [] })).status === 400,
    ]);
    checks.push([
      "identifiers without email are 400",
      (await patch({ sign_up_identifiers: ["username"] })).status === 400,
    ]);
    checks.push([
      "an unknown identifier is 400",
      (await patch({ sign_up_identifiers: ["email", "phone"] })).status === 400,
    ]);
    checks.push([
      "an unknown profile field is 400",
      (await patch({ sign_up_profile_fields: ["name", "phone"] })).status === 400,
    ]);
    checks.push([
      "a username minimum below 3 is 400",
      (await patch({ username_min_length: 2 })).status === 400,
    ]);
    checks.push([
      "a username maximum above 32 is 400",
      (await patch({ username_max_length: 33 })).status === 400,
    ]);
    checks.push([
      "a minimum above the maximum is 400",
      (await patch({ username_min_length: 10, username_max_length: 9 })).status === 400,
    ]);

    const written = await patch(policy);
    checks.push([
      "PATCH writes the registration policy",
      written.status === 200 &&
        sameList((written.body as { sign_up_identifiers?: unknown })?.sign_up_identifiers, policy.sign_up_identifiers) &&
        (written.body as { sign_up_email_verification_required?: unknown })
          ?.sign_up_email_verification_required === false &&
        (written.body as { username_min_length?: unknown })?.username_min_length === 4 &&
        (written.body as { username_max_length?: unknown })?.username_max_length === 16,
    ]);

    const publicRead = await call(`${base}/t/${TENANT}/sign-in-experience`);
    checks.push([
      "the public read carries the policy",
      publicRead.status === 200 &&
        sameList(
          (publicRead.body as { sign_up_identifiers?: unknown })?.sign_up_identifiers,
          policy.sign_up_identifiers,
        ) &&
        sameList(
          (publicRead.body as { sign_up_profile_fields?: unknown })?.sign_up_profile_fields,
          policy.sign_up_profile_fields,
        ) &&
        (publicRead.body as { sign_up_email_verification_required?: unknown })
          ?.sign_up_email_verification_required === false,
    ]);

    const direct = await begin("direct");
    if (direct === undefined) return failPolicy("authorize did not open an interaction");
    const created = await signUp(direct, {
      email: owner,
      password,
      username,
      display_name: "Registration Owner",
      avatar_url: "https://cdn.example/registration.png",
    });
    const redirectTo = (created.body as { redirect_to?: unknown })?.redirect_to;
    const sessionCookie = /monaca_session=([0-9a-f-]{36})/.exec(
      created.headers.get("set-cookie") ?? "",
    )?.[1];
    checks.push([
      "a direct sign-up creates the account in one request",
      created.status === 200 &&
        typeof redirectTo === "string" &&
        sessionCookie !== undefined &&
        (created.body as { verification_required?: unknown })?.verification_required === undefined,
    ]);
    if (typeof redirectTo !== "string" || sessionCookie === undefined) {
      return failPolicy(`direct sign-up → ${created.status} ${text(created.body)}`);
    }

    const ownRead = await call(`${base}/t/${TENANT}/account`, {
      headers: { cookie: `monaca_session=${sessionCookie}` },
    });
    checks.push([
      "the account carries the collected profile and the folded username",
      ownRead.status === 200 &&
        (ownRead.body as { username?: unknown })?.username === username.toLowerCase() &&
        (ownRead.body as { display_name?: unknown })?.display_name === "Registration Owner" &&
        (ownRead.body as { avatar_url?: unknown })?.avatar_url ===
          "https://cdn.example/registration.png",
    ]);

    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    const token = await tokenCall(
      base,
      {
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: "monaca-console",
        code_verifier: direct.verifier,
      },
      basic,
    );
    const claims = jwtClaims((token.body as { id_token?: unknown } | undefined)?.id_token);
    checks.push([
      "the sign-up token carries the name and avatar",
      token.status === 200 &&
        claims?.name === "Registration Owner" &&
        claims?.picture === "https://cdn.example/registration.png",
    ]);

    const belowBound = await begin("short");
    checks.push([
      "a username below the tenant minimum is 400",
      belowBound !== undefined &&
        (
          await signUp(belowBound, {
            email: `registration-short-${runId}@demo.localhost`,
            password,
            username: "abc",
          })
        ).status === 400,
    ]);

    const relativeAvatar = await begin("avatar");
    checks.push([
      "a relative avatar is 400",
      relativeAvatar !== undefined &&
        (
          await signUp(relativeAvatar, {
            email: `registration-avatar-${runId}@demo.localhost`,
            password,
            avatar_url: "avatar.png",
          })
        ).status === 400,
    ]);

    const noPassword = await begin("password");
    checks.push([
      "a direct sign-up without a password is 400",
      noPassword !== undefined &&
        (await signUp(noPassword, { email: `registration-pw-${runId}@demo.localhost` })).status === 400,
    ]);

    const emailOnly = await patch({ sign_up_identifiers: ["email"] });
    const rejectedUsername = await begin("username-off");
    checks.push([
      "a username the identifier policy does not offer is 400",
      emailOnly.status === 200 &&
        rejectedUsername !== undefined &&
        (
          await signUp(rejectedUsername, {
            email: `registration-nouser-${runId}@demo.localhost`,
            password,
            username: "reguser",
          })
        ).status === 400,
    ]);

    const nameOnly = await patch({ sign_up_profile_fields: ["name"] });
    const rejectedAvatar = await begin("avatar-off");
    checks.push([
      "an avatar the profile policy does not collect is 400",
      nameOnly.status === 200 &&
        rejectedAvatar !== undefined &&
        (
          await signUp(rejectedAvatar, {
            email: `registration-noavatar-${runId}@demo.localhost`,
            password,
            avatar_url: "https://cdn.example/no.png",
          })
        ).status === 400,
    ]);

    const verified = await patch({ sign_up_email_verification_required: true });
    const verifiedInteraction = await begin("verified");
    const codeRequest = verifiedInteraction
      ? await signUp(verifiedInteraction, { email: `registration-code-${runId}@demo.localhost` })
      : undefined;
    checks.push([
      "switching verification back on makes sign-up mail a code",
      verified.status === 200 &&
        codeRequest?.status === 200 &&
        (codeRequest.body as { verification_required?: unknown })?.verification_required === true,
    ]);

    // The password belongs to the verify step while verification is on; sending it here is refused.
    const earlyPassword = verifiedInteraction
      ? await signUp(verifiedInteraction, {
          email: `registration-early-${runId}@demo.localhost`,
          password,
        })
      : undefined;
    checks.push([
      "the request step refuses a password while verification is on",
      earlyPassword?.status === 400,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await patch(defaults).catch(() => undefined);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "49",
    title: "registration policy",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: validation 400s → policy → public read → direct sign-up → profile → bounds → identifier/profile/verification guards`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };

  function failPolicy(why: string): StepResult {
    return {
      step: "49",
      title: "registration policy",
      status: "fail",
      ms: Math.round(performance.now() - t),
      detail: why,
    };
  }
}

/**
 * Step 50: a third-party approval is remembered, listed and withdrawable.
 *
 * The approval is observed from both ends: the account centre lists the application and, while
 * the grant covers the request, a returning browser skips the screen (even with `prompt=none`);
 * `prompt=consent` still asks. Withdrawing removes the row, ends the client's refresh tokens and
 * makes the next silent request answer `consent_required`.
 */
async function consentFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const email = `consent-${runId}@demo.localhost`;
  const password = `pw-${runId}-consent`;
  const clientId = `e2e-consent-${runId}`;
  const redirectUri = "http://localhost:5173/bff/callback";
  const verifier = `cs-${runId}-${"v".repeat(32)}`;

  let clientRowId: string | undefined;
  try {
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Consent Owner", password }),
    });
    const accountId = (created.body as { id?: unknown } | undefined)?.id;
    checks.push([
      "POST /v1/accounts creates the account",
      created.status === 201 && typeof accountId === "string",
    ]);
    if (typeof accountId === "string") {
      await call(`${base}/v1/orgs/${ORG}/members`, {
        method: "POST",
        headers,
        body: JSON.stringify({ account_id: accountId, role: "member" }),
      });
    }

    const app = await call(`${base}/v1/clients`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        client_id: clientId,
        name: "E2E Consent",
        kind: "public",
        redirect_uris: [redirectUri],
        scopes: ["openid", "profile", "email", "offline_access"],
        is_third_party: true,
      }),
    });
    const appRowId = (app.body as { id?: unknown } | undefined)?.id;
    if (typeof appRowId === "string") clientRowId = appRowId;
    checks.push([
      "a third-party client is registered",
      app.status === 201 && clientRowId !== undefined,
    ]);
    if (clientRowId === undefined) {
      return {
        step: "50",
        title: "consent and authorized apps",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: `POST /v1/clients → ${app.status} ${text(app.body)}`,
      };
    }

    const appRead = await call(`${base}/v1/clients/${clientRowId}`, { headers });
    checks.push([
      "the management read marks the application third-party",
      (appRead.body as { is_third_party?: unknown } | undefined)?.is_third_party === true,
    ]);

    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const authorize = (tag: string, extra: Record<string, string> = {}, cookie?: string) =>
      call(
        `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
          response_type: "code",
          client_id: clientId,
          redirect_uri: redirectUri,
          scope: "openid profile email offline_access",
          state: `st-consent-${runId}-${tag}`,
          nonce: `n-consent-${runId}`,
          code_challenge: challenge,
          code_challenge_method: "S256",
          organization: ORG,
          ...extra,
        })}`,
        { redirect: "manual", ...(cookie === undefined ? {} : { headers: { cookie } }) },
      );

    const opened = await authorize("open");
    const interaction = new URL(
      opened.headers.get("location") ?? "",
      base,
    ).searchParams.get("interaction");
    checks.push([
      "a third-party authorize opens an interaction",
      opened.status === 302 && interaction !== null,
    ]);
    if (interaction === null) {
      return {
        step: "50",
        title: "consent and authorized apps",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: `authorize → ${opened.status} ${text(opened.body)}`,
      };
    }

    const signedIn = await call(
      `${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identifier: email, password }),
      },
    );
    const paused = (signedIn.body as { consent_required?: unknown } | undefined)
      ?.consent_required;
    const sessionCookie = /monaca_session=([0-9a-f-]{36})/.exec(
      signedIn.headers.get("set-cookie") ?? "",
    )?.[1];
    checks.push([
      "sign-in pauses at the consent step with a session cookie",
      signedIn.status === 200 && paused === true && sessionCookie !== undefined,
    ]);
    if (sessionCookie === undefined) {
      return {
        step: "50",
        title: "consent and authorized apps",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: `sign-in → ${signedIn.status} ${text(signedIn.body)}`,
      };
    }
    const cookie = `monaca_session=${sessionCookie}`;

    const approved = await call(
      `${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/consent`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ decision: "allow" }),
      },
    );
    const redirectTo = (approved.body as { redirect_to?: unknown } | undefined)?.redirect_to;
    checks.push([
      "approving consent issues the authorization code",
      approved.status === 200 && typeof redirectTo === "string",
    ]);
    if (typeof redirectTo !== "string") {
      return {
        step: "50",
        title: "consent and authorized apps",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: `consent → ${approved.status} ${text(approved.body)}`,
      };
    }

    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    const token = await tokenCall(base, {
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: verifier,
    });
    const firstRefresh = (token.body as { refresh_token?: unknown } | undefined)?.refresh_token;
    checks.push([
      "the approved code exchanges for tokens with a refresh token",
      token.status === 200 && typeof firstRefresh === "string",
    ]);

    const renewed = await tokenCall(base, {
      grant_type: "refresh_token",
      refresh_token: String(firstRefresh ?? ""),
      client_id: clientId,
    });
    const secondRefresh = (renewed.body as { refresh_token?: unknown } | undefined)
      ?.refresh_token;
    checks.push([
      "the refresh token renews before the approval is withdrawn",
      renewed.status === 200 && typeof secondRefresh === "string",
    ]);

    type AppRow = { client_id?: unknown; name?: unknown; scopes?: unknown; granted_at?: unknown };
    const listed = await call(`${base}/t/${TENANT}/account/authorized-apps`, {
      headers: { cookie },
    });
    const items =
      (listed.body as { items?: AppRow[] } | undefined)?.items ?? [];
    const grant = items.find((row) => row.client_id === clientId);
    checks.push([
      "the account centre lists the application with the approved scopes",
      listed.status === 200 &&
        grant?.name === "E2E Consent" &&
        Array.isArray(grant?.scopes) &&
        grant.scopes.includes("openid") &&
        grant.scopes.includes("offline_access") &&
        typeof grant?.granted_at === "string" &&
        !Number.isNaN(Date.parse(grant.granted_at)),
    ]);

    const silent = await authorize("silent", { prompt: "none" }, cookie);
    const silentLocation = new URL(silent.headers.get("location") ?? "", base);
    checks.push([
      "a stored grant lets prompt=none skip the consent screen",
      silent.status === 302 &&
        silentLocation.searchParams.get("code") !== null &&
        silentLocation.searchParams.get("error") === null,
    ]);

    const prompted = await authorize("prompted", { prompt: "consent" }, cookie);
    const promptedInteraction = new URL(
      prompted.headers.get("location") ?? "",
      base,
    ).searchParams.get("interaction");
    checks.push([
      "prompt=consent asks again despite the stored grant",
      prompted.status === 302 && promptedInteraction !== null,
    ]);
    if (promptedInteraction !== null) {
      await call(
        `${base}/t/${TENANT}/interaction/${encodeURIComponent(promptedInteraction)}/abort`,
        { method: "POST" },
      );
    }

    const withdrawn = await call(
      `${base}/t/${TENANT}/account/authorized-apps/${encodeURIComponent(clientId)}`,
      { method: "DELETE", headers: { cookie } },
    );
    checks.push(["the account withdraws the approval", withdrawn.status === 204]);

    const after = await call(`${base}/t/${TENANT}/account/authorized-apps`, {
      headers: { cookie },
    });
    const remaining = (after.body as { items?: AppRow[] } | undefined)?.items ?? [];
    checks.push([
      "the withdrawn application disappears from the list",
      after.status === 200 && remaining.every((row) => row.client_id !== clientId),
    ]);

    const dead = await tokenCall(base, {
      grant_type: "refresh_token",
      refresh_token: String(secondRefresh ?? ""),
      client_id: clientId,
    });
    checks.push([
      "withdrawal ends the application's refresh token",
      dead.status === 400 && (dead.body as { error?: unknown } | undefined)?.error === "invalid_grant",
    ]);

    const silentAfter = await authorize("after", { prompt: "none" }, cookie);
    const afterLocation = new URL(silentAfter.headers.get("location") ?? "", base);
    checks.push([
      "the next silent request asks for consent again",
      silentAfter.status === 302 &&
        afterLocation.searchParams.get("error") === "consent_required",
    ]);

    const secondWithdrawal = await call(
      `${base}/t/${TENANT}/account/authorized-apps/${encodeURIComponent(clientId)}`,
      { method: "DELETE", headers: { cookie } },
    );
    checks.push(["a second withdrawal is 404", secondWithdrawal.status === 404]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    if (clientRowId !== undefined) {
      await call(`${base}/v1/clients/${clientRowId}`, { method: "DELETE", headers }).catch(
        () => undefined,
      );
    }
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "50",
    title: "consent and authorized apps",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: third-party sign-in → consent → grant → list → silent skip → prompt re-ask → withdraw → refresh dies → ask again`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 54: per-language copy is writable, listable and negotiated by the public read.
 *
 * The hosted page is rendered by `auth-ui`, which the acceptance job does not run; the page
 * assertion is therefore left to the Playwright walk, while this checks the API that feeds it.
 */
async function signInCopyFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";
  const patch = (body: Record<string, unknown>): Promise<HttpResult> =>
    call(`${base}/v1/sign-in-copy`, {
      method: "PATCH",
      headers,
      body: JSON.stringify(body),
    });
  const languages = (body: unknown): string[] =>
    ((body as { languages?: { language?: string }[] } | undefined)?.languages ?? [])
      .map((item) => item.language ?? "");
  const defaultLanguage = (body: unknown): unknown =>
    (body as { default_language?: unknown } | undefined)?.default_language;

  try {
    const written = await patch({ language: "de", phrases: { "signIn.title": "Anmelden" } });
    const listed = await call(`${base}/v1/sign-in-copy`, { headers });
    const de = ((listed.body as { languages?: { language?: string; phrases?: Record<string, unknown> }[] } | undefined)
      ?.languages ?? []).find((item) => item.language === "de");
    checks.push([
      "PATCH stores a language and the list carries its phrase",
      written.status === 200 && listed.status === 200 &&
        languages(listed.body).includes("de") &&
        de?.phrases?.["signIn.title"] === "Anmelden",
    ]);

    const [badTag, singleSegment, longValue, empty] = await Promise.all([
      patch({ language: "de_DE", phrases: { "signIn.title": "Anmelden" } }),
      patch({ language: "de", phrases: { title: "Anmelden" } }),
      patch({ language: "de", phrases: { "signIn.title": "x".repeat(501) } }),
      patch({}),
    ]);
    checks.push([
      "a malformed tag, a single-segment key, a 501-character value and an empty patch are 400",
      badTag.status === 400 && singleSegment.status === 400 &&
        longValue.status === 400 && empty.status === 400,
    ]);

    const removed = await patch({ language: "de", phrases: {} });
    const afterRemove = await call(`${base}/v1/sign-in-copy`, { headers });
    checks.push([
      "an empty phrase set removes the language",
      removed.status === 200 && !languages(afterRemove.body).includes("de"),
    ]);

    const defaulted = await patch({ default_language: "de" });
    const afterDefault = await call(`${base}/v1/sign-in-copy`, { headers });
    checks.push([
      "changing the default keeps it listed",
      defaulted.status === 200 && defaultLanguage(afterDefault.body) === "de" &&
        languages(afterDefault.body).includes("de"),
    ]);

    const publicDefault = await call(`${base}/t/${TENANT}/sign-in-copy`);
    const publicDe = await call(`${base}/t/${TENANT}/sign-in-copy?lang=de`);
    const publicHeader = await call(`${base}/t/${TENANT}/sign-in-copy`, {
      headers: { "accept-language": "de" },
    });
    const publicFallback = await call(`${base}/t/${TENANT}/sign-in-copy?lang=fr`);
    checks.push([
      "the public read follows the default, ?lang, Accept-Language and an unknown fallback",
      defaultLanguage(publicDefault.body) === "de" &&
        defaultLanguage(publicDe.body) === "de" &&
        defaultLanguage(publicHeader.body) === "de" &&
        defaultLanguage(publicFallback.body) === "de",
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await patch({ default_language: "en" });
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "54",
    title: "language and custom copy",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: write → list → refusals → remove → default → public negotiation`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 57: remembered versus one-shot consent, incremental scopes and offline access.
 *
 * One third-party client walks the full path: consent without `offline_access`, a silent repeat,
 * a request that adds `offline_access` (which must not go silently), then a request that adds one
 * more scope (which must show a single screen naming only the new scope). A second client approves
 * a subset (a token with only those scopes and no refresh), records a remembered subset, signs in
 * afresh to see only the uncovered scopes, refuses every scope and finally holds a one-shot row
 * beside a remembered one, so the account centre must aggregate and withdrawal must clear both.
 * A separate client approves one-shot, proves the next silent request asks again, and proves
 * withdrawal ends its refresh token. The final read checks the `consent.granted` audit trail for
 * both modes.
 */
async function consentSemanticsFlow(
  base: string,
  adminToken: string,
  internalSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";
  const sameStringList = (value: unknown, expected: string[]): boolean =>
    Array.isArray(value) &&
    value.length === expected.length &&
    expected.every((item, index) => value[index] === item);

  const email = `consent-sem-${runId}@demo.localhost`;
  const password = `pw-${runId}-consent-sem`;
  const redirectUri = "http://localhost:5173/bff/callback";
  const client1 = `e2e-consent-rem-${runId}`;
  const client2 = `e2e-consent-one-${runId}`;
  const client3 = `e2e-consent-part-${runId}`;
  const scopes = "openid profile email offline_access projects:read";
  const verifier = `cs-sem-${runId}-${"v".repeat(32)}`;
  const challenge = base64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
  );
  let client1Row: string | undefined;
  let client2Row: string | undefined;
  let client3Row: string | undefined;

  const authorize = (
    clientId: string,
    tag: string,
    scope: string,
    extra: Record<string, string> = {},
    cookie?: string,
  ): Promise<HttpResult> =>
    call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        scope,
        state: `st-consent-sem-${runId}-${tag}`,
        nonce: `n-consent-sem-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
        ...extra,
      })}`,
      {
        redirect: "manual",
        ...(cookie === undefined ? {} : { headers: { cookie } }),
      },
    );

  const interactionOf = (response: HttpResult): string | null =>
    new URL(response.headers.get("location") ?? "", base).searchParams.get("interaction");
  const codeOf = (response: HttpResult): string | null => {
    const redirect =
      response.headers.get("location") ??
      (response.body as { redirect_to?: unknown } | undefined)?.redirect_to;
    return typeof redirect === "string"
      ? new URL(redirect, base).searchParams.get("code")
      : null;
  };
  const errorOf = (response: HttpResult): string | null => {
    const redirect =
      response.headers.get("location") ??
      (response.body as { redirect_to?: unknown } | undefined)?.redirect_to;
    return typeof redirect === "string" ? new URL(redirect, base).searchParams.get("error") : null;
  };
  const scopeOf = (body: unknown): string[] => {
    const scope = (body as { scope?: unknown } | undefined)?.scope;
    if (Array.isArray(scope)) {
      return scope.filter((item): item is string => typeof item === "string");
    }
    return typeof scope === "string" ? scope.split(" ").filter(Boolean) : [];
  };
  const consent = (
    iid: string,
    remember: boolean,
    allowedScopes?: string[],
  ): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/interaction/${encodeURIComponent(iid)}/consent`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(
        allowedScopes === undefined
          ? { decision: "allow", remember }
          : { decision: "allow", remember, allowed_scopes: allowedScopes },
      ),
    });

  try {
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Consent Semantics", password }),
    });
    const accountId = (created.body as { id?: unknown } | undefined)?.id;
    if (created.status !== 201 || typeof accountId !== "string") {
      return consentSemanticsFail(t, `POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });

    const makeClient = (id: string, name: string): Promise<HttpResult> =>
      call(`${base}/v1/clients`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          client_id: id,
          name,
          kind: "public",
          redirect_uris: [redirectUri],
          scopes: ["openid", "profile", "email", "offline_access", "projects:read"],
          is_third_party: true,
        }),
      });
    const [app1, app2, app3] = await Promise.all([
      makeClient(client1, "Remembered consent"),
      makeClient(client2, "One-shot consent"),
      makeClient(client3, "Partial consent"),
    ]);
    client1Row = (app1.body as { id?: unknown } | undefined)?.id as string | undefined;
    client2Row = (app2.body as { id?: unknown } | undefined)?.id as string | undefined;
    client3Row = (app3.body as { id?: unknown } | undefined)?.id as string | undefined;
    checks.push([
      "three third-party clients are registered",
      app1.status === 201 && app2.status === 201 && app3.status === 201 &&
        typeof client1Row === "string" && typeof client2Row === "string" &&
        typeof client3Row === "string",
    ]);
    if (
      typeof client1Row !== "string" ||
      typeof client2Row !== "string" ||
      typeof client3Row !== "string"
    ) {
      return consentSemanticsFail(
        t,
        `POST /v1/clients → ${app1.status}/${app2.status}/${app3.status}`,
      );
    }

    // --- first approval: no offline_access requested, so no refresh token ----------------------
    const opened = await authorize(client1, "open", "openid profile email");
    const firstIid = interactionOf(opened);
    const signedIn = firstIid === null
      ? undefined
      : await call(`${base}/t/${TENANT}/interaction/${encodeURIComponent(firstIid)}/sign-in`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ identifier: email, password }),
        });
    const sessionCookie = /monaca_session=([0-9a-f-]{36})/.exec(
      signedIn?.headers.get("set-cookie") ?? "",
    )?.[1];
    const firstConsent = firstIid === null ? undefined : await consent(firstIid, true);
    const firstCode = firstConsent === undefined ? null : codeOf(firstConsent);
    checks.push([
      "the first approval needs a screen and needs no offline access",
      opened.status === 302 && firstIid !== null && signedIn?.status === 200 &&
        sessionCookie !== undefined && firstConsent?.status === 200 && firstCode !== null,
    ]);
    if (sessionCookie === undefined || firstCode === null) {
      return consentSemanticsFail(
        t,
        `first flow: authorize=${opened.status}, iid=${firstIid}, signin=${signedIn?.status} ${text(signedIn?.body)}, cookie=${sessionCookie}, consent=${firstConsent?.status} ${text(firstConsent?.body)}`,
      );
    }
    const cookie = `monaca_session=${sessionCookie}`;
    const firstToken = await tokenCall(base, {
      grant_type: "authorization_code",
      code: firstCode,
      redirect_uri: redirectUri,
      client_id: client1,
      code_verifier: verifier,
    });
    checks.push([
      "without offline_access the exchange has no refresh token",
      firstToken.status === 200 &&
        (firstToken.body as { refresh_token?: unknown } | undefined)?.refresh_token === undefined,
    ]);

    // --- already approved: no screen; a new offline_access scope must not go silently ----------
    const repeated = await authorize(client1, "repeat", "openid profile email", { prompt: "none" }, cookie);
    checks.push([
      "an already approved scope set skips the screen silently",
      repeated.status === 302 && codeOf(repeated) !== null && errorOf(repeated) === null,
    ]);
    const offlineSilent = await authorize(
      client1,
      "offline-silent",
      "openid profile email offline_access",
      { prompt: "none" },
      cookie,
    );
    checks.push([
      "a new offline_access scope is not granted silently",
      offlineSilent.status === 302 && errorOf(offlineSilent) === "consent_required",
    ]);
    const offlineOpened = await authorize(
      client1,
      "offline-screen",
      "openid profile email offline_access",
      {},
      cookie,
    );
    const offlineIid = interactionOf(offlineOpened);
    const offlineDetails = offlineIid === null
      ? undefined
      : await call(`${base}/t/${TENANT}/interaction/${encodeURIComponent(offlineIid)}`, {
          headers: { cookie },
        });
    const offlineConsent = offlineIid === null ? undefined : await consent(offlineIid, true);
    const offlineCode = offlineConsent === undefined ? null : codeOf(offlineConsent);
    checks.push([
      "the offline_access screen names only the new scope and grants a refresh token",
      offlineOpened.status === 302 && offlineIid !== null &&
        sameStringList(
          (offlineDetails?.body as { consent_scopes?: unknown } | undefined)?.consent_scopes,
          ["offline_access"],
        ) &&
        offlineConsent?.status === 200 && offlineCode !== null,
    ]);
    if (offlineCode === null) return consentSemanticsFail(t, "offline consent did not issue a code");
    const offlineToken = await tokenCall(base, {
      grant_type: "authorization_code",
      code: offlineCode,
      redirect_uri: redirectUri,
      client_id: client1,
      code_verifier: verifier,
    });
    const liveRefresh = (offlineToken.body as { refresh_token?: unknown } | undefined)?.refresh_token;
    checks.push([
      "the offline_access grant issues a refresh token",
      offlineToken.status === 200 && typeof liveRefresh === "string",
    ]);

    // --- incremental scope: one screen naming only projects:read --------------------------------
    const incrementalSilent = await authorize(
      client1,
      "incremental-silent",
      scopes,
      { prompt: "none" },
      cookie,
    );
    checks.push([
      "a new incremental scope is not silently approved",
      incrementalSilent.status === 302 && errorOf(incrementalSilent) === "consent_required",
    ]);
    const incrementalOpened = await authorize(client1, "incremental", scopes, {}, cookie);
    const incrementalIid = interactionOf(incrementalOpened);
    const incrementalDetails = incrementalIid === null
      ? undefined
      : await call(`${base}/t/${TENANT}/interaction/${encodeURIComponent(incrementalIid)}`, {
          headers: { cookie },
        });
    const incrementalConsent = incrementalIid === null ? undefined : await consent(incrementalIid, true);
    checks.push([
      "the incremental screen carries only the newly requested scope",
      incrementalOpened.status === 302 && incrementalIid !== null &&
        sameStringList(
          (incrementalDetails?.body as { consent_scopes?: unknown } | undefined)?.consent_scopes,
          ["projects:read"],
        ) &&
        incrementalConsent?.status === 200 && codeOf(incrementalConsent) !== null,
    ]);
    const silentAll = await authorize(client1, "all-silent", scopes, { prompt: "none" }, cookie);
    checks.push([
      "after the incremental approval the full scope set is silent again",
      silentAll.status === 302 && codeOf(silentAll) !== null && errorOf(silentAll) === null,
    ]);

    const overScope = await authorize(client1, "over", "openid admin:all", {}, cookie);
    checks.push([
      "a scope outside the client registration is invalid_scope",
      overScope.status === 302 && errorOf(overScope) === "invalid_scope",
    ]);

    // --- partial approval: the account allows a subset and refuses offline_access ---------------
    const partialOpened = await authorize(client3, "partial", scopes, {}, cookie);
    const partialIid = interactionOf(partialOpened);
    const partialConsent = partialIid === null
      ? undefined
      : await consent(partialIid, true, ["openid", "profile"]);
    const partialCode = partialConsent === undefined ? null : codeOf(partialConsent);
    checks.push([
      "a partial approval issues a code for the approved subset only",
      partialOpened.status === 302 && partialIid !== null && partialConsent?.status === 200 &&
        partialCode !== null,
    ]);
    if (partialCode === null) return consentSemanticsFail(t, "partial consent did not issue a code");
    const partialToken = await tokenCall(base, {
      grant_type: "authorization_code",
      code: partialCode,
      redirect_uri: redirectUri,
      client_id: client3,
      code_verifier: verifier,
    });
    checks.push([
      "the token carries only the approved scopes and, without offline_access, no refresh token",
      partialToken.status === 200 &&
        sameStringList(scopeOf(partialToken.body), ["openid", "profile"]) &&
        (partialToken.body as { refresh_token?: unknown } | undefined)?.refresh_token === undefined,
    ]);
    const partialSilent = await authorize(
      client3,
      "partial-silent",
      "openid profile email",
      { prompt: "none" },
      cookie,
    );
    checks.push([
      "the remembered subset does not cover the unapproved scope",
      partialSilent.status === 302 && errorOf(partialSilent) === "consent_required",
    ]);

    // --- a fresh password sign-in sees only the scopes this account has not approved -----------
    const freshOpened = await authorize(client3, "fresh", "openid profile email");
    const freshIid = interactionOf(freshOpened);
    const freshSignIn = freshIid === null
      ? undefined
      : await call(`${base}/t/${TENANT}/interaction/${encodeURIComponent(freshIid)}/sign-in`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ identifier: email, password }),
        });
    const freshSession = /monaca_session=([0-9a-f-]{36})/.exec(
      freshSignIn?.headers.get("set-cookie") ?? "",
    )?.[1];
    const freshCookie = freshSession === undefined ? undefined : `monaca_session=${freshSession}`;
    const freshDetails = freshIid === null || freshCookie === undefined
      ? undefined
      : await call(`${base}/t/${TENANT}/interaction/${encodeURIComponent(freshIid)}`, {
          headers: { cookie: freshCookie },
        });
    checks.push([
      "a fresh sign-in exposes only the scopes the remembered approval does not cover",
      freshOpened.status === 302 && freshIid !== null && freshSignIn?.status === 200 &&
        freshCookie !== undefined &&
        sameStringList(
          (freshDetails?.body as { consent_scopes?: unknown } | undefined)?.consent_scopes,
          ["email"],
        ),
    ]);

    // --- refusing every scope is the existing deny path ------------------------------------------
    const allDenyOpened = await authorize(
      client3,
      "deny-all-screen",
      "openid profile email",
      { prompt: "consent" },
      cookie,
    );
    const allDenyIid = interactionOf(allDenyOpened);
    const allDeny = allDenyIid === null ? undefined : await consent(allDenyIid, true, []);
    checks.push([
      "refusing every scope answers access_denied and mints no code",
      allDenyOpened.status === 302 && allDenyIid !== null && allDeny?.status === 200 &&
        errorOf(allDeny) === "access_denied" && codeOf(allDeny) === null,
    ]);
    const allDenyReplay = allDenyIid === null ? undefined : await consent(allDenyIid, true, []);
    checks.push([
      "a refused interaction is consumed, so a replay cannot half-issue a code",
      allDenyReplay !== undefined && allDenyReplay.status >= 400 && codeOf(allDenyReplay) === null,
    ]);

    const badSubsetOpened = await authorize(
      client3,
      "bad-subset",
      "openid profile",
      { prompt: "consent" },
      cookie,
    );
    const badSubsetIid = interactionOf(badSubsetOpened);
    const badSubset = badSubsetIid === null
      ? undefined
      : await consent(badSubsetIid, true, ["email"]);
    checks.push([
      "an allowed scope outside the request is rejected",
      badSubsetOpened.status === 302 && badSubsetIid !== null && badSubset?.status === 400,
    ]);

    // --- one-shot: approved once, listed, revocable, and never covers the next request ----------
    const oneOpened = await authorize(client2, "one", scopes, {}, cookie);
    const oneIid = interactionOf(oneOpened);
    const oneConsent = oneIid === null ? undefined : await consent(oneIid, false);
    const oneCode = oneConsent === undefined ? null : codeOf(oneConsent);
    checks.push([
      "a one-shot approval issues a code without remembering",
      oneOpened.status === 302 && oneIid !== null && oneConsent?.status === 200 && oneCode !== null,
    ]);
    if (oneCode === null) return consentSemanticsFail(t, "one-shot consent did not issue a code");
    const oneToken = await tokenCall(base, {
      grant_type: "authorization_code",
      code: oneCode,
      redirect_uri: redirectUri,
      client_id: client2,
      code_verifier: verifier,
    });
    const oneRefresh = (oneToken.body as { refresh_token?: unknown } | undefined)?.refresh_token;
    const oneSilent = await authorize(client2, "one-silent", scopes, { prompt: "none" }, cookie);
    checks.push([
      "one-shot does not cover the next silent request",
      typeof oneRefresh === "string" && oneSilent.status === 302 &&
        errorOf(oneSilent) === "consent_required",
    ]);

    // --- one client holding both a remembered and a one-shot approval ---------------------------
    const mixedOpened = await authorize(client1, "mixed", scopes, { prompt: "consent" }, cookie);
    const mixedIid = interactionOf(mixedOpened);
    const mixedConsent = mixedIid === null ? undefined : await consent(mixedIid, false);
    checks.push([
      "a forced screen records a one-shot approval beside the remembered one",
      mixedOpened.status === 302 && mixedIid !== null && mixedConsent?.status === 200 &&
        codeOf(mixedConsent) !== null,
    ]);

    type AppRow = {
      client_id?: unknown;
      remember?: unknown;
      scopes?: unknown;
      kinds?: unknown;
    };
    const listed = await call(`${base}/t/${TENANT}/account/authorized-apps`, {
      headers: { cookie },
    });
    const items = (listed.body as { items?: AppRow[] } | undefined)?.items ?? [];
    const rememberRow = items.find((row) => row.client_id === client1);
    const oneShotRow = items.find((row) => row.client_id === client2);
    checks.push([
      "the account centre distinguishes remembered and one-shot approvals",
      listed.status === 200 && rememberRow?.remember === true &&
        oneShotRow?.remember === false,
    ]);
    const mixedRows = items.filter((row) => row.client_id === client1);
    checks.push([
      "one client's remembered and one-shot approvals are listed as a single entry",
      mixedRows.length === 1 && rememberRow?.remember === true &&
        Array.isArray(rememberRow?.kinds) &&
        (rememberRow.kinds as unknown[]).includes("remember") &&
        (rememberRow.kinds as unknown[]).includes("one_shot"),
    ]);

    const withdrawn = await call(
      `${base}/t/${TENANT}/account/authorized-apps/${encodeURIComponent(client2)}`,
      { method: "DELETE", headers: { cookie } },
    );
    const dead = await tokenCall(base, {
      grant_type: "refresh_token",
      refresh_token: String(oneRefresh ?? ""),
      client_id: client2,
    });
    checks.push([
      "withdrawing a one-shot approval revokes its refresh token",
      withdrawn.status === 204 && dead.status === 400 &&
        (dead.body as { error?: unknown } | undefined)?.error === "invalid_grant",
    ]);

    const mixedWithdrawn = await call(
      `${base}/t/${TENANT}/account/authorized-apps/${encodeURIComponent(client1)}`,
      { method: "DELETE", headers: { cookie } },
    );
    const afterMixed = await call(`${base}/t/${TENANT}/account/authorized-apps`, {
      headers: { cookie },
    });
    const mixedGone = ((afterMixed.body as { items?: AppRow[] } | undefined)?.items ?? []).every(
      (row) => row.client_id !== client1,
    );
    const mixedRefreshDead = await tokenCall(base, {
      grant_type: "refresh_token",
      refresh_token: String(liveRefresh ?? ""),
      client_id: client1,
    });
    const mixedSilentAgain = await authorize(client1, "mixed-gone", scopes, { prompt: "none" }, cookie);
    checks.push([
      "withdrawing an aggregated entry clears both kinds, its refresh token and the remembered access",
      mixedWithdrawn.status === 204 && mixedGone && mixedRefreshDead.status === 400 &&
        (mixedRefreshDead.body as { error?: unknown } | undefined)?.error === "invalid_grant" &&
        mixedSilentAgain.status === 302 && errorOf(mixedSilentAgain) === "consent_required",
    ]);

    const audit = await call(
      `${base}/internal/audit?${new URLSearchParams({
        tenant: TENANT,
        action: "consent.granted",
        limit: "100",
      })}`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    type AuditRow = {
      payload?: {
        client_id?: unknown;
        mode?: unknown;
        remember?: unknown;
        scopes?: unknown;
        interaction_id?: unknown;
      };
    };
    const events = (audit.body as { items?: AuditRow[] } | undefined)?.items ?? [];
    const silentEvent = events.find(
      (event) =>
        event.payload?.client_id === client1 &&
        event.payload?.mode === "silent" &&
        event.payload?.remember === true,
    );
    const oneShotEvent = events.find(
      (event) => event.payload?.client_id === client2 && event.payload?.remember === false,
    );
    checks.push([
      "silent and interactive consent decisions are audited with scope and interaction",
      audit.status === 200 &&
        typeof silentEvent?.payload?.interaction_id === "string" &&
        Array.isArray(silentEvent?.payload?.scopes) &&
        (silentEvent.payload.scopes as unknown[]).includes("offline_access") &&
        oneShotEvent?.payload?.mode === "interactive" &&
        Array.isArray(oneShotEvent?.payload?.scopes),
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    for (const id of [client1Row, client2Row, client3Row]) {
      if (typeof id === "string") {
        await call(`${base}/v1/clients/${id}`, { method: "DELETE", headers }).catch(() => undefined);
      }
    }
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "57",
    title: "consent semantics",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: first consent → silent repeat → offline_access gate → incremental scope → partial allow → fresh sign-in scopes → all-deny → one-shot → aggregation → revocation → audit`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

function consentSemanticsFail(t: number, why: string): StepResult {
  return {
    step: "57",
    title: "consent semantics",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why,
  };
}

/**
 * Step 51: mail copy is per tenant, rendered at send time, and restorable.
 *
 * The proof that a template is more than a stored string is the outbox: after a custom sign-up
 * template is saved, the dev mail for a real sign-up carries the tenant's words with the code and
 * expiry filled in — not the built-in sentence and not a literal `{{code}}`.
 */
async function emailTemplatesFlow(
  base: string,
  adminToken: string,
  internalSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const redirectUri = "http://localhost:5173/bff/callback";
  const email = `mail-copy-${runId}@demo.localhost`;
  const customSubject = "E2E {{tenant}} access code";
  const customBody = "Hello from {{tenant}}. Use {{code}} within {{expires_in}} minutes.";

  try {
    const before = await call(`${base}/v1/email-templates`, { headers });
    const items =
      (
        before.body as
          | { items?: { purpose?: unknown; customized?: unknown; subject?: unknown; variables?: unknown }[] }
          | undefined
      )?.items ?? [];
    const purposes = items.map((item) => item.purpose);
    const signUpBefore = items.find((item) => item.purpose === "sign_up");
    checks.push([
      "the nine purposes are listed with the built-in sign-up copy",
      before.status === 200 &&
        purposes.length === 9 &&
        purposes[0] === "sign_up" &&
        signUpBefore?.customized === false &&
        signUpBefore?.subject === "Your {{tenant}} verification code" &&
        Array.isArray(signUpBefore?.variables) &&
        signUpBefore.variables.includes("code"),
    ]);

    const saved = await call(`${base}/v1/email-templates/sign_up`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ subject: customSubject, body: customBody }),
    });
    checks.push([
      "a custom copy is stored and marked customized",
      saved.status === 200 &&
        (saved.body as { subject?: unknown })?.subject === customSubject &&
        (saved.body as { customized?: unknown })?.customized === true,
    ]);

    const [unknownPlaceholder, emptySubject, missingPurpose] = await Promise.all([
      call(`${base}/v1/email-templates/sign_up`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ subject: "Has {{typo}}", body: customBody }),
      }),
      call(`${base}/v1/email-templates/sign_up`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ subject: " ", body: customBody }),
      }),
      call(`${base}/v1/email-templates/no_such_purpose`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ subject: "Any", body: "Any" }),
      }),
    ]);
    checks.push([
      "an unknown placeholder, an empty subject and an unknown purpose are refused",
      unknownPlaceholder?.status === 400 &&
        emptySubject?.status === 400 &&
        missingPurpose?.status === 404,
    ]);

    // A real sign-up asks the server to mail the code; the outbox shows what the recipient reads.
    const verifier = `et-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const authorize = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: "monaca-console",
        redirect_uri: redirectUri,
        scope: "openid profile email",
        state: `st-email-template-${runId}`,
        nonce: `n-email-template-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(authorize.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    const requested =
      interaction === null
        ? undefined
        : await call(`${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-up`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ email }),
          });
    checks.push([
      "a sign-up interaction requests a code",
      authorize.status === 302 &&
        typeof interaction === "string" &&
        requested?.status === 200 &&
        (requested.body as { verification_required?: unknown })?.verification_required === true,
    ]);

    const mail = await call(
      `${base}/internal/mail?${new URLSearchParams({ tenant: TENANT, to: email, purpose: "sign_up" })}`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    const payload =
      (
        mail.body as
          | { payload?: { subject?: unknown; body?: unknown; code?: unknown } }
          | undefined
      )?.payload;
    const outboxBody = typeof payload?.body === "string" ? payload.body : "";
    checks.push([
      "the outbox carries the rendered copy, not the placeholders",
      mail.status === 200 &&
        payload?.subject === "E2E demo access code" &&
        typeof payload?.code === "string" &&
        outboxBody.includes(payload.code) &&
        outboxBody.includes("Hello from demo.") &&
        !outboxBody.includes("{{"),
    ]);

    const restored = await call(`${base}/v1/email-templates/sign_up`, { method: "DELETE", headers });
    const afterReset = await call(`${base}/v1/email-templates`, { headers });
    const signUpAfter = (
      afterReset.body as
        | { items?: { purpose?: unknown; customized?: unknown; subject?: unknown }[] }
        | undefined
    )?.items?.find((item) => item.purpose === "sign_up");
    checks.push([
      "DELETE restores the built-in copy",
      restored.status === 204 &&
        signUpAfter?.customized === false &&
        signUpAfter?.subject === "Your {{tenant}} verification code",
    ]);

    const secondReset = await call(`${base}/v1/email-templates/sign_up`, {
      method: "DELETE",
      headers,
    });
    checks.push(["a second reset is still 204", secondReset.status === 204]);

    const updatedAudit = await call(
      `${base}/internal/audit?tenant=${TENANT}&action=email_template.updated&limit=20`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    const resetAudit = await call(
      `${base}/internal/audit?tenant=${TENANT}&action=email_template.reset&limit=20`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    const updatedEvents =
      (
        updatedAudit.body as
          | { items?: { payload?: { purpose?: unknown; subject?: unknown } }[] }
          | undefined
      )?.items ?? [];
    const resetEvents =
      (resetAudit.body as { items?: { payload?: { purpose?: unknown } }[] } | undefined)?.items ?? [];
    checks.push([
      "both writes are on the tenant audit chain",
      updatedAudit.status === 200 &&
        updatedEvents[0]?.payload?.purpose === "sign_up" &&
        updatedEvents[0]?.payload?.subject === customSubject &&
        resetAudit.status === 200 &&
        resetEvents[0]?.payload?.purpose === "sign_up",
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "51",
    title: "email templates",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: defaults → custom copy → refused typo/empty/unknown → rendered outbox → reset → audit`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 53: a registered application's CORS origins gate browser preflights.
 *
 * The client is created with one foreign origin in a non-canonical form, so the check covers both
 * normalization and the runtime header. The same client then exercises the refusal cases, a
 * preflight, a JWKS read from the registered origin, an unregistered origin, and clearing the list.
 */
async function corsFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";
  const sameStringList = (value: unknown, expected: string[]): boolean =>
    Array.isArray(value) &&
    value.length === expected.length &&
    expected.every((item, index) => value[index] === item);

  const origin = "https://app.example.com";
  const clientId = `cors-${runId}`;
  const redirectUri = "http://localhost:5173/bff/callback";
  let rowId: string | undefined;
  const fail = (why: string): StepResult => ({
    step: "53",
    title: "application CORS",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });

  const preflight = (requestOrigin: string): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/oauth2/token`, {
      method: "OPTIONS",
      headers: {
        origin: requestOrigin,
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type",
      },
    });

  try {
    const created = await call(`${base}/v1/clients`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        client_id: clientId,
        name: "E2E CORS",
        kind: "public",
        redirect_uris: [redirectUri],
        scopes: ["openid"],
        cors_allowed_origins: ["https://App.Example.com:443/"],
      }),
    });
    const createdBody = created.body as { id?: unknown; cors_allowed_origins?: unknown } | undefined;
    rowId = typeof createdBody?.id === "string" ? createdBody.id : undefined;
    checks.push([
      "POST /v1/clients canonicalizes https://App.Example.com:443/ to the bare origin",
      created.status === 201 &&
        typeof rowId === "string" &&
        sameStringList(createdBody?.cors_allowed_origins, [origin]),
    ]);
    if (rowId === undefined) return fail(`POST /v1/clients → ${created.status} ${text(created.body)}`);

    const patch = (origins: unknown): Promise<HttpResult> =>
      call(`${base}/v1/clients/${rowId}`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ cors_allowed_origins: origins }),
      });
    const [wildcard, path, query, userinfo, longOrigin, many] = await Promise.all([
      patch(["*"]),
      patch([`${origin}/path`]),
      patch([`${origin}?x=1`]),
      patch(["https://user:pass@app.example.com"]),
      patch([`https://${"a".repeat(260)}.example`]),
      patch(Array.from({ length: 33 }, (_, index) => `https://app${index}.example.com`)),
    ]);
    checks.push([
      "a wildcard, a path, a query, userinfo, an origin over 255 characters and 33 entries are 400",
      wildcard.status === 400 &&
        path.status === 400 &&
        query.status === 400 &&
        userinfo.status === 400 &&
        longOrigin.status === 400 &&
        many.status === 400,
    ]);

    const allowed = await preflight(origin);
    checks.push([
      "a preflight from the registered origin is 204 with the allow-origin, credentials and methods",
      allowed.status === 204 &&
        allowed.headers.get("access-control-allow-origin") === origin &&
        allowed.headers.get("access-control-allow-credentials") === "true" &&
        (allowed.headers.get("access-control-allow-methods") ?? "").includes("POST"),
    ]);

    const jwks = await call(`${base}/t/${TENANT}/.well-known/jwks.json`, {
      headers: { origin },
    });
    checks.push([
      "a JWKS read from the registered origin carries the allow-origin header",
      jwks.status === 200 && jwks.headers.get("access-control-allow-origin") === origin,
    ]);

    const stranger = await preflight("https://stranger.example");
    checks.push([
      "an unregistered origin gets no allow-origin header",
      stranger.headers.get("access-control-allow-origin") === null,
    ]);

    const cleared = await patch([]);
    const afterClear = await preflight(origin);
    checks.push([
      "clearing the list removes the header",
      cleared.status === 200 && afterClear.headers.get("access-control-allow-origin") === null,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    if (rowId !== undefined) {
      await call(`${base}/v1/clients/${rowId}`, { method: "DELETE", headers });
    }
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "53",
    title: "application CORS",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: canonical origin → refusals → preflight → JWKS → stranger → clear`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 56: a tenant's username policy governs new claims without invalidating old ones.
 *
 * The walk-through first creates a legacy username under the old grammar, then tightens the
 * punctuation set so that name would now be refused, and signs in with it anyway: validation
 * runs on creation and on a username change, never on sign-in. The remaining checks use the
 * resulting policy: punctuation, length, reserved words, the email-local-part switch, and the
 * display form kept for a case-insensitive tenant.
 */
async function usernamePolicyFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";
  const fail = (why: string): StepResult => ({
    step: "56",
    title: "username policy",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why,
  });
  const sameStringList = (value: unknown, expected: string[]): boolean =>
    Array.isArray(value) &&
    value.length === expected.length &&
    expected.every((item, index) => value[index] === item);

  const redirectUri = "http://localhost:5173/bff/callback";
  const patch = (body: Record<string, unknown>): Promise<HttpResult> =>
    call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify(body),
    });

  const begin = async (
    tag: string,
  ): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `un-${tag}-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const started = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: "monaca-console",
        redirect_uri: redirectUri,
        scope: "openid profile email",
        state: `st-username-${tag}-${runId}`,
        nonce: `n-username-${tag}-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(started.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    if (started.status !== 302 || interaction === null) return undefined;
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  const signUp = (
    target: { interaction: string },
    body: Record<string, unknown>,
  ): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/interaction/${target.interaction}/sign-up`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });

  const signIn = async (identifier: string, password: string): Promise<HttpResult> => {
    const target = await begin("signin");
    if (target === undefined) return { status: 0, body: undefined, headers: new Headers() };
    return call(`${base}/t/${TENANT}/interaction/${target.interaction}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier, password }),
    });
  };

  const directoryUsername = async (email: string): Promise<unknown> => {
    const found = await call(
      `${base}/v1/accounts?${new URLSearchParams({ query: email, limit: "5" })}`,
      { headers },
    );
    const id = (found.body as { items?: { id?: unknown }[] } | undefined)?.items?.[0]?.id;
    if (typeof id !== "string") return undefined;
    const account = await call(`${base}/v1/accounts/${id}`, { headers });
    return (account.body as { username?: unknown } | undefined)?.username;
  };

  const legacy = {
    sign_up_identifiers: ["email", "username"],
    sign_up_email_verification_required: false,
    username_case_sensitive: false,
    username_min_length: 3,
    username_max_length: 16,
    username_allowed_punctuation: ["_", "-"],
    username_allow_email_local_part: true,
    username_preserve_case: false,
    username_reserved_words: [],
    sign_up_profile_fields: ["name"],
  };
  const policy = {
    ...legacy,
    username_min_length: 4,
    username_allowed_punctuation: ["_", "-", "."],
    username_allow_email_local_part: false,
    username_preserve_case: true,
    username_reserved_words: ["admin", "support"],
  };
  const defaults = {
    sign_up_identifiers: ["email"],
    sign_up_email_verification_required: true,
    username_case_sensitive: false,
    username_min_length: 3,
    username_max_length: 32,
    username_allowed_punctuation: ["_", "-"],
    username_allow_email_local_part: true,
    username_preserve_case: false,
    username_reserved_words: [],
    sign_up_profile_fields: ["name"],
  };

  const legacyEmail = `legacy-${runId}@demo.localhost`;
  const legacyPassword = `pw-${runId}-legacy-username`;
  const legacyUsername = `old-${runId}`;
  const validEmail = `good-${runId}@demo.localhost`;
  const validPassword = `pw-${runId}-good-username`;

  try {
    const [badPunctuation, duplicatePunctuation, shortReserved, contradiction] = await Promise.all([
      patch({ username_allowed_punctuation: ["*"] }),
      patch({ username_allowed_punctuation: ["_", "_"] }),
      patch({ username_reserved_words: ["ab"] }),
      patch({ username_case_sensitive: true, username_preserve_case: true }),
    ]);
    checks.push([
      "an unknown or duplicate punctuation character, a short reserved word and case-sensitive display preservation are 400",
      badPunctuation.status === 400 &&
        duplicatePunctuation.status === 400 &&
        shortReserved.status === 400 &&
        contradiction.status === 400,
    ]);

    const legacyPolicy = await patch(legacy);
    checks.push([
      "the legacy policy is accepted",
      legacyPolicy.status === 200 &&
        (legacyPolicy.body as { username_allowed_punctuation?: unknown } | undefined)
          ?.username_allowed_punctuation !== undefined,
    ]);

    const legacyTarget = await begin("legacy");
    if (legacyTarget === undefined) return fail(detail);
    const legacySignUp = await signUp(legacyTarget, {
      email: legacyEmail,
      password: legacyPassword,
      username: legacyUsername,
      display_name: "Legacy username",
    });
    checks.push([
      "a legacy username with a hyphen is created under the old grammar",
      legacySignUp.status === 200 && (await directoryUsername(legacyEmail)) === legacyUsername,
    ]);

    const tightened = await patch({
      username_allowed_punctuation: [],
      username_preserve_case: false,
    });
    checks.push([
      "removing the hyphen from the grammar is accepted",
      tightened.status === 200 &&
        sameStringList(
          (tightened.body as { username_allowed_punctuation?: unknown } | undefined)
            ?.username_allowed_punctuation,
          [],
        ),
    ]);

    const legacySignIn = await signIn(legacyUsername, legacyPassword);
    checks.push([
      "an existing username that no longer satisfies the grammar still signs in",
      legacySignIn.status === 200,
    ]);

    const hyphenTarget = await begin("hyphen");
    const hyphenSignUp = await signUp(hyphenTarget ?? { interaction: "" }, {
      email: `hyphen-${runId}@demo.localhost`,
      password: `pw-${runId}-hyphen`,
      username: `new-${runId}`,
    });
    checks.push([
      "a new username using the now-disallowed hyphen is 400",
      hyphenSignUp.status === 400 &&
        (hyphenSignUp.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_INVALID_REQUEST",
    ]);

    const written = await patch(policy);
    checks.push([
      "the strict policy is stored and echoed",
      written.status === 200 &&
        sameStringList(
          (written.body as { username_allowed_punctuation?: unknown } | undefined)
            ?.username_allowed_punctuation,
          policy.username_allowed_punctuation,
        ) &&
        (written.body as { username_preserve_case?: unknown } | undefined)?.username_preserve_case ===
          true &&
        (written.body as { username_allow_email_local_part?: unknown } | undefined)
          ?.username_allow_email_local_part === false,
    ]);

    const validTarget = await begin("valid");
    const validSignUp = validTarget === undefined
      ? undefined
      : await signUp(validTarget, {
          email: validEmail,
          password: validPassword,
          username: `good.${runId}`,
          display_name: "Good username",
        });
    checks.push([
      "a valid username with the configured punctuation passes",
      validSignUp?.status === 200,
    ]);

    const [badCharacter, tooLong, reserved] = await Promise.all([
      signUp((await begin("bad-char")) ?? { interaction: "" }, {
        email: `bad-char-${runId}@demo.localhost`,
        password: `pw-${runId}-bad-char`,
        username: `bad*${runId}`,
      }),
      signUp((await begin("long")) ?? { interaction: "" }, {
        email: `long-${runId}@demo.localhost`,
        password: `pw-${runId}-long`,
        username: "a".repeat(17),
      }),
      signUp((await begin("reserved")) ?? { interaction: "" }, {
        email: `reserved-${runId}@demo.localhost`,
        password: `pw-${runId}-reserved`,
        username: "Admin",
      }),
    ]);
    checks.push([
      "an illegal character, an over-long name and a reserved word are 400",
      badCharacter.status === 400 && tooLong.status === 400 && reserved.status === 400 &&
        (reserved.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_INVALID_REQUEST",
    ]);

    const localEmail = `local.${runId}@demo.localhost`;
    const localUsername = `local.${runId}`;
    const localTarget = await begin("local");
    const localRefused = localTarget === undefined
      ? undefined
      : await signUp(localTarget, {
          email: localEmail,
          password: `pw-${runId}-local`,
          username: localUsername,
        });
    const allowLocal = await patch({ username_allow_email_local_part: true });
    const localAllowed = localTarget === undefined
      ? undefined
      : await signUp(localTarget, {
          email: localEmail,
          password: `pw-${runId}-local`,
          username: localUsername,
        });
    checks.push([
      "the email-local-part switch refuses the match and then allows it",
      localRefused?.status === 400 &&
        allowLocal.status === 200 &&
        localAllowed?.status === 200,
    ]);
    await patch({ username_allow_email_local_part: false });

    const caseEmail = `case-${runId}@demo.localhost`;
    const caseUsername = `Case.${runId}`;
    const caseTarget = await begin("case");
    const caseSignUp = caseTarget === undefined
      ? undefined
      : await signUp(caseTarget, {
          email: caseEmail,
          password: `pw-${runId}-case`,
          username: caseUsername,
        });
    const stored = await directoryUsername(caseEmail);
    const caseSignIn = await signIn(caseUsername.toLowerCase(), `pw-${runId}-case`);
    const duplicateTarget = await begin("duplicate");
    const duplicate = duplicateTarget === undefined
      ? undefined
      : await signUp(duplicateTarget, {
          email: `case-dup-${runId}@demo.localhost`,
          password: `pw-${runId}-case-dup`,
          username: caseUsername.toUpperCase(),
        });
    checks.push([
      "case is preserved for display, matched case-insensitively and unique after folding",
      caseSignUp?.status === 200 &&
        stored === caseUsername &&
        caseSignIn.status === 200 &&
        duplicate?.status === 409 &&
        (duplicate.body as { monaca_error_code?: unknown } | undefined)?.monaca_error_code ===
          "MONACA_USERNAME_TAKEN",
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await patch(defaults);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "56",
    title: "username policy",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: validation → legacy exemption → punctuation/length/reserved → email local part → display case`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 55: an HTTP mail connector delivers rendered outbox mail to the tenant's endpoint.
 *
 * The receiver is a local `Bun.serve` with a random port, so the assertion is about what a provider
 * actually receives — JSON body, bearer token — rather than an internal function. A tenant with no
 * connector still keeps its mail only in the outbox; configuring one does not move templates, it
 * only moves transport.
 */
async function emailConnectorFlow(
  base: string,
  adminToken: string,
  internalSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const secret = `mail-secret-${runId}`;
  const fromAddress = "no-reply@demo.localhost";
  const fromName = "Monaca Demo";
  const email = `mail-connector-${runId}@demo.localhost`;
  const received: { authorization: string | null; body: Record<string, unknown> }[] = [];

  const receiver = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(request) {
      const url = new URL(request.url);
      if (request.method !== "POST" || url.pathname !== "/mail") {
        return new Response("not found", { status: 404 });
      }
      let body: Record<string, unknown> = {};
      try {
        body = (await request.json()) as Record<string, unknown>;
      } catch {
        // A non-JSON request is still recorded, so the failing assertion shows what arrived.
      }
      received.push({ authorization: request.headers.get("authorization"), body });
      return new Response("ok");
    },
  });
  const endpoint = `http://127.0.0.1:${receiver.port}/mail`;

  try {
    const before = await call(`${base}/v1/email-connector`, { headers });
    checks.push([
      "an unconfigured tenant reads configured:false",
      before.status === 200 && (before.body as { configured?: unknown })?.configured === false,
    ]);

    const configured = await call(`${base}/v1/email-connector`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        provider: "http",
        endpoint,
        from_address: fromAddress,
        from_name: fromName,
        secret,
        enabled: true,
      }),
    });
    const configuredJson = configured.body as Record<string, unknown> | undefined;
    checks.push([
      "PATCH stores the route, reports secret_set and never echoes the secret",
      configured.status === 200 &&
        configuredJson?.configured === true &&
        configuredJson?.provider === "http" &&
        configuredJson?.endpoint === endpoint &&
        configuredJson?.from_address === fromAddress &&
        configuredJson?.from_name === fromName &&
        configuredJson?.secret_set === true &&
        !Object.hasOwn(configuredJson ?? {}, "secret") &&
        !JSON.stringify(configuredJson).includes(secret),
    ]);

    const [smtp, ftp, userinfo, badFrom] = await Promise.all([
      call(`${base}/v1/email-connector`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ provider: "smtp", endpoint, from_address: fromAddress }),
      }),
      call(`${base}/v1/email-connector`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ provider: "http", endpoint: "ftp://mail.example/send", from_address: fromAddress }),
      }),
      call(`${base}/v1/email-connector`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ provider: "http", endpoint: "https://user:pass@mail.example/send", from_address: fromAddress }),
      }),
      call(`${base}/v1/email-connector`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ provider: "http", endpoint, from_address: "not-an-address" }),
      }),
    ]);
    checks.push([
      "smtp, a non-http endpoint, embedded credentials and a malformed sender are 400",
      smtp.status === 400 && ftp.status === 400 && userinfo.status === 400 && badFrom.status === 400,
    ]);

    // A real sign-up asks the server to queue mail; the connector is the only reason it leaves.
    const verifier = `ec-${runId}-${"q".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const authorize = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: "monaca-console",
        redirect_uri: "http://localhost:5173/bff/callback",
        scope: "openid profile email",
        state: `st-mail-connector-${runId}`,
        nonce: `n-mail-connector-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(authorize.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    const requested =
      interaction === null
        ? undefined
        : await call(`${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-up`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ email }),
          });
    checks.push([
      "a sign-up interaction queues a verification code",
      authorize.status === 302 &&
        typeof interaction === "string" &&
        requested?.status === 200 &&
        (requested.body as { verification_required?: unknown })?.verification_required === true,
    ]);

    const deadline = performance.now() + 20_000;
    while (
      received.filter((entry) => entry.body.to === email).length === 0 &&
      performance.now() < deadline
    ) {
      await Bun.sleep(250);
    }
    const delivered = received.filter((entry) => entry.body.to === email);

    const mail = await call(
      `${base}/internal/mail?${new URLSearchParams({ tenant: TENANT, to: email, purpose: "sign_up" })}`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    const code = (mail.body as { payload?: { code?: unknown } } | undefined)?.payload?.code;
    const first = delivered[0];
    const firstBody = first?.body as
      | { id?: unknown; tenant?: unknown; purpose?: unknown; subject?: unknown; text?: unknown; from?: unknown; from_name?: unknown }
      | undefined;
    checks.push([
      "the provider receives one JSON message with the rendered copy and bearer token",
      delivered.length === 1 &&
        first?.authorization === `Bearer ${secret}` &&
        typeof firstBody?.id === "string" &&
        firstBody?.tenant === TENANT &&
        firstBody?.purpose === "sign_up" &&
        typeof firstBody?.subject === "string" &&
        typeof firstBody?.text === "string" &&
        typeof code === "string" &&
        firstBody.text.includes(code) &&
        firstBody?.from === fromAddress &&
        firstBody?.from_name === fromName,
    ]);

    const updatedAudit = await call(
      `${base}/internal/audit?tenant=${TENANT}&action=email_connector.updated&limit=20`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    const updatedEvents =
      (
        updatedAudit.body as
          | { items?: { payload?: { endpoint?: unknown; secret_set?: unknown } }[] }
          | undefined
      )?.items ?? [];
    checks.push([
      "the write is on the tenant audit chain without the secret",
      updatedAudit.status === 200 &&
        updatedEvents[0]?.payload?.endpoint === endpoint &&
        updatedEvents[0]?.payload?.secret_set === true,
    ]);

    const cleared = await call(`${base}/v1/email-connector`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        provider: "http",
        endpoint,
        from_address: fromAddress,
        from_name: fromName,
        secret: "",
      }),
    });
    checks.push([
      "an empty secret clears it",
      cleared.status === 200 && (cleared.body as { secret_set?: unknown })?.secret_set === false,
    ]);

    const removed = await call(`${base}/v1/email-connector`, { method: "DELETE", headers });
    const after = await call(`${base}/v1/email-connector`, { headers });
    checks.push([
      "DELETE is 204 and the route reads unconfigured",
      removed.status === 204 && (after.body as { configured?: unknown })?.configured === false,
    ]);

    const deletedAudit = await call(
      `${base}/internal/audit?tenant=${TENANT}&action=email_connector.deleted&limit=20`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    checks.push([
      "the delete is on the tenant audit chain",
      deletedAudit.status === 200 &&
        ((deletedAudit.body as { items?: unknown[] } | undefined)?.items?.length ?? 0) > 0,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await call(`${base}/v1/email-connector`, { method: "DELETE", headers });
    receiver.stop(true);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "55",
    title: "email delivery connector",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: unconfigured → route + secret_set → refusals → provider JSON + bearer → clear → delete → audit`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 37: an administrator can edit an account's profile, and the edit is audited.
 *
 * The username is a sign-in identifier, so its uniqueness and grammar are the same rules the
 * account centre enforces — this step proves the management entrance did not bypass them.
 */
async function accountProfileFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const makeAccount = async (tag: string) => {
    const email = `profile-${tag}-${runId}@demo.localhost`;
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Profile", password: `pw-${runId}-profile` }),
    });
    return { status: created.status, id: (created.body as { id?: string })?.id, email };
  };

  try {
    const first = await makeAccount("first");
    const second = await makeAccount("second");
    if (first.status !== 201 || first.id === undefined || second.status !== 201 || second.id === undefined) {
      return failProfile(`account creation → ${first.status}/${second.status}`);
    }

    const before = await call(`${base}/v1/accounts/${first.id}`, { headers });
    checks.push([
      "the detail starts without a username",
      before.status === 200 && (before.body as { username?: unknown })?.username === null,
    ]);

    const empty = await call(`${base}/v1/accounts/${first.id}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({}),
    });
    checks.push(["an empty profile patch is 400", empty.status === 400]);

    const blank = await call(`${base}/v1/accounts/${first.id}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ display_name: "   " }),
    });
    checks.push(["a blank display name is 400", blank.status === 400]);

    const badUsername = await call(`${base}/v1/accounts/${first.id}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ username: "Bad Name" }),
    });
    checks.push(["an invalid username is 400", badUsername.status === 400]);

    const username = `profile-${runId}`;
    const renamed = await call(`${base}/v1/accounts/${first.id}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ display_name: "Renamed Profile", username }),
    });
    checks.push([
      "PATCH writes the display name and username",
      renamed.status === 200 &&
        (renamed.body as { display_name?: unknown })?.display_name === "Renamed Profile" &&
        (renamed.body as { username?: unknown })?.username === username,
    ]);

    const echoed = await call(`${base}/v1/accounts/${first.id}`, { headers });
    checks.push([
      "GET echoes the edited profile",
      echoed.status === 200 &&
        (echoed.body as { display_name?: unknown })?.display_name === "Renamed Profile" &&
        (echoed.body as { username?: unknown })?.username === username,
    ]);

    const taken = await call(`${base}/v1/accounts/${second.id}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ username }),
    });
    checks.push([
      "a username another account holds is 409 MONACA_USERNAME_TAKEN",
      taken.status === 409 &&
        (taken.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_USERNAME_TAKEN",
    ]);

    const suspended = await call(`${base}/v1/accounts/${first.id}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ state: "disabled" }),
    });
    checks.push([
      "a state-only patch still suspends",
      suspended.status === 200 && (suspended.body as { state?: unknown })?.state === "disabled",
    ]);
    const reactivated = await call(`${base}/v1/accounts/${first.id}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ state: "active" }),
    });
    checks.push([
      "and reactivates",
      reactivated.status === 200 && (reactivated.body as { state?: unknown })?.state === "active",
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "37",
    title: "account profile editing",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: detail → empty 400 → blank 400 → bad username 400 → rename → GET → duplicate 409 → state`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };

  function failProfile(why: string): StepResult {
    return {
      step: "37",
      title: "account profile editing",
      status: "fail",
      ms: Math.round(performance.now() - t),
      detail: why,
    };
  }
}

/**
 * Step 38: a tenant tunes how long a browser stays signed in and how long refresh tokens live.
 *
 * The session lifetime is observable on the wire: the SSO cookie's `Max-Age` and the row listed by
 * the account centre must both carry the tenant value. The code exchange then mints a refresh token
 * under the tuned value; its exact expiry is not exposed by the API, so the assertion is that the
 * token is still issued rather than that a specific timestamp is stored.
 */
async function sessionSettingsFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const headers = managementHeaders(adminToken);
  const basic = btoa(`monaca-console:${consoleSecret}`);
  const email = `session-settings-${runId}@demo.localhost`;
  const password = `pw-${runId}-settings`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const lifetimes = (body: unknown) =>
    body as { session_ttl_secs?: unknown; refresh_token_ttl_secs?: unknown };

  const begin = async (): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `s-${runId}-${"z".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const started = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: "monaca-console",
        redirect_uri: redirectUri,
        scope: "openid profile email offline_access",
        state: `st-settings-${runId}`,
        nonce: `n-settings-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(started.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    if (started.status !== 302 || interaction === null) return undefined;
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  try {
    for (const body of [
      { session_ttl_secs: 3_599 },
      { session_ttl_secs: 7_776_001 },
      { refresh_token_ttl_secs: 3_599 },
      { refresh_token_ttl_secs: 31_536_001 },
    ]) {
      const refused = await call(`${base}/v1/sign-in-experience`, {
        method: "PATCH",
        headers,
        body: JSON.stringify(body),
      });
      checks.push([
        `a ${Object.keys(body)[0]} outside its range is 400`,
        refused.status === 400,
      ]);
    }

    const tuned = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ session_ttl_secs: 3_600, refresh_token_ttl_secs: 7_200 }),
    });
    checks.push([
      "PATCH writes a one-hour session and a two-hour refresh token",
      tuned.status === 200 &&
        lifetimes(tuned.body).session_ttl_secs === 3_600 &&
        lifetimes(tuned.body).refresh_token_ttl_secs === 7_200,
    ]);

    const publicRead = await call(`${base}/t/${TENANT}/sign-in-experience`);
    checks.push([
      "the public read follows both lifetimes",
      publicRead.status === 200 &&
        lifetimes(publicRead.body).session_ttl_secs === 3_600 &&
        lifetimes(publicRead.body).refresh_token_ttl_secs === 7_200,
    ]);

    // An account that is already a member, so the console interaction completes.
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Session settings", password }),
    });
    const accountId = (created.body as { id?: unknown })?.id;
    if (created.status !== 201 || typeof accountId !== "string") {
      return failSettings(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    const member = await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    checks.push(["the run's account joined acme", member.status === 201]);

    const interaction = await begin();
    if (interaction === undefined) return failSettings("authorize did not open an interaction");
    const signedIn = await call(
      `${base}/t/${TENANT}/interaction/${interaction.interaction}/sign-in`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password }),
      },
    );
    const setCookie = signedIn.headers.get("set-cookie") ?? "";
    const cookie = /monaca_session=([0-9a-f-]{36})/.exec(setCookie)?.[1];
    checks.push([
      "the SSO cookie carries the tenant's Max-Age",
      signedIn.status === 200 && cookie !== undefined && setCookie.includes("Max-Age=3600"),
    ]);

    if (cookie !== undefined) {
      const sessions = await call(`${base}/t/${TENANT}/account/sessions`, {
        headers: { cookie: `monaca_session=${cookie}` },
      });
      const items =
        (sessions.body as { items?: { current?: unknown; expires_at?: unknown }[] })?.items ?? [];
      const current = items.find((item) => item.current === true);
      const expiresAt =
        typeof current?.expires_at === "string" ? Date.parse(current.expires_at) - Date.now() : NaN;
      checks.push([
        "the stored session expires with the same value",
        !Number.isNaN(expiresAt) && expiresAt > 3_500_000 && expiresAt <= 3_600_001,
      ]);
    } else {
      checks.push(["the stored session expires with the same value", false]);
    }

    const redirectTo = (signedIn.body as { redirect_to?: unknown })?.redirect_to;
    const code =
      typeof redirectTo === "string" ? new URL(redirectTo).searchParams.get("code") ?? "" : "";
    const tokens = await tokenCall(
      base,
      {
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: "monaca-console",
        code_verifier: interaction.verifier,
      },
      basic,
    );
    checks.push([
      "the exchange mints a refresh token under the tuned lifetime",
      tokens.status === 200 &&
        typeof (tokens.body as { refresh_token?: unknown })?.refresh_token === "string",
    ]);

    const restored = await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ session_ttl_secs: 2_592_000, refresh_token_ttl_secs: 2_592_000 }),
    });
    checks.push([
      "the 30-day defaults are restored",
      restored.status === 200 &&
        lifetimes(restored.body).session_ttl_secs === 2_592_000 &&
        lifetimes(restored.body).refresh_token_ttl_secs === 2_592_000,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ session_ttl_secs: 2_592_000, refresh_token_ttl_secs: 2_592_000 }),
    }).catch(() => undefined);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "38",
    title: "session lifetimes",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: four 400s → one-hour session/two-hour refresh → public echo → cookie Max-Age → session row → refresh token → restored`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };

  function failSettings(why: string): StepResult {
    return {
      step: "38",
      title: "session lifetimes",
      status: "fail",
      ms: Math.round(performance.now() - t),
      detail: why,
    };
  }
}

/**
 * Step 39: the tenant's password complexity policy is enforced wherever a password is set.
 *
 * Like step 35, both entrances are exercised: the administrator's create proves the management API
 * shares `check_password`, and the self-service sign-up proves the protocol does. A refused verify
 * must not consume the mailed code, so the same code is reused for the accepted attempt.
 */
async function passwordComplexityFlow(
  base: string,
  adminToken: string,
  internalSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const redirectUri = "http://localhost:5173/bff/callback";
  const headers = managementHeaders(adminToken);
  const email = `complexity-${runId}@demo.localhost`;
  const weakPassword = "lowercaseonly";
  const strongPassword = "Lowercase1";
  const checks: [string, boolean][] = [];
  let detail = "";

  const begin = async (): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `c-${runId}-${"z".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const started = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: "monaca-console",
        redirect_uri: redirectUri,
        scope: "openid profile email",
        state: `st-complexity-${runId}`,
        nonce: `n-complexity-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(started.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    if (started.status !== 302 || interaction === null) return undefined;
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  const setPolicy = (value: number): Promise<HttpResult> =>
    call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ password_min_character_types: value }),
    });

  const createAdminAccount = (tag: string, password: string): Promise<HttpResult> =>
    call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        email: `complexity-${tag}-${runId}@demo.localhost`,
        display_name: "Complexity",
        password,
      }),
    });

  try {
    for (const value of [0, 5]) {
      checks.push([`a minimum of ${value} types is 400`, (await setPolicy(value)).status === 400]);
    }

    const raised = await setPolicy(3);
    checks.push([
      "PATCH raises the minimum to three character types",
      raised.status === 200 &&
        (raised.body as { password_min_character_types?: unknown })?.password_min_character_types ===
          3,
    ]);

    const publicRead = await call(`${base}/t/${TENANT}/sign-in-experience`);
    checks.push([
      "the public read carries the complexity policy",
      publicRead.status === 200 &&
        (publicRead.body as { password_min_character_types?: unknown })
          ?.password_min_character_types === 3,
    ]);

    const weakAdmin = await createAdminAccount("weak", weakPassword);
    checks.push([
      "an administrator cannot create a lowercase-only password",
      weakAdmin.status === 400 &&
        (weakAdmin.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_WEAK_PASSWORD",
    ]);

    const strongAdmin = await createAdminAccount("strong", strongPassword);
    checks.push(["an administrator's password at three types succeeds", strongAdmin.status === 201]);

    const interaction = await begin();
    if (interaction === undefined) return failComplexity("authorize did not open an interaction");
    const requested = await call(
      `${base}/t/${TENANT}/interaction/${interaction.interaction}/sign-up`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email }),
      },
    );
    checks.push([
      "sign-up requests a code",
      requested.status === 200 &&
        (requested.body as { verification_required?: unknown })?.verification_required === true,
    ]);
    const mail = await call(
      `${base}/internal/mail?${new URLSearchParams({ tenant: TENANT, to: email, purpose: "sign_up" })}`,
      { headers: { "x-monaca-internal-secret": internalSecret } },
    );
    const code = (mail.body as { payload?: { code?: unknown } } | undefined)?.payload?.code;
    if (mail.status !== 200 || typeof code !== "string") {
      return failComplexity(`internal/mail → ${mail.status} ${text(mail.body)}`);
    }
    checks.push(["the dev outbox carries the sign-up code", true]);

    const weakSignUp = await call(
      `${base}/t/${TENANT}/interaction/${interaction.interaction}/sign-up/verify`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, code, password: weakPassword }),
      },
    );
    checks.push(["self-service sign-up refuses a lowercase-only password", weakSignUp.status === 400]);

    const strongSignUp = await call(
      `${base}/t/${TENANT}/interaction/${interaction.interaction}/sign-up/verify`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, code, password: strongPassword }),
      },
    );
    checks.push([
      "a password at three character types completes sign-up",
      strongSignUp.status === 200 &&
        typeof (strongSignUp.body as { redirect_to?: unknown })?.redirect_to === "string",
    ]);

    const restored = await setPolicy(1);
    checks.push([
      "the minimum is restored to one type",
      restored.status === 200 &&
        (restored.body as { password_min_character_types?: unknown })
          ?.password_min_character_types === 1,
    ]);

    const relaxed = await createAdminAccount("relaxed", weakPassword);
    checks.push(["and the lowercase-only password is accepted again", relaxed.status === 201]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await setPolicy(1).catch(() => undefined);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "39",
    title: "password complexity",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: two 400s → three types → public echo → weak admin 400 → strong admin 201 → weak sign-up 400 → strong sign-up 200 → restored → relaxed 201`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };

  function failComplexity(why: string): StepResult {
    return {
      step: "39",
      title: "password complexity",
      status: "fail",
      ms: Math.round(performance.now() - t),
      detail: why,
    };
  }
}

/**
 * Step 40: a tenant can append its own CSS to the hosted page.
 *
 * The public read is the page's only source for branding, so it is what proves the stylesheet
 * reached the hosted side; the management response alone would only prove it was stored.
 */
async function customCssFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";
  const css = ".mono-card { border-radius: 12px; }\n.mono-card button { letter-spacing: 0.02em; }";

  const branding = (body: unknown) =>
    (body as { branding?: { custom_css?: unknown } } | undefined)?.branding;

  const patch = (customCss: string): Promise<HttpResult> =>
    call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ branding: { custom_css: customCss } }),
    });

  try {
    const written = await patch(css);
    checks.push([
      "PATCH stores the stylesheet",
      written.status === 200 && branding(written.body)?.custom_css === css,
    ]);

    const publicRead = await call(`${base}/t/${TENANT}/sign-in-experience`);
    checks.push([
      "the public read echoes it",
      publicRead.status === 200 && branding(publicRead.body)?.custom_css === css,
    ]);

    const tooLong = await patch("x".repeat(20_001));
    checks.push(["a stylesheet over 20,000 characters is 400", tooLong.status === 400]);

    const cleared = await patch("");
    checks.push([
      "an empty string clears it",
      cleared.status === 200 && branding(cleared.body)?.custom_css === null,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await patch("").catch(() => undefined);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "40",
    title: "custom CSS",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: write → public echo → 20,001 is 400 → empty clears`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 41: the tenant's password rejection rules, which Logto applies by default.
 *
 * The two rules are checked separately, so a failure names the rule that broke: one refuses a
 * password containing the account's own names, the other refuses repeated runs and sequences.
 * Passwords in this flow are either deliberately rejected or fixed strings with no runs, so the
 * assertion does not depend on the random run id.
 */
async function passwordRejectionsFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const policy = (body: unknown) =>
    body as {
      password_reject_user_info?: unknown;
      password_reject_repetition_and_sequence?: unknown;
    };

  const setRules = (userInfo: boolean, repetition: boolean): Promise<HttpResult> =>
    call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        password_reject_user_info: userInfo,
        password_reject_repetition_and_sequence: repetition,
      }),
    });

  const create = (tag: string, password: string): Promise<HttpResult> =>
    call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        email: `reject-${tag}-${runId}@demo.localhost`,
        display_name: "Rejected",
        password,
      }),
    });

  try {
    const bothOff = await setRules(false, false);
    checks.push([
      "PATCH turns both rejection rules off",
      bothOff.status === 200 &&
        policy(bothOff.body).password_reject_user_info === false &&
        policy(bothOff.body).password_reject_repetition_and_sequence === false,
    ]);

    const firstRead = await call(`${base}/t/${TENANT}/sign-in-experience`);
    checks.push([
      "the public read carries both rules",
      firstRead.status === 200 &&
        policy(firstRead.body).password_reject_user_info === false &&
        policy(firstRead.body).password_reject_repetition_and_sequence === false,
    ]);

    const userInfoOn = await setRules(true, false);
    checks.push([
      "PATCH enables only the user-info rule",
      userInfoOn.status === 200 &&
        policy(userInfoOn.body).password_reject_user_info === true &&
        policy(userInfoOn.body).password_reject_repetition_and_sequence === false,
    ]);

    // The local part is `reject-info-<runId>`, so a password containing it is refused.
    const ownName = await create("info", `reject-info-${runId}-secret`);
    checks.push([
      "a password containing the email local part is 400 MONACA_WEAK_PASSWORD",
      ownName.status === 400 &&
        (ownName.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_WEAK_PASSWORD",
    ]);

    const cleanName = await create("info-clean", `pw-${runId}-account`);
    checks.push(["a password without the account's names is 201", cleanName.status === 201]);

    const repetitionOn = await setRules(false, true);
    checks.push([
      "PATCH enables only the repetition rule",
      repetitionOn.status === 200 &&
        policy(repetitionOn.body).password_reject_user_info === false &&
        policy(repetitionOn.body).password_reject_repetition_and_sequence === true,
    ]);

    const repeated = await create("repeat", "zzzz1234");
    checks.push(["four identical characters in a row are 400", repeated.status === 400]);

    const sequential = await create("sequence", "Abcd5678");
    checks.push(["four consecutive characters are 400", sequential.status === 400]);

    const cleanRuns = await create("runs-clean", "Pw-clean-9!x");
    checks.push(["a password with no runs is 201", cleanRuns.status === 201]);

    const restored = await setRules(true, false);
    checks.push([
      "the defaults are restored",
      restored.status === 200 &&
        policy(restored.body).password_reject_user_info === true &&
        policy(restored.body).password_reject_repetition_and_sequence === false,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await setRules(true, false).catch(() => undefined);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "41",
    title: "password rejections",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: both off → public read → user-info only → own name 400 → clean 201 → repetition only → repeat 400 → sequence 400 → clean 201 → restored`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 42: the tenant can forbid a list of words in passwords.
 *
 * The list is normalised to lowercase and de-duplicated on write; the create path then proves the
 * rule reached the shared `check_password`, and the public read proves the hosted page sees it.
 */
async function passwordWordListFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const words = (body: unknown) =>
    (body as { password_rejected_words?: unknown } | undefined)?.password_rejected_words;

  const setWords = (passwordRejectedWords: string[]): Promise<HttpResult> =>
    call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ password_rejected_words: passwordRejectedWords }),
    });

  const create = (tag: string, password: string): Promise<HttpResult> =>
    call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        email: `words-${tag}-${runId}@demo.localhost`,
        display_name: "Word list",
        password,
      }),
    });

  try {
    const written = await setWords(["monaca", "QWERTY"]);
    checks.push([
      "PATCH lowercases and stores the list",
      written.status === 200 &&
        JSON.stringify(words(written.body)) === JSON.stringify(["monaca", "qwerty"]),
    ]);

    const publicRead = await call(`${base}/t/${TENANT}/sign-in-experience`);
    checks.push([
      "the public read carries the list",
      publicRead.status === 200 &&
        JSON.stringify(words(publicRead.body)) === JSON.stringify(["monaca", "qwerty"]),
    ]);

    const short = await setWords(["ab"]);
    checks.push(["a word shorter than three characters is 400", short.status === 400]);

    const tooMany = await setWords(
      Array.from({ length: 101 }, (_, index) => `word-${index}`),
    );
    checks.push(["a list over 100 words is 400", tooMany.status === 400]);

    const listed = await create("blocked", "monaca-9!Ab");
    checks.push([
      "a password containing a listed word is 400 MONACA_WEAK_PASSWORD",
      listed.status === 400 &&
        (listed.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_WEAK_PASSWORD",
    ]);

    const clean = await create("clean", "Pw-words-9!x");
    checks.push(["a password without a listed word is 201", clean.status === 201]);

    const cleared = await setWords([]);
    checks.push([
      "an empty list clears the rule",
      cleared.status === 200 && JSON.stringify(words(cleared.body)) === "[]",
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await setWords([]).catch(() => undefined);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "42",
    title: "password word list",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: write → public read → two 400s → listed word 400 → clean 201 → cleared`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 43: an application's own stylesheet replaces the tenant's on its hosted page.
 *
 * The precedence is deliberately narrow: the tenant stylesheet is the fallback, and the
 * application one applies only when the public read is told which `client_id` is signing in.
 * An unknown id or a cleared value therefore returns the tenant style, which is what a
 * misconfigured authorize request should render rather than an unstyled page.
 */
async function applicationCssFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const clientId = `e2e-css-${runId}`;
  const tenantCss = ".mono-card { border-radius: 4px; }";
  const applicationCss = ".mono-card { border-radius: 16px; }";

  const brandingCss = (body: unknown): unknown =>
    (body as { branding?: { custom_css?: unknown } } | undefined)?.branding?.custom_css;
  const clientCss = (body: unknown): unknown =>
    (body as { custom_css?: unknown } | undefined)?.custom_css;

  const setTenantCss = (css: string): Promise<HttpResult> =>
    call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ branding: { custom_css: css } }),
    });

  const publicRead = (query: string): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/sign-in-experience${query}`);

  let rowId: string | undefined;
  try {
    const tenantWritten = await setTenantCss(tenantCss);
    checks.push(["the tenant stylesheet is set", tenantWritten.status === 200]);

    const created = await call(`${base}/v1/clients`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        client_id: clientId,
        name: "E2E Styled",
        kind: "public",
        redirect_uris: ["http://localhost:5173/bff/callback"],
        scopes: ["openid", "profile"],
      }),
    });
    const createdRowId = (created.body as { id?: unknown } | undefined)?.id;
    if (typeof createdRowId === "string") rowId = createdRowId;
    checks.push([
      "POST /v1/clients starts without an application stylesheet",
      created.status === 201 && clientCss(created.body) === null,
    ]);
    if (rowId === undefined) {
      return {
        step: "43",
        title: "application custom CSS",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: `POST /v1/clients → ${created.status} ${text(created.body)}`,
      };
    }

    const styled = await call(`${base}/v1/clients/${rowId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ custom_css: applicationCss }),
    });
    checks.push([
      "PATCH stores the application stylesheet",
      styled.status === 200 && clientCss(styled.body) === applicationCss,
    ]);

    const scoped = await publicRead(`?client_id=${encodeURIComponent(clientId)}`);
    checks.push([
      "the client-scoped public read serves the application stylesheet",
      scoped.status === 200 && brandingCss(scoped.body) === applicationCss,
    ]);

    const tenantRead = await publicRead("");
    checks.push([
      "without client_id the public read keeps the tenant stylesheet",
      tenantRead.status === 200 && brandingCss(tenantRead.body) === tenantCss,
    ]);

    const unknown = await publicRead(`?client_id=unknown-${runId}`);
    checks.push([
      "an unknown client_id falls back to the tenant stylesheet",
      unknown.status === 200 && brandingCss(unknown.body) === tenantCss,
    ]);

    const tooLong = await call(`${base}/v1/clients/${rowId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ custom_css: "x".repeat(20_001) }),
    });
    checks.push(["a stylesheet over 20,000 characters is 400", tooLong.status === 400]);

    const cleared = await call(`${base}/v1/clients/${rowId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ custom_css: "" }),
    });
    checks.push([
      "an empty string clears the application stylesheet",
      cleared.status === 200 && clientCss(cleared.body) === null,
    ]);

    const fallen = await publicRead(`?client_id=${encodeURIComponent(clientId)}`);
    checks.push([
      "after clearing, the client-scoped read falls back to the tenant stylesheet",
      fallen.status === 200 && brandingCss(fallen.body) === tenantCss,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    if (rowId !== undefined) {
      await call(`${base}/v1/clients/${rowId}`, { method: "DELETE", headers }).catch(() => undefined);
    }
    await setTenantCss("").catch(() => undefined);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "43",
    title: "application custom CSS",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: tenant set → create → PATCH → scoped/tenant/unknown reads → 20,001 is 400 → cleared → fallback`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 44: the tenant can switch passwordless passkey sign-in off.
 *
 * The gate sits on the shared interaction resolver, so both the options and the verify call are
 * refused — a browser holding a challenge from before the switch cannot finish either. The flow
 * needs no authenticator: the options answer itself is the observable effect, and only the switch
 * is restored afterwards.
 */
async function passkeySignInSwitchFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const clientId = `e2e-passkey-${runId}`;
  const redirectUri = "http://localhost:5173/bff/callback";
  const state = `st-passkey-${runId}`;
  const nonce = `n-passkey-${runId}`;

  const enabled = (body: unknown): unknown =>
    (body as { passkey_sign_in_enabled?: unknown } | undefined)?.passkey_sign_in_enabled;

  const setSwitch = (value: boolean): Promise<HttpResult> =>
    call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ passkey_sign_in_enabled: value }),
    });

  const publicRead = (): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/sign-in-experience`);

  let rowId: string | undefined;
  try {
    const off = await setSwitch(false);
    checks.push([
      "PATCH turns passkey sign-in off",
      off.status === 200 && enabled(off.body) === false,
    ]);

    const publicOff = await publicRead();
    checks.push([
      "the public read follows the switch",
      publicOff.status === 200 && enabled(publicOff.body) === false,
    ]);

    const created = await call(`${base}/v1/clients`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        client_id: clientId,
        name: "E2E Passkey",
        kind: "public",
        redirect_uris: [redirectUri],
        scopes: ["openid"],
      }),
    });
    const createdRowId = (created.body as { id?: unknown } | undefined)?.id;
    if (typeof createdRowId === "string") rowId = createdRowId;
    checks.push(["the flow has an application to authorize", created.status === 201]);
    if (rowId === undefined) {
      return {
        step: "44",
        title: "passkey sign-in switch",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: `POST /v1/clients → ${created.status} ${text(created.body)}`,
      };
    }

    const verifier = `pk-${runId}-${"v".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const authorize = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: "openid",
        state,
        nonce,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(
      authorize.headers.get("location") ?? "",
      base,
    ).searchParams.get("interaction");
    checks.push([
      "authorize opens an interaction",
      authorize.status === 302 && typeof interaction === "string",
    ]);
    if (interaction === null) {
      return {
        step: "44",
        title: "passkey sign-in switch",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: `authorize → ${authorize.status} ${text(authorize.body)}`,
      };
    }
    const interactionPath = `${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}`;

    const refused = await call(`${interactionPath}/sign-in/passkey/options`, { method: "POST" });
    checks.push([
      "passkey options is 403 MONACA_PASSKEY_SIGN_IN_DISABLED",
      refused.status === 403 &&
        (refused.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_PASSKEY_SIGN_IN_DISABLED",
    ]);

    const on = await setSwitch(true);
    checks.push([
      "PATCH turns passkey sign-in back on",
      on.status === 200 && enabled(on.body) === true,
    ]);

    const publicOn = await publicRead();
    checks.push([
      "the public read follows it back on",
      publicOn.status === 200 && enabled(publicOn.body) === true,
    ]);

    const options = await call(`${interactionPath}/sign-in/passkey/options`, { method: "POST" });
    const optionBody = options.body as {
      challenge?: unknown;
      allowCredentials?: unknown;
    } | undefined;
    checks.push([
      "passkey options offers a discoverable ceremony",
      options.status === 200 &&
        typeof optionBody?.challenge === "string" &&
        Array.isArray(optionBody?.allowCredentials) &&
        optionBody.allowCredentials.length === 0,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    if (rowId !== undefined) {
      await call(`${base}/v1/clients/${rowId}`, { method: "DELETE", headers }).catch(() => undefined);
    }
    await setSwitch(true).catch(() => undefined);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "44",
    title: "passkey sign-in switch",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: off → public read → authorize → 403 options → on → public read → options`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 45: an account's avatar is a profile field the account and an administrator can set, and
 * the `profile` scope turns it into the standard `picture` claim.
 *
 * The id_token is minted at code exchange, so the avatar the account sets just before exchanging
 * is the one the token must carry — that proves the claim reads current state rather than a
 * snapshot taken during sign-in.
 */
async function accountAvatarFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const email = `avatar-${runId}@demo.localhost`;
  const password = `pw-${runId}-avatar`;
  const clientId = `e2e-avatar-${runId}`;
  const redirectUri = "http://localhost:5173/bff/callback";
  const firstAvatar = "https://cdn.example/avatar-one.png";
  const secondAvatar = "https://cdn.example/avatar-two.png";

  const avatar = (body: unknown): unknown =>
    (body as { avatar_url?: unknown } | undefined)?.avatar_url;

  let rowId: string | undefined;
  let clientRowId: string | undefined;
  try {
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Avatar Owner", password }),
    });
    const accountId = (created.body as { id?: unknown } | undefined)?.id;
    if (typeof accountId === "string") rowId = accountId;
    checks.push(["POST /v1/accounts creates the account", created.status === 201]);
    if (rowId === undefined) {
      return {
        step: "45",
        title: "account avatar",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: `POST /v1/accounts → ${created.status} ${text(created.body)}`,
      };
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: rowId, role: "member" }),
    });

    const written = await call(`${base}/v1/accounts/${rowId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ avatar_url: firstAvatar }),
    });
    checks.push([
      "an administrator can set the avatar",
      written.status === 200 && avatar(written.body) === firstAvatar,
    ]);

    const relative = await call(`${base}/v1/accounts/${rowId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ avatar_url: "avatar.png" }),
    });
    checks.push(["a relative avatar URL is 400", relative.status === 400]);

    const directory = await call(`${base}/v1/accounts/${rowId}`, { headers });
    checks.push([
      "the directory read carries the avatar",
      directory.status === 200 && avatar(directory.body) === firstAvatar,
    ]);

    const app = await call(`${base}/v1/clients`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        client_id: clientId,
        name: "E2E Avatar",
        kind: "public",
        redirect_uris: [redirectUri],
        scopes: ["openid", "profile", "email"],
      }),
    });
    const appRowId = (app.body as { id?: unknown } | undefined)?.id;
    if (typeof appRowId === "string") clientRowId = appRowId;
    checks.push(["the flow has a client to authorize", app.status === 201]);
    if (clientRowId === undefined) {
      return {
        step: "45",
        title: "account avatar",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: `POST /v1/clients → ${app.status} ${text(app.body)}`,
      };
    }

    const verifier = `av-${runId}-${"v".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const authorize = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: "openid profile email",
        state: `st-avatar-${runId}`,
        nonce: `n-avatar-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(
      authorize.headers.get("location") ?? "",
      base,
    ).searchParams.get("interaction");
    checks.push(["authorize opens an interaction", authorize.status === 302 && interaction !== null]);
    if (interaction === null) {
      return {
        step: "45",
        title: "account avatar",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: `authorize → ${authorize.status} ${text(authorize.body)}`,
      };
    }

    const signedIn = await call(
      `${base}/t/${TENANT}/interaction/${encodeURIComponent(interaction)}/sign-in`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identifier: email, password }),
      },
    );
    const redirectTo = (signedIn.body as { redirect_to?: unknown } | undefined)?.redirect_to;
    const sessionCookie = /monaca_session=([0-9a-f-]{36})/.exec(
      signedIn.headers.get("set-cookie") ?? "",
    )?.[1];
    checks.push([
      "a password sign-in issues the code and a session",
      signedIn.status === 200 && typeof redirectTo === "string" && sessionCookie !== undefined,
    ]);
    if (typeof redirectTo !== "string" || sessionCookie === undefined) {
      return {
        step: "45",
        title: "account avatar",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: `sign-in → ${signedIn.status} ${text(signedIn.body)}`,
      };
    }

    const cookie = { cookie: `monaca_session=${sessionCookie}` };
    const ownRead = await call(`${base}/t/${TENANT}/account`, { headers: cookie });
    checks.push([
      "the account centre reads the administrator-set avatar",
      ownRead.status === 200 && avatar(ownRead.body) === firstAvatar,
    ]);

    const ownPatch = await call(`${base}/t/${TENANT}/account`, {
      method: "PATCH",
      headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify({ avatar_url: secondAvatar }),
    });
    checks.push([
      "the account can change its own avatar",
      ownPatch.status === 200 && avatar(ownPatch.body) === secondAvatar,
    ]);

    const badOwnPatch = await call(`${base}/t/${TENANT}/account`, {
      method: "PATCH",
      headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify({ avatar_url: "not-a-url" }),
    });
    checks.push(["the account centre refuses a relative avatar URL", badOwnPatch.status === 400]);

    const code = new URL(redirectTo).searchParams.get("code") ?? "";
    const token = await tokenCall(
      base,
      { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier },
    );
    const claims = jwtClaims((token.body as { id_token?: unknown } | undefined)?.id_token);
    checks.push([
      "the id_token carries the avatar as the picture claim",
      token.status === 200 &&
        claims?.picture === secondAvatar &&
        claims?.name === "Avatar Owner" &&
        claims?.aud === clientId,
    ]);

    const cleared = await call(`${base}/t/${TENANT}/account`, {
      method: "PATCH",
      headers: { ...cookie, "content-type": "application/json" },
      body: JSON.stringify({ avatar_url: "" }),
    });
    checks.push([
      "an empty string clears the avatar",
      cleared.status === 200 && avatar(cleared.body) === null,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    if (clientRowId !== undefined) {
      await call(`${base}/v1/clients/${clientRowId}`, { method: "DELETE", headers }).catch(() => undefined);
    }
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "45",
    title: "account avatar",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: admin set → 400 → directory → sign-in → account read/write → picture → cleared`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 46: the tenant chooses whether browsers may be remembered past MFA, and for how long.
 *
 * The duration is observed twice: in the `Max-Age` of the device cookie and in the row's
 * `expires_at`. Switching the policy off must also retire cookies issued before the switch, so an
 * old cookie is offered on a fresh sign-in and still stops at the challenge.
 */
async function trustedDevicePolicyFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const email = `trust-policy-${runId}@demo.localhost`;
  const password = `pw-${runId}-trust`;
  const redirectUri = "http://localhost:5173/bff/callback";
  const trustDays = 7;
  const trustSecs = trustDays * 86_400;

  const enabled = (body: unknown): unknown =>
    (body as { mfa_trusted_devices_enabled?: unknown } | undefined)?.mfa_trusted_devices_enabled;
  const ttlDays = (body: unknown): unknown =>
    (body as { mfa_trusted_device_ttl_days?: unknown } | undefined)?.mfa_trusted_device_ttl_days;

  const setPolicy = (patch: {
    mfa_trusted_devices_enabled?: boolean;
    mfa_trusted_device_ttl_days?: number;
  }): Promise<HttpResult> =>
    call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify(patch),
    });

  const publicRead = (): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/sign-in-experience`);

  /** A fresh authorize → interaction for the console client. */
  const begin = async (
    tag: string,
  ): Promise<{ interaction: string; verifier: string } | undefined> => {
    const verifier = `td-${tag}-${runId}-${"v".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const response = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: "monaca-console",
        redirect_uri: redirectUri,
        scope: "openid profile email",
        state: `st-td-${tag}-${runId}`,
        nonce: `n-td-${tag}-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(
      response.headers.get("location") ?? "",
      base,
    ).searchParams.get("interaction");
    if (response.status !== 302 || interaction === null) {
      detail = `authorize(${tag}) → ${response.status} ${text(response.body)}`;
      return undefined;
    }
    return { interaction: encodeURIComponent(interaction), verifier };
  };

  /** Password sign-in, optionally carrying a remembered-browser cookie. */
  const signIn = async (
    tag: string,
    cookie?: string,
  ): Promise<
    | {
        interaction: string;
        verifier: string;
        status: number;
        body: unknown;
        session?: string;
      }
    | undefined
  > => {
    const started = await begin(tag);
    if (started === undefined) return undefined;
    const response = await call(`${base}/t/${TENANT}/interaction/${started.interaction}/sign-in`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(cookie === undefined ? {} : { cookie }),
      },
      body: JSON.stringify({ identifier: email, password }),
    });
    const session = /monaca_session=([0-9a-f-]{36})/.exec(
      response.headers.get("set-cookie") ?? "",
    )?.[1];
    return { ...started, status: response.status, body: response.body, session };
  };

  let accountId: string | undefined;
  try {
    const on = await setPolicy({
      mfa_trusted_devices_enabled: true,
      mfa_trusted_device_ttl_days: trustDays,
    });
    checks.push([
      "PATCH enables remembered browsers and sets a seven-day trust",
      on.status === 200 && enabled(on.body) === true && ttlDays(on.body) === trustDays,
    ]);

    const publicOn = await publicRead();
    checks.push([
      "the public read carries the policy",
      publicOn.status === 200 &&
        enabled(publicOn.body) === true &&
        ttlDays(publicOn.body) === trustDays,
    ]);

    for (const days of [0, 366]) {
      const refusal = await setPolicy({ mfa_trusted_device_ttl_days: days });
      checks.push([`a trust of ${days} days is 400`, refusal.status === 400]);
    }

    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Trusted policy", password }),
    });
    const createdId = (created.body as { id?: unknown } | undefined)?.id;
    if (typeof createdId === "string") accountId = createdId;
    checks.push(["POST /v1/accounts creates the account", created.status === 201]);
    if (accountId === undefined) {
      return {
        step: "46",
        title: "trusted-device policy",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: `POST /v1/accounts → ${created.status} ${text(created.body)}`,
      };
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });

    const first = await signIn("first");
    if (first?.session === undefined) {
      return {
        step: "46",
        title: "trusted-device policy",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: "the first sign-in set no session cookie",
      };
    }
    const accountHeaders = {
      cookie: `monaca_session=${first.session}`,
      "content-type": "application/json",
    };
    const enrollment = await call(`${base}/t/${TENANT}/account/mfa/totp`, {
      method: "POST",
      headers: accountHeaders,
    });
    const secret = (enrollment.body as { secret?: unknown } | undefined)?.secret;
    if (typeof secret !== "string") {
      return {
        step: "46",
        title: "trusted-device policy",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: `POST /account/mfa/totp → ${enrollment.status} ${text(enrollment.body)}`,
      };
    }
    const confirmed = await call(`${base}/t/${TENANT}/account/mfa/totp/verify`, {
      method: "POST",
      headers: accountHeaders,
      body: JSON.stringify({ code: totpFromBase32(secret) }),
    });
    checks.push(["the account enrols an authenticator app", confirmed.status === 200]);

    const challenged = await signIn("challenged");
    checks.push([
      "a password sign-in asks for the second factor",
      challenged?.status === 200 &&
        (challenged.body as { mfa_required?: unknown })?.mfa_required === true,
    ]);
    if (challenged === undefined) {
      return {
        step: "46",
        title: "trusted-device policy",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: "the challenged sign-in failed",
      };
    }

    const verified = await call(
      `${base}/t/${TENANT}/interaction/${challenged.interaction}/mfa/verify`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          code: totpFromBase32(secret),
          factor: "totp",
          remember_device: true,
        }),
      },
    );
    const setCookie = verified.headers.get("set-cookie") ?? "";
    const deviceToken = /monaca_mfa_device=([0-9a-f]{64})/.exec(setCookie)?.[1];
    checks.push([
      "the verified browser is remembered for the configured seven days",
      verified.status === 200 &&
        deviceToken !== undefined &&
        setCookie.includes(`Max-Age=${trustSecs}`),
    ]);
    if (deviceToken === undefined) {
      return {
        step: "46",
        title: "trusted-device policy",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: `mfa/verify → ${verified.status} ${text(verified.body)}`,
      };
    }

    const deviceCookie = `monaca_mfa_device=${deviceToken}`;
    const trusted = await signIn("trusted", deviceCookie);
    checks.push([
      "a remembered browser skips the second factor",
      trusted?.status === 200 &&
        typeof (trusted.body as { redirect_to?: unknown } | undefined)?.redirect_to === "string",
    ]);

    const listed = await call(`${base}/t/${TENANT}/account/mfa/devices`, {
      headers: { cookie: `monaca_session=${first.session}; ${deviceCookie}` },
    });
    const expiresAt = (
      listed.body as { items?: { expires_at?: unknown }[] } | undefined
    )?.items?.[0]?.expires_at;
    const expires = typeof expiresAt === "string" ? Date.parse(expiresAt) : Number.NaN;
    const daysOut = (expires - Date.now()) / 86_400_000;
    checks.push([
      "the stored device expires seven days out",
      Number.isFinite(expires) && daysOut > 6.5 && daysOut < 7.5,
    ]);

    const off = await setPolicy({ mfa_trusted_devices_enabled: false });
    checks.push([
      "PATCH disables remembered browsers",
      off.status === 200 && enabled(off.body) === false,
    ]);
    const publicOff = await publicRead();
    checks.push([
      "the public read follows the switch off",
      publicOff.status === 200 && enabled(publicOff.body) === false,
    ]);

    const stale = await signIn("stale", deviceCookie);
    checks.push([
      "a cookie issued before the switch no longer skips the second factor",
      stale?.status === 200 &&
        (stale.body as { mfa_required?: unknown })?.mfa_required === true,
    ]);
    if (stale === undefined) {
      return {
        step: "46",
        title: "trusted-device policy",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: "the stale-device sign-in failed",
      };
    }

    const whileOff = await call(
      `${base}/t/${TENANT}/interaction/${stale.interaction}/mfa/verify`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          code: totpFromBase32(secret),
          factor: "totp",
          remember_device: true,
        }),
      },
    );
    checks.push([
      "remember_device is ignored while the policy is off",
      whileOff.status === 200 &&
        !(whileOff.headers.get("set-cookie") ?? "").includes("monaca_mfa_device="),
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await setPolicy({
      mfa_trusted_devices_enabled: true,
      mfa_trusted_device_ttl_days: 30,
    }).catch(() => undefined);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "46",
    title: "trusted-device policy",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: on + 7 days → two 400s → enroll → remember → skip → expires 7d → off → stale cookie challenged → no new cookie → restored`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 47: enterprise SSO can be switched off without deleting the connectors.
 *
 * The lookup turns empty rather than failing, so the hosted page falls back to its ordinary forms;
 * the provider redirect and callback are refused, so an in-flight round-trip cannot complete a
 * sign-in through a method the tenant has since disabled.
 */
async function ssoSwitchFlow(base: string, adminToken: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const checks: [string, boolean][] = [];
  let detail = "";

  const connectorId = `sso-switch-${runId}`;
  const domain = `switch-${runId}.example`;
  const clientId = `e2e-sso-switch-${runId}`;
  const redirectUri = "http://localhost:5173/bff/callback";
  const authorizeUrl = "https://idp.example/authorize";

  const enabled = (body: unknown): unknown =>
    (body as { single_sign_on_enabled?: unknown } | undefined)?.single_sign_on_enabled;
  const lookupIds = (body: unknown): string[] =>
    ((body as { items?: { connector_id?: string }[] } | undefined)?.items ?? []).map(
      (item) => item.connector_id ?? "",
    );

  const setSwitch = (value: boolean): Promise<HttpResult> =>
    call(`${base}/v1/sign-in-experience`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ single_sign_on_enabled: value }),
    });
  const publicRead = (): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/sign-in-experience`);
  const lookup = (): Promise<HttpResult> =>
    call(`${base}/t/${TENANT}/sso-connectors?email=${encodeURIComponent(`user@${domain}`)}`);

  let clientRowId: string | undefined;
  try {
    const registered = await call(`${base}/v1/sso-connectors`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        connector_id: connectorId,
        display_name: "SSO switch",
        issuer: "https://idp.example",
        authorize_url: authorizeUrl,
        token_url: "https://idp.example/token",
        userinfo_url: "https://idp.example/userinfo",
        client_id: "switch-client",
        client_secret: `secret-${runId}`,
        email_domains: [domain],
      }),
    });
    checks.push(["POST registers the connector", registered.status === 201]);

    const found = await lookup();
    checks.push([
      "the enabled lookup finds the connector",
      found.status === 200 && lookupIds(found.body).includes(connectorId),
    ]);

    const off = await setSwitch(false);
    checks.push([
      "PATCH turns enterprise SSO off",
      off.status === 200 && enabled(off.body) === false,
    ]);
    const publicOff = await publicRead();
    checks.push([
      "the public read follows the switch",
      publicOff.status === 200 && enabled(publicOff.body) === false,
    ]);

    const hidden = await lookup();
    checks.push([
      "the lookup is empty while SSO is off",
      hidden.status === 200 && lookupIds(hidden.body).length === 0,
    ]);

    const app = await call(`${base}/v1/clients`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        client_id: clientId,
        name: "E2E SSO switch",
        kind: "public",
        redirect_uris: [redirectUri],
        scopes: ["openid"],
      }),
    });
    const appRowId = (app.body as { id?: unknown } | undefined)?.id;
    if (typeof appRowId === "string") clientRowId = appRowId;
    const verifier = `ss-${runId}-${"v".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const authorize = await call(
      `${base}/t/${TENANT}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: "openid",
        state: `st-sso-${runId}`,
        nonce: `n-sso-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
        organization: ORG,
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(
      authorize.headers.get("location") ?? "",
      base,
    ).searchParams.get("interaction");
    checks.push([
      "authorize opens an interaction",
      authorize.status === 302 && interaction !== null,
    ]);
    if (interaction === null || clientRowId === undefined) {
      return {
        step: "47",
        title: "enterprise SSO switch",
        status: "fail",
        ms: Math.round(performance.now() - t),
        detail: `authorize → ${authorize.status} ${text(authorize.body)}`,
      };
    }

    const href = `${base}/t/${TENANT}/sso/${encodeURIComponent(connectorId)}/authorize?interaction=${encodeURIComponent(interaction)}`;
    const refused = await call(href, { redirect: "manual" });
    checks.push([
      "the provider redirect is 403 MONACA_SSO_DISABLED",
      refused.status === 403 &&
        (refused.body as { monaca_error_code?: unknown })?.monaca_error_code === "MONACA_SSO_DISABLED",
    ]);

    const refusedCallback = await call(
      `${base}/t/${TENANT}/sso/${encodeURIComponent(connectorId)}/callback?state=01920000-0000-7000-8000-000000000000&code=x`,
    );
    checks.push([
      "the callback is 403 MONACA_SSO_DISABLED",
      refusedCallback.status === 403 &&
        (refusedCallback.body as { monaca_error_code?: unknown })?.monaca_error_code ===
          "MONACA_SSO_DISABLED",
    ]);

    const on = await setSwitch(true);
    checks.push([
      "PATCH turns enterprise SSO back on",
      on.status === 200 && enabled(on.body) === true,
    ]);
    const publicOn = await publicRead();
    checks.push([
      "the public read follows it back on",
      publicOn.status === 200 && enabled(publicOn.body) === true,
    ]);

    const foundAgain = await lookup();
    checks.push([
      "the lookup finds the connector again",
      foundAgain.status === 200 && lookupIds(foundAgain.body).includes(connectorId),
    ]);

    const redirect = await call(href, { redirect: "manual" });
    const location = redirect.headers.get("location") ?? "";
    checks.push([
      "the provider redirect is a 302 to the connector's authorize URL",
      redirect.status === 302 && location.startsWith(authorizeUrl),
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    await call(`${base}/v1/sso-connectors/${encodeURIComponent(connectorId)}`, {
      method: "DELETE",
      headers,
    }).catch(() => undefined);
    if (clientRowId !== undefined) {
      await call(`${base}/v1/clients/${clientRowId}`, { method: "DELETE", headers }).catch(() => undefined);
    }
    await setSwitch(true).catch(() => undefined);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "47",
    title: "enterprise SSO switch",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: register → lookup → off → public read → empty lookup → 403 redirect/callback → on → lookup → 302`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/** Decodes the base64url payloads this walk-through mints or reads back. */
function base64UrlDecode(value: string): Uint8Array {
  const normalised = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalised + "=".repeat((4 - (normalised.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

/**
 * A minimal OAuth2 provider for step 15.
 *
 * The identity it asserts is fixed in the authorize URL the connector was configured with, so each
 * connector stands for one provider account. `/token` hands the code back as the access token and
 * `/userinfo` decodes it: no state lives in the mock, which is what lets the walk-through run
 * without a provider service.
 */
function startMockProvider(): { url: string; stop: () => void } {
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(request) {
      const url = new URL(request.url);
      if (url.pathname === "/authorize") {
        const target = new URL(url.searchParams.get("redirect_uri") ?? "");
        target.searchParams.set(
          "code",
          base64UrlJson({
            sub: url.searchParams.get("sub") ?? "",
            email: url.searchParams.get("email") ?? "",
            email_verified: url.searchParams.get("verified") === "1",
            name: url.searchParams.get("name") ?? "",
          }),
        );
        target.searchParams.set("state", url.searchParams.get("state") ?? "");
        return Response.redirect(target.toString(), 302);
      }
      if (url.pathname === "/token") {
        const form = await request.formData();
        const code = String(form.get("code") ?? "");
        if (code === "") return Response.json({ error: "invalid_grant" }, { status: 400 });
        return Response.json({ access_token: code, token_type: "Bearer", expires_in: 600 });
      }
      if (url.pathname === "/userinfo") {
        const token = (request.headers.get("authorization") ?? "").replace(/^Bearer /, "");
        return new Response(new TextDecoder().decode(base64UrlDecode(token)), {
          headers: { "content-type": "application/json" },
        });
      }
      return new Response("not found", { status: 404 });
    },
  });
  return {
    url: `http://127.0.0.1:${server.port}`,
    stop: () => {
      void server.stop(true);
    },
  };
}

function typeIdUuid(id: string): string {
  const alphabet = "0123456789abcdefghjkmnpqrstvwxyz";
  const suffix = id.slice(id.indexOf("_") + 1);
  let value = 0n;
  for (const symbol of suffix) {
    value = (value << 5n) | BigInt(alphabet.indexOf(symbol));
  }
  const hex = (value & ((1n << 128n) - 1n)).toString(16).padStart(32, "0");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Step 76 — tenant roles grant management tiers (§6.2).
 *
 * A role names permission scopes. Three of them are management tiers: `management:read` opens
 * every `GET`, `management:write` adds ordinary mutations, and `monaca:admin` adds role
 * administration itself. The tier is re-read from the account's current roles on every request,
 * so assigning or removing a role changes the next call without minting a new token.
 */
async function roleTierFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const email = `tier-${runId}@demo.localhost`;
  const password = `pw-${runId}-tier`;
  const viewerName = `viewer-${runId}`;
  const operatorName = `operator-${runId}`;
  const delegateName = `delegate-${runId}`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "76",
    title: "role access tiers",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });
  const errorCode = (body: unknown): unknown =>
    (body as { monaca_error_code?: unknown })?.monaca_error_code;
  const role = async (name: string, permissions: string[]): Promise<string | undefined> => {
    const created = await call(`${base}/v1/roles`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name, description: "e2e tier", permissions }),
    });
    return created.status === 201 ? (created.body as { id?: string })?.id : undefined;
  };
  const assign = (accountId: string, roleId: string, token: string): Promise<HttpResult> =>
    call(`${base}/v1/accounts/${accountId}/roles/${roleId}`, {
      method: "POST",
      headers: managementHeaders(token),
    });
  const unassign = (accountId: string, roleId: string, token: string): Promise<HttpResult> =>
    call(`${base}/v1/accounts/${accountId}/roles/${roleId}`, {
      method: "DELETE",
      headers: managementHeaders(token),
    });
  const listAccounts = (token: string): Promise<HttpResult> =>
    call(`${base}/v1/accounts?limit=1`, { headers: managementHeaders(token) });
  const createAccount = (token: string, suffix: string): Promise<HttpResult> =>
    call(`${base}/v1/accounts`, {
      method: "POST",
      headers: managementHeaders(token),
      body: JSON.stringify({
        email: `tier-write-${suffix}-${runId}@demo.localhost`,
        display_name: "Tier writer",
        password: `pw-${runId}-${suffix}`,
      }),
    });
  const patchRole = (roleId: string, token: string, body: Record<string, unknown>): Promise<HttpResult> =>
    call(`${base}/v1/roles/${roleId}`, {
      method: "PATCH",
      headers: managementHeaders(token),
      body: JSON.stringify(body),
    });
  const createRole = (token: string, name: string, permissions: string[]): Promise<HttpResult> =>
    call(`${base}/v1/roles`, {
      method: "POST",
      headers: managementHeaders(token),
      body: JSON.stringify({ name, permissions }),
    });
  const audit = (token: string, query: Record<string, string>): Promise<HttpResult> =>
    call(`${base}/v1/audit?${new URLSearchParams(query)}`, { headers: managementHeaders(token) });

  try {
    const viewerId = await role(viewerName, ["management:read"]);
    const operatorId = await role(operatorName, ["management:read", "management:write"]);
    const delegateId = await role(delegateName, ["monaca:admin"]);
    checks.push([
      "read, write and full roles are created",
      viewerId !== undefined && operatorId !== undefined && delegateId !== undefined,
    ]);
    if (viewerId === undefined || operatorId === undefined || delegateId === undefined) {
      return fail("a tier role was not created");
    }

    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Tier holder", password }),
    });
    const accountId = (created.body as { id?: string })?.id;
    if (created.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });

    const signedIn = await consoleSignIn(
      base,
      email,
      password,
      consoleSecret,
      "tier-none",
      "openid offline_access monaca:admin",
    );
    if (signedIn.session === undefined) return fail(signedIn.error ?? "sign-in failed");
    const token0 = signedIn.session.accessToken;
    const scope0 = jwtClaims(token0)?.scope as unknown;
    checks.push([
      "an account with no role receives no monaca:admin scope",
      Array.isArray(scope0) && !scope0.map(String).includes("monaca:admin"),
    ]);

    const beforeAssign = await listAccounts(token0);
    checks.push([
      "a token with no role cannot read /v1",
      beforeAssign.status === 403 && errorCode(beforeAssign.body) === "MONACA_INSUFFICIENT_SCOPE",
    ]);

    // --- read tier ------------------------------------------------------------------------------
    checks.push(["assigning management:read is 204", (await assign(accountId, viewerId, adminToken)).status === 204]);
    checks.push(["the same token now reads /v1", (await listAccounts(token0)).status === 200]);
    checks.push([
      "read tier cannot create an account",
      (await createAccount(token0, "viewer")).status === 403,
    ]);
    checks.push([
      "read tier cannot change a role",
      (await patchRole(viewerId, token0, { description: "not allowed" })).status === 403,
    ]);

    // --- write tier -----------------------------------------------------------------------------
    checks.push([
      "assigning management:write is 204",
      (await assign(accountId, operatorId, adminToken)).status === 204,
    ]);
    checks.push([
      "the same token now creates an account",
      (await createAccount(token0, "operator")).status === 201,
    ]);
    checks.push([
      "write tier cannot create a role (privilege escalation is full-only)",
      (await createRole(token0, `escalate-${runId}`, ["monaca:admin"])).status === 403,
    ]);

    // --- full tier ------------------------------------------------------------------------------
    checks.push([
      "assigning monaca:admin is 204",
      (await assign(accountId, delegateId, adminToken)).status === 204,
    ]);
    const updated = await patchRole(viewerId, token0, {
      permissions: ["management:read", "tools:read"],
    });
    checks.push([
      "the pre-existing token can change a role as soon as the full role is assigned",
      updated.status === 200 &&
        ((updated.body as { permissions?: unknown })?.permissions as string[] | undefined)?.includes(
          "tools:read",
        ) === true,
    ]);

    const elevated = await consoleSignIn(
      base,
      email,
      password,
      consoleSecret,
      "tier-full",
      "openid offline_access monaca:admin",
    );
    if (elevated.session === undefined) return fail(elevated.error ?? "re-sign-in failed");
    const token1 = elevated.session.accessToken;
    const scope1 = jwtClaims(token1)?.scope as unknown;
    checks.push([
      "issuance keeps monaca:admin for an account whose role grants it",
      Array.isArray(scope1) && scope1.map(String).includes("monaca:admin"),
    ]);

    const tempRole = await createRole(token1, `temp-${runId}`, []);
    const tempRoleId = (tempRole.body as { id?: string })?.id;
    checks.push([
      "full tier can create a role",
      tempRole.status === 201 && tempRoleId !== undefined,
    ]);
    if (tempRoleId !== undefined) {
      checks.push([
        "full tier can delete a role",
        (await call(`${base}/v1/roles/${tempRoleId}`, {
          method: "DELETE",
          headers: managementHeaders(token1),
        })).status === 204,
      ]);
    }

    const updatedEvents = await audit(token1, { action: "role.updated", limit: "200" });
    checks.push([
      "reading roles as the full tier is allowed and the update is audited",
      updatedEvents.status === 200 && JSON.stringify(updatedEvents.body).includes(viewerId),
    ]);
    const assignedEvents = await audit(token1, {
      action: "role.assigned",
      subject: accountId,
      limit: "200",
    });
    checks.push([
      "each assignment writes role.assigned with the account as its subject",
      assignedEvents.status === 200 &&
        Number((assignedEvents.body as { total?: unknown })?.total) >= 3,
    ]);

    // --- demotion is immediate, even for a token carrying monaca:admin -------------------------
    checks.push([
      "removing the full role is 204",
      (await unassign(accountId, delegateId, token1)).status === 204,
    ]);
    checks.push([
      "the token that carried monaca:admin can no longer change a role",
      (await patchRole(viewerId, token1, { description: "after demotion" })).status === 403,
    ]);
    checks.push([
      "the token that carried monaca:admin can no longer create a role",
      (await createRole(token1, `demoted-${runId}`, [])).status === 403,
    ]);
    checks.push([
      "removing the write role is 204",
      (await unassign(accountId, operatorId, adminToken)).status === 204,
    ]);
    checks.push([
      "the same token can no longer create an account",
      (await createAccount(token1, "demoted")).status === 403,
    ]);
    checks.push(["the same token still reads /v1 as the read tier", (await listAccounts(token1)).status === 200]);
    checks.push([
      "removing the read role is 204",
      (await unassign(accountId, viewerId, adminToken)).status === 204,
    ]);
    checks.push([
      "with no role left the token cannot read /v1",
      (await listAccounts(token1)).status === 403,
    ]);

    const unassignedEvents = await audit(adminToken, {
      action: "role.unassigned",
      subject: accountId,
      limit: "200",
    });
    checks.push([
      "each removal writes role.unassigned with the account as its subject",
      unassignedEvents.status === 200 &&
        Number((unassignedEvents.body as { total?: unknown })?.total) >= 3,
    ]);

    // --- validation ------------------------------------------------------------------------------
    checks.push([
      "an empty role patch is 400",
      (await patchRole(viewerId, adminToken, {})).status === 400,
    ]);
    checks.push([
      "a permission outside the scope grammar is 400",
      (await patchRole(viewerId, adminToken, { permissions: ["bad scope"] })).status === 400,
    ]);
    checks.push([
      "a patch naming a missing role is 404",
      (await patchRole("rol_01h455vb4pex5vsknk084sn02q", adminToken, { description: "x" })).status === 404,
    ]);

    for (const id of [viewerId, operatorId, delegateId]) {
      await call(`${base}/v1/roles/${id}`, { method: "DELETE", headers });
    }
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "76",
    title: "role access tiers",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: no role 403 → read → write → full → issuance → audit → demotion → validation`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 77 — `/v1/me` and the tenant lifecycle pair (§6.2).
 *
 * The console needs the signed-in account's current management tier, and an operator needs the
 * archive/reactivate pair. The test proves both: `/v1/me` follows a role assignment without a new
 * token, an archived tenant refuses `/v1/me`, and the lifecycle pair is the only surface that still
 * answers while archived. The tenant is reactivated in `finally` so a failed assertion cannot leave
 * the rest of the run against an archived demo.
 */
async function tenantLifecycleAndMeFlow(
  base: string,
  adminToken: string,
  consoleSecret: string,
): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const headers = managementHeaders(adminToken);
  const email = `lifecycle-${runId}@demo.localhost`;
  const password = `pw-${runId}-lifecycle`;
  const roleName = `me-reader-${runId}`;
  const checks: [string, boolean][] = [];
  let detail = "";

  const fail = (why: string): StepResult => ({
    step: "77",
    title: "me and tenant lifecycle",
    status: "fail",
    ms: Math.round(performance.now() - t),
    detail: why || detail,
  });
  const errorCode = (body: unknown): unknown =>
    (body as { monaca_error_code?: unknown })?.monaca_error_code;
  const me = (token: string): Promise<HttpResult> =>
    call(`${base}/v1/me`, { headers: managementHeaders(token) });
  const tenantCall = (token: string, method = "GET", body?: unknown): Promise<HttpResult> =>
    call(`${base}/v1/tenant`, {
      method,
      headers: managementHeaders(token),
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  const audit = (query: Record<string, string>): Promise<HttpResult> =>
    call(`${base}/v1/audit?${new URLSearchParams(query)}`, { headers });

  let roleId: string | undefined;
  let accountId: string | undefined;
  try {
    const createdRole = await call(`${base}/v1/roles`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: roleName, permissions: ["management:read"] }),
    });
    roleId = (createdRole.body as { id?: string })?.id;
    if (createdRole.status !== 201 || roleId === undefined) {
      return fail(`POST /v1/roles → ${createdRole.status} ${text(createdRole.body)}`);
    }
    const created = await call(`${base}/v1/accounts`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email, display_name: "Lifecycle holder", password }),
    });
    accountId = (created.body as { id?: string })?.id;
    if (created.status !== 201 || accountId === undefined) {
      return fail(`POST /v1/accounts → ${created.status} ${text(created.body)}`);
    }
    await call(`${base}/v1/orgs/${ORG}/members`, {
      method: "POST",
      headers,
      body: JSON.stringify({ account_id: accountId, role: "member" }),
    });
    await call(`${base}/v1/accounts/${accountId}/roles/${roleId}`, {
      method: "POST",
      headers,
    });

    const signedIn = await consoleSignIn(
      base,
      email,
      password,
      consoleSecret,
      "lifecycle",
      "openid offline_access monaca:admin",
    );
    if (signedIn.session === undefined) return fail(signedIn.error ?? "sign-in failed");
    const userToken = signedIn.session.accessToken;

    const firstMe = await me(userToken);
    const body = firstMe.body as {
      account_id?: string;
      email?: string;
      management?: string;
      is_tenant_admin?: boolean;
      roles?: { name?: string; permissions?: string[] }[];
    };
    checks.push([
      "GET /v1/me reports the account, its role and the read tier",
      firstMe.status === 200 &&
        body.account_id === accountId &&
        body.email === email &&
        body.management === "read" &&
        body.is_tenant_admin === false &&
        (body.roles ?? []).some(
          (role) => role.name === roleName && role.permissions?.includes("management:read") === true,
        ),
    ]);

    checks.push([
      "removing the role lowers /v1/me on the same token",
      (await call(`${base}/v1/accounts/${accountId}/roles/${roleId}`, {
        method: "DELETE",
        headers,
      })).status === 204 &&
        (await me(userToken)).status === 200 &&
        ((await me(userToken)).body as { management?: string }).management === "none",
    ]);

    const readTenant = await tenantCall(adminToken);
    const tenantBody = readTenant.body as { id?: string; slug?: string; state?: string };
    checks.push([
      "GET /v1/tenant reports the tenant and its active state",
      readTenant.status === 200 && tenantBody.slug === TENANT && tenantBody.state === "active",
    ]);
    const tenantId = tenantBody.id;

    checks.push([
      "suspension is refused through the API",
      (await tenantCall(adminToken, "PATCH", { state: "suspended" })).status === 400,
    ]);
    checks.push([
      "an invalid lifecycle state is 400",
      (await tenantCall(adminToken, "PATCH", { state: "provisioning" })).status === 400,
    ]);

    const archived = await tenantCall(adminToken, "PATCH", { state: "archived" });
    checks.push([
      "archiving the tenant is 200 and reports archived",
      archived.status === 200 &&
        (archived.body as { state?: string }).state === "archived",
    ]);
    checks.push([
      "an archived tenant refuses /v1/me",
      (await me(userToken)).status === 403 &&
        errorCode((await me(userToken)).body) === "MONACA_TENANT_ARCHIVED",
    ]);
    checks.push([
      "the lifecycle read still answers while archived",
      (await tenantCall(adminToken)).status === 200 &&
        ((await tenantCall(adminToken)).body as { state?: string }).state === "archived",
    ]);

    const reactivated = await tenantCall(adminToken, "PATCH", { state: "active" });
    checks.push([
      "reactivating the tenant is 200 and reports active",
      reactivated.status === 200 &&
        (reactivated.body as { state?: string }).state === "active",
    ]);
    checks.push([
      "the same user token reads /v1/me once the tenant is active",
      (await me(userToken)).status === 200,
    ]);

    const archivedEvents = await audit({ action: "tenant.archived", limit: "200" });
    const archivedItems = (archivedEvents.body as {
      items?: { action?: string; subject?: { id?: string } }[];
    }).items ?? [];
    checks.push([
      "tenant.archived is on the tenant chain with the tenant as its subject",
      archivedEvents.status === 200 &&
        archivedItems.length >= 1 &&
        archivedItems.every(
          (item) => item.action === "tenant.archived" && item.subject?.id === tenantId,
        ),
    ]);
    const reactivatedEvents = await audit({ action: "tenant.reactivated", limit: "200" });
    const reactivatedItems = (reactivatedEvents.body as {
      items?: { action?: string; subject?: { id?: string } }[];
    }).items ?? [];
    checks.push([
      "tenant.reactivated is on the tenant chain with the tenant as its subject",
      reactivatedEvents.status === 200 &&
        reactivatedItems.length >= 1 &&
        reactivatedItems.every(
          (item) => item.action === "tenant.reactivated" && item.subject?.id === tenantId,
        ),
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    // Never leave the shared demo tenant archived for the rest of the run.
    await tenantCall(adminToken, "PATCH", { state: "active" }).catch(() => undefined);
    if (roleId !== undefined) {
      await call(`${base}/v1/roles/${roleId}`, { method: "DELETE", headers }).catch(() => undefined);
    }
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "77",
    title: "me and tenant lifecycle",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: /v1/me tier → role removal → archive → 403 → reactivate → audit`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Step 78 — SAML connectors and the assertion consumer service.
 *
 * The positive round-trip needs a signed assertion; that lives in the Rust unit test
 * `saml::tests::a_signed_assertion_from_a_compliant_idp_completes_the_flow`, which drives a real
 * risaml IdP. This step pins the configuration gate and the rejection paths the HTTP surface owns:
 * an IdP that demands signed AuthnRequests is refused at creation, DTDs / multiple assertions /
 * unsigned assertions are refused at the ACS, the RelayState is single-use, and IdP-initiated
 * responses have no entry at all.
 */
async function samlFlow(base: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const slug = `saml-${runId}`;
  const adminEmail = `admin@${slug}.localhost`;
  const adminPassword = `Saml-${runId}-9xQ`;
  const adminSecret = `saml-admin-${runId}`;
  const loginClient = "e2e-login";
  const redirectUri = "http://localhost:5173/bff/callback";
  const idpEntity = `https://idp-${runId}.example.com/metadata`;
  const idpCert =
    "MIIC6TCCAdOgAwIBAgIBATALBgkqhkiG9w0BAQswODELMAkGA1UEBhMCQ04xDzANBgNVBAoMBk1vbmFjYTEYMBYGA1UEAwwPTW9uYWNhIFRlc3QgSWRQMCIYDzIwMjYxMTA2MDk1MTEwWhgPMjA0NjExMDEwOTUxMTBaMDgxCzAJBgNVBAYTAkNOMQ8wDQYDVQQKDAZNb25hY2ExGDAWBgNVBAMMD01vbmFjYSBUZXN0IElkUDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMHTWirLVrxweZFfdnSb1Fq1ECY586Nn3sNq/V030lMyEjF4nopoKhjNNm0ueaANJRKxunOHYa2hiNrprDtHGYBx/mV3BEwjk2SwNJIZ+7OwWZz7frNTenPcECgE3p0QnnE/pTtw+VDBTT2blDnAh4E5bxbJGllc/ltWfi84VC+jLd3DQ19vlgar+FVbTMcxJibmEUpq5Wwn50moulH25HNFIhjXm22smvlgvq/BPm/SI5mBDWMIDG6DAfXO2+1xjOu+dhpc1sfT0+vKL2+1ESt03mmkWGwFep9JUacBDqNj0ujroXH1Rm/+qZHDt2c+ctEFhUN9pIlaY6PKxEiwohsCAwEAATALBgkqhkiG9w0BAQsDggEBAGzL0pvJNEgAjIfg5XGlC4ZXDrpzWjkvKb5MylJ/FkfLg/mM3NBFjAYkslOxXnA3OjFxDYabtRgV1hguuHZZBmBlylnGTh2R/k0Jj5CJ/xqdH7Z1CECvOCNk8mYUe4Z/nRIdEi1In4pD2QgHMFDWBU8i65VbcWZPLfxS8WkaUohmiGHlLYnwJybwQuGB90bfWLT8OqHNLysEpmuv6Gp8wQ3AQEm4Ams3fx4ib5MihhDi9OXPU+jsxOkf96QIA9r8uVA38FNIRKIDAEYQyaNVCPp4IWKk5I8/TbRUoeTyvgHhntisXL4FZi2Dy6nUq1QqZExCUaIGdf1S7jep+C12NWU=";
  const bin =
    process.env.MONACA_SERVER_BIN ??
    (process.platform === "win32"
      ? ".monaca/bin/monaca-server.exe"
      : ".monaca/bin/monaca-server");
  const checks: [string, boolean][] = [];
  let detail = "";

  const cli = async (args: string[]): Promise<{ code: number; stdout: string; stderr: string }> => {
    const proc = Bun.spawn([bin, ...args], {
      cwd: process.cwd(),
      env: { ...process.env },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, code] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    return { code, stdout, stderr };
  };

  const metadata = (options: {
    signedRequests?: boolean;
    signingCertificate?: boolean;
    redirectSso?: boolean;
  }): string => {
    const signed =
      options.signedRequests === true ? ' WantAuthnRequestsSigned="true"' : "";
    const key =
      options.signingCertificate === false
        ? ""
        : `<KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${idpCert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>`;
    const sso =
      options.redirectSso === false
        ? ""
        : `<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp-${runId}.example.com/sso"/>`;
    return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${idpEntity}"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"${signed}>${key}${sso}</IDPSSODescriptor></EntityDescriptor>`;
  };

  const acs = (field: Record<string, string>): Promise<HttpResult> =>
    call(`${base}/t/${slug}/sso/okta/acs`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(field).toString(),
    });

  const problemDetail = (body: unknown): string =>
    String((body as { detail?: unknown })?.detail ?? "");

  try {
    const created = await cli([
      "tenant",
      "create",
      "--slug",
      slug,
      "--admin-email",
      adminEmail,
      "--admin-password",
      adminPassword,
      "--admin-client-secret",
      adminSecret,
      "--login-client-id",
      loginClient,
      "--login-redirect-uri",
      redirectUri,
    ]);
    checks.push([
      "a SAML test tenant is provisioned",
      created.code === 0 && created.stdout.includes(slug),
    ]);
    if (created.code !== 0) throw new Error(created.stderr || created.stdout);

    const minted = await call(`${base}/t/${slug}/oauth2/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${btoa(`monaca-admin:${adminSecret}`)}`,
      },
      body: "grant_type=client_credentials&scope=monaca:admin",
    });
    const token = (minted.body as { access_token?: string })?.access_token ?? "";
    if (minted.status !== 200 || token === "") throw new Error("no management token");
    const headers = { authorization: `Bearer ${token}`, "content-type": "application/json" };

    const create = (body: unknown): Promise<HttpResult> =>
      call(`${base}/v1/saml-connectors`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
    const baseBody = {
      connector_id: "okta",
      display_name: "Okta",
      metadata_xml: metadata({}),
      email_domains: [`corp-${runId}.localhost`],
    };

    const signedRequests = await create({
      ...baseBody,
      metadata_xml: metadata({ signedRequests: true }),
    });
    checks.push([
      "a connector whose IdP requires signed AuthnRequests is refused with the reason",
      signedRequests.status === 400 &&
        problemDetail(signedRequests.body).includes("WantAuthnRequestsSigned"),
    ]);

    const noCertificate = await create({
      ...baseBody,
      metadata_xml: metadata({ signingCertificate: false }),
    });
    checks.push([
      "metadata without a signing certificate is refused",
      noCertificate.status === 400 &&
        problemDetail(noCertificate.body).includes("signing certificate"),
    ]);

    const noRedirect = await create({
      ...baseBody,
      metadata_xml: metadata({ redirectSso: false }),
    });
    checks.push([
      "metadata without an HTTP-Redirect SSO endpoint is refused",
      noRedirect.status === 400 && problemDetail(noRedirect.body).includes("HTTP-Redirect"),
    ]);

    const createdConnector = await create(baseBody);
    const connectorBody = createdConnector.body as {
      connector_id?: string;
      entity_id?: string;
      email_attribute?: string;
      acs_url?: string;
      sp_metadata_url?: string;
    };
    checks.push([
      "a valid connector is stored with its entity id, ACS and SP metadata URL",
      createdConnector.status === 201 &&
        connectorBody.connector_id === "okta" &&
        connectorBody.entity_id === idpEntity &&
        connectorBody.email_attribute === "email" &&
        (connectorBody.acs_url ?? "").endsWith(`/t/${slug}/sso/okta/acs`) &&
        (connectorBody.sp_metadata_url ?? "").endsWith(`/t/${slug}/sso/okta/metadata`),
    ]);

    const conflicting = await call(`${base}/v1/sso-connectors`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        connector_id: `oidc-${runId}`,
        display_name: "OIDC",
        issuer: `https://idp-${runId}.example.com`,
        authorize_url: `https://idp-${runId}.example.com/authorize`,
        token_url: `https://idp-${runId}.example.com/token`,
        userinfo_url: `https://idp-${runId}.example.com/userinfo`,
        client_id: "client",
        client_secret: "secret",
        email_domains: [`corp-${runId}.localhost`],
      }),
    });
    checks.push([
      "the domain cannot belong to an OIDC connector as well",
      conflicting.status === 409 &&
        (conflicting.body as { monaca_error_code?: string })?.monaca_error_code ===
          "MONACA_SSO_DOMAIN_TAKEN",
    ]);

    const lookup = await call(
      `${base}/t/${slug}/sso-connectors?${new URLSearchParams({
        email: `someone@corp-${runId}.localhost`,
      })}`,
    );
    const lookupItems =
      (lookup.body as { items?: { connector_id?: string; display_name?: string }[] }).items ?? [];
    checks.push([
      "the public domain lookup routes the address to the SAML connector",
      lookup.status === 200 &&
        lookupItems.length === 1 &&
        lookupItems[0]?.connector_id === "okta" &&
        lookupItems[0]?.display_name === "Okta",
    ]);

    const spMetadata = await call(`${base}/t/${slug}/sso/okta/metadata`);
    checks.push([
      "the SP metadata advertises the ACS and asks for signed assertions",
      spMetadata.status === 200 &&
        spMetadata.headers.get("content-type")?.includes("samlmetadata") === true &&
        String(spMetadata.body).includes(`/t/${slug}/sso/okta/acs`) &&
        String(spMetadata.body).includes("WantAssertionsSigned=\"true\""),
    ]);

    const verifier = `saml-${runId}-${"v".repeat(40)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const started = await call(
      `${base}/t/${slug}/oauth2/authorize?${new URLSearchParams({
        response_type: "code",
        client_id: loginClient,
        redirect_uri: redirectUri,
        scope: "openid profile email",
        state: `saml-${runId}`,
        code_challenge: challenge,
        code_challenge_method: "S256",
      })}`,
      { redirect: "manual" },
    );
    const interaction = new URL(started.headers.get("location") ?? "", base).searchParams.get(
      "interaction",
    );
    if (interaction === null) throw new Error(`authorize answered ${started.status}`);

    const authorize = await call(
      `${base}/t/${slug}/sso/okta/authorize?${new URLSearchParams({ interaction })}`,
      { redirect: "manual" },
    );
    const redirect = new URL(authorize.headers.get("location") ?? "https://missing.invalid");
    const relay = redirect.searchParams.get("RelayState") ?? "";
    checks.push([
      "the SP sends an unsigned AuthnRequest with a RelayState to the IdP",
      authorize.status === 302 &&
        redirect.origin === `https://idp-${runId}.example.com` &&
        redirect.searchParams.get("SAMLRequest") !== null &&
        relay !== "" &&
        redirect.searchParams.get("Signature") === null,
    ]);

    const responseXml = (extra: string): string =>
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="_unknown"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${idpEntity}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${extra}</samlp:Response>`;
    const assertion = (id: string): string =>
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" IssueInstant="2026-11-06T00:00:00Z" Version="2.0"><saml:Issuer>${idpEntity}</saml:Issuer></saml:Assertion>`;
    const encode = (xml: string): string => Buffer.from(xml, "utf8").toString("base64");

    const noRelayState = await acs({ SAMLResponse: encode(responseXml(assertion("_a1"))) });
    checks.push([
      "a response without RelayState is refused before any lookup",
      noRelayState.status === 400 && problemDetail(noRelayState.body).includes("RelayState"),
    ]);

    const unsolicited = await acs({
      SAMLResponse: encode(
        `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"/></samlp:Response>`,
      ),
      RelayState: "not-a-state",
    });
    checks.push([
      "an IdP-initiated response has no entry at the ACS",
      unsolicited.status === 400 && problemDetail(unsolicited.body).includes("InResponseTo"),
    ]);

    const garbage = await acs({ SAMLResponse: "%%%", RelayState: relay });
    checks.push([
      "a SAMLResponse that is not base64 is refused",
      garbage.status === 400 && problemDetail(garbage.body).includes("not base64"),
    ]);

    const twoAssertions = await acs({
      SAMLResponse: encode(responseXml(`${assertion("_a1")}${assertion("_a2")}`)),
      RelayState: relay,
    });
    checks.push([
      "a response carrying two Assertions is refused",
      twoAssertions.status === 400 && problemDetail(twoAssertions.body).includes("exactly one"),
    ]);

    const doctype = await acs({
      SAMLResponse: encode(
        `<!DOCTYPE Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>${responseXml(assertion("_a1"))}`,
      ),
      RelayState: relay,
    });
    checks.push([
      "a response carrying a DTD is refused",
      doctype.status === 400 && problemDetail(doctype.body).includes("DTD"),
    ]);

    const unsigned = await acs({
      SAMLResponse: encode(responseXml(assertion("_a1"))),
      RelayState: relay,
    });
    checks.push([
      "an unsigned assertion is refused",
      unsigned.status === 400 && problemDetail(unsigned.body).includes("rejected"),
    ]);

    const replay = await acs({
      SAMLResponse: encode(responseXml(assertion("_a1"))),
      RelayState: relay,
    });
    checks.push([
      "the same RelayState is single-use even after a failed attempt",
      replay.status === 400 && problemDetail(replay.body).includes("already used"),
    ]);

    const audit = await call(
      `${base}/v1/audit?${new URLSearchParams({ action: "sso_connector.created", limit: "5" })}`,
      { headers },
    );
    const auditItems = (audit.body as { items?: { action?: string; payload?: unknown }[] }).items ?? [];
    checks.push([
      "the SAML connector creation is on the tenant audit chain",
      audit.status === 200 &&
        auditItems.some(
          (item) =>
            item.action === "sso_connector.created" &&
            (item.payload as { protocol?: string })?.protocol === "saml",
        ),
    ]);

    const removed = await call(`${base}/v1/saml-connectors/okta`, {
      method: "DELETE",
      headers,
    });
    checks.push([
      "the connector is deleted",
      removed.status === 204,
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "78",
    title: "SAML connectors and assertion checks",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: creation gate → SP metadata → unsigned request → XSW/DTD/base64 → unsigned assertion → single-use RelayState → audit → delete`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

/**
 * Custom tenant hostnames — the three pinned properties of contract §5.8.
 *
 * The server is started with `MONACA_DOMAIN_TXT_ENDPOINT` pointing at the local mock below; the
 * mock is the DNS plane, so a record can be published, removed and restored without real DNS.
 * The step proves: ownership needs the tenant's nonce; unknown/unverified/archived hosts are
 * indistinguishable; a failed re-check degrades instead of deleting and a later success restores;
 * the issuer stays the platform issuer; and activation never rewrites registered redirect URIs.
 */
async function domainFlow(base: string, adminToken: string, adminSecret: string): Promise<StepResult> {
  const t = performance.now();
  const runId = Date.now().toString(36);
  const checks: [string, boolean][] = [];
  let detail = "";
  const mockPort = Number(process.env.MONACA_DOMAIN_MOCK_PORT ?? 38400);
  const primaryHost = `login-${runId}.example.test`;
  const pendingHost = `pending-${runId}.example.test`;
  const archivedHost = `archived-${runId}.example.test`;
  const unknownHost = `unknown-${runId}.example.test`;
  const redirectUri = "http://localhost:5173/bff/callback";
  const records = new Map<string, string[]>();
  let mock: ReturnType<typeof Bun.serve> | undefined;

  const headers = { authorization: `Bearer ${adminToken}`, "content-type": "application/json" };
  const bin =
    process.env.MONACA_SERVER_BIN ??
    (process.platform === "win32" ? ".monaca/bin/monaca-server.exe" : ".monaca/bin/monaca-server");

  const cli = async (args: string[]): Promise<{ code: number; stdout: string; stderr: string }> => {
    const proc = Bun.spawn([bin, ...args], {
      cwd: process.cwd(),
      env: { ...process.env },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, code] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    return { code, stdout, stderr };
  };

  /** A protocol request whose Host header names a custom hostname. */
  const hostCall = (host: string, path: string, init?: RequestInit): Promise<HttpResult> =>
    call(`${base}${path}`, {
      ...init,
      headers: { ...(init?.headers as Record<string, string> | undefined), host },
    });

  const authorizePath = (clientId: string, challenge: string, state: string): string =>
    `/oauth2/authorize?${new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: "openid profile email",
      state,
      nonce: `n-${state}`,
      code_challenge: challenge,
      code_challenge_method: "S256",
      organization: ORG,
    })}`;

  const bodyText = (body: unknown): string => (typeof body === "string" ? body : JSON.stringify(body));
  const domain = (body: unknown) => body as { host?: string; state?: string; verification_record?: string; verification_value?: string; verified_at?: string | null; check_failures?: number };
  const problem = (body: unknown): string => String((body as { detail?: unknown })?.detail ?? "");

  const createDomain = (host: string, token: string): Promise<HttpResult> =>
    call(`${base}/v1/tenant-domains`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ domain: host }),
    });

  const domainAction = (host: string, action: string, token: string): Promise<HttpResult> =>
    call(`${base}/v1/tenant-domains/${host}/${action}`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    });

  /** Publish the expected value for a claimed host. */
  const publish = (host: string, value: string): void => {
    records.set(`_monaca-verify.${host}`, [value]);
  };

  try {
    mock = Bun.serve({
      port: mockPort,
      fetch(request) {
        const name = new URL(request.url).searchParams.get("name") ?? "";
        return Response.json({ records: records.get(name) ?? [] });
      },
    });

    const before = await call(`${base}/v1/clients`, { headers });
    const beforeRows = (before.body as { items?: { id?: string; client_id?: string; redirect_uris?: unknown }[] }).items ?? [];
    const consoleRow = beforeRows.find((row) => row.client_id === "monaca-console");
    const beforeUris = JSON.stringify(consoleRow?.redirect_uris);
    const consoleRowId = consoleRow?.id ?? "";

    // --- claim, prove ownership, activate ---------------------------------------------------
    const claimed = await createDomain(primaryHost, adminToken);
    const claimedView = domain(claimed.body);
    checks.push([
      "a hostname claim returns the TXT record and a tenant-bound nonce",
      claimed.status === 201 &&
        claimedView.state === "pending" &&
        claimedView.verification_record === `_monaca-verify.${primaryHost}` &&
        typeof claimedView.verification_value === "string" &&
        claimedView.verification_value.startsWith("monaca-verify-v1=") &&
        claimedView.verification_value.includes(":"),
    ]);
    const claimedValue = claimedView.verification_value ?? "";

    const duplicate = await createDomain(primaryHost, adminToken);
    checks.push([
      "a second claim of the same host is 409",
      duplicate.status === 409,
    ]);

    publish(primaryHost, "monaca-verify-v1=someone-else:stolen");
    const wrong = await domainAction(primaryHost, "verify", adminToken);
    checks.push([
      "a TXT value that is not this tenant's nonce is refused",
      wrong.status === 400 && problem(wrong.body).includes("monaca-verify-v1="),
    ]);
    // The recheck above must not have verified the binding either.
    const stillPending = await call(`${base}/v1/tenant-domains/${primaryHost}`, { headers });
    checks.push([
      "the wrong record did not verify the binding",
      stillPending.status === 200 && domain(stillPending.body).state === "pending",
    ]);

    publish(primaryHost, claimedValue);
    const verified = await domainAction(primaryHost, "verify", adminToken);
    checks.push([
      "the tenant's TXT value verifies the binding and records verified_at",
      verified.status === 200 &&
        domain(verified.body).state === "verified" &&
        typeof domain(verified.body).verified_at === "string",
    ]);

    const activated = await domainAction(primaryHost, "activate", adminToken);
    checks.push([
      "a verified binding activates",
      activated.status === 200 && domain(activated.body).state === "active",
    ]);

    // --- serving, issuer, discovery --------------------------------------------------------
    const verifier = `s-${runId}-${"z".repeat(32)}`;
    const challenge = base64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
    );
    const served = await hostCall(primaryHost, authorizePath("monaca-console", challenge, `st-${runId}`), {
      redirect: "manual",
    });
    const interaction = new URL(served.headers.get("location") ?? "", base).searchParams.get("interaction");
    checks.push([
      "an authorize on the active custom host is served as the tenant",
      served.status === 302 && interaction !== null,
    ]);

    const discovery = await hostCall(primaryHost, "/.well-known/openid-configuration");
    const platformDiscovery = await call(`${base}/t/${TENANT}/.well-known/openid-configuration`);
    const platformIssuer = (platformDiscovery.body as { issuer?: string }).issuer;
    checks.push([
      "the custom host does not answer discovery",
      discovery.status === 404,
    ]);
    checks.push([
      "discovery stays on the platform issuer",
      platformDiscovery.status === 200 && typeof platformIssuer === "string" && platformIssuer.length > 0,
    ]);

    const customToken = await hostCall(primaryHost, "/oauth2/token", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${btoa(`monaca-admin:${adminSecret}`)}`,
      },
      body: "grant_type=client_credentials&scope=monaca:admin",
    });
    const customIss = jwtClaims((customToken.body as { access_token?: unknown }).access_token)?.iss;
    checks.push([
      "a token minted through the custom host keeps the platform iss",
      customToken.status === 200 && customIss === platformIssuer,
    ]);

    const after = consoleRowId === "" ? undefined : await call(`${base}/v1/clients/${consoleRowId}`, { headers });
    const afterUris = JSON.stringify((after?.body as { redirect_uris?: unknown } | undefined)?.redirect_uris);
    checks.push([
      "activation neither rewrites nor invalidates the registered redirect URIs",
      before.status === 200 && consoleRowId !== "" && after?.status === 200 && beforeUris === afterUris,
    ]);

    // --- cookie attributes -------------------------------------------------------------
    if (interaction === null) throw new Error(`authorize did not yield an interaction: ${served.status}`);
    const signIn = await hostCall(primaryHost, `/interaction/${encodeURIComponent(interaction)}/sign-in`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: BOOTSTRAP_ADMIN.email, password: BOOTSTRAP_ADMIN.password }),
    });
    const setCookie = signIn.headers.get("set-cookie") ?? "";
    checks.push([
      "the session cookie is host-only (no Domain), Lax, HttpOnly and Path=/",
      signIn.status === 200 &&
        setCookie.includes("monaca_session=") &&
        !/domain=/i.test(setCookie) &&
        setCookie.includes("Path=/") &&
        setCookie.includes("HttpOnly") &&
        setCookie.includes("SameSite=Lax") &&
        (base.startsWith("https://") || !setCookie.includes("Secure")),
    ]);

    // --- enumeration: unknown vs pending vs archived are identical --------------------------
    const pending = await createDomain(pendingHost, adminToken);
    checks.push(["a pending binding is created", pending.status === 201]);

    const probe = authorizePath("monaca-console", challenge, "st-probe");
    const unknown = await hostCall(unknownHost, probe, { redirect: "manual" });
    const unverified = await hostCall(pendingHost, probe, { redirect: "manual" });

    // An archived tenant's verified host must answer exactly like the other two.
    const archivedSlug = `dom-${runId}`;
    const archivedSecret = `dom-admin-${runId}`;
    const created = await cli([
      "tenant",
      "create",
      "--slug",
      archivedSlug,
      "--admin-email",
      `admin@${archivedSlug}.localhost`,
      "--admin-password",
      `Dom-${runId}-9xQ`,
      "--admin-client-secret",
      archivedSecret,
      "--login-client-id",
      "e2e-login",
      "--login-redirect-uri",
      redirectUri,
    ]);
    checks.push(["a tenant for the archived case is provisioned", created.code === 0]);
    if (created.code !== 0) throw new Error(created.stderr || created.stdout);

    const archivedTokenResponse = await call(`${base}/t/${archivedSlug}/oauth2/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${btoa(`monaca-admin:${archivedSecret}`)}`,
      },
      body: "grant_type=client_credentials&scope=monaca:admin",
    });
    const archivedToken = (archivedTokenResponse.body as { access_token?: string }).access_token ?? "";
    if (archivedTokenResponse.status !== 200 || archivedToken === "") {
      throw new Error("the archived-case tenant has no management token");
    }
    const archivedClaim = await createDomain(archivedHost, archivedToken);
    if (archivedClaim.status !== 201) throw new Error(`archived-case claim: ${archivedClaim.status}`);
    publish(archivedHost, domain(archivedClaim.body).verification_value ?? "");
    const archivedVerified = await domainAction(archivedHost, "verify", archivedToken);
    const archivedActive = await domainAction(archivedHost, "activate", archivedToken);
    const archivedProbe = authorizePath("e2e-login", challenge, `st-arch-${runId}`);
    checks.push([
      "the archived-case host serves before the tenant is archived",
      archivedVerified.status === 200 &&
        archivedActive.status === 200 &&
        (await hostCall(archivedHost, archivedProbe, { redirect: "manual" })).status === 302,
    ]);
    const archived = await cli(["tenant", "archive", "--slug", archivedSlug]);
    checks.push(["the case tenant is archived through the CLI", archived.code === 0]);

    // Propagation is bounded by MONACA_DOMAIN_CACHE_REFRESH_SECS; poll, then compare exactly.
    let archivedAnswer: HttpResult | undefined;
    for (let attempt = 0; attempt < 24; attempt++) {
      archivedAnswer = await hostCall(archivedHost, archivedProbe, { redirect: "manual" });
      if (archivedAnswer.status !== 302) break;
      await Bun.sleep(500);
    }
    checks.push([
      "unknown, unverified and archived-tenant hosts answer the same status and body",
      unknown.status === unverified.status &&
        unverified.status === archivedAnswer?.status &&
        bodyText(unknown.body) === bodyText(unverified.body) &&
        bodyText(unverified.body) === bodyText(archivedAnswer?.body ?? ""),
    ]);

    // --- degrade on a failed re-check, recover on a later success ---------------------------
    records.delete(`_monaca-verify.${primaryHost}`);
    const degraded = await domainAction(primaryHost, "recheck", adminToken);
    const degradedView = domain(degraded.body);
    checks.push([
      "removing the TXT record degrades the binding and records the check",
      degraded.status === 200 &&
        degradedView.state === "degraded" &&
        (degradedView.check_failures ?? 0) >= 1 &&
        typeof (degradedView as { last_checked_at?: unknown }).last_checked_at === "string",
    ]);
    const degradedServe = await hostCall(primaryHost, probe, { redirect: "manual" });
    checks.push([
      "a degraded binding stops serving with the same response",
      degradedServe.status === unknown.status && bodyText(degradedServe.body) === bodyText(unknown.body),
    ]);
    const retained = await call(`${base}/v1/tenant-domains/${primaryHost}`, { headers });
    checks.push(["the degraded row is retained, not deleted", retained.status === 200]);

    publish(primaryHost, claimedValue);
    const recovered = await domainAction(primaryHost, "recheck", adminToken);
    checks.push([
      "restoring the record recovers the binding to its previous state",
      recovered.status === 200 && domain(recovered.body).state === "active",
    ]);
    checks.push([
      "the recovered binding serves again",
      (await hostCall(primaryHost, probe, { redirect: "manual" })).status === 302,
    ]);

    // --- revoke keeps the row; renew rotates the nonce -------------------------------------
    const revoked = await domainAction(primaryHost, "revoke", adminToken);
    checks.push([
      "revoking stops serving but keeps the row",
      revoked.status === 200 &&
        domain(revoked.body).state === "revoked" &&
        (await hostCall(primaryHost, probe, { redirect: "manual" })).status === unknown.status,
    ]);
    const renewed = await domainAction(primaryHost, "renew", adminToken);
    const renewedValue = domain(renewed.body).verification_value ?? "";
    checks.push([
      "renewing a revoked binding issues a different one-time nonce",
      renewed.status === 200 &&
        domain(renewed.body).state === "pending" &&
        renewedValue.startsWith("monaca-verify-v1=") &&
        renewedValue !== claimedValue,
    ]);
    const revokedAgain = await domainAction(primaryHost, "revoke", adminToken);
    const revokedPending = await domainAction(pendingHost, "revoke", adminToken);
    checks.push([
      "the pending binding can be revoked too",
      revokedAgain.status === 200 && revokedPending.status === 200,
    ]);

    const listed = await call(`${base}/v1/tenant-domains`, { headers });
    const items = (listed.body as { items?: { host?: string; state?: string }[] }).items ?? [];
    checks.push([
      "the list retains every binding including revoked ones",
      listed.status === 200 &&
        items.some((item) => item.host === primaryHost && item.state === "revoked") &&
        items.some((item) => item.host === pendingHost && item.state === "revoked"),
    ]);

    const audit = await call(
      `${base}/v1/audit?${new URLSearchParams({ action_prefix: "tenant_domain.", limit: "50" })}`,
      { headers },
    );
    const auditItems = (audit.body as { items?: { action?: string }[] }).items ?? [];
    const actions = new Set(auditItems.map((item) => item.action));
    checks.push([
      "claim, verify, activate, degrade, recover, revoke and renew are all on the tenant chain",
      audit.status === 200 &&
        ["created", "verified", "activated", "degraded", "recovered", "revoked", "renewed"].every(
          (action) => actions.has(`tenant_domain.${action}`),
        ),
    ]);
  } catch (error) {
    detail = error instanceof Error ? error.message : String(error);
    checks.push([`the flow completed without an exception (${detail})`, false]);
  } finally {
    mock?.stop();
  }

  const ok = checks.length > 0 && checks.every(([, passed]) => passed);
  return {
    step: "79",
    title: "custom tenant hostnames",
    status: ok ? "pass" : "fail",
    ms: Math.round(performance.now() - t),
    detail: ok
      ? `${checks.length} checks: claim/nonce → TXT mismatch → verify → activate → serving/issuer → cookie → enumeration → degrade/recover → revoke/renew → audit`
      : `${detail || checks.filter(([, passed]) => !passed).map(([name]) => name).join(", ")}`,
  };
}

async function main(): Promise<number> {
  const parsed = parseArgs(process.argv.slice(2));
  if ("error" in parsed) {
    if (parsed.error === "__help__") {
      console.log(usage());
      return 0;
    }
    process.stderr.write(`${parsed.error}\n\n${usage()}\n`);
    return 2;
  }

  const normalised = normaliseBaseUrl(parsed.baseUrl);
  if (typeof normalised !== "string") {
    process.stderr.write(`${normalised.invalid}\n`);
    return 2;
  }
  const base = normalised;
  const startedAt = new Date();
  const t0 = performance.now();
  const quiet = parsed.json;

  if (!quiet) {
    console.log(`monaca e2e walk-through — ${base}`);
  }

  const steps: StepResult[] = [];
  const report: Report = {
    base_url: base,
    started_at: startedAt.toISOString(),
    finished_at: "",
    duration_ms: 0,
    stage: 1,
    ok: false,
    steps,
  };
  const push = (result: StepResult): void => {
    steps.push(result);
    if (!quiet) {
      const label = result.status === "pass" ? "pass" : result.status.toUpperCase();
      console.log(`  ${label}  ${result.step.padEnd(3)} ${result.title}${result.ms === undefined ? "" : ` (${result.ms} ms)`}  ${result.detail}`);
    }
  };

  // --- 1. health -----------------------------------------------------------------------------
  let healthDetail: string | undefined;
  let healthOk = false;
  let healthMs = 0;
  try {
    const t = performance.now();
    const res = await fetch(`${base}/healthz`, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
    });
    healthMs = Math.round(performance.now() - t);
    const body = await res.text();
    if (!res.ok) {
      healthDetail = `HTTP ${res.status} ${res.statusText} — ${truncate(body)}`;
    } else {
      let parsedBody: unknown;
      try {
        parsedBody = JSON.parse(body);
      } catch {
        healthDetail = `200 but the body is not JSON — ${truncate(body)}`;
      }
      if (parsedBody !== undefined) {
        const status = (parsedBody as { status?: unknown }).status;
        if (status === "ok") {
          healthOk = true;
          healthDetail = `200 {"status":"ok"} in ${healthMs} ms`;
        } else {
          healthDetail = `200 but status is ${JSON.stringify(status)}, expected "ok"`;
        }
      }
    }
  } catch (err) {
    healthMs = 0;
    healthDetail = describeNetError(err);
  }

  push({
    step: "1",
    title: "health",
    status: healthOk ? "pass" : "fail",
    ms: healthMs,
    detail: healthDetail,
  });

  if (!healthOk) {
    // Nothing else can run; the remaining steps are reported as skipped rather than failed.
    for (const step of ACCEPTANCE_STEPS.slice(1)) {
      steps.push({ step: step.step, title: step.title, status: "todo", detail: step.assertion });
    }
    report.ok = false;
    report.error = `health failed: ${base}/healthz — ${healthDetail}`;
    report.duration_ms = Math.round(performance.now() - t0);
    report.finished_at = new Date().toISOString();
    await writeReport(parsed.report, report);

    process.stderr.write(
      `\ne2e walk-through: cannot reach ${base}/healthz (${healthDetail}).\n` +
        `  mode a: is \`bun run dev\` running?  mode b: check MONACA_REMOTE_URL.  CI: check the server log.\n` +
        `  report: ${parsed.report}\n`,
    );
    return 1;
  }

  // --- 0. a management token (step 2's credential) -------------------------------------------
  const admin = await tokenCall(base, { grant_type: "client_credentials", scope: "monaca:admin" }, btoa(`${ADMIN_CLIENT_ID}:${parsed.adminSecret}`));
  const adminToken = (admin.body as { access_token?: string })?.access_token;
  if (admin.status !== 200 || adminToken === undefined) {
    for (const step of ACCEPTANCE_STEPS.slice(1)) {
      steps.push({ step: step.step, title: step.title, status: "todo", detail: step.assertion });
    }
    report.ok = false;
    report.error = `no management token: ${admin.status} ${text(admin.body)}`;
    report.duration_ms = Math.round(performance.now() - t0);
    report.finished_at = new Date().toISOString();
    await writeReport(parsed.report, report);
    process.stderr.write(
      `\ne2e walk-through: the seeded ${ADMIN_CLIENT_ID} client did not yield a token (${admin.status} ${text(admin.body)}).\n` +
        `  pass its secret with --admin-secret.\n`,
    );
    return 1;
  }

  const setupResult = await setup(base, adminToken, (line) => {
    if (!quiet) console.log(line);
  });
  push({
    step: "2",
    title: "setup",
    status: setupResult.ok ? "pass" : "fail",
    detail: setupResult.detail,
  });

  if (setupResult.walk === undefined) {
    report.ok = false;
    report.error = setupResult.detail;
    report.duration_ms = Math.round(performance.now() - t0);
    report.finished_at = new Date().toISOString();
    await writeReport(parsed.report, report);
    return 1;
  }

  const walk = setupResult.walk;
  if (setupResult.agentKey === undefined) {
    report.ok = false;
    report.error = "the setup step returned no key pair";
    report.duration_ms = Math.round(performance.now() - t0);
    report.finished_at = new Date().toISOString();
    await writeReport(parsed.report, report);
    return 1;
  }
  const grants = await tokenGrants(base, walk, setupResult.agentKey.sign);
  push(grants.step3);
  push(grants.step3b);

  const tools = await toolCalls(base, grants.accessToken);
  push(tools.step4);
  push(tools.step4b);

  push(await auditChain(base, adminToken, walk));
  push(await browserFlow(base, parsed.consoleSecret));
  push(await sessionFlow(base, parsed.consoleSecret, adminToken));
  push(await emailFlow(base, parsed.consoleSecret, parsed.internalSecret));
  push(await mfaFlow(base, adminToken, parsed.consoleSecret));
  push(await accountFlow(base, adminToken, parsed.internalSecret));
  push(await backupCodeFlow(base, adminToken, parsed.consoleSecret));
  push(await passkeyFlow(base, adminToken, parsed.consoleSecret));
  push(await usernameFlow(base, adminToken, parsed.consoleSecret));
  push(await emailChangeFlow(base, adminToken, parsed.consoleSecret, parsed.internalSecret));
  push(await socialFlow(base, adminToken, parsed.consoleSecret));
  push(await trustedDeviceFlow(base, adminToken, parsed.consoleSecret));
  push(await accountDeletionFlow(base, adminToken, parsed.internalSecret));
  push(await signInLinkFlow(base, adminToken, parsed.consoleSecret, parsed.internalSecret));
  push(await roleFlow(base, adminToken, parsed.consoleSecret));
  push(await scopeGrantFlow(base, adminToken, parsed.consoleSecret));
  push(await loginHintFlow(base, adminToken, parsed.consoleSecret));
  push(await clientFlow(base, adminToken));
  push(await userManagementFlow(base, adminToken, parsed.consoleSecret));
  push(await signInExperienceFlow(base, adminToken));
  push(await apiResourceFlow(base, adminToken));
  push(await organizationFlow(base, adminToken));
  push(await orgMemberFlow(base, adminToken));
  push(await orgDomainFlow(base, adminToken));
  push(await orgRoleFlow(base, adminToken));
  push(await orgInvitationFlow(base, adminToken));
  push(await ssoFlow(base, adminToken));
  push(await accountSecurityFlow(base, adminToken));
  push(await mandatoryMfaFlow(base, adminToken, parsed.consoleSecret));
  push(await webhookFlow(base, adminToken));
  push(await passwordPolicyFlow(base, adminToken, parsed.consoleSecret, parsed.internalSecret));
  push(await brandingFlow(base, adminToken));
  push(await brandingExtrasFlow(base, adminToken));
  push(await accountProfileFlow(base, adminToken));
  push(await sessionSettingsFlow(base, adminToken, parsed.consoleSecret));
  push(await passwordComplexityFlow(base, adminToken, parsed.internalSecret));
  push(await customCssFlow(base, adminToken));
  push(await passwordRejectionsFlow(base, adminToken));
  push(await passwordWordListFlow(base, adminToken));
  push(await applicationCssFlow(base, adminToken));
  push(await passkeySignInSwitchFlow(base, adminToken));
  push(await accountAvatarFlow(base, adminToken));
  push(await trustedDevicePolicyFlow(base, adminToken));
  push(await ssoSwitchFlow(base, adminToken));
  push(await registrationPolicyFlow(base, adminToken, parsed.consoleSecret));
  push(await consentFlow(base, adminToken));
  push(await emailTemplatesFlow(base, adminToken, parsed.internalSecret));
  push(await captchaFlow(base, adminToken));
  push(await corsFlow(base, adminToken));
  push(await signInCopyFlow(base, adminToken));
  push(await consentSemanticsFlow(base, adminToken, parsed.internalSecret));
  push(await emailConnectorFlow(base, adminToken, parsed.internalSecret));
  push(await usernamePolicyFlow(base, adminToken));
  push(await capCaptchaFlow(base, adminToken));
  push(await socialProvidersFlow(base, adminToken, parsed.consoleSecret, parsed.internalSecret));
  push(await revocationFlow(base, parsed.adminSecret));
  push(await rateLimitFlow(base, adminToken, parsed.adminSecret));
  push(await ipRateLimitFlow(base, adminToken));
  push(await persistenceFlow(base, adminToken, parsed.consoleSecret));
  push(await sharedRateLimitFlow(base, adminToken, parsed.adminSecret));
  push(await metricsFlow(base, parsed.internalSecret));
  push(await sdkFlow(base, adminToken));
  push(await tenantLifecycleFlow(base));
  push(await smsVerificationFlow(base, adminToken));
  push(await smtpDeliveryFlow(base, adminToken));
  push(await templateFallbackFlow(base, adminToken));
  push(await administrativeDisposalFlow(base, adminToken, parsed.consoleSecret, parsed.internalSecret));
  push(await sessionKickFlow(base, adminToken, parsed.consoleSecret));
  push(await auditQueryFlow(base, adminToken, parsed.consoleSecret));
  push(await revocationImmediateFlow(base, adminToken, parsed.consoleSecret));
  push(await usageQuotaFlow(base, adminToken, parsed.consoleSecret));
  push(await roleTierFlow(base, adminToken, parsed.consoleSecret));
  push(await tenantLifecycleAndMeFlow(base, adminToken, parsed.consoleSecret));
  push(await samlFlow(base));
  push(await domainFlow(base, adminToken, parsed.adminSecret));

  const failures = steps.filter((step) => step.status === "fail");
  report.ok = failures.length === 0;
  report.duration_ms = Math.round(performance.now() - t0);
  report.finished_at = new Date().toISOString();
  await writeReport(parsed.report, report);

  if (quiet) console.log(JSON.stringify(report, null, 2));
  else {
    const skipped = steps.filter((step) => step.status === "skip").length;
    console.log(
      `\n${report.ok ? "walk-through ok" : "walk-through FAILED"} (${report.duration_ms} ms, ${steps.length} steps` +
        `${skipped === 0 ? "" : `, ${skipped} skipped`}) — report: ${parsed.report}`,
    );
  }
  return report.ok ? 0 : 1;
}

function truncate(text: string, max = 200): string {
  const collapsed = text.replace(/\s+/g, " ").trim();
  return collapsed.length <= max ? collapsed : `${collapsed.slice(0, max)}…`;
}

try {
  process.exit(await main());
} catch (err) {
  process.stderr.write(`e2e skeleton: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
