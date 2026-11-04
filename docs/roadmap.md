# Post-M0 hardening roadmap

This document sequences the work after the M0 feature build. The batches are ordered by what
breaks first in a real deployment, not by what is easiest to write.

Each capability in every batch closes the same way: contract update + migration (when storage
changes) + a positive e2e step + a negative e2e step that fails when the capability is bypassed.
A configuration switch alone is not acceptance.

## Batch A — Functional and security correctness

These are defects in behavior that M0 already promises. They come first because a production
deployment cannot compensate for them with operational tooling.

1. **Revocation propagation.** `/t/{tenant}/oauth2/revoke` records an access token's `jti` in
   `tenant.revoked_access_tokens`, and `userinfo` consults it, but the `/v1` management verifier
   does not. A revoked admin or automation token still opens the management API. The fix is a
   revocation check in `management::authorize_admin`; the negative e2e mints two tokens, revokes
   one, and proves the revoked token is `401` while the other still works.
2. **Rate limiting.** No layer currently bounds request volume. Add a configurable gate with a
   tenant-wide layer and a per-client layer for the `authorize`, `token`, `userinfo` and
   management endpoint classes. Config lives in the tenant schema (`rate_limits`), is managed
   through `/v1/rate-limits`, and is enforced in-process with a bounded bucket cache. A rejected
   request is `429 MONACA_TOO_MANY_ATTEMPTS` with `Retry-After`. Defaults are deliberately
   generous so an existing deployment is not throttled on upgrade.
3. **Interaction state persistence.** `interactions`, pending TOTP enrollments and WebAuthn
   challenges live in process memory (`AppState`). A restart loses in-flight sign-ins, and a
   second instance cannot complete a flow that started on the first. Move all three to the tenant
   schema (`interactions`, `totp_enrollments`, `passkey_challenges`), seal the pending TOTP seed
   with the tenant DEK, and make every transition a transactional row update. The e2e proves a
   flow that starts on one server process and finishes on a freshly started one; replay after
   restart must still be `409`, and an unknown interaction `404`.
4. **Bounded caches.** After (3) the remaining process maps are the signing-key cache and the
   rate-limit buckets. Both get an explicit capacity with eviction, so a long-lived process cannot
   grow without a bound.

Why first: (1) is a security bypass, (2) is availability, (3) breaks single-instance restarts and
blocks horizontal scaling. All three change protocol/management contracts, so doing them before B
keeps the contract surface stable while metrics and roles are layered on.

## Batch B — Operability and contracts

1. **Structured logs and metrics.** Request count, latency (P50/P95/P99), error rate, and the
   answer to "which client/tenant/endpoint is slow", covering the new rate-limit rejections and
   revocation failures. Includes OTLP export from the existing `MONACA_OTLP_ENDPOINT`.
2. **Least-privilege `monaca_app` role.** Tenant pools currently reuse the control database DSN
   (a superuser) for request-path work. The runtime login must be `monaca_app`, granted only the
   org roles it needs; provisioning and migrations keep the admin DSN.
3. **OpenAPI completeness.** `ApiDoc` only registers `/healthz` and `/version`, and
   `packages/sdk` is `export {}`. Register the protocol/management surface and generate the SDK
   from it, with the drift check enforcing both.

Why second: metrics should observe the gates added in A rather than be rewritten around them, and
the DB role change touches provisioning, pools and migrations — after A, those paths have
regression coverage. OpenAPI is a contract artifact; it is cheaper once the A endpoints are final.

## Batch C — Performance

1. **A repeatable benchmark first.** A committed script (`scripts/bench/`) drives a fresh database
   and records P50/P90/P99 for `authorize`, `token` and `userinfo`, tenant-pool acquisition time,
   and database queries per request. It must run against the same server binary the e2e uses, be
   repeatable on a CI runner, and store the raw numbers as a report artifact.
2. **Optimize only what the baseline names.** Candidate work: pool/policy caching, query
   reduction on the interactive path, and token verification reuse. Every change cites the
   baseline number it moves.

Why last: A and B change the query mix and request instrumentation, so a benchmark taken before
them measures the wrong program. No optimization lands without a before/after number.

## Not in these batches

Consent/interaction storage beyond the three state tables, per-IP limiting, distributed rate
limiting across instances, WAL/PITR, KMS-backed KEK, KMS key rotation, and a console UI for
rate-limit configuration. They are either follow-ups to B/C or require infrastructure decisions
outside this repository.
