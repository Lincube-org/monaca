//! Shared application state: the store, the configuration, the key cache and the interaction map.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use monaca_audit::AuditEvent;
use monaca_crypto::{Argon2Params, EnvKeyProvider, KeyProvider, SigningKeyPair, seal};
use monaca_oidc::Interaction as InteractionRequest;
use monaca_store::{InteractionRow, OrgRow, Store, TenantRow};
use monaca_types::{Clock, KeyId, OrgCtx, SystemClock};
use serde_json::Value;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{ApiError, kinds};
use crate::metrics::Metrics;
use crate::rate_limit::RateLimiter;

/// Upper bound on the decoded signing keys kept in memory. One entry is a few kilobytes and the
/// cache is a speed-up, not a source of truth, so evicting the oldest loaded tenant is safe.
const SIGNING_CACHE_CAP: usize = 256;

/// How long Google's JWKS is reused before a scheduled refresh. An unknown `kid` forces a refresh
/// immediately, which is the rotation path that matters.
const GOOGLE_JWKS_TTL_SECS: i64 = 3_600;

/// One fetched copy of Google's signing keys.
struct GoogleJwksCache {
    keys: Arc<Vec<Value>>,
    fetched_at: time::OffsetDateTime,
}

/// Everything a handler needs.
pub struct AppState {
    /// PostgreSQL for the request path. Its tenant-pool cache is the one the mailer must not
    /// evict.
    pub store: Arc<Store>,
    /// The mailer's own tenant-pool cache over the same control and provisioning connections.
    /// Bounded by `MONACA_MAILER_POOL_SIZE`/`MONACA_MAILER_POOL_CACHE`, so a sweep over every
    /// connector tenant cannot churn the request-path working set.
    pub mailer_store: Arc<Store>,
    /// Environment-derived configuration.
    pub config: Arc<Config>,
    /// Key provider (the environment-supplied KEK in M0; a KMS provider replaces this behind the
    /// same trait).
    pub keys: Arc<dyn KeyProvider>,
    /// Argon2 parameters.
    pub argon: Argon2Params,
    /// Time.
    pub clock: Arc<dyn Clock>,
    /// The active signing key per tenant, decoded. Cached because every token needs it and the
    /// private half is sealed at rest.
    signing: Mutex<HashMap<Uuid, Arc<SigningKeyPair>>>,
    /// The client webhook deliveries are posted with. One pool-backed client, so a tenant with
    /// many subscriptions does not open a new connection pool per event.
    pub http: reqwest::Client,
    /// Per-endpoint request gates (§6.2).
    pub rate_limit: RateLimiter,
    /// Per-IP gates for the authentication endpoints. Counted in this process, not in the
    /// database: the address space is much larger than the tenant set and a row per address would
    /// tax every unauthenticated request.
    pub ip_limit: crate::ip_limit::IpRateLimiter,
    /// Prometheus text metrics (§6.4).
    pub metrics: Metrics,
    /// Google's signing keys. Provider-global, so one cache serves every tenant connector.
    google_jwks: Mutex<Option<GoogleJwksCache>>,
    /// Hostname → tenant slug for custom domains that currently serve. Rebuilt from the control
    /// plane on an interval and after a management write; a request-path read takes only this
    /// lock, so host routing never adds a database round trip.
    domain_routes: RwLock<HashMap<String, String>>,
    /// The lazily built system DNS resolver used by custom-domain verification.
    dns: tokio::sync::OnceCell<hickory_resolver::TokioResolver>,
}

impl AppState {
    /// Build the state from a connected store and a config.
    pub fn new(store: Store, config: Config) -> Result<Arc<Self>, anyhow::Error> {
        // `Config::validate` has already checked the shape; the error here names the variable
        // without ever printing the value.
        let keys = EnvKeyProvider::from_hex_with_previous(
            &config.kek_hex,
            config.previous_kek_hex.as_deref(),
        )
        .map_err(|err| anyhow::anyhow!("MONACA_KEK/MONACA_DEV_KEK: {err}"))?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|err| anyhow::anyhow!("webhook HTTP client: {err}"))?;
        let mailer_store = store.separate_tenant_cache(
            store.config().mailer_pool_size,
            store.config().mailer_pool_cache,
        );
        Ok(Arc::new(Self {
            store: Arc::new(store),
            mailer_store: Arc::new(mailer_store),
            config: Arc::new(config),
            keys: Arc::new(keys),
            argon: Argon2Params::from_env(),
            clock: Arc::new(SystemClock),
            signing: Mutex::new(HashMap::new()),
            http,
            rate_limit: RateLimiter::default(),
            ip_limit: crate::ip_limit::IpRateLimiter::default(),
            metrics: Metrics::default(),
            google_jwks: Mutex::new(None),
            domain_routes: RwLock::new(HashMap::new()),
            dns: tokio::sync::OnceCell::new(),
        }))
    }

    /// The current instant.
    pub fn now(&self) -> time::OffsetDateTime {
        self.clock.now()
    }

    /// Rebuild the hostname → tenant map from the control plane.
    ///
    /// Only a binding that serves and a tenant that serves can be routed. The tenant half calls
    /// [`TenantRow::serving`], the same gate `tenant()` and the path-based handlers use; this
    /// function never re-implements the lifecycle decision. A database failure leaves the
    /// previous map in place: a stale binding is bounded by `MONACA_DOMAIN_CACHE_REFRESH_SECS` and
    /// is preferable to dropping every custom hostname on a transient read failure.
    pub async fn refresh_domain_routes(&self) -> Result<(), ApiError> {
        let routes = self.store.serving_domain_routes().await?;
        let mut map = HashMap::with_capacity(routes.len());
        for route in routes {
            let tenant = route.tenant();
            if tenant.serving().is_ok() {
                map.insert(route.host, route.tenant_slug);
            }
        }
        let mut current = self
            .domain_routes
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        *current = map;
        Ok(())
    }

    /// The tenant serving a custom hostname, if the cached map has one.
    pub fn domain_route(&self, host: &str) -> Option<String> {
        self.domain_routes
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(host)
            .cloned()
    }

    /// The system resolver, built once. Verification failures keep the cell empty so a transient
    /// configuration failure is retried on the next check.
    pub async fn dns(&self) -> Result<&hickory_resolver::TokioResolver, String> {
        self.dns
            .get_or_try_init(|| async {
                hickory_resolver::TokioResolver::builder_tokio()
                    .map(|builder| builder.build())
                    .map_err(|err| err.to_string())
            })
            .await
    }

    /// A tenant by slug that is allowed to serve requests.
    ///
    /// `suspended` and `archived` are explicit refusals, not a `404`: the caller learns that the
    /// tenant exists but is not serving. `provisioning` stays a `404`, because a half-provisioned
    /// tenant is not addressable yet. Every handler that resolves a tenant through this method
    /// inherits the gate; `authorize_admin` has its own check because it resolves by typed id.
    pub async fn tenant(&self, slug: &str) -> Result<TenantRow, ApiError> {
        let tenant = self.store.tenant_by_slug(slug).await?;
        tenant.serving().map_err(|state| match state {
            "suspended" => ApiError::problem(
                kinds::TENANT_SUSPENDED,
                "this tenant is suspended; contact its administrator",
            ),
            "archived" => ApiError::problem(
                kinds::TENANT_ARCHIVED,
                "this tenant is archived; contact its administrator",
            ),
            _ => ApiError::problem(kinds::NOT_FOUND, "tenant is not active"),
        })?;
        Ok(tenant)
    }

    /// Count one request against the tenant and client layers for `endpoint` (§6.2).
    ///
    /// The configuration is cached per tenant for [`crate::rate_limit::config_ttl_secs`] seconds;
    /// a management write in this process invalidates it immediately.
    pub async fn enforce_rate_limit(
        &self,
        tenant: &TenantRow,
        endpoint: &str,
        client: Option<&str>,
    ) -> Result<(), ApiError> {
        let now = self.now();
        let rows = match self.rate_limit.cached(tenant.id, now).await {
            Some(rows) => rows,
            None => {
                let loaded = Arc::new(self.store.rate_limits(tenant).await?);
                self.rate_limit
                    .remember(tenant.id, Arc::clone(&loaded), now)
                    .await;
                loaded
            }
        };
        let (tenant_layer, client_layer) = crate::rate_limit::layer_limits(&rows, endpoint, client);
        let key = format!("{endpoint}|tenant");
        let (count, window_start) = self
            .store
            .rate_limit_hit(tenant, &key, tenant_layer.1, now)
            .await?;
        if let Some(rejection) =
            crate::rate_limit::rejection(count, tenant_layer.0, window_start, tenant_layer.1, now)
        {
            self.metrics
                .record_rejection(&tenant.slug, endpoint, "tenant", None);
            return Err(ApiError::rate_limited(rejection.retry_after));
        }
        if let (Some((limit, window_secs)), Some(client)) = (client_layer, client) {
            let key = format!("{endpoint}|client|{client}");
            let (count, window_start) = self
                .store
                .rate_limit_hit(tenant, &key, window_secs, now)
                .await?;
            if let Some(rejection) =
                crate::rate_limit::rejection(count, limit, window_start, window_secs, now)
            {
                self.metrics
                    .record_rejection(&tenant.slug, endpoint, "client", Some(client));
                return Err(ApiError::rate_limited(rejection.retry_after));
            }
        }
        Ok(())
    }

    /// Count one request against the per-IP layer for `endpoint` (§6.2).
    ///
    /// The address is already resolved through the trusted-proxy boundary by the caller. `None`
    /// means the request has no socket peer (a router exercised directly in a unit test), in which
    /// case the gate is skipped; a real connection always has one. `0`
    /// (`MONACA_IP_RATE_LIMIT_PER_MINUTE`) disables the layer.
    pub async fn enforce_ip_rate_limit(
        &self,
        ip: Option<std::net::IpAddr>,
        endpoint: &'static str,
    ) -> Result<(), ApiError> {
        let Some(ip) = ip else {
            return Ok(());
        };
        if self.config.ip_rate_limit_per_minute == 0 {
            return Ok(());
        }
        if let Some(retry_after) = self
            .ip_limit
            .hit(
                ip,
                endpoint,
                self.config.ip_rate_limit_per_minute,
                std::time::Instant::now(),
            )
            .await
        {
            // The tenant is unknown at this point (the gate runs before tenant resolution).
            self.metrics.record_rejection("-", endpoint, "ip", None);
            return Err(ApiError::rate_limited(retry_after));
        }
        Ok(())
    }

    /// Drop the tenant's cached limit configuration after a management write.
    pub async fn invalidate_rate_limits(&self, tenant: &TenantRow) {
        self.rate_limit.invalidate(tenant.id).await;
    }

    /// The tenant's data-encryption key, for sealing per-account secrets such as a TOTP seed.
    pub fn tenant_dek(&self, tenant: &TenantRow) -> Result<[u8; 32], ApiError> {
        self.keys
            .tenant_dek(&tenant.tenant_id())
            .ok_or_else(|| ApiError::internal("tenant DEK missing"))
    }

    /// Open a sealed tenant value with the current KEK, or the retiring one during a rotation.
    pub fn open_tenant(&self, tenant: &TenantRow, sealed: &[u8]) -> Result<Vec<u8>, ApiError> {
        self.open_tenant_id(&tenant.tenant_id(), sealed)
    }

    /// The same for a caller that has the id but not the row (the mailer and the webhook relay).
    pub fn open_tenant_id(
        &self,
        tenant_id: &monaca_types::TenantId,
        sealed: &[u8],
    ) -> Result<Vec<u8>, ApiError> {
        monaca_crypto::open_any(&self.keys.tenant_deks(tenant_id), sealed)
            .map_err(|err| ApiError::internal(format!("sealed value: {err}")))
    }

    /// An org by slug, or the configured default when the slug is empty.
    pub async fn org(&self, tenant: &TenantRow, slug: Option<&str>) -> Result<OrgRow, ApiError> {
        let slug = slug
            .filter(|slug| !slug.is_empty())
            .unwrap_or(self.config.default_org.as_str());
        Ok(self.store.org_by_slug(tenant, slug).await?)
    }

    /// The tenant's active signing key, generated and sealed on first use.
    pub async fn signing_key(&self, tenant: &TenantRow) -> Result<Arc<SigningKeyPair>, ApiError> {
        if let Some(key) = self.signing.lock().await.get(&tenant.id).cloned() {
            return Ok(key);
        }

        let rows = self.store.signing_keys(tenant).await?;
        let key = if let Some(row) = rows.first() {
            let der = self
                .open_tenant(tenant, &row.private_enc)
                .map_err(|err| ApiError::internal(format!("signing key: {err}")))?;
            SigningKeyPair::from_pkcs8_der(KeyId::from_uuid(row.id), der)
                .map_err(|err| ApiError::internal(format!("signing key: {err}")))?
        } else {
            let dek = self.tenant_dek(tenant)?;
            let kid = KeyId::new();
            let generated = SigningKeyPair::generate(kid)
                .map_err(|err| ApiError::internal(format!("key generation: {err}")))?;
            let sealed = seal(&dek, generated.pkcs8_der())
                .map_err(|err| ApiError::internal(format!("sealing key: {err}")))?;
            self.store
                .insert_signing_key(tenant, kid.uuid(), &sealed, generated.public_jwk())
                .await?;
            generated
        };

        let key = Arc::new(key);
        let mut cache = self.signing.lock().await;
        if !cache.contains_key(&tenant.id) && cache.len() >= SIGNING_CACHE_CAP {
            // The cache is a speed-up, not the source of truth: dropping any one entry only costs
            // the next request for that tenant a database read.
            if let Some(oldest) = cache.keys().next().copied() {
                cache.remove(&oldest);
            }
        }
        cache.insert(tenant.id, Arc::clone(&key));
        Ok(key)
    }

    /// Every non-retired public JWK for the tenant.
    pub async fn jwks(&self, tenant: &TenantRow) -> Result<Vec<Value>, ApiError> {
        let rows = self.store.signing_keys(tenant).await?;
        if rows.is_empty() {
            // Provision the key on first read so a freshly bootstrapped tenant has a JWKS.
            let _ = self.signing_key(tenant).await?;
            return Ok(self
                .store
                .signing_keys(tenant)
                .await?
                .into_iter()
                .map(|row| row.public_jwk)
                .collect());
        }
        Ok(rows.into_iter().map(|row| row.public_jwk).collect())
    }

    /// Google's signing keys, with a one-hour cache and an immediate refresh when `force_refresh`
    /// is set (the unknown-`kid` rotation path).
    ///
    /// A failed fetch does not discard a usable stale copy: providers do occasionally have short
    /// outages, and the alternative is refusing every Google sign-in. A caller that forced a
    /// refresh still verifies against the stale set, so an unknown `kid` remains refused.
    pub async fn google_jwks(&self, force_refresh: bool) -> Result<Arc<Vec<Value>>, ApiError> {
        let now = self.now();
        let mut cache = self.google_jwks.lock().await;
        if !force_refresh
            && let Some(entry) = cache.as_ref()
            && now - entry.fetched_at < time::Duration::seconds(GOOGLE_JWKS_TTL_SECS)
        {
            return Ok(Arc::clone(&entry.keys));
        }

        let url = self.config.google_jwks_url();
        let fetched = async {
            let response = self
                .http
                .get(&url)
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await
                .map_err(|err| {
                    tracing::warn!(%err, "Google JWKS could not be fetched");
                    "request failed"
                })?;
            if !response.status().is_success() {
                tracing::warn!(status = %response.status(), "Google JWKS refused");
                return Err("non-success status");
            }
            let document: Value = response.json().await.map_err(|err| {
                tracing::warn!(%err, "Google JWKS is not JSON");
                "invalid JSON"
            })?;
            let keys = document
                .get("keys")
                .and_then(Value::as_array)
                .map(|keys| {
                    keys.iter()
                        .filter(|key| key.get("kid").and_then(Value::as_str).is_some())
                        .cloned()
                        .collect::<Vec<Value>>()
                })
                .filter(|keys| !keys.is_empty())
                .ok_or("no usable keys")?;
            Ok::<Arc<Vec<Value>>, &'static str>(Arc::new(keys))
        }
        .await;

        match fetched {
            Ok(keys) => {
                cache.replace(GoogleJwksCache {
                    keys: Arc::clone(&keys),
                    fetched_at: now,
                });
                Ok(keys)
            }
            Err(reason) => {
                if let Some(entry) = cache.as_ref() {
                    tracing::warn!(reason, "using the stale Google JWKS");
                    return Ok(Arc::clone(&entry.keys));
                }
                Err(ApiError::problem(
                    kinds::SOCIAL_PROVIDER_ERROR,
                    "Google's signing keys could not be fetched",
                ))
            }
        }
    }

    /// Store a freshly minted interaction and its expiry.
    pub async fn put_interaction(
        &self,
        tenant: &TenantRow,
        interaction: InteractionRequest,
    ) -> Result<(), ApiError> {
        let payload = serde_json::to_value(&interaction).map_err(ApiError::internal)?;
        self.store
            .interaction_put(
                tenant,
                &interaction.interaction_id.to_string(),
                &payload,
                interaction.expires_at,
            )
            .await
            .map_err(ApiError::internal)
    }

    /// Read an interaction without consuming it.
    pub async fn peek_interaction(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<InteractionRequest, monaca_oidc::InteractionError> {
        Ok(self.peek_interaction_state(tenant, id).await?.0)
    }

    /// Read an interaction and whether sign-in already happened (for the consent-only page).
    pub async fn peek_interaction_state(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<(InteractionRequest, Option<Uuid>), monaca_oidc::InteractionError> {
        let row = self.interaction_row(tenant, id).await?;
        Ok((interaction_payload(&row)?, row.signed_in_account))
    }

    /// Mark an interaction consumed, returning it. A second call is `Consumed`.
    pub async fn consume_interaction(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<InteractionRequest, monaca_oidc::InteractionError> {
        match self
            .store
            .interaction_consume(tenant, id)
            .await
            .map_err(interaction_store_error)?
        {
            Some(row) => interaction_payload(&row),
            None => Err(self.interaction_failure(tenant, id).await),
        }
    }

    /// Record that `account` authenticated, leaving the interaction redeemable by the consent step.
    pub async fn mark_interaction_signed_in(
        &self,
        tenant: &TenantRow,
        id: &str,
        account: Uuid,
        session_id: Uuid,
    ) -> Result<InteractionRequest, monaca_oidc::InteractionError> {
        let row = self
            .require_interaction_update(
                self.store
                    .interaction_mark_signed_in(tenant, id, account, session_id)
                    .await,
                tenant,
                id,
            )
            .await?;
        interaction_payload(&row)
    }

    /// Attach the SAML identity a verified assertion carried to the interaction it completes.
    pub async fn attach_interaction_saml(
        &self,
        tenant: &TenantRow,
        id: &str,
        saml: &monaca_oidc::SamlLogin,
    ) -> Result<InteractionRequest, monaca_oidc::InteractionError> {
        let value = serde_json::to_value(saml).map_err(|err| {
            tracing::error!(%err, "the SAML identity is not serializable");
            monaca_oidc::InteractionError::NotFound
        })?;
        let row = self
            .require_interaction_update(
                self.store.interaction_attach_saml(tenant, id, &value).await,
                tenant,
                id,
            )
            .await?;
        interaction_payload(&row)
    }

    /// Redeem an interaction that has signed in, returning the account awaiting consent and the
    /// session it authenticated.
    pub async fn take_signed_in_interaction(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<(InteractionRequest, Uuid, Option<Uuid>), monaca_oidc::InteractionError> {
        match self
            .store
            .interaction_take_signed_in(tenant, id)
            .await
            .map_err(interaction_store_error)?
        {
            Some(row) => {
                let account = row
                    .signed_in_account
                    .ok_or(monaca_oidc::InteractionError::NotSignedIn)?;
                Ok((interaction_payload(&row)?, account, row.session_id))
            }
            None => Err(self.take_failure(tenant, id).await),
        }
    }

    /// Remember that the primary factor passed and a TOTP code is still owed.
    ///
    /// The interaction stays redeemable: nothing is signed in yet, so a reload must find the same
    /// challenge rather than a fresh sign-in form.
    pub async fn mark_mfa_pending(
        &self,
        tenant: &TenantRow,
        id: &str,
        account: Uuid,
    ) -> Result<(), monaca_oidc::InteractionError> {
        self.require_interaction_update(
            self.store
                .interaction_mfa_pending(tenant, id, account)
                .await,
            tenant,
            id,
        )
        .await?;
        Ok(())
    }

    /// Park the interaction on an enrollment step: the account has no factor and the tenant's
    /// policy requires one before the sign-in may finish.
    pub async fn mark_mfa_enrollment(
        &self,
        tenant: &TenantRow,
        id: &str,
        account: Uuid,
    ) -> Result<(), monaca_oidc::InteractionError> {
        self.require_interaction_update(
            self.store
                .interaction_mfa_enrollment(tenant, id, account)
                .await,
            tenant,
            id,
        )
        .await?;
        Ok(())
    }

    /// The account an enrollment step belongs to, if the interaction is parked on one.
    pub async fn mfa_enrollment_pending(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<Option<Uuid>, monaca_oidc::InteractionError> {
        Ok(self.interaction_row(tenant, id).await?.mfa_enrollment)
    }

    /// The account waiting for a TOTP code on this interaction, if any.
    pub async fn mfa_pending(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<Option<Uuid>, monaca_oidc::InteractionError> {
        Ok(self.interaction_row(tenant, id).await?.mfa_account)
    }

    /// Count a rejected TOTP code, returning the running total.
    pub async fn record_mfa_failure(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<u32, monaca_oidc::InteractionError> {
        match self
            .store
            .interaction_record_mfa_failure(tenant, id)
            .await
            .map_err(interaction_store_error)?
        {
            Some(attempts) => Ok(attempts.max(0) as u32),
            None => Err(self.interaction_failure(tenant, id).await),
        }
    }

    /// Drop the challenge once a code verified, so the sign-in can finish.
    pub async fn clear_mfa_pending(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<(), monaca_oidc::InteractionError> {
        self.require_interaction_update(
            self.store.interaction_clear_mfa_pending(tenant, id).await,
            tenant,
            id,
        )
        .await?;
        Ok(())
    }

    /// Mark this interaction's second factor as satisfied by a completed enrollment.
    pub async fn mark_mfa_satisfied(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<(), monaca_oidc::InteractionError> {
        self.require_interaction_update(
            self.store.interaction_mfa_satisfied(tenant, id).await,
            tenant,
            id,
        )
        .await?;
        Ok(())
    }

    /// Whether a completed enrollment has already satisfied this interaction's second factor.
    pub async fn mfa_satisfied(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<bool, monaca_oidc::InteractionError> {
        Ok(self.interaction_row(tenant, id).await?.mfa_satisfied)
    }

    /// Hold the unconfirmed secret of a TOTP setup until the user proves the app works.
    ///
    /// The secret is sealed with the tenant DEK before it reaches the database, exactly like the
    /// enrolled credential next to it.
    pub async fn put_totp_enrollment(
        &self,
        tenant: &TenantRow,
        account: Uuid,
        secret: Vec<u8>,
        expires_at: OffsetDateTime,
    ) -> Result<(), ApiError> {
        let dek = self.tenant_dek(tenant)?;
        let sealed = seal(&dek, &secret)
            .map_err(|err| ApiError::internal(format!("totp enrollment: {err}")))?;
        self.store
            .totp_enrollment_put(tenant, account, &sealed, expires_at)
            .await
            .map_err(ApiError::internal)
    }

    /// The pending TOTP secret of a setup, if it has not expired.
    pub async fn totp_enrollment(&self, tenant: &TenantRow, account: Uuid) -> Option<Vec<u8>> {
        let sealed = match self.store.totp_enrollment_get(tenant, account).await {
            Ok(sealed) => sealed?,
            Err(err) => {
                tracing::warn!(%err, "could not read a pending TOTP enrollment");
                return None;
            }
        };
        match self.open_tenant(tenant, &sealed) {
            Ok(secret) => Some(secret),
            Err(err) => {
                tracing::warn!(%err, "could not open a pending TOTP enrollment");
                None
            }
        }
    }

    /// Forget a pending setup, e.g. when the account removes or replaces it.
    pub async fn drop_totp_enrollment(&self, tenant: &TenantRow, account: Uuid) {
        if let Err(err) = self.store.totp_enrollment_delete(tenant, account).await {
            tracing::warn!(%err, "could not drop a pending TOTP enrollment");
        }
    }

    /// Remember a freshly generated WebAuthn challenge until its ceremony completes.
    pub async fn put_passkey_challenge(
        &self,
        tenant: &TenantRow,
        key: String,
        challenge: Vec<u8>,
        expires_at: OffsetDateTime,
    ) -> Result<(), ApiError> {
        self.store
            .passkey_challenge_put(tenant, &key, &challenge, expires_at)
            .await
            .map_err(ApiError::internal)
    }

    /// Redeem a challenge: it is removed whether it is valid or not, so every ceremony is one-shot.
    pub async fn take_passkey_challenge(&self, tenant: &TenantRow, key: &str) -> Option<Vec<u8>> {
        match self.store.passkey_challenge_take(tenant, key).await {
            Ok(challenge) => challenge,
            Err(err) => {
                tracing::warn!(%err, "could not read a passkey challenge");
                None
            }
        }
    }

    /// Read a live interaction row, classifying a missing, expired or consumed one.
    async fn interaction_row(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<InteractionRow, monaca_oidc::InteractionError> {
        let row = self
            .store
            .interaction_get(tenant, id)
            .await
            .map_err(interaction_store_error)?
            .ok_or(monaca_oidc::InteractionError::NotFound)?;
        interaction_status(&row, self.now())?;
        Ok(row)
    }

    /// A conditional update that matched nothing: classify the row we can still read.
    async fn interaction_failure(
        &self,
        tenant: &TenantRow,
        id: &str,
    ) -> monaca_oidc::InteractionError {
        match self.store.interaction_get(tenant, id).await {
            Ok(Some(row)) => interaction_status(&row, self.now())
                .err()
                .unwrap_or(monaca_oidc::InteractionError::Consumed),
            Ok(None) => monaca_oidc::InteractionError::NotFound,
            Err(err) => interaction_store_error(err),
        }
    }

    /// `take_signed_in` failing on a live row means it was never signed in.
    async fn take_failure(&self, tenant: &TenantRow, id: &str) -> monaca_oidc::InteractionError {
        match self.store.interaction_get(tenant, id).await {
            Ok(Some(row)) => {
                if let Err(err) = interaction_status(&row, self.now()) {
                    return err;
                }
                if row.signed_in_account.is_none() {
                    monaca_oidc::InteractionError::NotSignedIn
                } else {
                    monaca_oidc::InteractionError::Consumed
                }
            }
            Ok(None) => monaca_oidc::InteractionError::NotFound,
            Err(err) => interaction_store_error(err),
        }
    }

    async fn require_interaction_update(
        &self,
        result: Result<Option<InteractionRow>, monaca_store::StoreError>,
        tenant: &TenantRow,
        id: &str,
    ) -> Result<InteractionRow, monaca_oidc::InteractionError> {
        match result.map_err(interaction_store_error)? {
            Some(row) => Ok(row),
            None => Err(self.interaction_failure(tenant, id).await),
        }
    }

    /// Append an audit event to an org chain in its own transaction.
    pub async fn audit_org(
        self: &Arc<Self>,
        org: &OrgCtx,
        event: &AuditEvent,
    ) -> Result<(), ApiError> {
        let mut tx = self.store.begin_org(org).await?;
        self.store
            .audit_append(&mut *tx, &org.schema_name, event)
            .await?;
        tx.commit().await?;
        crate::webhooks::dispatch(self, org.tenant.tenant_id, &org.tenant.db_name, event).await;
        Ok(())
    }

    /// Append an audit event to the tenant chain in its own transaction.
    pub async fn audit_tenant(
        self: &Arc<Self>,
        tenant: &TenantRow,
        event: &AuditEvent,
    ) -> Result<(), ApiError> {
        let mut tx = self.store.begin_tenant(tenant).await?;
        self.store.audit_append(&mut *tx, "tenant", event).await?;
        tx.commit().await?;
        crate::webhooks::dispatch(self, tenant.tenant_id(), &tenant.db_name, event).await;
        Ok(())
    }
}

fn interaction_payload(
    row: &InteractionRow,
) -> Result<InteractionRequest, monaca_oidc::InteractionError> {
    serde_json::from_value(row.payload.clone()).map_err(|err| {
        tracing::error!(%err, "stored interaction payload is not readable");
        monaca_oidc::InteractionError::NotFound
    })
}

fn interaction_status(
    row: &InteractionRow,
    now: OffsetDateTime,
) -> Result<(), monaca_oidc::InteractionError> {
    if now >= row.expires_at {
        return Err(monaca_oidc::InteractionError::Expired);
    }
    if row.consumed {
        return Err(monaca_oidc::InteractionError::Consumed);
    }
    Ok(())
}

fn interaction_store_error(err: monaca_store::StoreError) -> monaca_oidc::InteractionError {
    tracing::error!(%err, "interaction state store failed");
    monaca_oidc::InteractionError::NotFound
}
