//! Shared application state: the store, the configuration, the key cache and the interaction map.

use std::collections::HashMap;
use std::sync::Arc;

use monaca_audit::AuditEvent;
use monaca_crypto::{Argon2Params, DevEnvKeyProvider, KeyProvider, SigningKeyPair, seal};
use monaca_oidc::Interaction as InteractionRequest;
use monaca_store::{OrgRow, Store, TenantRow};
use monaca_types::{Clock, KeyId, OrgCtx, SystemClock};
use serde_json::Value;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::config::Config;
use crate::error::ApiError;

/// An interaction plus whether it has been redeemed.
#[derive(Debug)]
pub struct StoredInteraction {
    /// The authorize request as captured.
    pub interaction: InteractionRequest,
    /// Set the moment sign-in succeeds, so a replay is a 409 rather than a 404.
    pub consumed: bool,
    /// The account that signed in, when the flow is waiting for consent.
    pub signed_in_account: Option<Uuid>,
}

/// Everything a handler needs.
pub struct AppState {
    /// PostgreSQL.
    pub store: Arc<Store>,
    /// Environment-derived configuration.
    pub config: Arc<Config>,
    /// Key provider (dev KEK in M0).
    pub keys: Arc<DevEnvKeyProvider>,
    /// Argon2 parameters.
    pub argon: Argon2Params,
    /// Time.
    pub clock: Arc<dyn Clock>,
    /// Pending logins, keyed by `int_…`. In-memory in M0: the gateway is a single process, and an
    /// interaction is short-lived by design. M1 moves this to a table so the server can scale out.
    interactions: Mutex<HashMap<String, StoredInteraction>>,
    /// The active signing key per tenant, decoded. Cached because every token needs it and the
    /// private half is sealed at rest.
    signing: Mutex<HashMap<Uuid, Arc<SigningKeyPair>>>,
}

impl AppState {
    /// Build the state from a connected store and a config.
    pub fn new(store: Store, config: Config) -> Result<Arc<Self>, anyhow::Error> {
        let keys = DevEnvKeyProvider::from_hex(&crate::config::dev_kek())
            .map_err(|err| anyhow::anyhow!("MONACA_DEV_KEK: {err}"))?;
        Ok(Arc::new(Self {
            store: Arc::new(store),
            config: Arc::new(config),
            keys: Arc::new(keys),
            argon: Argon2Params::from_env(),
            clock: Arc::new(SystemClock),
            interactions: Mutex::new(HashMap::new()),
            signing: Mutex::new(HashMap::new()),
        }))
    }

    /// The current instant.
    pub fn now(&self) -> time::OffsetDateTime {
        self.clock.now()
    }

    /// A tenant by slug.
    pub async fn tenant(&self, slug: &str) -> Result<TenantRow, ApiError> {
        Ok(self.store.tenant_by_slug(slug).await?)
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

        let dek = self
            .keys
            .tenant_dek(&tenant.tenant_id())
            .ok_or_else(|| ApiError::internal("tenant DEK missing"))?;

        let rows = self.store.signing_keys(tenant).await?;
        let key = if let Some(row) = rows.first() {
            let der = monaca_crypto::open(&dek, &row.private_enc)
                .map_err(|err| ApiError::internal(format!("signing key: {err}")))?;
            SigningKeyPair::from_pkcs8_der(KeyId::from_uuid(row.id), der)
                .map_err(|err| ApiError::internal(format!("signing key: {err}")))?
        } else {
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
        self.signing
            .lock()
            .await
            .insert(tenant.id, Arc::clone(&key));
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

    /// Store a freshly minted interaction, sweeping expired ones first.
    pub async fn put_interaction(&self, interaction: InteractionRequest) {
        let now = self.now();
        let mut map = self.interactions.lock().await;
        map.retain(|_, stored| !stored.interaction.is_expired(now));
        let id = interaction.interaction_id.to_string();
        map.insert(
            id,
            StoredInteraction {
                interaction,
                consumed: false,
                signed_in_account: None,
            },
        );
    }

    /// Read an interaction without consuming it.
    pub async fn peek_interaction(
        &self,
        id: &str,
    ) -> Result<InteractionRequest, monaca_oidc::InteractionError> {
        let now = self.now();
        let map = self.interactions.lock().await;
        let stored = map.get(id).ok_or(monaca_oidc::InteractionError::NotFound)?;
        if stored.interaction.is_expired(now) {
            return Err(monaca_oidc::InteractionError::Expired);
        }
        if stored.consumed {
            return Err(monaca_oidc::InteractionError::Consumed);
        }
        Ok(stored.interaction.clone())
    }

    /// Mark an interaction consumed, returning it. A second call is `Consumed`.
    pub async fn consume_interaction(
        &self,
        id: &str,
    ) -> Result<InteractionRequest, monaca_oidc::InteractionError> {
        let now = self.now();
        let mut map = self.interactions.lock().await;
        let stored = map
            .get_mut(id)
            .ok_or(monaca_oidc::InteractionError::NotFound)?;
        if stored.interaction.is_expired(now) {
            return Err(monaca_oidc::InteractionError::Expired);
        }
        if stored.consumed {
            return Err(monaca_oidc::InteractionError::Consumed);
        }
        stored.consumed = true;
        Ok(stored.interaction.clone())
    }

    /// Record that `account` authenticated, leaving the interaction redeemable by the consent step.
    pub async fn mark_interaction_signed_in(
        &self,
        id: &str,
        account: Uuid,
    ) -> Result<InteractionRequest, monaca_oidc::InteractionError> {
        let now = self.now();
        let mut map = self.interactions.lock().await;
        let stored = map
            .get_mut(id)
            .ok_or(monaca_oidc::InteractionError::NotFound)?;
        if stored.interaction.is_expired(now) {
            return Err(monaca_oidc::InteractionError::Expired);
        }
        if stored.consumed {
            return Err(monaca_oidc::InteractionError::Consumed);
        }
        stored.signed_in_account = Some(account);
        Ok(stored.interaction.clone())
    }

    /// Redeem an interaction that has signed in, returning the account awaiting consent.
    pub async fn take_signed_in_interaction(
        &self,
        id: &str,
    ) -> Result<(InteractionRequest, Uuid), monaca_oidc::InteractionError> {
        let now = self.now();
        let mut map = self.interactions.lock().await;
        let stored = map
            .get_mut(id)
            .ok_or(monaca_oidc::InteractionError::NotFound)?;
        if stored.interaction.is_expired(now) {
            return Err(monaca_oidc::InteractionError::Expired);
        }
        if stored.consumed {
            return Err(monaca_oidc::InteractionError::Consumed);
        }
        let account = stored
            .signed_in_account
            .ok_or(monaca_oidc::InteractionError::NotSignedIn)?;
        stored.consumed = true;
        Ok((stored.interaction.clone(), account))
    }

    /// Append an audit event to an org chain in its own transaction.
    pub async fn audit_org(&self, org: &OrgCtx, event: &AuditEvent) -> Result<(), ApiError> {
        let mut tx = self.store.begin_org(org).await?;
        self.store
            .audit_append(&mut *tx, &org.schema_name, event)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Append an audit event to the tenant chain in its own transaction.
    pub async fn audit_tenant(
        &self,
        tenant: &TenantRow,
        event: &AuditEvent,
    ) -> Result<(), ApiError> {
        let mut tx = self.store.begin_tenant(tenant).await?;
        self.store.audit_append(&mut *tx, "tenant", event).await?;
        tx.commit().await?;
        Ok(())
    }
}
