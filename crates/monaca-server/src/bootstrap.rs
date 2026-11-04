//! `monaca-server bootstrap` — seed the dev/CI tenants, accounts and clients (contract §5.6).

use std::sync::Arc;

use monaca_crypto::{KeyProvider, hash_password, seal};
use monaca_store::Store;
use monaca_types::AccountId;

use crate::state::AppState;

/// Seed everything the walk-through needs. Idempotent.
///
/// The seed credentials (`MONACA_BOOTSTRAP_ADMIN_PASSWORD`,
/// `MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET`, `MONACA_CONSOLE_CLIENT_SECRET`) are read only when the
/// corresponding row does not exist yet. Re-running on a populated database does not re-hash or
/// overwrite an existing password or client secret; `create_client`'s conflict update changes the
/// name and logout URIs only (§5.6).
pub async fn run(state: &Arc<AppState>) -> anyhow::Result<()> {
    let store = Arc::clone(&state.store);
    let config = Arc::clone(&state.config);
    let control_url = store.config().control_url.as_str();
    let admin_url = store.config().admin_url.as_str();

    // A cluster row carries the (sealed) DSN pair provisioning uses.
    let admin_dsn = seal(state.keys.platform_kek(), admin_url.as_bytes())
        .map_err(|err| anyhow::anyhow!("sealing admin DSN: {err}"))?;
    let app_dsn = seal(state.keys.platform_kek(), control_url.as_bytes())
        .map_err(|err| anyhow::anyhow!("sealing control DSN: {err}"))?;
    let cluster_id = store.ensure_cluster("local", &admin_dsn, &app_dsn).await?;

    for slug in ["system", "demo"] {
        let tenant = store
            .provision_tenant(slug, &config.public_base_url, cluster_id)
            .await?;
        tracing::info!(tenant = %tenant.slug, state = %tenant.state, "tenant ready");
    }

    let demo = store.tenant_by_slug("demo").await?;
    let orgs = store.orgs(&demo).await?;
    let acme = if let Some(org) = orgs.iter().find(|org| org.slug == "acme") {
        org.clone()
    } else {
        store
            .provision_org(&demo, "acme", monaca_types::OrgId::new(), true)
            .await?
    };

    // The admin account. An existing account keeps its stored password; the seed value is not
    // even hashed when the row is present.
    let (account, admin_created) = match store
        .account_by_email(&demo, &config.bootstrap_admin_email)
        .await?
    {
        Some((account, _)) => (account, false),
        None => {
            let phc = hash_password(config.bootstrap_admin_password.clone(), state.argon).await?;
            let account = store
                .create_account(
                    &demo,
                    AccountId::new(),
                    &config.bootstrap_admin_email,
                    "Dev Admin",
                    Some(&phc),
                    true,
                    None,
                    None,
                )
                .await?;
            (account, true)
        }
    };
    tracing::info!(
        email = %config.bootstrap_admin_email,
        created = admin_created,
        "bootstrap admin account"
    );

    let ctx = acme.ctx(&demo);
    let mut tx = store.begin_org(&ctx).await?;
    store
        .org_member_add(&mut *tx, account.account_id(), "owner")
        .await?;
    tx.commit().await?;

    // The two seeded clients. `create_client` refreshes the name and the redirect URIs on every
    // run, but it never touches `secret_hash` on a conflict; a present client's secret is not
    // re-hashed here.
    let seeded_clients: Vec<String> = store
        .clients(&demo)
        .await?
        .into_iter()
        .map(|client| client.client_id)
        .collect();
    let console_exists = seeded_clients
        .iter()
        .any(|client_id| client_id == &config.console_client_id);
    let console_phc = if console_exists {
        None
    } else {
        Some(hash_password(config.console_client_secret.clone(), state.argon).await?)
    };
    store
        .create_client(
            &demo,
            &config.console_client_id,
            "Monaca Console",
            "confidential",
            console_phc.as_deref(),
            "client_secret_basic",
            None,
            &[
                "openid".into(),
                "profile".into(),
                "email".into(),
                "offline_access".into(),
                "monaca:admin".into(),
                // An API scope the user's roles must grant; requesting it without one is refused
                // (§6.1 scope grants).
                "tools:read".into(),
            ],
            &[
                "http://localhost:5173/bff/callback".into(),
                "http://localhost:8080/bff/callback".into(),
            ],
            &[
                "http://localhost:5173/bff/callback".into(),
                "http://localhost:8080/bff/callback".into(),
            ],
        )
        .await?;

    let admin_exists = seeded_clients.iter().any(|client_id| client_id == "monaca-admin");
    let admin_phc = if admin_exists {
        None
    } else {
        Some(hash_password(config.admin_client_secret.clone(), state.argon).await?)
    };
    store
        .create_client(
            &demo,
            "monaca-admin",
            "Monaca Automation",
            "confidential",
            admin_phc.as_deref(),
            "client_secret_basic",
            None,
            &["monaca:admin".into()],
            &[],
            &[],
        )
        .await?;

    // Provision the signing key now rather than at the first token request.
    state
        .signing_key(&demo)
        .await
        .map_err(|err| anyhow::anyhow!("provisioning the tenant signing key: {err}"))?;

    tracing::info!(
        tenant = %config.console_tenant,
        org = %acme.slug,
        admin = %config.bootstrap_admin_email,
        "bootstrap complete"
    );
    Ok(())
}

/// Apply the control and tenant migration sets — `monaca-server migrate`.
pub async fn migrate(store: &Store) -> anyhow::Result<()> {
    let report = monaca_store::apply_control(store.control()).await?;
    tracing::info!(applied = ?report.applied, skipped = report.skipped, "control migrations");

    for tenant in store.tenants().await? {
        let pool = store.tenant_pool(&tenant.db_name).await?;
        let report = monaca_store::apply_tenant(&pool, &tenant.short).await?;
        tracing::info!(
            tenant = %tenant.slug,
            applied = ?report.applied,
            skipped = report.skipped,
            "tenant migrations"
        );
        for (slug, org_report) in store.migrate_orgs(&tenant).await? {
            tracing::info!(
                tenant = %tenant.slug,
                org = %slug,
                applied = ?org_report.applied,
                skipped = org_report.skipped,
                "org migrations"
            );
        }
    }
    Ok(())
}
