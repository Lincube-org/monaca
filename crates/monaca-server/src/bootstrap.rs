//! `monaca-server bootstrap` — seed the dev/CI tenants, accounts and clients (contract §5.6).

use std::sync::Arc;

use monaca_crypto::{KeyProvider, hash_password, seal};
use monaca_store::Store;
use monaca_types::AccountId;

use crate::state::AppState;

/// Seed everything the walk-through needs. Idempotent.
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

    // The admin account.
    let account = match store
        .account_by_email(&demo, &config.bootstrap_admin_email)
        .await?
    {
        Some((account, _)) => account,
        None => {
            let phc = hash_password(config.bootstrap_admin_password.clone(), state.argon).await?;
            store
                .create_account(
                    &demo,
                    AccountId::new(),
                    &config.bootstrap_admin_email,
                    "Dev Admin",
                    Some(&phc),
                    true,
                    None,
                )
                .await?
        }
    };

    let ctx = acme.ctx(&demo);
    let mut tx = store.begin_org(&ctx).await?;
    store
        .org_member_add(&mut *tx, account.account_id(), "owner")
        .await?;
    tx.commit().await?;

    // The two seeded clients.
    let console_phc = hash_password(config.console_client_secret.clone(), state.argon).await?;
    store
        .create_client(
            &demo,
            &config.console_client_id,
            "Monaca Console",
            "confidential",
            Some(&console_phc),
            "client_secret_basic",
            None,
            &[
                "openid".into(),
                "profile".into(),
                "email".into(),
                "offline_access".into(),
                "monaca:admin".into(),
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

    let admin_phc = hash_password(config.admin_client_secret.clone(), state.argon).await?;
    store
        .create_client(
            &demo,
            "monaca-admin",
            "Monaca Automation",
            "confidential",
            Some(&admin_phc),
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
    }
    Ok(())
}
