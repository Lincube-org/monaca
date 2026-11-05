//! `monaca-server bootstrap` — seed the dev/CI tenants, accounts and clients (contract §5.6).

use std::sync::Arc;

use monaca_crypto::{hash_password, seal};
use monaca_store::Store;
use monaca_types::AccountId;

use crate::state::AppState;

/// Seed everything the walk-through needs. Idempotent.
///
/// The seed credentials (`MONACA_BOOTSTRAP_ADMIN_PASSWORD`,
/// `MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET`, `MONACA_CONSOLE_CLIENT_SECRET`) never overwrite an
/// existing row. The admin password is hashed only when the account is absent, and
/// `create_client`'s conflict update changes the name and logout URIs only — the stored
/// `secret_hash` is left alone (§5.6). Client secrets are hashed on every run because the
/// insert that carries them must still satisfy the row's check constraint.
pub async fn run(state: &Arc<AppState>) -> anyhow::Result<()> {
    let store = Arc::clone(&state.store);
    let config = Arc::clone(&state.config);
    let cluster_id = ensure_local_cluster(state).await?;

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

    // The request path's login is provisioned here, after every tenant and org role exists. In
    // `prod` the password is a required seed value; outside it the documented dev default applies.
    if config.app_db_password.is_empty() {
        tracing::warn!(
            "MONACA_APP_DB_PASSWORD is empty; tenant pools cannot use the app login. Set it and \
             rerun bootstrap before starting the server."
        );
    } else {
        store
            .provision_app_role(&config.app_db_user, &config.app_db_password)
            .await?;
        tracing::info!(role = %config.app_db_user, "app role provisioned for every tenant");
    }

    // The two seeded clients. `create_client` refreshes the name and the redirect URIs on every
    // run, but its conflict update never touches `secret_hash`. The hash has to be supplied even
    // when the row exists: the attempted insert must satisfy `clients_check` before the conflict
    // is resolved.
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

/// The local cluster row, sealed with the platform KEK. `bootstrap` and `tenant create` share it.
pub(crate) async fn ensure_local_cluster(state: &Arc<AppState>) -> anyhow::Result<uuid::Uuid> {
    let store = &state.store;
    let control_url = store.config().control_url.as_str();
    let admin_url = store.config().admin_url.as_str();
    let admin_dsn = seal(state.keys.platform_kek(), admin_url.as_bytes())
        .map_err(|err| anyhow::anyhow!("sealing admin DSN: {err}"))?;
    let app_dsn = seal(
        state.keys.platform_kek(),
        state
            .config
            .app_database_url
            .as_deref()
            .unwrap_or(control_url)
            .as_bytes(),
    )
    .map_err(|err| anyhow::anyhow!("sealing the app DSN: {err}"))?;
    Ok(store.ensure_cluster("local", &admin_dsn, &app_dsn).await?)
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
        // Upgrade path for connectors created before the control-plane index existed. The
        // connector write path maintains the index from here on.
        store.reconcile_email_connector_index(&tenant).await?;
    }
    Ok(())
}
