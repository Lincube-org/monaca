//! `monaca-server tenant` — create, suspend, resume and archive a tenant.
//!
//! This is the offline lifecycle entry point: it runs with the owner connection, never through the
//! request path, and does not need a management token. `suspended` and `archived` are enforced by
//! [`AppState::tenant`](crate::state::AppState::tenant) and by `authorize_admin`, so the CLI's
//! state change is visible to every running server immediately.
//!
//! `archive` is deliberately non-destructive: the database, its schemas and its audit chains stay
//! in place, and `tenant resume` may return the tenant to service. There is no delete command.

use std::sync::Arc;

use monaca_audit::{AuditActor, AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_crypto::hash_password;
use monaca_types::{AccountId, EventId, OrgId, TypedId};
use serde_json::json;

use crate::cli::{TenantArgs, TenantCommand, TenantCreateArgs, TenantDemoteArgs, TenantStateArgs};

/// Run the `tenant` subcommand.
pub async fn run(args: TenantArgs) -> anyhow::Result<()> {
    match args.command {
        TenantCommand::Create(args) => create(args).await,
        TenantCommand::Suspend(args) => change_state(args, "suspended").await,
        TenantCommand::Resume(args) => change_state(args, "active").await,
        TenantCommand::Archive(args) => change_state(args, "archived").await,
        TenantCommand::DemoteAdmin(args) => demote_admin(args).await,
    }
}

fn check_slug(slug: &str) -> anyhow::Result<()> {
    let valid = slug.len() >= 2
        && slug.len() <= 31
        && slug.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid {
        anyhow::bail!("tenant slug `{slug}` must match [a-z0-9][a-z0-9-]{{1,30}}");
    }
    Ok(())
}

async fn create(args: TenantCreateArgs) -> anyhow::Result<()> {
    check_slug(&args.slug)?;
    if !args.admin_email.contains('@') {
        anyhow::bail!("--admin-email must be an email address");
    }
    if args.admin_password.is_empty() {
        anyhow::bail!("--admin-password must not be empty");
    }
    if args.admin_client_secret.is_empty() {
        anyhow::bail!("--admin-client-secret must not be empty");
    }

    let state = crate::admin_state().await?;
    let store = &state.store;

    if args.dry_run {
        match store.tenant_by_slug(&args.slug).await {
            Ok(tenant) => println!(
                "tenant {}: exists in state `{}`; create would be refused unless provisioning resumes",
                tenant.slug, tenant.state
            ),
            Err(monaca_store::StoreError::UnknownTenant(_)) => {
                println!(
                    "tenant {}: would provision a database, default org `acme`, admin `{}`, \
                     clients `{}` and `{}`",
                    args.slug, args.admin_email, args.admin_client_id, args.login_client_id
                );
            }
            Err(err) => return Err(err.into()),
        }
        return Ok(());
    }

    if let Ok(existing) = store.tenant_by_slug(&args.slug).await
        && existing.state != "provisioning"
    {
        anyhow::bail!(
            "tenant `{}` already exists in state `{}`; use `tenant resume` for a stopped tenant",
            existing.slug,
            existing.state
        );
    }

    let cluster_id = crate::bootstrap::ensure_local_cluster(&state).await?;
    let tenant = store
        .provision_tenant(&args.slug, &state.config.public_base_url, cluster_id)
        .await?;

    let org = match store
        .orgs(&tenant)
        .await?
        .into_iter()
        .find(|org| org.slug == "acme")
    {
        Some(org) => org,
        None => {
            store
                .provision_org(&tenant, "acme", OrgId::new(), true)
                .await?
        }
    };

    let (account, _created) = match store.account_by_email(&tenant, &args.admin_email).await? {
        Some((account, _)) => (account, false),
        None => {
            let phc = hash_password(args.admin_password.clone(), state.argon).await?;
            let account = store
                .create_account(
                    &tenant,
                    AccountId::new(),
                    &args.admin_email,
                    "Tenant Admin",
                    Some(&phc),
                    true,
                    None,
                    None,
                    None,
                )
                .await?;
            (account, true)
        }
    };

    let ctx = org.ctx(&tenant);
    let mut tx = store.begin_org(&ctx).await?;
    store
        .org_member_add(&mut *tx, account.account_id(), "owner")
        .await?;
    tx.commit().await?;

    let admin_phc = hash_password(args.admin_client_secret.clone(), state.argon).await?;
    store
        .create_client(
            &tenant,
            &args.admin_client_id,
            "Tenant Admin",
            "confidential",
            Some(&admin_phc),
            "client_secret_basic",
            None,
            &["monaca:admin".into()],
            &[],
            &[],
        )
        .await?;

    store
        .create_client(
            &tenant,
            &args.login_client_id,
            "Tenant Login",
            "public",
            None,
            "none",
            None,
            &[
                "openid".into(),
                "profile".into(),
                "email".into(),
                "offline_access".into(),
            ],
            std::slice::from_ref(&args.login_redirect_uri),
            std::slice::from_ref(&args.login_redirect_uri),
        )
        .await?;

    state
        .signing_key(&tenant)
        .await
        .map_err(|err| anyhow::anyhow!("provisioning the tenant signing key: {err}"))?;

    if state.config.app_db_password.is_empty() {
        tracing::warn!(
            "MONACA_APP_DB_PASSWORD is empty; the new tenant has no app-role grants. Run bootstrap \
             before serving it."
        );
    } else {
        store
            .provision_app_role(&state.config.app_db_user, &state.config.app_db_password)
            .await?;
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "tenant": {
                "id": tenant.tenant_id().to_typed_string(),
                "slug": tenant.slug,
                "db_name": tenant.db_name,
                "issuer": tenant.issuer,
                "state": tenant.state,
            },
            "org": org.slug,
            "admin_email": args.admin_email,
            "admin_client_id": args.admin_client_id,
            "login_client_id": args.login_client_id,
            "login_redirect_uri": args.login_redirect_uri,
        }))?
    );
    Ok(())
}

/// Clear the owner override. There is deliberately no HTTP endpoint for this: a tenant
/// administrator cannot demote the owner through the API they share.
async fn demote_admin(args: TenantDemoteArgs) -> anyhow::Result<()> {
    check_slug(&args.slug)?;
    let state = Arc::clone(&crate::admin_state().await?);
    let store = &state.store;
    let tenant = store.tenant_by_slug(&args.slug).await?;
    let Some((account, _)) = store.account_by_email(&tenant, &args.email).await? else {
        anyhow::bail!("no account `{}` in tenant `{}`", args.email, args.slug);
    };
    if !account.is_tenant_admin {
        println!(
            "tenant {}: {} ({}) is already not a tenant administrator",
            tenant.slug,
            account.primary_email,
            account.account_id().to_typed_string()
        );
        return Ok(());
    }
    if args.dry_run {
        println!(
            "tenant {}: would clear is_tenant_admin on {} ({})",
            tenant.slug,
            account.primary_email,
            account.account_id().to_typed_string()
        );
        return Ok(());
    }
    store
        .set_tenant_admin(&tenant, account.account_id(), false)
        .await?;
    // Clearing the owner override is the only action that can remove the tenant's highest
    // privilege, so it must be visible in the same tenant chain every other administrative change
    // writes to. The actor is the tenant itself: this ran on the owner connection, not as an
    // account, and attributing it to a person would be a lie.
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "account.tenant_admin_demoted".into(),
        actor_chain: vec![AuditActor::tenant(tenant.tenant_id())],
        subject: AuditSubject {
            subject_type: AuditActorType::Account,
            id: Some(account.account_id().to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "email": account.primary_email,
            "via": "cli",
            "before": true,
            "after": false,
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        // The override is already cleared; failing the command here would suggest it was not.
        // Surface the missed chain entry loudly instead.
        tracing::error!(%err, "could not append account.tenant_admin_demoted audit event");
    }
    println!(
        "tenant {}: cleared is_tenant_admin on {} ({})",
        tenant.slug,
        account.primary_email,
        account.account_id().to_typed_string()
    );
    Ok(())
}

async fn change_state(args: TenantStateArgs, target: &str) -> anyhow::Result<()> {
    check_slug(&args.slug)?;
    let state = Arc::clone(&crate::admin_state().await?);
    let store = &state.store;
    let tenant = store.tenant_by_slug(&args.slug).await?;
    let allowed = match (tenant.state.as_str(), target) {
        ("active", "suspended") | ("active", "archived") => true,
        ("suspended", "active") | ("suspended", "archived") => true,
        ("archived", "active") => true,
        (state, target) if state == target => true,
        _ => false,
    };

    if args.dry_run {
        println!(
            "tenant {}: {} -> {} ({})",
            tenant.slug,
            tenant.state,
            target,
            if allowed {
                "would apply"
            } else {
                "not allowed"
            }
        );
        if target == "archived" {
            println!(
                "archive keeps {} and its data; `tenant resume` can return it to service",
                tenant.db_name
            );
        }
        return Ok(());
    }
    if !allowed {
        anyhow::bail!(
            "tenant `{}` cannot move from `{}` to `{target}`",
            tenant.slug,
            tenant.state
        );
    }

    let updated = store.set_tenant_state(&args.slug, target).await?;
    println!(
        "tenant {}: {} -> {}",
        updated.slug, tenant.state, updated.state
    );
    if target == "archived" {
        println!(
            "archive retained {} and its data; `tenant resume --slug {}` reactivates it",
            updated.db_name, updated.slug
        );
    }
    Ok(())
}
