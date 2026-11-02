//! `monaca-server` — the axum 0.8 binary that fronts the whole system.
//!
//! Routes are split by the audiences in `docs/contracts/m0.md` §6:
//!
//! * the **protocol** endpoints under `/t/{tenant}` and `/.well-known`, reached through the
//!   gateway and issuing every `iss`;
//! * the **management** API under `/v1`, bearer-authenticated with `monaca:admin`;
//! * **`/internal/*`**, shared-secret authenticated, the only way the Bun side writes core data.

mod account;
mod bootstrap;
mod captcha;
mod cli;
mod clients;
mod config;
mod cors;
mod email_templates;
mod error;
mod internal;
mod management;
mod oauth;
mod openapi;
mod org_roles;
mod orgs;
mod passkey;
mod protocol;
mod resources;
mod routes;
mod session;
mod social;
mod sso;
mod state;
mod webhooks;

#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use clap::Parser;
use monaca_store::{Store, StoreConfig};

use crate::cli::{Cli, Command};
use crate::config::Config;
use crate::state::AppState;

/// The default bind address — §2.2 `MONACA_SERVER_ADDR`.
pub const DEFAULT_ADDR: &str = "127.0.0.1:8081";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    cli::init_tracing(cli.log_level.as_deref(), cli.log_format.as_deref());

    match cli.command {
        Command::Serve(args) => serve(args).await,
        Command::Openapi(args) => openapi::run(args),
        Command::Migrate => migrate().await,
        Command::Bootstrap => bootstrap().await,
        Command::Audit(args) => match args.command {
            cli::AuditCommand::Verify => audit_verify().await,
        },
    }
}

/// Build the configuration, store and shared state.
async fn build_state() -> anyhow::Result<Arc<AppState>> {
    let config = Config::from_env();
    config.validate()?;
    let store = Store::connect(StoreConfig::from_env())
        .await
        .context("could not connect to PostgreSQL; run `monaca-server migrate` first")?;
    AppState::new(store, config).map_err(|err| anyhow::anyhow!("{err}"))
}

/// Start the HTTP server on the configured address and serve until Ctrl-C.
async fn serve(args: cli::ServeArgs) -> anyhow::Result<()> {
    let addr = resolve_addr(args.addr.as_deref())?;
    let state = build_state().await?;
    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("could not bind {addr}"))?;
    let bound = listener
        .local_addr()
        .context("could not read the bound address")?;

    tracing::info!(%bound, "monaca-server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("the server stopped with an error")
}

/// `monaca-server migrate`.
async fn migrate() -> anyhow::Result<()> {
    let config = Config::from_env();
    config.validate()?;
    let store = Store::connect(StoreConfig::from_env())
        .await
        .context("could not connect to PostgreSQL")?;
    bootstrap::migrate(&store).await
}

/// `monaca-server bootstrap`.
async fn bootstrap() -> anyhow::Result<()> {
    let config = Config::from_env();
    config.validate()?;
    let store = Store::connect(StoreConfig::from_env())
        .await
        .context("could not connect to PostgreSQL")?;
    bootstrap::migrate(&store).await?;
    let state = AppState::new(store, config).map_err(|err| anyhow::anyhow!("{err}"))?;
    bootstrap::run(&state).await
}

/// `monaca-server audit verify` — recompute one org's chain.
async fn audit_verify() -> anyhow::Result<()> {
    let store = Store::connect(StoreConfig::from_env()).await?;
    let tenant_slug = std::env::var("MONACA_AUDIT_TENANT").unwrap_or_else(|_| "demo".into());
    let org_slug = std::env::var("MONACA_AUDIT_ORG").unwrap_or_else(|_| "acme".into());

    let tenant = store.tenant_by_slug(&tenant_slug).await?;
    let org = store.org_by_slug(&tenant, &org_slug).await?;
    let ctx = org.ctx(&tenant);

    let mut tx = store.begin_org(&ctx).await?;
    let report = store
        .audit_verify(&mut *tx, &ctx.schema_name, 1, None)
        .await?;
    tx.rollback().await?;

    println!("{}", serde_json::to_string_pretty(&report.to_json())?);
    if !report.valid {
        anyhow::bail!("audit chain is broken");
    }
    Ok(())
}

/// The bind address, from `--addr`, `MONACA_SERVER_ADDR`, or [`DEFAULT_ADDR`].
///
/// Parsed here rather than left to `TcpListener::bind` so a malformed address is a startup error
/// with a usable message, not a bind failure with a parse error inside it.
fn resolve_addr(explicit: Option<&str>) -> anyhow::Result<SocketAddr> {
    let raw = explicit
        .map(str::to_owned)
        .or_else(|| std::env::var("MONACA_SERVER_ADDR").ok())
        .unwrap_or_else(|| DEFAULT_ADDR.to_owned());

    raw.parse::<SocketAddr>()
        .with_context(|| format!("MONACA_SERVER_ADDR/--addr is not a socket address: `{raw}`"))
}

/// Resolve when the process should stop.
///
/// Ctrl-C on every platform, plus SIGTERM on Unix, so a container stop drains in-flight requests
/// instead of cutting them off.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(%err, "could not listen for Ctrl-C");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::error!(%err, "could not listen for SIGTERM");
                // Never resolve, so a broken signal handler cannot make the server exit early.
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    tracing::info!("shutdown signal received; draining");
}

#[cfg(test)]
mod addr_tests {
    use super::*;

    #[test]
    fn the_default_addr_matches_the_contract() {
        // §2.1: monaca-server is 8081 in dev, and it is never the public origin.
        assert_eq!(DEFAULT_ADDR, "127.0.0.1:8081");
    }

    #[test]
    fn an_explicit_addr_wins() {
        let addr = resolve_addr(Some("0.0.0.0:9999")).expect("parses");
        assert_eq!(addr.port(), 9999);
    }

    #[test]
    fn a_malformed_addr_is_a_startup_error() {
        let err = resolve_addr(Some("not-an-address")).expect_err("must fail");
        assert!(err.to_string().contains("not-an-address"));
    }
}
