//! The command-line surface.
//!
//! The subcommands are the interface `docs/contracts/m0.md` §4.1 and the CI workflows call:
//! `serve`, `migrate`, `bootstrap`, `audit verify` and `openapi`. Their names and flags are part
//! of the contract — `.github/workflows/rust.yml` runs
//! `cargo run -p monaca-server -- openapi events --out spec/events`, so the nesting below is
//! load-bearing.

use clap::{Args, Parser, Subcommand};

/// Monaca — identity and access management for the AI-agent era.
#[derive(Debug, Parser)]
#[command(name = "monaca-server", version, about, long_about = None)]
pub struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,

    /// `tracing` `EnvFilter` syntax — §2.2 `MONACA_LOG_LEVEL`.
    #[arg(long, global = true, env = "MONACA_LOG_LEVEL")]
    pub log_level: Option<String>,

    /// `pretty` or `json` — §2.2 `MONACA_LOG_FORMAT`.
    #[arg(long, global = true, env = "MONACA_LOG_FORMAT")]
    pub log_format: Option<String>,
}

/// What to do.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the HTTP server.
    Serve(ServeArgs),
    /// Apply the control, tenant and org migration sets.
    Migrate,
    /// Seed the dev/CI tenants, accounts and clients.
    Bootstrap,
    /// Audit-chain operations.
    Audit(AuditArgs),
    /// Re-wrap sealed values under the current KEK (the second step of a rotation).
    Rewrap(RewrapArgs),
    /// Print generated contracts.
    Openapi(OpenapiArgs),
}

/// `rewrap` options.
#[derive(Debug, Args)]
pub struct RewrapArgs {
    /// Only this tenant slug; without it, every registered tenant.
    #[arg(long)]
    pub tenant: Option<String>,
    /// Report how many values would move without writing anything.
    #[arg(long)]
    pub dry_run: bool,
}

/// `serve` options.
#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Bind address; overrides `MONACA_SERVER_ADDR`.
    #[arg(long)]
    pub addr: Option<String>,
}

/// `audit` options.
#[derive(Debug, Args)]
pub struct AuditArgs {
    /// The audit subcommand.
    #[command(subcommand)]
    pub command: AuditCommand,
}

/// `audit` subcommands.
#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Recompute an organization's chain and report the first broken row.
    Verify,
}

/// `openapi` options.
#[derive(Debug, Args)]
pub struct OpenapiArgs {
    /// A nested target: with no value, print the OpenAPI document.
    #[command(subcommand)]
    pub target: Option<OpenapiTarget>,
}

/// The nested `openapi` targets.
#[derive(Debug, Subcommand)]
pub enum OpenapiTarget {
    /// Write the audit-event JSON Schemas into `--out`.
    Events {
        /// Destination directory. Its previous contents are the subcommand's to replace.
        #[arg(long)]
        out: String,
    },
}

impl Default for OpenapiArgs {
    fn default() -> Self {
        Self { target: None }
    }
}

/// Configure the global tracing subscriber.
///
/// `MONACA_LOG_LEVEL` is a `tracing` `EnvFilter` for Rust (§2.2), so a bare `info` works and so
/// does `monaca_server=debug,axum=info`. An unparseable filter falls back to `info` rather than
/// aborting startup: a typo in an environment variable should not stop a server from booting.
pub fn init_tracing(log_level: Option<&str>, log_format: Option<&str>) {
    use tracing_subscriber::EnvFilter;

    let filter = log_level
        .map(|level| EnvFilter::builder().parse_lossy(level))
        .unwrap_or_else(|| EnvFilter::builder().parse_lossy("info"));

    let json = matches!(log_format, Some("json"));

    // `try_init` rather than `init`: the integration test installs a subscriber too, and a second
    // global install must not panic.
    if json {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .with_target(true)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .try_init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn the_cli_definition_is_valid() {
        // Catches a malformed clap definition at test time rather than at first run.
        Cli::command().debug_assert();
    }

    #[test]
    fn serve_is_the_default_shaped_subcommand() {
        let cli = Cli::try_parse_from(["monaca-server", "serve"]).expect("parses");
        assert!(matches!(cli.command, Command::Serve(_)));
    }

    /// The CI workflow's exact invocation — `openapi events --out <dir>`.
    #[test]
    fn openapi_events_out_parses() {
        let cli =
            Cli::try_parse_from(["monaca-server", "openapi", "events", "--out", "spec/events"])
                .expect("parses");

        let Command::Openapi(args) = cli.command else {
            panic!("expected the openapi subcommand");
        };
        match args.target {
            Some(OpenapiTarget::Events { out }) => assert_eq!(out, "spec/events"),
            other => panic!("expected events, got {other:?}"),
        }
    }

    #[test]
    fn bare_openapi_parses() {
        let cli = Cli::try_parse_from(["monaca-server", "openapi"]).expect("parses");
        let Command::Openapi(args) = cli.command else {
            panic!("expected the openapi subcommand");
        };
        assert!(args.target.is_none());
    }

    #[test]
    fn migrate_bootstrap_and_audit_verify_parse() {
        for args in [
            vec!["monaca-server", "migrate"],
            vec!["monaca-server", "bootstrap"],
            vec!["monaca-server", "audit", "verify"],
        ] {
            Cli::try_parse_from(args.clone())
                .unwrap_or_else(|err| panic!("{args:?} should parse: {err}"));
        }
    }

    #[test]
    fn the_global_log_flags_parse_after_the_subcommand() {
        let cli = Cli::try_parse_from(["monaca-server", "serve", "--log-format", "json"])
            .expect("parses");
        assert_eq!(cli.log_format.as_deref(), Some("json"));
    }
}
