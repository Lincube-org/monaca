//! Runtime configuration — `docs/contracts/m0.md` §2.2.
//!
//! Every value has the contract's dev default so a fresh checkout runs without an `.env`. Values
//! that end up in a token or a discovery document come from `public_base_url` only: the server
//! never derives an issuer from the request's `Host`, because in dev that is `127.0.0.1:8081` and
//! §2.1 forbids it in a token.

use std::time::Duration;

/// The server's configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// The single public origin; source of every `iss`.
    pub public_base_url: String,
    /// The hosted sign-in page.
    pub auth_ui_url: String,
    /// `X-Monaca-Internal-Secret`.
    pub internal_secret: String,
    /// User access-token TTL (`MONACA_ACCESS_TOKEN_TTL_SECS`, 900).
    pub access_token_ttl: Duration,
    /// Refresh-token TTL (`MONACA_REFRESH_TOKEN_TTL_SECS`, 30 days).
    pub refresh_token_ttl: Duration,
    /// Authorization code TTL (`MONACA_AUTH_CODE_TTL_SECS`, 60).
    pub auth_code_ttl: Duration,
    /// id_token TTL (`MONACA_ID_TOKEN_TTL_SECS`, 900).
    pub id_token_ttl: Duration,
    /// Interaction TTL (`MONACA_INTERACTION_TTL_SECS`, 600).
    pub interaction_ttl: Duration,
    /// Pushed authorization request TTL (`MONACA_PAR_REQUEST_TTL_SECS`, 60).
    pub par_request_ttl: Duration,
    /// The tenant the console signs into (`MONACA_CONSOLE_TENANT`, `demo`).
    pub console_tenant: String,
    /// The org the console resolves when the flow names none (`MONACA_BFF_DEFAULT_ORG`, `acme`).
    pub default_org: String,
    /// The console's OIDC client id.
    pub console_client_id: String,
    /// The console's client secret (dev only).
    pub console_client_secret: String,
    /// The automation client's secret (dev only).
    pub admin_client_secret: String,
    /// The seeded tenant-admin email.
    pub bootstrap_admin_email: String,
    /// The seeded tenant-admin password (dev only).
    pub bootstrap_admin_password: String,
    /// Whether `MONACA_ENV=prod`, which forbids the dev KEK and the bootstrap password.
    pub production: bool,
}

impl Config {
    /// Read the configuration from the environment.
    pub fn from_env() -> Self {
        let public_base_url = env("MONACA_PUBLIC_BASE_URL")
            .unwrap_or_else(|| "http://localhost:8080".to_owned())
            .trim_end_matches('/')
            .to_owned();
        let environment = env("MONACA_ENV").unwrap_or_else(|| "dev".to_owned());

        Self {
            public_base_url,
            auth_ui_url: env("MONACA_AUTH_UI_URL")
                .unwrap_or_else(|| "http://localhost:5174".to_owned()),
            internal_secret: env("MONACA_INTERNAL_SECRET")
                .unwrap_or_else(|| "dev-internal-secret-change-me".to_owned()),
            access_token_ttl: secs("MONACA_ACCESS_TOKEN_TTL_SECS", 900),
            refresh_token_ttl: secs("MONACA_REFRESH_TOKEN_TTL_SECS", 2_592_000),
            auth_code_ttl: secs("MONACA_AUTH_CODE_TTL_SECS", 60),
            id_token_ttl: secs("MONACA_ID_TOKEN_TTL_SECS", 900),
            interaction_ttl: secs("MONACA_INTERACTION_TTL_SECS", 600),
            par_request_ttl: secs("MONACA_PAR_REQUEST_TTL_SECS", 60),
            console_tenant: env("MONACA_CONSOLE_TENANT").unwrap_or_else(|| "demo".to_owned()),
            default_org: env("MONACA_BFF_DEFAULT_ORG").unwrap_or_else(|| "acme".to_owned()),
            console_client_id: env("MONACA_CONSOLE_CLIENT_ID")
                .unwrap_or_else(|| "monaca-console".to_owned()),
            console_client_secret: env("MONACA_CONSOLE_CLIENT_SECRET")
                .unwrap_or_else(|| "dev-console-client-secret".to_owned()),
            admin_client_secret: env("MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET")
                .unwrap_or_else(|| "dev-admin-client-secret".to_owned()),
            bootstrap_admin_email: env("MONACA_BOOTSTRAP_ADMIN_EMAIL")
                .unwrap_or_else(|| "admin@demo.localhost".to_owned()),
            bootstrap_admin_password: env("MONACA_BOOTSTRAP_ADMIN_PASSWORD")
                .unwrap_or_else(|| "monaca-dev-password".to_owned()),
            production: environment == "prod",
        }
    }

    /// The issuer for a tenant slug.
    pub fn issuer(&self, tenant: &str) -> String {
        format!("{}/t/{tenant}", self.public_base_url)
    }

    /// The token endpoint for a tenant.
    pub fn token_endpoint(&self, tenant: &str) -> String {
        format!("{}/oauth2/token", self.issuer(tenant))
    }

    /// The UserInfo endpoint for a tenant.
    pub fn userinfo_endpoint(&self, tenant: &str) -> String {
        format!("{}/oauth2/userinfo", self.issuer(tenant))
    }

    /// The introspection endpoint for a tenant.
    pub fn introspection_endpoint(&self, tenant: &str) -> String {
        format!("{}/oauth2/introspect", self.issuer(tenant))
    }

    /// The revocation endpoint for a tenant.
    pub fn revocation_endpoint(&self, tenant: &str) -> String {
        format!("{}/oauth2/revoke", self.issuer(tenant))
    }

    /// The pushed authorization request endpoint for a tenant.
    pub fn par_endpoint(&self, tenant: &str) -> String {
        format!("{}/oauth2/par", self.issuer(tenant))
    }

    /// The management API audience.
    pub fn management_audience(&self) -> String {
        format!("{}/v1", self.public_base_url)
    }

    /// Reject a configuration that must never reach production — §2.2.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.production {
            if std::env::var("MONACA_DEV_KEK").is_ok() {
                anyhow::bail!("MONACA_DEV_KEK is forbidden when MONACA_ENV=prod");
            }
            if std::env::var("MONACA_BOOTSTRAP_ADMIN_PASSWORD").is_ok() {
                anyhow::bail!("MONACA_BOOTSTRAP_ADMIN_PASSWORD is forbidden when MONACA_ENV=prod");
            }
        }
        Ok(())
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn secs(name: &str, default: u64) -> Duration {
    Duration::from_secs(
        env(name)
            .and_then(|value| value.parse().ok())
            .unwrap_or(default),
    )
}

/// The dev KEK, 32 hex-encoded bytes.
pub fn dev_kek() -> String {
    env("MONACA_DEV_KEK").unwrap_or_else(|| "11".repeat(32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_issuer_is_built_from_the_public_base_only() {
        let config = Config {
            public_base_url: "http://localhost:8080".into(),
            auth_ui_url: String::new(),
            internal_secret: String::new(),
            access_token_ttl: Duration::from_secs(900),
            refresh_token_ttl: Duration::from_secs(1),
            auth_code_ttl: Duration::from_secs(60),
            id_token_ttl: Duration::from_secs(900),
            interaction_ttl: Duration::from_secs(600),
            par_request_ttl: Duration::from_secs(60),
            console_tenant: "demo".into(),
            default_org: "acme".into(),
            console_client_id: "monaca-console".into(),
            console_client_secret: String::new(),
            admin_client_secret: String::new(),
            bootstrap_admin_email: String::new(),
            bootstrap_admin_password: String::new(),
            production: false,
        };
        assert_eq!(config.issuer("demo"), "http://localhost:8080/t/demo");
        assert_eq!(
            config.token_endpoint("demo"),
            "http://localhost:8080/t/demo/oauth2/token"
        );
        assert_eq!(config.management_audience(), "http://localhost:8080/v1");
        assert_eq!(
            config.userinfo_endpoint("demo"),
            "http://localhost:8080/t/demo/oauth2/userinfo"
        );
        assert_eq!(
            config.par_endpoint("demo"),
            "http://localhost:8080/t/demo/oauth2/par"
        );
    }

    #[test]
    fn the_dev_kek_is_32_bytes() {
        assert_eq!(dev_kek().len(), 64);
    }
}
