//! Runtime configuration — `docs/contracts/m0.md` §2.2.
//!
//! Every value has the contract's dev default so a fresh checkout runs without an `.env`. Values
//! that end up in a token or a discovery document come from `public_base_url` only: the server
//! never derives an issuer from the request's `Host`, because in dev that is `127.0.0.1:8081` and
//! §2.1 forbids it in a token.
//!
//! `MONACA_ENV=prod` removes every credential default. [`Config::validate`] covers what a running
//! server needs (the KEK and the `/internal/*` secret); [`Config::validate_bootstrap`] additionally
//! covers the seed values, because only `monaca-server bootstrap` consumes them and a server
//! restart must not depend on the credentials that created the first tenant.
//!
//! The struct deliberately does not derive `Debug`: it holds the KEK and the seeded credentials,
//! and a derived `Debug` is how a key ends up in a log line.

use std::time::Duration;

/// The dev/ci default for `MONACA_INTERNAL_SECRET`. `MONACA_ENV=prod` refuses it.
const DEV_INTERNAL_SECRET: &str = "dev-internal-secret-change-me";
/// The dev/ci default for `MONACA_BOOTSTRAP_ADMIN_PASSWORD`. `MONACA_ENV=prod` refuses it.
const DEV_ADMIN_PASSWORD: &str = "monaca-dev-password";
/// The dev/ci default for `MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET`.
const DEV_ADMIN_CLIENT_SECRET: &str = "dev-admin-client-secret";
/// The dev/ci default for `MONACA_CONSOLE_CLIENT_SECRET`.
const DEV_CONSOLE_CLIENT_SECRET: &str = "dev-console-client-secret";

/// The server's configuration.
#[derive(Clone)]
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
    /// SSO session lifetime (`MONACA_SESSION_TTL_SECS`, 30 days).
    pub session_ttl: Duration,
    /// The tenant the console signs into (`MONACA_CONSOLE_TENANT`, `demo`).
    pub console_tenant: String,
    /// The org the console resolves when the flow names none (`MONACA_BFF_DEFAULT_ORG`, `acme`).
    pub default_org: String,
    /// The console's OIDC client id.
    pub console_client_id: String,
    /// The console's client secret (a dev default outside `prod`).
    pub console_client_secret: String,
    /// The automation client's secret (a dev default outside `prod`).
    pub admin_client_secret: String,
    /// The seeded tenant-admin email.
    pub bootstrap_admin_email: String,
    /// The seeded tenant-admin password (a dev default outside `prod`).
    pub bootstrap_admin_password: String,
    /// Whether `MONACA_ENV=prod`.
    pub production: bool,
    /// The key-encryption key, 64 hex characters. In `prod` it comes from `MONACA_KEK` and must be
    /// explicit; outside `prod` it falls back to `MONACA_DEV_KEK` and then to a public constant.
    /// Never log this value.
    pub kek_hex: String,
    /// Whether `MONACA_DEV_KEK` was supplied; `prod` refuses it.
    pub dev_kek_supplied: bool,
    /// A dev/CI-only siteverify endpoint that replaces the provider's documented URL
    /// (`MONACA_CAPTCHA_SITEVERIFY_URL`). For `cap` it replaces the instance base, and the
    /// site-key path is appended exactly as the real protocol expects. The acceptance
    /// walk-through points this at a local mock so a valid token can be proven without calling a
    /// real provider. Ignored in production, where the provider URL is always the documented one.
    pub captcha_siteverify_url: Option<String>,
    /// A dev/CI-only base that replaces the built-in social provider endpoints
    /// (`MONACA_SOCIAL_PROVIDER_BASE_URL`), so acceptance can run a local mock. Ignored in
    /// production, where the provider's documented endpoints always win.
    pub social_provider_base_url: Option<String>,
    /// An optional second listener that serves only `/metrics` (`MONACA_METRICS_ADDR`).
    /// Empty disables it; the main server still answers `/metrics` on its own address.
    pub metrics_addr: Option<String>,
}

impl Config {
    /// Read the configuration from the environment.
    pub fn from_env() -> Self {
        let public_base_url = env("MONACA_PUBLIC_BASE_URL")
            .unwrap_or_else(|| "http://localhost:8080".to_owned())
            .trim_end_matches('/')
            .to_owned();
        let environment = env("MONACA_ENV").unwrap_or_else(|| "dev".to_owned());
        let production = environment == "prod";

        let dev_kek = env("MONACA_DEV_KEK");
        let dev_kek_supplied = dev_kek.is_some();
        let kek_hex = if production {
            env("MONACA_KEK").unwrap_or_default()
        } else if let Some(kek) = env("MONACA_KEK") {
            kek
        } else if let Some(kek) = dev_kek {
            kek
        } else {
            // A missing key would otherwise be silent; say it once, loudly, at startup.
            tracing::warn!(
                "MONACA_KEK and MONACA_DEV_KEK are both unset; using the public dev fallback KEK. \
                 This must never happen outside dev or ci."
            );
            "11".repeat(32)
        };

        Self {
            public_base_url,
            auth_ui_url: env("MONACA_AUTH_UI_URL")
                .unwrap_or_else(|| "http://localhost:5174".to_owned()),
            internal_secret: match env("MONACA_INTERNAL_SECRET") {
                Some(secret) => secret,
                None if production => String::new(),
                None => DEV_INTERNAL_SECRET.to_owned(),
            },
            access_token_ttl: secs("MONACA_ACCESS_TOKEN_TTL_SECS", 900),
            refresh_token_ttl: secs("MONACA_REFRESH_TOKEN_TTL_SECS", 2_592_000),
            auth_code_ttl: secs("MONACA_AUTH_CODE_TTL_SECS", 60),
            id_token_ttl: secs("MONACA_ID_TOKEN_TTL_SECS", 900),
            interaction_ttl: secs("MONACA_INTERACTION_TTL_SECS", 600),
            par_request_ttl: secs("MONACA_PAR_REQUEST_TTL_SECS", 60),
            session_ttl: secs("MONACA_SESSION_TTL_SECS", 2_592_000),
            console_tenant: env("MONACA_CONSOLE_TENANT").unwrap_or_else(|| "demo".to_owned()),
            default_org: env("MONACA_BFF_DEFAULT_ORG").unwrap_or_else(|| "acme".to_owned()),
            console_client_id: env("MONACA_CONSOLE_CLIENT_ID")
                .unwrap_or_else(|| "monaca-console".to_owned()),
            console_client_secret: seeded(
                "MONACA_CONSOLE_CLIENT_SECRET",
                DEV_CONSOLE_CLIENT_SECRET,
                production,
            ),
            admin_client_secret: seeded(
                "MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET",
                DEV_ADMIN_CLIENT_SECRET,
                production,
            ),
            bootstrap_admin_email: env("MONACA_BOOTSTRAP_ADMIN_EMAIL")
                .unwrap_or_else(|| "admin@demo.localhost".to_owned()),
            bootstrap_admin_password: seeded(
                "MONACA_BOOTSTRAP_ADMIN_PASSWORD",
                DEV_ADMIN_PASSWORD,
                production,
            ),
            production,
            kek_hex,
            dev_kek_supplied,
            captcha_siteverify_url: matches!(environment.as_str(), "dev" | "ci")
                .then(|| env("MONACA_CAPTCHA_SITEVERIFY_URL"))
                .flatten(),
            social_provider_base_url: matches!(environment.as_str(), "dev" | "ci")
                .then(|| env("MONACA_SOCIAL_PROVIDER_BASE_URL"))
                .flatten(),
            metrics_addr: env("MONACA_METRICS_ADDR"),
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

    /// Reject a startup configuration that must never reach production — §2.2.
    ///
    /// Only what a running server uses is checked here. The bootstrap seed values are checked by
    /// [`Config::validate_bootstrap`], so a restart of an already-provisioned deployment does not
    /// depend on them.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.production {
            return Ok(());
        }
        if self.dev_kek_supplied {
            anyhow::bail!(
                "MONACA_DEV_KEK is forbidden when MONACA_ENV=prod; set MONACA_KEK instead"
            );
        }

        let mut problems: Vec<String> = Vec::new();
        if self.kek_hex.is_empty() {
            problems.push(
                "MONACA_KEK is not set (must be 32 bytes, 64 hex characters)".to_owned(),
            );
        } else if let Err(err) = monaca_crypto::EnvKeyProvider::from_hex(&self.kek_hex) {
            // `err` reports the shape (`not hex`, `wrong length`), never the value.
            problems.push(format!("MONACA_KEK is invalid: {err}"));
        }
        if self.internal_secret.is_empty() {
            problems.push(
                "MONACA_INTERNAL_SECRET is not set (X-Monaca-Internal-Secret for /internal/*)"
                    .to_owned(),
            );
        } else if self.internal_secret == DEV_INTERNAL_SECRET {
            problems.push("MONACA_INTERNAL_SECRET must not be the dev default".to_owned());
        }

        reject("startup", problems)
    }

    /// Reject a production `monaca-server bootstrap` that lacks the seed credentials — §2.2.
    ///
    /// `bootstrap` is idempotent and runs on every deploy, but the values are only consumed when
    /// the tenant, account or client row does not exist yet. Existing rows are never rewritten
    /// (§5.6), so these variables are a first-deploy requirement, not a restart requirement.
    pub fn validate_bootstrap(&self) -> anyhow::Result<()> {
        self.validate()?;
        if !self.production {
            return Ok(());
        }

        let mut problems = Vec::new();
        require_seed(
            &mut problems,
            "MONACA_BOOTSTRAP_ADMIN_PASSWORD",
            &self.bootstrap_admin_password,
            DEV_ADMIN_PASSWORD,
            "seeded admin password",
        );
        require_seed(
            &mut problems,
            "MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET",
            &self.admin_client_secret,
            DEV_ADMIN_CLIENT_SECRET,
            "seeded monaca-admin secret",
        );
        require_seed(
            &mut problems,
            "MONACA_CONSOLE_CLIENT_SECRET",
            &self.console_client_secret,
            DEV_CONSOLE_CLIENT_SECRET,
            "seeded monaca-console secret",
        );

        reject("bootstrap", problems)
    }
}

fn reject(phase: &str, problems: Vec<String>) -> anyhow::Result<()> {
    if problems.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "MONACA_ENV=prod {phase} requires explicit secrets; refusing to continue:\n  - {}",
        problems.join("\n  - ")
    )
}

fn require_seed(
    problems: &mut Vec<String>,
    name: &str,
    value: &str,
    dev_default: &str,
    detail: &str,
) {
    if value.is_empty() {
        problems.push(format!("{name} is not set ({detail})"));
    } else if value == dev_default {
        problems.push(format!("{name} must not be the dev default"));
    }
}

/// A seeded credential: the environment value, or the documented dev default outside `prod`.
fn seeded(name: &str, dev_default: &str, production: bool) -> String {
    match env(name) {
        Some(value) => value,
        None if production => String::new(),
        None => dev_default.to_owned(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn dev_config() -> Config {
        Config {
            public_base_url: "http://localhost:8080".into(),
            auth_ui_url: String::new(),
            internal_secret: DEV_INTERNAL_SECRET.into(),
            access_token_ttl: Duration::from_secs(900),
            refresh_token_ttl: Duration::from_secs(1),
            auth_code_ttl: Duration::from_secs(60),
            id_token_ttl: Duration::from_secs(900),
            interaction_ttl: Duration::from_secs(600),
            par_request_ttl: Duration::from_secs(60),
            session_ttl: Duration::from_secs(2_592_000),
            console_tenant: "demo".into(),
            default_org: "acme".into(),
            console_client_id: "monaca-console".into(),
            console_client_secret: DEV_CONSOLE_CLIENT_SECRET.into(),
            admin_client_secret: DEV_ADMIN_CLIENT_SECRET.into(),
            bootstrap_admin_email: "admin@demo.localhost".into(),
            bootstrap_admin_password: DEV_ADMIN_PASSWORD.into(),
            production: false,
            kek_hex: "11".repeat(32),
            dev_kek_supplied: false,
            captcha_siteverify_url: None,
            social_provider_base_url: None,
            metrics_addr: None,
        }
    }

    fn prod_config() -> Config {
        let mut config = dev_config();
        config.production = true;
        config
    }

    fn seed_all(config: &mut Config) {
        config.kek_hex = "ab".repeat(32);
        config.internal_secret = "explicit-internal-secret".into();
        config.bootstrap_admin_password = "explicit-admin-password".into();
        config.admin_client_secret = "explicit-admin-secret".into();
        config.console_client_secret = "explicit-console-secret".into();
    }

    #[test]
    fn the_issuer_is_built_from_the_public_base_only() {
        let config = dev_config();
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
    fn the_dev_fallback_kek_is_a_32_byte_hex_key() {
        let fallback = "11".repeat(32);
        assert_eq!(fallback.len(), 64);
        assert!(monaca_crypto::EnvKeyProvider::from_hex(&fallback).is_ok());
    }

    #[test]
    fn prod_startup_requires_the_kek_and_the_internal_secret() {
        let mut config = prod_config();
        config.kek_hex = String::new();
        config.internal_secret = String::new();
        let err = config.validate().expect_err("must fail");
        let text = err.to_string();
        assert!(text.contains("MONACA_KEK"), "{text}");
        assert!(text.contains("MONACA_INTERNAL_SECRET"), "{text}");
    }

    #[test]
    fn prod_bootstrap_requires_the_seed_credentials() {
        let mut config = prod_config();
        config.kek_hex = "ab".repeat(32);
        config.internal_secret = "explicit-internal-secret".into();

        let err = config.validate_bootstrap().expect_err("must fail");
        let text = err.to_string();
        assert!(text.contains("MONACA_BOOTSTRAP_ADMIN_PASSWORD"), "{text}");
        assert!(
            text.contains("MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET"),
            "{text}"
        );
        assert!(text.contains("MONACA_CONSOLE_CLIENT_SECRET"), "{text}");
    }

    #[test]
    fn prod_startup_does_not_depend_on_the_bootstrap_seeds() {
        let mut config = prod_config();
        config.kek_hex = "ab".repeat(32);
        config.internal_secret = "explicit-internal-secret".into();
        config.bootstrap_admin_password = String::new();
        config.admin_client_secret = String::new();
        config.console_client_secret = String::new();

        assert!(config.validate().is_ok());
    }

    #[test]
    fn prod_accepts_explicit_secrets() {
        let mut config = prod_config();
        seed_all(&mut config);
        assert!(config.validate().is_ok());
        assert!(config.validate_bootstrap().is_ok());
    }

    #[test]
    fn prod_rejects_the_documented_dev_defaults() {
        let mut config = prod_config();
        config.kek_hex = "ab".repeat(32);
        config.internal_secret = DEV_INTERNAL_SECRET.into();
        let err = config.validate().expect_err("must fail");
        assert!(err.to_string().contains("dev default"));

        let mut config = prod_config();
        seed_all(&mut config);
        config.bootstrap_admin_password = DEV_ADMIN_PASSWORD.into();
        let err = config.validate_bootstrap().expect_err("must fail");
        assert!(err.to_string().contains("dev default"));
    }

    #[test]
    fn prod_refuses_the_dev_kek() {
        let mut config = prod_config();
        seed_all(&mut config);
        config.dev_kek_supplied = true;
        let err = config.validate().expect_err("must fail");
        assert!(err.to_string().contains("MONACA_DEV_KEK"));
    }

    #[test]
    fn a_malformed_kek_is_named_in_the_error() {
        let mut config = prod_config();
        seed_all(&mut config);
        config.kek_hex = "aabb".into();
        let err = config.validate().expect_err("must fail");
        assert!(err.to_string().contains("MONACA_KEK"), "{err}");
    }
}
