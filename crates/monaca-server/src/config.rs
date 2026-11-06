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

use std::net::IpAddr;
use std::time::Duration;

/// The dev/ci default for `MONACA_INTERNAL_SECRET`. `MONACA_ENV=prod` refuses it.
const DEV_INTERNAL_SECRET: &str = "dev-internal-secret-change-me";
/// The dev/ci default for `MONACA_BOOTSTRAP_ADMIN_PASSWORD`. `MONACA_ENV=prod` refuses it.
const DEV_ADMIN_PASSWORD: &str = "monaca-dev-password";
/// The dev/ci default for `MONACA_BOOTSTRAP_ADMIN_CLIENT_SECRET`.
const DEV_ADMIN_CLIENT_SECRET: &str = "dev-admin-client-secret";
/// The dev/ci default for `MONACA_CONSOLE_CLIENT_SECRET`.
const DEV_CONSOLE_CLIENT_SECRET: &str = "dev-console-client-secret";
/// The dev/ci default for `MONACA_APP_DB_PASSWORD`; `MONACA_ENV=prod` refuses it.
const DEV_APP_DB_PASSWORD: &str = "monaca_app_dev";

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
    /// The least-privilege login tenant pools connect as (`MONACA_APP_DB_USER`, `monaca_app`).
    pub app_db_user: String,
    /// Its password (`MONACA_APP_DB_PASSWORD`); `bootstrap` creates or updates the role with it.
    pub app_db_password: String,
    /// The least-privilege tenant-pool DSN (`MONACA_APP_DATABASE_URL`), when configured. `serve`
    /// refuses to start without it unless `MONACA_ALLOW_SUPERUSER_TENANT_POOLS=1` is set.
    pub app_database_url: Option<String>,
    /// Whether `MONACA_ENV=prod`.
    pub production: bool,
    /// The key-encryption key, 64 hex characters. In `prod` it comes from `MONACA_KEK` and must be
    /// explicit; outside `prod` it falls back to `MONACA_DEV_KEK` and then to a public constant.
    /// Never log this value.
    pub kek_hex: String,
    /// The KEK being retired during a rotation (`MONACA_KEK_PREVIOUS`). New writes use `kek_hex`;
    /// reads try the current key first and this one second until `monaca-server rewrap` has moved
    /// every sealed value. `None` means no rotation is in progress.
    pub previous_kek_hex: Option<String>,
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
    /// A dev/CI-only base that replaces Twilio's documented API host
    /// (`MONACA_SMS_PROVIDER_BASE_URL`), so acceptance can point a real provider shape at a local
    /// capture. Ignored in production, where `api.twilio.com` always wins.
    pub sms_provider_base_url: Option<String>,
    /// SMS verification-code lifetime (`MONACA_SMS_CODE_TTL_SECS`, 600). Dev/CI may shorten it so
    /// expiry is testable; production always uses 600.
    pub sms_code_ttl_secs: i64,
    /// SMS per-address resend cooldown (`MONACA_SMS_RESEND_SECS`, 60). Dev/CI may shorten it;
    /// production always uses 60.
    pub sms_resend_secs: i64,
    /// An optional second listener that serves only `/metrics` (`MONACA_METRICS_ADDR`).
    /// Empty disables it; the main server still answers `/metrics` on its own address.
    pub metrics_addr: Option<String>,
    /// Peers allowed to speak for the client through `X-Forwarded-For`
    /// (`MONACA_TRUSTED_PROXY_CIDRS`, comma-separated CIDRs). Empty means the header is ignored
    /// and the socket peer is the client. Defaults to loopback outside `prod`, because the dev
    /// and CI gateway is on the same host.
    pub trusted_proxies: Vec<TrustedProxy>,
    /// Per-IP requests per minute for the authentication endpoints
    /// (`MONACA_IP_RATE_LIMIT_PER_MINUTE`, 600). `0` disables the IP layer.
    pub ip_rate_limit_per_minute: u32,
    /// Tenant visits the mailer runs at once (`MONACA_MAILER_TENANT_CONCURRENCY`, 8). Bounded to
    /// 1–32; the poller's connection reservation is this value × `MONACA_MAILER_POOL_SIZE`.
    pub mailer_tenant_concurrency: usize,
    /// A dev/CI-only DNS TXT resolver endpoint (`MONACA_DOMAIN_TXT_ENDPOINT`). When set, custom
    /// domain verification asks `{endpoint}?name=<record>` for `{"records":[…]}` instead of the
    /// system resolver. Ignored in production, where only real DNS can prove ownership.
    pub domain_txt_endpoint: Option<String>,
    /// How often the host-routing cache is rebuilt from the control plane
    /// (`MONACA_DOMAIN_CACHE_REFRESH_SECS`, 5). This is the cross-instance propagation bound for a
    /// bind/revoke/degrade made in another process.
    pub domain_cache_refresh: Duration,
    /// How often the daily DNS re-check runs (`MONACA_DOMAIN_RECHECK_SECS`, 86400). One failed
    /// check degrades a serving binding; the next successful check restores it.
    pub domain_recheck_interval: Duration,
}

/// One entry of the `X-Forwarded-For` trust boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedProxy {
    /// The network's base address.
    addr: IpAddr,
    /// Network prefix length in bits.
    prefix: u8,
}

impl TrustedProxy {
    /// Parse `address` or `address/prefix`; a missing prefix means the whole address (`/32` or
    /// `/128`).
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        let (addr, prefix) = match raw.split_once('/') {
            Some((addr, prefix)) => (addr.parse::<IpAddr>().ok()?, prefix.parse::<u8>().ok()?),
            None => {
                let addr = raw.parse::<IpAddr>().ok()?;
                let prefix = match addr {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                (addr, prefix)
            }
        };
        match addr {
            IpAddr::V4(_) if prefix > 32 => return None,
            IpAddr::V6(_) if prefix > 128 => return None,
            _ => {}
        }
        Some(Self { addr, prefix })
    }

    /// Whether `ip` falls inside this network. An IPv4-mapped IPv6 address is matched as IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = unmap(ip);
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                (u32::from(network) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                (u128::from(network) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

/// Convert an IPv4-mapped IPv6 address to IPv4 so one CIDR list covers both spellings.
pub fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(_) => ip,
    }
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

        let trusted_proxies = match env("MONACA_TRUSTED_PROXY_CIDRS") {
            Some(raw) => raw
                .split(',')
                .filter_map(|entry| {
                    let entry = entry.trim();
                    let parsed = TrustedProxy::parse(entry);
                    if parsed.is_none() && !entry.is_empty() {
                        tracing::warn!(%entry, "ignoring an unparseable MONACA_TRUSTED_PROXY_CIDRS entry");
                    }
                    parsed
                })
                .collect(),
            None if production => Vec::new(),
            None => vec![
                TrustedProxy::parse("127.0.0.1/32").expect("literal CIDR"),
                TrustedProxy::parse("::1/128").expect("literal CIDR"),
            ],
        };
        if production && trusted_proxies.is_empty() {
            tracing::warn!(
                "MONACA_TRUSTED_PROXY_CIDRS is empty; X-Forwarded-For is ignored and the socket \
                 peer is treated as the client"
            );
        }

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
            app_db_user: env("MONACA_APP_DB_USER").unwrap_or_else(|| "monaca_app".to_owned()),
            app_db_password: seeded("MONACA_APP_DB_PASSWORD", DEV_APP_DB_PASSWORD, production),
            app_database_url: env("MONACA_APP_DATABASE_URL"),
            production,
            kek_hex,
            previous_kek_hex: env("MONACA_KEK_PREVIOUS"),
            dev_kek_supplied,
            captcha_siteverify_url: matches!(environment.as_str(), "dev" | "ci")
                .then(|| env("MONACA_CAPTCHA_SITEVERIFY_URL"))
                .flatten(),
            social_provider_base_url: matches!(environment.as_str(), "dev" | "ci")
                .then(|| env("MONACA_SOCIAL_PROVIDER_BASE_URL"))
                .flatten(),
            sms_provider_base_url: matches!(environment.as_str(), "dev" | "ci")
                .then(|| env("MONACA_SMS_PROVIDER_BASE_URL"))
                .flatten(),
            sms_code_ttl_secs: if matches!(environment.as_str(), "dev" | "ci") {
                env("MONACA_SMS_CODE_TTL_SECS")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(600)
                    .clamp(1, 3600)
            } else {
                600
            },
            sms_resend_secs: if matches!(environment.as_str(), "dev" | "ci") {
                env("MONACA_SMS_RESEND_SECS")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(60)
                    .clamp(1, 3600)
            } else {
                60
            },
            metrics_addr: env("MONACA_METRICS_ADDR"),
            trusted_proxies,
            ip_rate_limit_per_minute: env("MONACA_IP_RATE_LIMIT_PER_MINUTE")
                .and_then(|value| value.parse().ok())
                .unwrap_or(600),
            mailer_tenant_concurrency: env("MONACA_MAILER_TENANT_CONCURRENCY")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(8)
                .clamp(1, 32),
            domain_txt_endpoint: matches!(environment.as_str(), "dev" | "ci")
                .then(|| env("MONACA_DOMAIN_TXT_ENDPOINT"))
                .flatten(),
            domain_cache_refresh: Duration::from_secs(
                env("MONACA_DOMAIN_CACHE_REFRESH_SECS")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(5)
                    .clamp(1, 300),
            ),
            domain_recheck_interval: Duration::from_secs(
                env("MONACA_DOMAIN_RECHECK_SECS")
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(86_400)
                    .clamp(60, 604_800),
            ),
        }
    }

    /// Google's signing keys, or the dev/CI mock's sibling path.
    pub fn google_jwks_url(&self) -> String {
        match self.social_provider_base_url.as_deref() {
            Some(base) => format!("{}/google/jwks", base.trim_end_matches('/')),
            None => "https://www.googleapis.com/oauth2/v3/certs".to_owned(),
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
            problems.push("MONACA_KEK is not set (must be 32 bytes, 64 hex characters)".to_owned());
        } else if let Err(err) = monaca_crypto::EnvKeyProvider::from_hex(&self.kek_hex) {
            // `err` reports the shape (`not hex`, `wrong length`), never the value.
            problems.push(format!("MONACA_KEK is invalid: {err}"));
        }
        if let Some(previous) = self.previous_kek_hex.as_deref()
            && let Err(err) = monaca_crypto::EnvKeyProvider::from_hex(previous)
        {
            problems.push(format!("MONACA_KEK_PREVIOUS is invalid: {err}"));
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
        require_seed(
            &mut problems,
            "MONACA_APP_DB_PASSWORD",
            &self.app_db_password,
            DEV_APP_DB_PASSWORD,
            "least-privilege app role password",
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
            app_db_user: "monaca_app".into(),
            app_db_password: DEV_APP_DB_PASSWORD.into(),
            app_database_url: None,
            production: false,
            kek_hex: "11".repeat(32),
            previous_kek_hex: None,
            dev_kek_supplied: false,
            captcha_siteverify_url: None,
            social_provider_base_url: None,
            sms_provider_base_url: None,
            sms_code_ttl_secs: 600,
            sms_resend_secs: 60,
            metrics_addr: None,
            trusted_proxies: vec![
                TrustedProxy::parse("127.0.0.1/32").expect("literal CIDR"),
                TrustedProxy::parse("::1/128").expect("literal CIDR"),
            ],
            ip_rate_limit_per_minute: 600,
            mailer_tenant_concurrency: 8,
            domain_txt_endpoint: None,
            domain_cache_refresh: Duration::from_secs(5),
            domain_recheck_interval: Duration::from_secs(86_400),
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
        config.app_db_password = "explicit-app-password".into();
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
        assert!(text.contains("MONACA_APP_DB_PASSWORD"), "{text}");
    }

    #[test]
    fn prod_startup_does_not_depend_on_the_bootstrap_seeds() {
        let mut config = prod_config();
        config.kek_hex = "ab".repeat(32);
        config.internal_secret = "explicit-internal-secret".into();
        config.bootstrap_admin_password = String::new();
        config.admin_client_secret = String::new();
        config.console_client_secret = String::new();
        config.app_db_password = String::new();

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

        let mut config = prod_config();
        seed_all(&mut config);
        config.app_db_password = DEV_APP_DB_PASSWORD.into();
        let err = config.validate_bootstrap().expect_err("must fail");
        assert!(err.to_string().contains("MONACA_APP_DB_PASSWORD"));
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
