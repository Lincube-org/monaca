//! Channel dispatch for outbound messages — docs/contracts/m0.md §6.3.
//!
//! Email and SMS share the connector row shape, the outbox retry path, the per-address cooldown
//! counters and the metrics. Only the transport differs:
//!
//! * email: `http` (JSON POST with an optional bearer) or `smtp`;
//! * SMS: `http` (JSON POST with an optional bearer) or `twilio` (form POST to the documented
//!   Messages endpoint).
//!
//! SMTP TLS is never downgraded: `smtps://` and `smtp+starttls://` use the default rustls
//! verification, and plain `smtp://` is accepted only for loopback (the local capture in dev and
//! CI). There is no "skip certificate verification" switch anywhere.

use std::time::Duration;

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use monaca_store::{DeliveryConnectorRow, OutboxMailRow, TenantRow};
use serde_json::{Value, json};

use crate::state::AppState;

/// The email channel name used in the connector table, API paths and metrics.
pub const EMAIL: &str = "email";
/// The SMS channel name.
pub const SMS: &str = "sms";

/// Outbox topic for rendered email.
pub const TOPIC_EMAIL: &str = "mail.verification";
/// Outbox topic for rendered SMS.
pub const TOPIC_SMS: &str = "sms.verification";

/// The topic a channel's mailer claims.
pub fn topic_for(channel: &str) -> &'static str {
    if channel == SMS { TOPIC_SMS } else { TOPIC_EMAIL }
}

/// The longest one transport call may take.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Send one claimed row through its connector. A returned `Ok` carries the provider/transport
/// detail; `Err` is retryable.
pub async fn deliver(
    state: &AppState,
    tenant: &TenantRow,
    connector: &DeliveryConnectorRow,
    secret: Option<&str>,
    row: &OutboxMailRow,
) -> Result<String, String> {
    match (connector.channel.as_str(), connector.provider.as_str()) {
        (EMAIL, "http") => {
            deliver_email_http(state, tenant, connector, secret, row).await
        }
        (EMAIL, "smtp") => deliver_smtp(connector, secret, &row.payload).await,
        (SMS, "http") => deliver_sms_http(state, tenant, connector, secret, row).await,
        (SMS, "twilio") => deliver_twilio(state, connector, secret, row).await,
        (channel, provider) => Err(format!("unsupported {channel} provider `{provider}`")),
    }
}

/// The current HTTP email body: the rendered copy plus the row id for de-duplication.
fn email_http_body(tenant: &TenantRow, connector: &DeliveryConnectorRow, row: &OutboxMailRow) -> Value {
    json!({
        "id": row.id.to_string(),
        "tenant": tenant.slug,
        "purpose": row.payload.get("purpose"),
        "to": row.payload.get("to"),
        "subject": row.payload.get("subject"),
        "text": row.payload.get("body"),
        "from": connector.from_address,
        "from_name": connector.from_name,
    })
}

async fn deliver_email_http(
    state: &AppState,
    tenant: &TenantRow,
    connector: &DeliveryConnectorRow,
    secret: Option<&str>,
    row: &OutboxMailRow,
) -> Result<String, String> {
    let body = email_http_body(tenant, connector, row);
    let mut request = state.http.post(&connector.endpoint).json(&body);
    if let Some(secret) = secret {
        request = request.bearer_auth(secret);
    }
    let response = request
        .timeout(DELIVERY_TIMEOUT)
        .send()
        .await
        .map_err(|err| format!("request failed: {err}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("provider answered {status}"));
    }
    Ok(format!("http {status}"))
}

/// The generic SMS gateway body. A real gateway can map these fields; tests point it at a local
/// capture.
fn sms_http_body(tenant: &TenantRow, connector: &DeliveryConnectorRow, row: &OutboxMailRow) -> Value {
    json!({
        "id": row.id.to_string(),
        "tenant": tenant.slug,
        "purpose": row.payload.get("purpose"),
        "to": row.payload.get("to"),
        "text": row.payload.get("body"),
        "from": connector.from_address,
    })
}

async fn deliver_sms_http(
    state: &AppState,
    tenant: &TenantRow,
    connector: &DeliveryConnectorRow,
    secret: Option<&str>,
    row: &OutboxMailRow,
) -> Result<String, String> {
    let body = sms_http_body(tenant, connector, row);
    let mut request = state.http.post(&connector.endpoint).json(&body);
    if let Some(secret) = secret {
        request = request.bearer_auth(secret);
    }
    let response = request
        .timeout(DELIVERY_TIMEOUT)
        .send()
        .await
        .map_err(|err| format!("request failed: {err}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("provider answered {status}"));
    }
    Ok(format!("http {status}"))
}

/// The Twilio Messages API shape: `POST {base}/2010-04-01/Accounts/{sid}/Messages.json`,
/// form-encoded, HTTP basic `sid:token`. The secret is `account_sid:auth_token`.
async fn deliver_twilio(
    state: &AppState,
    connector: &DeliveryConnectorRow,
    secret: Option<&str>,
    row: &OutboxMailRow,
) -> Result<String, String> {
    let Some(secret) = secret else {
        return Err("the Twilio connector has no account sid/token".to_owned());
    };
    let (sid, token) = secret
        .split_once(':')
        .ok_or_else(|| "the Twilio secret must be `account_sid:auth_token`".to_owned())?;
    let to = row
        .payload
        .get("to")
        .and_then(Value::as_str)
        .ok_or_else(|| "the SMS payload has no `to`".to_owned())?;
    let text = row
        .payload
        .get("body")
        .and_then(Value::as_str)
        .ok_or_else(|| "the SMS payload has no `body`".to_owned())?;

    let base = state
        .config
        .sms_provider_base_url
        .as_deref()
        .unwrap_or(connector.endpoint.as_str())
        .trim_end_matches('/');
    let url = format!(
        "{base}/2010-04-01/Accounts/{}/Messages.json",
        url_encode(sid)
    );
    let form = [
        ("To", to),
        ("From", connector.from_address.as_str()),
        ("Body", text),
    ];
    let response = state
        .http
        .post(url.as_str())
        .basic_auth(sid, Some(token))
        .form(&form)
        .timeout(DELIVERY_TIMEOUT)
        .send()
        .await
        .map_err(|err| format!("Twilio request failed: {err}"))?;
    let status = response.status();
    if !status.is_success() {
        let detail = response.text().await.unwrap_or_default();
        return Err(format!("Twilio answered {status}: {detail}"));
    }
    Ok(format!("twilio {status}"))
}

/// Percent-encode the account sid for a path segment. Sids are alphanumeric, but the helper keeps
/// a misconfigured value from changing the URL shape.
fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Deliver one message over SMTP.
async fn deliver_smtp(
    connector: &DeliveryConnectorRow,
    secret: Option<&str>,
    payload: &Value,
) -> Result<String, String> {
    let (mode, host, port) = parse_smtp_endpoint(&connector.endpoint)?;
    if mode == SmtpMode::Plain && !is_loopback_host(&host) {
        return Err("plaintext SMTP is allowed only on a loopback host".to_owned());
    }

    let to = payload
        .get("to")
        .and_then(Value::as_str)
        .ok_or_else(|| "the mail payload has no `to`".to_owned())?;
    let subject = payload
        .get("subject")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let body = payload
        .get("body")
        .and_then(Value::as_str)
        .ok_or_else(|| "the mail payload has no `body`".to_owned())?;

    let from = Mailbox::new(
        connector.from_name.clone(),
        connector
            .from_address
            .parse()
            .map_err(|err| format!("invalid from address: {err}"))?,
    );
    let to = Mailbox::new(
        None,
        to.parse()
            .map_err(|err| format!("invalid recipient address: {err}"))?,
    );
    let message = Message::builder()
        .from(from)
        .to(to)
        .subject(subject)
        .body(body.to_owned())
        .map_err(|err| format!("invalid SMTP message: {err}"))?;

    let mut builder = match mode {
        SmtpMode::Plain => {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host).port(port)
        }
        SmtpMode::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
            .map_err(|err| format!("SMTP STARTTLS configuration: {err}"))?
            .port(port),
        SmtpMode::ImplicitTls => AsyncSmtpTransport::<Tokio1Executor>::smtps_relay(&host)
            .map_err(|err| format!("SMTP TLS configuration: {err}"))?
            .port(port),
    };
    if let Some(secret) = secret {
        let (user, password) = secret.split_once(':').ok_or_else(|| {
            "the SMTP credential must be `username:password`".to_owned()
        })?;
        builder = builder.credentials(Credentials::new(user.to_owned(), password.to_owned()));
    }

    let transport = builder.build();
    let sent = tokio::time::timeout(DELIVERY_TIMEOUT, transport.send(message))
        .await
        .map_err(|_| "SMTP delivery timed out".to_owned())?
        .map_err(|err| format!("SMTP delivery failed: {err}"))?;
    Ok(format!("smtp accepted ({})", sent.code()))
}

/// The SMTP endpoint schemes. TLS verification is on for both TLS modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmtpMode {
    /// No TLS at all; loopback only.
    Plain,
    /// STARTTLS is required and the certificate is verified.
    Starttls,
    /// Implicit TLS from the first byte; the certificate is verified.
    ImplicitTls,
}

/// Parse `smtp://host:port`, `smtps://host:port` or `smtp+starttls://host:port`.
fn parse_smtp_endpoint(raw: &str) -> Result<(SmtpMode, String, u16), String> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| "the SMTP endpoint must carry a scheme".to_owned())?;
    let (mode, default_port) = match scheme.to_ascii_lowercase().as_str() {
        "smtp" => (SmtpMode::Plain, 25),
        "smtp+starttls" => (SmtpMode::Starttls, 587),
        "smtps" => (SmtpMode::ImplicitTls, 465),
        other => return Err(format!("unsupported SMTP scheme `{other}`")),
    };
    let rest = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(']') => {
            let port: u16 = port
                .parse()
                .map_err(|_| format!("invalid SMTP port `{port}`"))?;
            (host.to_owned(), port)
        }
        _ => (rest.to_owned(), default_port),
    };
    if host.is_empty() {
        return Err("the SMTP endpoint has no host".to_owned());
    }
    Ok((mode, host, port))
}

/// A loopback host is the only place plaintext SMTP is allowed.
fn is_loopback_host(host: &str) -> bool {
    matches!(
        host.to_ascii_lowercase().as_str(),
        "127.0.0.1" | "::1" | "[::1]" | "localhost"
    )
}

/// Validate an SMTP endpoint at configuration time. A non-loopback plaintext relay is refused.
pub fn validate_smtp_endpoint(raw: &str) -> Result<(), String> {
    let (mode, host, _) = parse_smtp_endpoint(raw)?;
    if mode == SmtpMode::Plain && !is_loopback_host(&host) {
        return Err(
            "`smtp://` is plaintext and is accepted only on 127.0.0.1/localhost; use \
             `smtp+starttls://` or `smtps://` for a relay"
                .to_owned(),
        );
    }
    Ok(())
}

/// Validate a Twilio endpoint. Production pins the documented host; dev/CI may point at a local
/// capture through `MONACA_SMS_PROVIDER_BASE_URL` instead.
pub fn validate_twilio_endpoint(raw: &str, production: bool) -> Result<(), String> {
    let rest = raw
        .strip_prefix("https://")
        .ok_or_else(|| "the Twilio endpoint must be an https URL".to_owned())?;
    let host = rest.split(['/', ':', '?', '#']).next().unwrap_or_default();
    if production && host != "api.twilio.com" {
        return Err("the Twilio endpoint must be https://api.twilio.com in production".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_endpoints_parse_into_modes_and_default_ports() {
        assert_eq!(
            parse_smtp_endpoint("smtp://127.0.0.1:2525").expect("plain"),
            (SmtpMode::Plain, "127.0.0.1".into(), 2525)
        );
        assert_eq!(
            parse_smtp_endpoint("smtps://mail.example.com").expect("implicit"),
            (SmtpMode::ImplicitTls, "mail.example.com".into(), 465)
        );
        assert_eq!(
            parse_smtp_endpoint("smtp+starttls://mail.example.com:587").expect("starttls"),
            (SmtpMode::Starttls, "mail.example.com".into(), 587)
        );
    }

    #[test]
    fn plaintext_smtp_is_loopback_only() {
        assert!(validate_smtp_endpoint("smtp://127.0.0.1:2525").is_ok());
        assert!(validate_smtp_endpoint("smtp://localhost:2525").is_ok());
        assert!(validate_smtp_endpoint("smtp://mail.example.com:25").is_err());
        assert!(validate_smtp_endpoint("smtp+starttls://mail.example.com:587").is_ok());
        assert!(validate_smtp_endpoint("smtps://mail.example.com:465").is_ok());
    }

    #[test]
    fn twilio_is_pinned_in_production() {
        assert!(validate_twilio_endpoint("https://api.twilio.com", true).is_ok());
        assert!(validate_twilio_endpoint("https://127.0.0.1:3939", true).is_err());
        assert!(validate_twilio_endpoint("https://127.0.0.1:3939", false).is_ok());
        assert!(validate_twilio_endpoint("http://api.twilio.com", false).is_err());
    }
}
