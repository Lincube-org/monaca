//! Enterprise SSO over SAML 2.0 — `docs/contracts/m0.md` §6.1 and §6.2.
//!
//! A tenant-level SAML connector stores the identity provider's metadata verbatim; that document
//! is the trust anchor, and the signing certificates inside it are the only keys an assertion is
//! ever verified against. The browser is sent through the HTTP-Redirect binding, the identity
//! provider POSTs an assertion back to the connector's ACS, and the verified subject is handed to
//! the same completion path a password uses, so MFA, consent, organization membership and the SSO
//! session are not reimplemented here.
//!
//! Three properties are enforced here rather than left to convention:
//!
//! * **One signed node is the one consumed.** `risaml` verifies the XML-DSig and returns only
//!   content covered by a verified reference; this module reads every business field from that
//!   [`SsoSession`] and never re-parses the message to look an assertion up by ID. A targeted
//!   pre-scan rejects DTDs, entity references, encrypted assertions and anything other than one
//!   `Response/Assertion` at the path the profile names, so signature wrapping has no room.
//! * **Replay is a database claim.** A response is accepted only after the `InResponseTo` state
//!   row is consumed by a conditional `UPDATE`, and only after the assertion ID is claimed once
//!   with the same `consumed_at IS NULL AND expires_at > now()` semantics.
//! * **Time is narrow.** `NotBefore` / `NotOnOrAfter` are checked with at most two minutes of
//!   clock skew, and an assertion without an upper bound is refused because it could never be
//!   recorded as spent.
//!
//! IdP-initiated responses (no `InResponseTo`) are refused at the ACS. A Monaca session is always
//! bound to an interaction and a client redirect, neither of which an unsolicited POST can name;
//! accepting one would be a second, looser path into the same completion code.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration as StdDuration, SystemTime};

use axum::Json;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Path, Query, RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use data_encoding::BASE64;
use monaca_audit::{AuditActor, AuditActorType, AuditDecision, AuditEvent, AuditSubject};
use monaca_oidc::SamlLogin;
use monaca_store::{AccountRow, SamlConnectorRow, TenantRow};
use monaca_types::{AccountId, EventId, TypedId};
use risaml::constants::{Binding, CertUse};
use risaml::{
    AcsEndpoint, AuthnRequest, AuthnRequestSigningPolicy, BrowserInput, ClockSkew, EntityId,
    FormField, IdpDescriptor, LogoutRequest, LogoutResponse, MetadataTrustPolicy, NameId, Outbound,
    PendingAuthnRequest, PendingSnapshot, RelayStateParam, ReplayCache, ReplayKey, ReplayPolicy,
    Saml, SamlInstant, SamlValidationContext, SessionIndex, SloEndpoint, Sp, SpConfig,
    SpValidationPolicy, SsoResponse, SsoSession, StartSso, XmlPolicy,
};
use serde::Deserialize;
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::error::{ApiError, kinds};
use crate::management::{authorize_admin, authorize_admin_read};
use crate::social::check_connector_id;
use crate::sso::{email_domain, join_org_and_audit, normalise_domains};
use crate::state::AppState;

/// How long a visitor may spend at the identity provider before the correlation state is refused.
const SAML_STATE_TTL_SECS: u64 = 600;

/// The widest clock skew this deployment tolerates on `NotBefore` and `NotOnOrAfter`: two minutes.
const SAML_CLOCK_SKEW_MS: i64 = 120_000;

/// The largest assertion message this ACS accepts after base64 decoding.
const MAX_SAML_XML_BYTES: usize = 1024 * 1024;

/// How long a LogoutRequest without `NotOnOrAfter` stays on the one-time replay list.
const SAML_LOGOUT_REPLAY_TTL_SECS: i64 = 300;

/// The assertion attribute used when the administrator names none.
const DEFAULT_EMAIL_ATTRIBUTE: &str = "email";

/// A replay cache that deliberately claims nothing.
///
/// `risaml` asks for a cache only so the profile's one-time rules can be satisfied; the durable,
/// cross-instance claim is [`monaca_store::Store::consume_saml_assertion_once`], which runs
/// immediately after validation and before any account side effect. Keeping the library's cache a
/// no-op avoids a second, per-process source of truth while still letting an assertion that
/// carries `OneTimeUse` pass the library's profile check.
struct CallerOwnedReplay;

impl ReplayCache for CallerOwnedReplay {
    fn check_and_store(
        &mut self,
        _key: ReplayKey,
        _expires_at: SystemTime,
    ) -> Result<(), risaml::SamlError> {
        Ok(())
    }
}

/// The body of `POST /v1/saml-connectors` (§6.2).
#[derive(Debug, Deserialize)]
pub struct CreateSamlConnectorBody {
    /// The slug the protocol and the page use, e.g. `okta`.
    pub connector_id: String,
    /// The name the sign-in page shows.
    pub display_name: String,
    /// The identity provider's metadata XML, exactly as downloaded from it.
    pub metadata_xml: String,
    /// The email domains whose sign-ins route to this provider.
    pub email_domains: Vec<String>,
    /// The assertion attribute carrying the verified address; `email` when absent.
    #[serde(default)]
    pub email_attribute: Option<String>,
    /// The assertion attribute whose values name tenant roles; absent means no mapping.
    #[serde(default)]
    pub role_attribute: Option<String>,
}

/// `POST /v1/saml-connectors` — register a SAML identity provider.
pub async fn create_saml_connector(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateSamlConnectorBody>,
) -> Result<Response, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    let connector_id = check_connector_id(&body.connector_id)?;
    let display_name = body.display_name.trim();
    if display_name.is_empty() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "display_name must not be empty",
        ));
    }
    let metadata_xml = body.metadata_xml.trim();
    if metadata_xml.is_empty() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "metadata_xml must not be empty",
        ));
    }
    scan_xml(metadata_xml).map_err(|detail| ApiError::problem(kinds::INVALID_REQUEST, detail))?;
    let idp = IdpDescriptor::from_metadata_xml(
        metadata_xml,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
    .map_err(|err| {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("metadata_xml is not usable IdP metadata: {err}"),
        )
    })?;
    // The SP does not sign AuthnRequests (§6.1 SAML). An IdP that requires a signature would
    // refuse every sign-in, so the connector is not created instead of being stored and left to
    // fail on the first attempt.
    if idp.metadata().is_want_authn_requests_signed() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the IdP metadata sets WantAuthnRequestsSigned=true; this SP sends unsigned \
             AuthnRequests, so the connector cannot be created without silently downgrading \
             the IdP's requirement",
        ));
    }
    if idp
        .metadata()
        .get_single_sign_on_service(Binding::Redirect)
        .is_none()
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the IdP metadata declares no SingleSignOnService with the HTTP-Redirect binding",
        ));
    }
    if idp
        .metadata()
        .x509_certificates(CertUse::Signing)
        .is_empty()
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the IdP metadata declares no signing certificate; assertions could not be verified",
        ));
    }
    let email_domains = normalise_domains(&body.email_domains)?;
    let email_attribute = attribute_name(body.email_attribute.as_deref(), DEFAULT_EMAIL_ATTRIBUTE)?;
    let role_attribute = body
        .role_attribute
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| attribute_name(Some(name), DEFAULT_EMAIL_ATTRIBUTE))
        .transpose()?;
    let connector = state
        .store
        .create_saml_connector(
            &tenant,
            &connector_id,
            display_name,
            metadata_xml,
            idp.entity_id().as_str(),
            &email_domains,
            &email_attribute,
            role_attribute.as_deref(),
        )
        .await?;

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "sso_connector.created".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "connector_id": connector.connector_id,
            "email_domains": connector.email_domains,
            "protocol": "saml",
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append sso_connector.created audit event");
    }

    Ok((
        StatusCode::CREATED,
        Json(saml_connector_json(&state, &tenant, &connector)),
    )
        .into_response())
}

/// `GET /v1/saml-connectors` — every SAML provider the tenant configured.
pub async fn list_saml_connectors(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let (tenant, _) = authorize_admin_read(&state, &headers).await?;
    let rows = state.store.saml_connectors(&tenant).await?;
    let items: Vec<Value> = rows
        .iter()
        .map(|row| saml_connector_json(&state, &tenant, row))
        .collect();
    Ok(Json(json!({ "items": items, "next": null })))
}

/// `DELETE /v1/saml-connectors/{connector}` — remove the provider, its states and replay keys.
pub async fn delete_saml_connector(
    State(state): State<Arc<AppState>>,
    Path(connector_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let (tenant, admin) = authorize_admin(&state, &headers).await?;
    if !state
        .store
        .delete_saml_connector(&tenant, &connector_id)
        .await?
    {
        return Err(ApiError::not_found("SAML connector"));
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "sso_connector.deleted".into(),
        actor_chain: vec![admin.actor()],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "connector_id": connector_id, "protocol": "saml" }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append sso_connector.deleted audit event");
    }

    Ok(StatusCode::NO_CONTENT)
}

/// `GET /t/{tenant}/sso/{connector}/metadata` — the SP metadata the tenant gives the IdP.
pub async fn sp_metadata(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, connector_id)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;
    if !tenant.is_active() {
        return Err(ApiError::not_found("tenant"));
    }
    let Some(connector) = state.store.saml_connector(&tenant, &connector_id).await? else {
        return Err(ApiError::not_found("SAML connector"));
    };
    if !connector.enabled {
        return Err(ApiError::not_found("SAML connector"));
    }
    let sp = saml_sp(&state, &tenant, &connector.connector_id)?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
        sp.metadata_xml().to_owned(),
    )
        .into_response())
}

/// The query of a LogoutRequest delivered over HTTP-Redirect.
#[derive(Debug, Deserialize)]
pub struct SloQuery {
    /// The raw `<LogoutRequest>`, DEFLATE-compressed and base64-encoded by the binding.
    #[serde(rename = "SAMLRequest")]
    pub saml_request: String,
    /// Opaque state the IdP asks this SP to echo on the response.
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// The form body of a LogoutRequest delivered over HTTP-POST.
#[derive(Debug, Deserialize)]
pub struct SloForm {
    /// The base64-encoded `<LogoutRequest>`.
    #[serde(rename = "SAMLRequest")]
    pub saml_request: String,
    /// Opaque state the IdP asks this SP to echo on the response.
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// One inbound LogoutRequest, already decoded far enough to be scanned.
struct SloInput {
    /// The binding the IdP used; the response prefers the same binding.
    binding: Binding,
    /// The base64 value exactly as received, replayed into `risaml`.
    saml_request: String,
    /// The received RelayState, when present.
    relay_state: Option<String>,
    /// The raw query string for the HTTP-Redirect binding.
    raw_query: Option<String>,
    /// The decoded XML the structural pre-scan reads.
    xml: String,
}

/// `GET /t/{tenant}/sso/{connector}/slo` — receive an IdP logout over HTTP-Redirect.
pub async fn saml_slo_redirect(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, connector_id)): Path<(String, String)>,
    Query(query): Query<SloQuery>,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let xml = decode_redirect_request(&query.saml_request)?;
    consume_logout_request(
        state,
        tenant_slug,
        connector_id,
        SloInput {
            binding: Binding::Redirect,
            saml_request: query.saml_request,
            relay_state: query.relay_state,
            raw_query: Some(raw.unwrap_or_default()),
            xml,
        },
    )
    .await
}

/// `POST /t/{tenant}/sso/{connector}/slo` — receive an IdP logout over HTTP-POST.
pub async fn saml_slo_post(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, connector_id)): Path<(String, String)>,
    form: Result<Form<SloForm>, FormRejection>,
) -> Result<Response, ApiError> {
    let Form(form) = form.map_err(|_| {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            "the LogoutRequest must be an application/x-www-form-urlencoded form",
        )
    })?;
    let xml = decode_saml_request(&form.saml_request)?;
    consume_logout_request(
        state,
        tenant_slug,
        connector_id,
        SloInput {
            binding: Binding::Post,
            saml_request: form.saml_request,
            relay_state: form.relay_state,
            raw_query: None,
            xml,
        },
    )
    .await
}

/// The shared receive path for both front-channel bindings.
async fn consume_logout_request(
    state: Arc<AppState>,
    tenant_slug: String,
    connector_id: String,
    input: SloInput,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;
    if !tenant.is_active() {
        return Err(ApiError::not_found("tenant"));
    }
    let Some(connector) = state.store.saml_connector(&tenant, &connector_id).await? else {
        return Err(ApiError::not_found("SAML connector"));
    };
    if !connector.enabled {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this SAML connector is disabled",
        ));
    }

    // The structural pre-scan runs before any parser inside `risaml` sees the bytes: a DTD, an
    // entity reference, a nested LogoutRequest or a signature below the root can only be an
    // attempt to redirect the verifier away from the element the business fields are read from.
    scan_logout_request(&input.xml)
        .map_err(|detail| ApiError::problem(kinds::INVALID_REQUEST, detail))?;

    let sp = saml_sp(&state, &tenant, &connector_id)?;
    let idp = saml_idp(&connector)?;
    let mut replay = CallerOwnedReplay;
    let validation = SamlValidationContext::new(
        system_time(state.now())?,
        ReplayPolicy::RequireCache(&mut replay),
    )
    .with_clock_skew(ClockSkew::from_millis(
        -SAML_CLOCK_SKEW_MS,
        SAML_CLOCK_SKEW_MS,
    ));

    let mut fields = vec![FormField::new("SAMLRequest", input.saml_request.as_str())];
    if let Some(relay_state) = input.relay_state.as_deref() {
        fields.push(FormField::new("RelayState", relay_state));
    }
    let browser_input = match input.binding {
        Binding::Redirect => {
            BrowserInput::<LogoutRequest>::redirect(input.raw_query.as_deref().unwrap_or_default())
        }
        _ => BrowserInput::<LogoutRequest>::post(fields),
    };
    let received = sp
        .receive_slo(&idp, browser_input, validation)
        .map_err(saml_rejected)?;
    let request = received.message();

    // `risaml` enforces `NotOnOrAfter`; the lower half is ours: a request whose IssueInstant is
    // stale is refused with the same narrow two-minute skew the assertion window uses.
    let issued_at = parse_instant(request.issue_instant().as_str())?;
    if !logout_issue_instant_acceptable(issued_at, state.now()) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the LogoutRequest IssueInstant is outside the accepted clock window",
        ));
    }

    let now = state.now();
    let replay_until = match request.not_on_or_after() {
        Some(instant) => parse_instant(instant.as_str())?,
        None => now + time::Duration::seconds(SAML_LOGOUT_REPLAY_TTL_SECS),
    };
    if replay_until <= now {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this LogoutRequest is already expired",
        ));
    }
    if !state
        .store
        .consume_saml_logout_once(&tenant, &connector_id, request.id().as_str(), replay_until)
        .await?
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this LogoutRequest was already received",
        ));
    }

    // Only a request that names a session may end one. A request that names none matches nothing
    // and still answers success below: the endpoint must not become a SessionIndex probe.
    let targets = live_logout_targets(
        &state,
        &tenant,
        &connector_id,
        request.name_id().map(NameId::value),
        request.session_indexes(),
    )
    .await?;
    let mut revoked = 0usize;
    for session_id in &targets {
        if revoke_logout_session(&state, &tenant, &connector_id, *session_id).await? {
            revoked += 1;
        }
    }

    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "sso_logout.received".into(),
        actor_chain: vec![AuditActor::tenant(tenant.tenant_id())],
        subject: AuditSubject {
            subject_type: AuditActorType::Tenant,
            id: None,
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({
            "connector_id": connector_id,
            "protocol": "saml",
            "sessions_revoked": revoked,
        }),
    };
    if let Err(err) = state.audit_tenant(&tenant, &event).await {
        tracing::warn!(%err, "could not append sso_logout.received audit event");
    }

    // The response is Success whether or not a session matched. That is the contract, not a
    // courtesy: a difference would let the IdP (or anyone holding a signed request) probe which
    // SessionIndex values exist here.
    let binding = slo_response_binding(&idp, input.binding).ok_or_else(|| {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            "the IdP metadata declares no SingleLogoutService this SP can answer; \
             update the connector metadata",
        )
    })?;
    logout_response(&sp, &idp, request, received.relay_state(), binding)
}

/// The sessions a LogoutRequest identifies, never "every session of the connector".
async fn live_logout_targets(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    connector_id: &str,
    name_id: Option<&str>,
    session_indexes: &[SessionIndex],
) -> Result<Vec<Uuid>, ApiError> {
    if !logout_can_match(name_id, session_indexes) {
        return Ok(Vec::new());
    }
    let mut targets = BTreeSet::new();
    if session_indexes.is_empty() {
        targets.extend(
            state
                .store
                .live_saml_bound_sessions(tenant, connector_id, name_id, None)
                .await?,
        );
    } else {
        for session_index in session_indexes {
            targets.extend(
                state
                    .store
                    .live_saml_bound_sessions(
                        tenant,
                        connector_id,
                        name_id,
                        Some(session_index.as_str()),
                    )
                    .await?,
            );
        }
    }
    Ok(targets.into_iter().collect())
}

/// A request that names neither identifier must match nothing; it is never "all sessions".
fn logout_can_match(name_id: Option<&str>, session_indexes: &[SessionIndex]) -> bool {
    name_id.is_some() || !session_indexes.is_empty()
}

/// The `IssueInstant` window: the same two minutes the assertion bounds use.
fn logout_issue_instant_acceptable(issued_at: OffsetDateTime, now: OffsetDateTime) -> bool {
    let skew = time::Duration::milliseconds(SAML_CLOCK_SKEW_MS);
    issued_at >= now - skew && issued_at <= now + skew
}

/// Revoke one matched session through the existing session/refresh-token path.
async fn revoke_logout_session(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    connector_id: &str,
    session_id: Uuid,
) -> Result<bool, ApiError> {
    let Some(row) = state.store.session_by_id(tenant, session_id).await? else {
        return Ok(false);
    };
    state
        .store
        .revoke_session_refresh_tokens(tenant, session_id)
        .await?;
    if !state.store.revoke_session(tenant, session_id).await? {
        return Ok(false);
    }
    let event = AuditEvent {
        id: EventId::new(),
        at: state.now(),
        action: "session.logout".into(),
        actor_chain: vec![AuditActor::account(AccountId::from_uuid(row.account_id))],
        subject: AuditSubject {
            subject_type: AuditActorType::Session,
            id: Some(monaca_types::SessionId::from_uuid(session_id).to_typed_string()),
        },
        decision: AuditDecision::Allow,
        grant_id: None,
        jti: None,
        payload: json!({ "reason": "saml_slo", "connector_id": connector_id }),
    };
    if let Err(err) = state.audit_tenant(tenant, &event).await {
        tracing::warn!(%err, "could not append session.logout audit event");
    }
    Ok(true)
}

/// Choose the binding for the LogoutResponse: the IdP's own binding first, then either it
/// declares. `None` means the metadata cannot receive a response at all.
fn slo_response_binding(idp: &IdpDescriptor, inbound: Binding) -> Option<Binding> {
    if idp.metadata().get_single_logout_service(inbound).is_some() {
        Some(inbound)
    } else if idp
        .metadata()
        .get_single_logout_service(Binding::Post)
        .is_some()
    {
        Some(Binding::Post)
    } else if idp
        .metadata()
        .get_single_logout_service(Binding::Redirect)
        .is_some()
    {
        Some(Binding::Redirect)
    } else {
        None
    }
}

/// Build the unsigned LogoutResponse.
///
/// `risaml::respond_slo` always signs, and this SP has no signing key (§6.1). The library's
/// renderer is used directly with `want_signed=false`; the SP metadata declares no
/// `KeyDescriptor`, so an unsigned answer is the only truthful one.
fn logout_response(
    sp: &Saml<Sp>,
    idp: &IdpDescriptor,
    request: &LogoutRequest,
    relay_state: &RelayStateParam,
    binding: Binding,
) -> Result<Response, ApiError> {
    let context = logout_response_context(sp, idp, request, relay_state, binding)?;
    let outbound = Outbound::<LogoutResponse>::try_from(context).map_err(ApiError::internal)?;
    if binding == Binding::Redirect {
        Ok(crate::social::found(
            outbound.redirect_url().map_err(ApiError::internal)?,
        ))
    } else {
        Ok(Html(outbound.raw_context().post_form()).into_response())
    }
}

/// The rendered LogoutResponse, before it is turned into a browser action.
fn logout_response_context(
    sp: &Saml<Sp>,
    idp: &IdpDescriptor,
    request: &LogoutRequest,
    relay_state: &RelayStateParam,
    binding: Binding,
) -> Result<risaml::entity::BindingContext, ApiError> {
    let raw = sp.raw_service_provider();
    risaml::logout::create_logout_response(
        &raw.setting,
        &raw.metadata,
        idp.metadata(),
        binding,
        Some(request.id().as_str()),
        relay_state.as_deref(),
        false,
    )
    .map_err(|err| {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("the LogoutResponse could not be built: {err}"),
        )
    })
}

/// Decode an HTTP-Redirect `SAMLRequest` far enough for the structural pre-scan.
fn decode_redirect_request(value: &str) -> Result<String, ApiError> {
    let compressed = risaml::binding::base64_decode_with_limit(value, MAX_SAML_XML_BYTES)
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, "SAMLRequest is not base64"))?;
    let bytes = risaml::binding::deflate_raw_decode_with_limit(&compressed, MAX_SAML_XML_BYTES)
        .map_err(|_| {
            ApiError::problem(
                kinds::INVALID_REQUEST,
                "SAMLRequest is not raw-DEFLATE data",
            )
        })?;
    String::from_utf8(bytes).map_err(|_| {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            "SAMLRequest does not decode to an XML document",
        )
    })
}

/// Reject the constructs that make a LogoutRequest ambiguous.
///
/// The signed node must be the consumed node: exactly one `LogoutRequest` root, no nested
/// `LogoutRequest`, and no `Signature` below the root (an enveloped signature over the root is
/// the only one the profile allows). DTDs and entity references are refused for the same reason
/// as in [`scan_xml`].
fn scan_logout_request(xml: &str) -> Result<(), String> {
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().check_end_names = true;
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut root: Option<String> = None;
    let mut roots = 0usize;
    let mut nested_requests = 0usize;
    let mut nested_signatures = 0usize;
    let mut encrypted_ids = 0usize;
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(element)) => {
                let local = element.name().local_name().as_ref().to_vec();
                let depth = stack.len();
                if depth == 0 {
                    roots += 1;
                    root = Some(String::from_utf8_lossy(&local).into_owned());
                } else {
                    if local == b"LogoutRequest" {
                        nested_requests += 1;
                    }
                    if local == b"Signature" && depth > 1 {
                        nested_signatures += 1;
                    }
                    if local == b"EncryptedID" {
                        encrypted_ids += 1;
                    }
                }
                stack.push(local);
            }
            Ok(quick_xml::events::Event::Empty(element)) => {
                let local = element.name().local_name().as_ref().to_vec();
                let depth = stack.len();
                if depth == 0 {
                    roots += 1;
                    root = Some(String::from_utf8_lossy(&local).into_owned());
                } else {
                    if local == b"LogoutRequest" {
                        nested_requests += 1;
                    }
                    if local == b"Signature" && depth > 1 {
                        nested_signatures += 1;
                    }
                    if local == b"EncryptedID" {
                        encrypted_ids += 1;
                    }
                }
            }
            Ok(quick_xml::events::Event::End(_)) => {
                stack.pop();
            }
            Ok(quick_xml::events::Event::DocType(_)) => {
                return Err("DTDs are not accepted in SAML messages".into());
            }
            Ok(quick_xml::events::Event::GeneralRef(reference)) => {
                let name = reference
                    .decode()
                    .map_err(|err| err.to_string())?
                    .into_owned();
                if !name.starts_with('#')
                    && !matches!(name.as_str(), "amp" | "lt" | "gt" | "quot" | "apos")
                {
                    return Err(format!(
                        "the SAML message references an undeclared entity `{name}`"
                    ));
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Ok(_) => {}
            Err(err) => return Err(format!("the SAML XML is malformed: {err}")),
        }
    }
    if roots != 1 {
        return Err("the message must have exactly one root element".into());
    }
    if root.as_deref() != Some("LogoutRequest") {
        return Err("the message is not a LogoutRequest".into());
    }
    if nested_requests > 0 {
        return Err("a LogoutRequest must not contain another LogoutRequest".into());
    }
    if nested_signatures > 0 {
        return Err("a signature below the LogoutRequest cannot sign the consumed element".into());
    }
    if encrypted_ids > 0 {
        return Err("encrypted NameIDs are not supported by this SP".into());
    }
    Ok(())
}

/// The form the identity provider POSTs to the ACS.
#[derive(Debug, Deserialize)]
pub struct AcsForm {
    /// The base64-encoded `<Response>`.
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    /// The opaque correlation state this SP sent in the AuthnRequest.
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// `POST /t/{tenant}/sso/{connector}/acs` — consume an SP-initiated response.
pub async fn saml_acs(
    State(state): State<Arc<AppState>>,
    Path((tenant_slug, connector_id)): Path<(String, String)>,
    headers: HeaderMap,
    form: Result<Form<AcsForm>, FormRejection>,
) -> Result<Response, ApiError> {
    let tenant = state.tenant(&tenant_slug).await?;
    if !tenant.is_active() {
        return Err(ApiError::not_found("tenant"));
    }
    if !state
        .store
        .sign_in_experience(&tenant)
        .await?
        .single_sign_on_enabled
    {
        return Err(ApiError::problem(
            kinds::SSO_DISABLED,
            "single sign-on is disabled for this tenant",
        ));
    }
    let form = form.map_err(|_| {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            "the SAML response must be an application/x-www-form-urlencoded form",
        )
    })?;
    let Some(relay_state) = form
        .relay_state
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        // Without RelayState there is no local correlation state, which is exactly the shape of an
        // IdP-initiated response. There is no second, looser path into the completion code.
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "missing RelayState; IdP-initiated SAML responses are not accepted, start sign-in \
             at /t/{tenant}/sso/{connector}/authorize",
        ));
    };
    let xml = decode_saml_response(&form.saml_response)?;
    let scan =
        scan_xml(&xml).map_err(|detail| ApiError::problem(kinds::INVALID_REQUEST, detail))?;
    if scan.in_response_to.is_none() {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the response has no InResponseTo; IdP-initiated SAML responses are not accepted",
        ));
    }

    let Some(connector) = state.store.saml_connector(&tenant, &connector_id).await? else {
        return Err(ApiError::not_found("SAML connector"));
    };
    if !connector.enabled {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this SAML connector is disabled",
        ));
    }
    let Some(pending) = state
        .store
        .take_saml_state(&tenant, relay_state, &connector_id)
        .await?
    else {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the RelayState is unknown, expired or already used",
        ));
    };

    let sp = saml_sp(&state, &tenant, &connector_id)?;
    let idp = saml_idp(&connector)?;
    let pending_request = pending_request(&pending)?;
    let mut replay = CallerOwnedReplay;
    let validation = SamlValidationContext::new(
        system_time(state.now())?,
        ReplayPolicy::RequireCache(&mut replay),
    )
    .with_clock_skew(ClockSkew::from_millis(
        -SAML_CLOCK_SKEW_MS,
        SAML_CLOCK_SKEW_MS,
    ));
    let input = BrowserInput::<SsoResponse>::post(vec![
        FormField::new("SAMLResponse", form.saml_response.as_str()),
        FormField::new("RelayState", relay_state),
    ]);
    let session = sp
        .finish_sso(&idp, &pending_request, input, validation)
        .map_err(|err| saml_rejected(err))?;

    // `risaml` has already proved the response echoes the request ID this SP issued; the check is
    // repeated so the invariant is visible where the state is consumed.
    if session.in_response_to().map(|id| id.as_str()) != Some(pending.request_id.as_str()) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the response does not answer the AuthnRequest this SP issued",
        ));
    }
    let expires_at = assertion_expiry(&session)?;
    if !state
        .store
        .consume_saml_assertion_once(
            &tenant,
            &connector_id,
            session.assertion_id().as_str(),
            expires_at,
        )
        .await?
    {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this assertion was already used",
        ));
    }

    let email = asserted_email(&session, &connector)?;
    let interaction = state
        .peek_interaction(&tenant, &pending.interaction_id)
        .await
        .map_err(ApiError::Interaction)?;
    if interaction.tenant != tenant.slug {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the interaction belongs to another tenant",
        ));
    }

    let (account, created) = match state.store.account_by_email(&tenant, &email).await? {
        Some((account, _)) => (account, false),
        None => {
            let display = session
                .attributes()
                .get("name")
                .and_then(|attribute| attribute.values().first())
                .map(|value| value.as_str().trim())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| email.split('@').next().unwrap_or(&email))
                .to_owned();
            let account = state
                .store
                .create_account(
                    &tenant,
                    AccountId::new(),
                    &email,
                    &display,
                    None,
                    false,
                    None,
                    None,
                    None,
                )
                .await?;
            (account, true)
        }
    };
    if account.state != "active" {
        return Err(ApiError::problem(
            kinds::INVALID_CREDENTIALS,
            "this account cannot sign in",
        ));
    }
    if created {
        join_org_and_audit(
            &state,
            &tenant,
            &account,
            &interaction.organization,
            &connector.connector_id,
        )
        .await?;
    }
    apply_role_attribute(&state, &tenant, &connector, &session, &account).await?;

    // The logout credentials travel with the interaction, not just with this call: a second
    // factor or a consent screen pauses the flow and resumes it from storage, and the session
    // those steps create must still be addressable by the IdP that authenticated it.
    let interaction = state
        .attach_interaction_saml(
            &tenant,
            &pending.interaction_id,
            &saml_login(&connector, &session),
        )
        .await
        .map_err(ApiError::Interaction)?;

    crate::protocol::finish_sign_in_browser(
        state,
        tenant,
        interaction,
        &pending.interaction_id,
        &headers,
        account,
    )
    .await
}

/// What the verified assertion binds to the session this flow will create.
fn saml_login(connector: &SamlConnectorRow, session: &SsoSession) -> SamlLogin {
    SamlLogin {
        connector_id: connector.connector_id.clone(),
        name_id: session.name_id().value().to_owned(),
        name_id_format: session
            .name_id()
            .format()
            .map(|format| format.as_uri().to_owned()),
        session_indexes: session
            .authn_sessions()
            .iter()
            .filter_map(|statement| {
                statement
                    .session_index()
                    .map(|index| index.as_str().to_owned())
            })
            .collect(),
    }
}

/// Start an SP-initiated SAML round-trip. The caller has already checked the tenant, the SSO
/// switch and the interaction; this function only speaks SAML.
pub(crate) async fn saml_authorize(
    state: &Arc<AppState>,
    tenant: TenantRow,
    connector_id: &str,
    interaction_id: &str,
) -> Result<Response, ApiError> {
    let Some(connector) = state.store.saml_connector(&tenant, connector_id).await? else {
        return Err(ApiError::not_found("SSO connector"));
    };
    if !connector.enabled {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "this SAML connector is disabled",
        ));
    }
    let interaction = state
        .peek_interaction(&tenant, interaction_id)
        .await
        .map_err(ApiError::Interaction)?;
    if interaction.tenant != tenant.slug {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "the interaction belongs to another tenant",
        ));
    }

    let sp = saml_sp(state, &tenant, connector_id)?;
    let idp = saml_idp(&connector)?;
    let state_id = Uuid::now_v7().to_string();
    let relay_state =
        RelayStateParam::try_from_option(Some(state_id.clone())).map_err(ApiError::internal)?;
    let started = sp
        .start_sso(
            &idp,
            StartSso::redirect()
                .relay_state(relay_state)
                .pending_lifetime(StdDuration::from_secs(SAML_STATE_TTL_SECS)),
        )
        .map_err(|err| {
            ApiError::problem(
                kinds::INVALID_REQUEST,
                format!("the SAML AuthnRequest could not be created: {err}"),
            )
        })?;
    let issued_at = started.pending.issued_at().map(SamlInstant::as_str);
    let expires_at = started
        .pending
        .expires_at()
        .ok_or_else(|| ApiError::internal("the pending request has no expiry"))?;
    let expires_at =
        OffsetDateTime::parse(expires_at.as_str(), &Rfc3339).map_err(ApiError::internal)?;
    state
        .store
        .insert_saml_state(
            &tenant,
            &state_id,
            connector_id,
            interaction_id,
            started.pending.request_id().as_str(),
            started.pending.idp_entity_id().as_str(),
            started.pending.acs().location().as_str(),
            "redirect",
            "post",
            issued_at,
            expires_at,
        )
        .await?;
    let url = started
        .outbound
        .redirect_url()
        .map_err(ApiError::internal)?;
    Ok(crate::social::found(url))
}

/// The public routing lookup, shared with the OIDC connectors.
pub(crate) async fn saml_lookup(
    state: &AppState,
    tenant: &TenantRow,
    domain: Option<&str>,
) -> Result<Vec<(String, String)>, ApiError> {
    let rows = match domain {
        Some(domain) => state
            .store
            .saml_connector_for_domain(tenant, domain)
            .await?
            .into_iter()
            .filter(|row| row.enabled)
            .collect::<Vec<_>>(),
        None => state
            .store
            .saml_connectors(tenant)
            .await?
            .into_iter()
            .filter(|row| row.enabled)
            .collect(),
    };
    Ok(rows
        .into_iter()
        .map(|row| (row.connector_id, row.display_name))
        .collect())
}

/// Resolve the connector's IdP descriptor from the metadata stored at creation time.
fn saml_idp(connector: &SamlConnectorRow) -> Result<IdpDescriptor, ApiError> {
    let expected = EntityId::try_new(connector.entity_id.clone()).map_err(|err| {
        ApiError::problem(kinds::INVALID_REQUEST, format!("invalid entity id: {err}"))
    })?;
    IdpDescriptor::from_metadata_xml_for(
        expected,
        &connector.metadata_xml,
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
    .map_err(|err| {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("the stored IdP metadata is no longer usable: {err}"),
        )
    })
}

/// Build this connector's SP facade: strict assertion validation, unsigned requests.
fn saml_sp(state: &AppState, tenant: &TenantRow, connector_id: &str) -> Result<Saml<Sp>, ApiError> {
    sp_facade(
        &sp_metadata_url(state, &tenant.slug, connector_id),
        &acs_url(state, &tenant.slug, connector_id),
        &slo_url(state, &tenant.slug, connector_id),
    )
}

/// The SP configuration itself, separate from `AppState` so the policy is unit-testable.
fn sp_facade(sp_metadata_url: &str, acs_url: &str, slo_url: &str) -> Result<Saml<Sp>, ApiError> {
    let mut policy = SpValidationPolicy::strict();
    policy.authn_requests = AuthnRequestSigningPolicy::DoNotSignForCompatibility;
    let config = SpConfig::builder(EntityId::try_new(sp_metadata_url).map_err(ApiError::internal)?)
        .acs_endpoint(AcsEndpoint::post(acs_url).map_err(ApiError::internal)?)
        // Both front-channel bindings are accepted and advertised; the SOAP back-channel is
        // deliberately absent, so metadata never promises it (§6.1 SAML SLO).
        .slo_endpoint(SloEndpoint::redirect(slo_url).map_err(ApiError::internal)?)
        .slo_endpoint(SloEndpoint::post(slo_url).map_err(ApiError::internal)?)
        .validation(policy)
        .xml(XmlPolicy {
            // Skew is applied additively to each bound: widening the lower bound means a negative
            // drift, widening the upper bound a positive one.
            clock_drifts: (-SAML_CLOCK_SKEW_MS, SAML_CLOCK_SKEW_MS),
            ..XmlPolicy::default()
        })
        .build()
        .map_err(ApiError::internal)?;
    Saml::sp(config).map_err(ApiError::internal)
}

/// Rebuild the pending AuthnRequest the response must answer.
fn pending_request(pending: &monaca_store::SamlStateRow) -> Result<PendingAuthnRequest, ApiError> {
    let mut snapshot = PendingSnapshot::<AuthnRequest>::authn_request(
        pending.request_id.clone(),
        RelayStateParam::try_from_option(Some(pending.id.clone())).map_err(ApiError::internal)?,
        pending.idp_entity_id.clone(),
        pending.response_binding.clone(),
        pending.acs_url.clone(),
        pending.response_binding.clone(),
    );
    snapshot.request_binding = Some(pending.request_binding.clone());
    snapshot.issued_at = pending
        .issued_at
        .as_deref()
        .map(SamlInstant::try_new)
        .transpose()
        .map_err(ApiError::internal)?;
    snapshot.expires_at = Some(
        SamlInstant::try_new(
            pending
                .expires_at
                .format(&Rfc3339)
                .map_err(ApiError::internal)?,
        )
        .map_err(|err| ApiError::internal(err))?,
    );
    PendingAuthnRequest::from_snapshot(snapshot).map_err(|err| ApiError::internal(err))
}

/// The response's assertion upper bound, in the database's clock.
///
/// An assertion without `NotOnOrAfter` (in `Conditions` or an `AuthnStatement`) has no expiry to
/// record, so it could never be marked spent; it is refused instead of being treated as valid
/// forever.
fn assertion_expiry(session: &SsoSession) -> Result<OffsetDateTime, ApiError> {
    let conditions = session
        .not_on_or_after()
        .map(|instant| parse_instant(instant.as_str()))
        .transpose()?;
    let statements = session
        .authn_sessions()
        .iter()
        .filter_map(|statement| statement.not_on_or_after())
        .map(|instant| parse_instant(instant.as_str()))
        .collect::<Result<Vec<_>, _>>()?;
    let earliest = statements.into_iter().min();
    let expires_at = match (conditions, earliest) {
        (Some(left), Some(right)) => left.min(right),
        (Some(value), None) | (None, Some(value)) => value,
        (None, None) => {
            return Err(ApiError::problem(
                kinds::INVALID_REQUEST,
                "the assertion carries no NotOnOrAfter, so it cannot be recorded as spent",
            ));
        }
    };
    Ok(expires_at)
}

fn parse_instant(value: &str) -> Result<OffsetDateTime, ApiError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|err| {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("the SAML message carries an unusable time value: {err}"),
        )
    })
}

/// The verified address the assertion asserts, at a domain this connector owns.
fn asserted_email(session: &SsoSession, connector: &SamlConnectorRow) -> Result<String, ApiError> {
    let asserted = session
        .attributes()
        .get(&connector.email_attribute)
        .and_then(|attribute| attribute.values().first())
        .map(|value| value.as_str().trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::problem(
                kinds::SSO_EMAIL_UNVERIFIED,
                format!(
                    "the assertion carries no `{}` attribute",
                    connector.email_attribute
                ),
            )
        })?;
    let email = crate::protocol::normalise_email(asserted)?;
    let Some(domain) = email_domain(&email) else {
        return Err(ApiError::problem(
            kinds::SSO_DOMAIN_MISMATCH,
            "the asserted address is outside this connector's domains",
        ));
    };
    if !connector.email_domains.iter().any(|owned| owned == &domain) {
        return Err(ApiError::problem(
            kinds::SSO_DOMAIN_MISMATCH,
            "the asserted address is outside this connector's domains",
        ));
    }
    Ok(email)
}

/// Assign the roles the configured attribute names, additively.
///
/// Unknown names are skipped. A role whose permissions include `monaca:admin` is also skipped: an
/// identity provider assertion must not be able to hand out the tenant's highest privilege on its
/// own, even when an administrator named that role in the connector. Those assignments stay on the
/// management API and the CLI.
async fn apply_role_attribute(
    state: &Arc<AppState>,
    tenant: &TenantRow,
    connector: &SamlConnectorRow,
    session: &SsoSession,
    account: &AccountRow,
) -> Result<(), ApiError> {
    let Some(role_attribute) = connector.role_attribute.as_deref() else {
        return Ok(());
    };
    let Some(attribute) = session.attributes().get(role_attribute) else {
        return Ok(());
    };
    if attribute.values().is_empty() {
        return Ok(());
    }
    let roles = state.store.roles(tenant).await?;
    for value in attribute.values() {
        let name = value.as_str().trim();
        let Some(role) = roles.iter().find(|role| role.name == name) else {
            tracing::warn!(
                connector = %connector.connector_id,
                role = name,
                "the IdP named a role this tenant does not define"
            );
            continue;
        };
        if role
            .permissions
            .iter()
            .any(|permission| permission == "monaca:admin")
        {
            tracing::warn!(
                connector = %connector.connector_id,
                role = %role.name,
                "refusing to map a monaca:admin role from an IdP assertion"
            );
            continue;
        }
        if !state
            .store
            .assign_role(tenant, account.account_id(), role.id)
            .await?
        {
            continue;
        }
        let event = AuditEvent {
            id: EventId::new(),
            at: state.now(),
            action: "role.assigned".into(),
            actor_chain: vec![AuditActor::account(account.account_id())],
            subject: AuditSubject {
                subject_type: AuditActorType::Account,
                id: Some(account.account_id().to_typed_string()),
            },
            decision: AuditDecision::Allow,
            grant_id: None,
            jti: None,
            payload: json!({
                "role": role.name,
                "role_id": monaca_types::RoleId::from_uuid(role.id).to_typed_string(),
                "sso_connector": connector.connector_id,
            }),
        };
        if let Err(err) = state.audit_tenant(tenant, &event).await {
            tracing::warn!(%err, "could not append role.assigned audit event");
        }
    }
    Ok(())
}

/// Decode a POSTed SAML message and cap its size before any parser sees it.
fn decode_saml_message(value: &str, field: &str) -> Result<String, ApiError> {
    let compact: String = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let bytes = BASE64
        .decode(compact.as_bytes())
        .map_err(|_| ApiError::problem(kinds::INVALID_REQUEST, format!("{field} is not base64")))?;
    if bytes.len() > MAX_SAML_XML_BYTES {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("{field} is larger than this SP accepts"),
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        ApiError::problem(
            kinds::INVALID_REQUEST,
            format!("{field} does not decode to an XML document"),
        )
    })
}

/// Decode the POSTed `SAMLResponse`.
fn decode_saml_response(value: &str) -> Result<String, ApiError> {
    decode_saml_message(value, "SAMLResponse")
}

/// Decode the POSTed `SAMLRequest`.
fn decode_saml_request(value: &str) -> Result<String, ApiError> {
    decode_saml_message(value, "SAMLRequest")
}

/// What the pre-scan needs from a SAML message.
struct XmlScan {
    /// The root `InResponseTo`, when present and non-empty.
    in_response_to: Option<String>,
}

/// Reject the constructs the SAML profile forbids and pin the one assertion the profile allows.
///
/// The scan runs before `risaml` sees the document. It rejects a DTD (so no entity can be
/// declared), any named entity reference outside the five XML predefined ones, an encrypted
/// assertion (this deployment has no decryption key) and any document that is not exactly
/// `Response` → one `Assertion` at the first level. That is the structural invariant signature
/// wrapping attacks violate, and it is cheaper to state here than to reconstruct later.
fn scan_xml(xml: &str) -> Result<XmlScan, String> {
    let mut reader = quick_xml::Reader::from_str(xml);
    reader.config_mut().check_end_names = true;
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut root: Option<String> = None;
    let mut in_response_to: Option<String> = None;
    let mut assertions = 0usize;
    let mut encrypted = 0usize;
    let mut assertion_depth = 0usize;
    let mut assertion_parent: Option<String> = None;
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(element)) => {
                let local = element.name().local_name().as_ref().to_vec();
                if stack.is_empty() {
                    root = Some(String::from_utf8_lossy(&local).into_owned());
                    for attribute in element.attributes() {
                        let attribute = attribute.map_err(|err| err.to_string())?;
                        if attribute.key.local_name().as_ref() == b"InResponseTo" {
                            let value = attribute
                                .decoded_and_normalized_value(
                                    quick_xml::XmlVersion::Implicit1_0,
                                    reader.decoder(),
                                )
                                .map_err(|err| err.to_string())?;
                            in_response_to = (!value.is_empty()).then(|| value.into_owned());
                        }
                    }
                } else if local == b"Assertion" {
                    assertions += 1;
                    assertion_depth = stack.len();
                    assertion_parent = stack
                        .last()
                        .map(|parent| String::from_utf8_lossy(parent).into_owned());
                } else if local == b"EncryptedAssertion" {
                    encrypted += 1;
                }
                stack.push(local);
            }
            Ok(quick_xml::events::Event::Empty(element)) => {
                let local = element.name().local_name().as_ref().to_vec();
                if local == b"Assertion" {
                    assertions += 1;
                    assertion_depth = stack.len();
                    assertion_parent = stack
                        .last()
                        .map(|parent| String::from_utf8_lossy(parent).into_owned());
                } else if local == b"EncryptedAssertion" {
                    encrypted += 1;
                }
            }
            Ok(quick_xml::events::Event::End(_)) => {
                stack.pop();
            }
            Ok(quick_xml::events::Event::DocType(_)) => {
                return Err("DTDs are not accepted in SAML messages".into());
            }
            Ok(quick_xml::events::Event::GeneralRef(reference)) => {
                let name = reference
                    .decode()
                    .map_err(|err| err.to_string())?
                    .into_owned();
                if !name.starts_with('#')
                    && !matches!(name.as_str(), "amp" | "lt" | "gt" | "quot" | "apos")
                {
                    return Err(format!(
                        "the SAML message references an undeclared entity `{name}`"
                    ));
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Ok(_) => {}
            Err(err) => return Err(format!("the SAML XML is malformed: {err}")),
        }
    }
    if encrypted > 0 {
        return Err("encrypted assertions are not supported by this SP".into());
    }
    if root.as_deref() == Some("Response") && assertions != 1 {
        return Err(format!(
            "the response must carry exactly one Assertion, found {assertions}"
        ));
    }
    if assertions == 1 && (assertion_parent.as_deref() != Some("Response") || assertion_depth != 1)
    {
        return Err("the Assertion must be a direct child of the Response".into());
    }
    Ok(XmlScan { in_response_to })
}

/// Map a library rejection to a problem without leaking whether a key or the clock was at fault —
/// the reason is useful to the tenant's operator and useless as an oracle to anyone else.
fn saml_rejected(err: risaml::SamlError) -> ApiError {
    ApiError::problem(
        kinds::INVALID_REQUEST,
        format!("the SAML message was rejected: {err}"),
    )
}

/// Validate an attribute name the administrator configured.
fn attribute_name(value: Option<&str>, fallback: &str) -> Result<String, ApiError> {
    let name = value
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(fallback);
    if name.contains(char::is_whitespace) {
        return Err(ApiError::problem(
            kinds::INVALID_REQUEST,
            "attribute names must not contain whitespace",
        ));
    }
    Ok(name.to_owned())
}

/// Where the identity provider POSTs its response.
fn acs_url(state: &AppState, tenant_slug: &str, connector_id: &str) -> String {
    format!(
        "{}/t/{tenant_slug}/sso/{connector_id}/acs",
        state.config.public_base_url.trim_end_matches('/')
    )
}

/// The SP entity id and metadata location the tenant registers at the IdP.
fn sp_metadata_url(state: &AppState, tenant_slug: &str, connector_id: &str) -> String {
    format!(
        "{}/t/{tenant_slug}/sso/{connector_id}/metadata",
        state.config.public_base_url.trim_end_matches('/')
    )
}

/// Where the IdP sends a LogoutRequest.
fn slo_url(state: &AppState, tenant_slug: &str, connector_id: &str) -> String {
    format!(
        "{}/t/{tenant_slug}/sso/{connector_id}/slo",
        state.config.public_base_url.trim_end_matches('/')
    )
}

/// The connector's management shape — metadata XML stays out of list responses.
fn saml_connector_json(state: &AppState, tenant: &TenantRow, row: &SamlConnectorRow) -> Value {
    json!({
        "connector_id": row.connector_id,
        "display_name": row.display_name,
        "entity_id": row.entity_id,
        "email_domains": row.email_domains,
        "email_attribute": row.email_attribute,
        "role_attribute": row.role_attribute,
        "enabled": row.enabled,
        "acs_url": acs_url(state, &tenant.slug, &row.connector_id),
        "slo_url": slo_url(state, &tenant.slug, &row.connector_id),
        "sp_metadata_url": sp_metadata_url(state, &tenant.slug, &row.connector_id),
        "created_at": row.created_at.format(&Rfc3339).unwrap_or_default(),
    })
}

/// A stored instant as `SystemTime`, for the library's validation context.
fn system_time(at: OffsetDateTime) -> Result<SystemTime, ApiError> {
    let since = at - OffsetDateTime::UNIX_EPOCH;
    let converted = if since.is_negative() {
        SystemTime::UNIX_EPOCH.checked_sub(since.unsigned_abs())
    } else {
        SystemTime::UNIX_EPOCH.checked_add(since.unsigned_abs())
    };
    converted.ok_or_else(|| ApiError::internal("the clock is outside the supported range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESPONSE: &str = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" InResponseTo="_req1"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"/></samlp:Response>"#;

    /// Test-only RSA key for the stand-in identity provider. It signs nothing outside this test.
    const IDP_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDB01oqy1a8cHmR
X3Z0m9RatRAmOfOjZ97Dav1dN9JTMhIxeJ6KaCoYzTZtLnmgDSUSsbpzh2GtoYja
6aw7RxmAcf5ldwRMI5NksDSSGfuzsFmc+36zU3pz3BAoBN6dEJ5xP6U7cPlQwU09
m5Q5wIeBOW8WyRpZXP5bVn4vOFQvoy3dw0Nfb5YGq/hVW0zHMSYm5hFKauVsJ+dJ
qLpR9uRzRSIY15ttrJr5YL6vwT5v0iOZgQ1jCAxugwH1ztvtcYzrvnYaXNbH09Pr
yi9vtRErdN5ppFhsBXqfSVGnAQ6jY9Lo66Fx9UZv/qmRw7dnPnLRBYVDfaSJWmOj
ysRIsKIbAgMBAAECggEAb+xv4M5SY7Y/POb3LBbf5RExJiHIws80H3wkmjOlzEzZ
nJ+eTSYhSPkXOKzhpr5wbf8bP6MpkG367Q6KWiCQZU9uK4EyhhT1A+uML+G5KuXm
mXPQkhTeXRDyc2l8cw4psBOkglKWZT96Lt0sFr1KgiB8OZgfEwNUDcJAU1wfoPGC
yAprCBu8JdaNL7GP5AJGWllNTX9XVc3AlSJsxd+DjWLcp9zERrZoNYkp2j6swGyJ
Gywj+++5PiBL2bla9B17Ofor4IplG6UqgvtvE5AX6dsXEUR2RfHbQlXJVAb6KDRr
QoxoD1L6jWbiTXDlNrGttjk7yipJOtGZEh1xK3f8gQKBgQD4Ah3+LOjBjJFxGIDU
FZ6U3dF0SuyXQGqu5zYrjr3OSQk3DnslvYrNcVuz02Pc64rBBL9nTjShwOEXumiK
RsoUT22CCjgKybwJjXfCLbyrcjECjkK/Yr4rvWFwui8aQn7+ajBoYVH7YMs6HrWM
J106IMcYk7m0IYAAm3a2dZd8EQKBgQDIEkS7Zg3nby5JnEUck3gIxXh2GJlpi9fp
KjoL9cQoSb2mSygS2NY8Y+MrXKwgt8Mqyd0eaOX/dczsrkEwrxEA6F45/aW/C3iz
BBiP2F3lq3/Cjg0mx3i1bsPWyv64uFs90EK9tRQdPzFhgxs/TXh5tef8erCRv2wR
/pH+4dZXawKBgGEYoxlyB6ZPHFoE19swo6dwuKIo+zu0MpBLYT/oYJM0sPDnMHt0
G7WXHennZv+FEAvFihIt4hk55GZfyrHoSRFuj1cMHSjMFlw/EJXrRiRxTpLLk4JO
bFm/iTiTDAHh6so8VLto7qnWGXqlrzox5yPs1UXgACJvwyd5th51J1uhAoGACR5k
CZKGMbUsi+hWcg36m5O8gM1wOJJKHfNxv9fMv/VUcn7cbbd6VDhNQ02u/rLBb3LR
5C/tw63v0B3FFN31zW/J06TO6B0yvB4ErJG0/eHKKejlio3u334T6PdJksu8RN34
HMNjDk4yBvq9xC3YvttennBNGed6mnta1h4e8c8CgYBC6XARTavQJMraSlsOQTao
HbIAwJ9GHRmCDguZ6whrqRrdl6p/FQREAxiBUFQtusNfvx6UG7Yvu77FF9UfTC8s
r47SylD28QklkagEgpf8wl0yNrcTr9dBasFGYV1xiC7tuCND0fR6LeuoMSreq6uB
yBmB6zxGbMUOJqnBXVciUg==
-----END PRIVATE KEY-----
"#;

    /// The certificate matching [`IDP_KEY_PEM`], as the bare base64 metadata carries.
    const IDP_CERT_B64: &str = "MIIC6TCCAdOgAwIBAgIBATALBgkqhkiG9w0BAQswODELMAkGA1UEBhMCQ04xDzANBgNVBAoMBk1vbmFjYTEYMBYGA1UEAwwPTW9uYWNhIFRlc3QgSWRQMCIYDzIwMjYxMTA2MDk1MTEwWhgPMjA0NjExMDEwOTUxMTBaMDgxCzAJBgNVBAYTAkNOMQ8wDQYDVQQKDAZNb25hY2ExGDAWBgNVBAMMD01vbmFjYSBUZXN0IElkUDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMHTWirLVrxweZFfdnSb1Fq1ECY586Nn3sNq/V030lMyEjF4nopoKhjNNm0ueaANJRKxunOHYa2hiNrprDtHGYBx/mV3BEwjk2SwNJIZ+7OwWZz7frNTenPcECgE3p0QnnE/pTtw+VDBTT2blDnAh4E5bxbJGllc/ltWfi84VC+jLd3DQ19vlgar+FVbTMcxJibmEUpq5Wwn50moulH25HNFIhjXm22smvlgvq/BPm/SI5mBDWMIDG6DAfXO2+1xjOu+dhpc1sfT0+vKL2+1ESt03mmkWGwFep9JUacBDqNj0ujroXH1Rm/+qZHDt2c+ctEFhUN9pIlaY6PKxEiwohsCAwEAATALBgkqhkiG9w0BAQsDggEBAGzL0pvJNEgAjIfg5XGlC4ZXDrpzWjkvKb5MylJ/FkfLg/mM3NBFjAYkslOxXnA3OjFxDYabtRgV1hguuHZZBmBlylnGTh2R/k0Jj5CJ/xqdH7Z1CECvOCNk8mYUe4Z/nRIdEi1In4pD2QgHMFDWBU8i65VbcWZPLfxS8WkaUohmiGHlLYnwJybwQuGB90bfWLT8OqHNLysEpmuv6Gp8wQ3AQEm4Ams3fx4ib5MihhDi9OXPU+jsxOkf96QIA9r8uVA38FNIRKIDAEYQyaNVCPp4IWKk5I8/TbRUoeTyvgHhntisXL4FZi2Dy6nUq1QqZExCUaIGdf1S7jep+C12NWU=";

    fn certificate_pem() -> String {
        format!("-----BEGIN CERTIFICATE-----\n{IDP_CERT_B64}\n-----END CERTIFICATE-----\n")
    }

    fn idp_metadata() -> String {
        format!(
            r#"<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{IDP_CERT_B64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/slo"/><SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/slo"/></IDPSSODescriptor></EntityDescriptor>"#
        )
    }

    #[test]
    fn a_response_with_one_direct_assertion_is_accepted_by_the_scan() {
        let scan = scan_xml(RESPONSE).expect("a plain response");
        assert_eq!(scan.in_response_to.as_deref(), Some("_req1"));
    }

    #[test]
    fn an_unsolicited_response_is_visible_to_the_scan() {
        let scan = scan_xml(&RESPONSE.replace(r#" InResponseTo="_req1""#, "")).expect("a response");
        assert_eq!(scan.in_response_to, None);
    }

    #[test]
    fn two_assertions_are_rejected() {
        let xml = RESPONSE.replace("</samlp:Response>", "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a2\"/></samlp:Response>");
        assert!(scan_xml(&xml).is_err());
    }

    #[test]
    fn an_assertion_outside_the_response_is_rejected() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:Extensions><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"/></samlp:Extensions></samlp:Response>"#;
        assert!(scan_xml(xml).is_err());
    }

    #[test]
    fn an_encrypted_assertion_is_rejected() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/></samlp:Response>"#;
        assert!(scan_xml(xml).is_err());
    }

    #[test]
    fn a_doctype_is_rejected() {
        let xml = r#"<!DOCTYPE Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1"/></samlp:Response>"#;
        assert!(scan_xml(xml).is_err());
    }

    /// The SP policy must accept the shape a compliant IdP actually sends: a signed Assertion
    /// inside an unsigned Response, with the request's ID echoed in `InResponseTo`.
    #[test]
    fn a_signed_assertion_from_a_compliant_idp_completes_the_flow() {
        use risaml::{
            NameId, RespondSso, SpDescriptor, SsoEndpoint,
            config::{CertificatePem, Credentials, IdpConfig, IdpValidationPolicy, PrivateKeyPem},
        };

        let sp = sp_facade(
            "https://sp.example.com/t/acme/sso/okta/metadata",
            "https://sp.example.com/t/acme/sso/okta/acs",
            "https://sp.example.com/t/acme/sso/okta/slo",
        )
        .expect("the SP configuration");
        let sp_descriptor = SpDescriptor::from_metadata_xml_for(
            EntityId::try_new("https://sp.example.com/t/acme/sso/okta/metadata")
                .expect("entity id"),
            sp.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )
        .expect("the SP metadata the IdP reads");
        let idp = IdpDescriptor::from_metadata_xml_for(
            EntityId::try_new("https://idp.example.com/metadata").expect("entity id"),
            &idp_metadata(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )
        .expect("the IdP metadata");
        let idp_facade = Saml::idp(
            IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata").expect("id"))
                .sso_endpoint(SsoEndpoint::redirect("https://idp.example.com/sso").expect("sso"))
                .credentials(Credentials {
                    signing_key: Some(PrivateKeyPem::new(IDP_KEY_PEM)),
                    signing_certificate: Some(CertificatePem::new(certificate_pem())),
                    ..Credentials::default()
                })
                .validation(IdpValidationPolicy::compatibility())
                .build()
                .expect("the IdP configuration"),
        )
        .expect("the IdP facade");

        let started = sp
            .start_sso(
                &idp,
                StartSso::redirect().relay_state(
                    RelayStateParam::try_from_option(Some("state-1".to_owned())).expect("relay"),
                ),
            )
            .expect("the AuthnRequest");
        let url = started
            .outbound
            .redirect_url()
            .expect("redirect")
            .to_owned();
        let query = url
            .split_once('?')
            .map(|(_, query)| query.to_owned())
            .expect("a query string");
        let received = idp_facade
            .receive_sso(
                &sp_descriptor,
                BrowserInput::<AuthnRequest>::redirect(query),
                SamlValidationContext::new(
                    SystemTime::now(),
                    ReplayPolicy::DisabledForCompatibility,
                ),
            )
            .expect("the IdP accepts the AuthnRequest");
        let outbound = idp_facade
            .respond_sso(
                &sp_descriptor,
                &received,
                risaml::Subject::new(NameId::new("user@corp.example", None), Vec::new()),
                RespondSso::post(),
            )
            .expect("the signed response");
        let fields = outbound
            .post_form()
            .expect("the POST form")
            .fields()
            .to_vec();
        let xml_field = fields
            .iter()
            .find(|field| field.name() == "SAMLResponse")
            .expect("the SAMLResponse field")
            .value()
            .to_owned();
        let xml = String::from_utf8(
            BASE64
                .decode(xml_field.as_bytes())
                .expect("base64-encoded XML"),
        )
        .expect("utf-8 XML");
        scan_xml(&xml).expect("our pre-scan accepts the signed response");

        let mut replay = CallerOwnedReplay;
        let validation =
            SamlValidationContext::new(SystemTime::now(), ReplayPolicy::RequireCache(&mut replay))
                .with_clock_skew(ClockSkew::from_millis(
                    -SAML_CLOCK_SKEW_MS,
                    SAML_CLOCK_SKEW_MS,
                ));
        let session = sp
            .finish_sso(
                &idp,
                &started.pending,
                BrowserInput::<SsoResponse>::post(fields),
                validation,
            )
            .expect("the SP accepts the signed assertion");
        assert_eq!(
            session.in_response_to().map(|id| id.as_str()),
            Some(started.pending.request_id().as_str())
        );
        assert!(
            session.not_on_or_after().is_some(),
            "the assertion must carry an upper bound we can record as spent"
        );
        assert!(
            session
                .audience()
                .iter()
                .any(|audience| audience.as_str() == sp_descriptor.entity_id().as_str())
        );
        assert!(!session.assertion_id().as_str().is_empty());
    }

    const SP_METADATA: &str = "https://sp.example.com/t/acme/sso/okta/metadata";
    const SP_ACS: &str = "https://sp.example.com/t/acme/sso/okta/acs";
    const SP_SLO: &str = "https://sp.example.com/t/acme/sso/okta/slo";

    fn test_sp() -> Saml<Sp> {
        sp_facade(SP_METADATA, SP_ACS, SP_SLO).expect("the SP configuration")
    }

    fn test_idp_descriptor() -> IdpDescriptor {
        IdpDescriptor::from_metadata_xml_for(
            EntityId::try_new("https://idp.example.com/metadata").expect("entity id"),
            &idp_metadata(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )
        .expect("the IdP metadata")
    }

    fn test_sp_descriptor(sp: &Saml<Sp>) -> risaml::SpDescriptor {
        risaml::SpDescriptor::from_metadata_xml_for(
            EntityId::try_new(SP_METADATA).expect("entity id"),
            sp.metadata_xml(),
            MetadataTrustPolicy::UnsignedForCompatibility,
        )
        .expect("the SP metadata the IdP reads")
    }

    fn test_idp_facade() -> Saml<risaml::Idp> {
        use risaml::config::{
            CertificatePem, Credentials, IdpConfig, IdpValidationPolicy, PrivateKeyPem,
        };

        Saml::idp(
            IdpConfig::builder(EntityId::try_new("https://idp.example.com/metadata").expect("id"))
                .sso_endpoint(
                    risaml::SsoEndpoint::redirect("https://idp.example.com/sso").expect("sso"),
                )
                .slo_endpoint(
                    risaml::SloEndpoint::redirect("https://idp.example.com/slo").expect("slo"),
                )
                .credentials(Credentials {
                    signing_key: Some(PrivateKeyPem::new(IDP_KEY_PEM)),
                    signing_certificate: Some(CertificatePem::new(certificate_pem())),
                    ..Credentials::default()
                })
                .validation(IdpValidationPolicy::compatibility())
                .build()
                .expect("the IdP configuration"),
        )
        .expect("the IdP facade")
    }

    fn slo_validation() -> SamlValidationContext<'static> {
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility)
            .with_clock_skew(ClockSkew::from_millis(
                -SAML_CLOCK_SKEW_MS,
                SAML_CLOCK_SKEW_MS,
            ))
    }

    #[test]
    fn a_plain_logout_request_passes_the_scan() {
        let xml = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_l1" Version="2.0" IssueInstant="2026-11-06T00:00:00Z"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/metadata</saml:Issuer><saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">user@corp.example</saml:NameID><samlp:SessionIndex>_s1</samlp:SessionIndex></samlp:LogoutRequest>"#;
        assert!(scan_logout_request(xml).is_ok());
    }

    #[test]
    fn a_logout_doctype_is_rejected() {
        let xml = r#"<!DOCTYPE LogoutRequest [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_l1">&xxe;</samlp:LogoutRequest>"#;
        assert!(scan_logout_request(xml).is_err());
    }

    #[test]
    fn a_nested_logout_request_is_rejected() {
        let xml = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_l1"><samlp:Extensions><samlp:LogoutRequest ID="_l2"/></samlp:Extensions></samlp:LogoutRequest>"#;
        assert!(scan_logout_request(xml).is_err());
    }

    #[test]
    fn a_signature_below_the_root_is_rejected() {
        let xml = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_l1"><samlp:Extensions><ds:Signature/></samlp:Extensions></samlp:LogoutRequest>"#;
        assert!(scan_logout_request(xml).is_err());
    }

    #[test]
    fn a_message_that_is_not_a_logout_request_is_rejected() {
        assert!(scan_logout_request(RESPONSE).is_err());
    }

    #[test]
    fn a_logout_request_that_names_nothing_matches_no_session() {
        let index = SessionIndex::try_new("_s1").expect("index");
        assert!(
            !logout_can_match(None, &[]),
            "naming neither NameID nor SessionIndex must never mean every session"
        );
        assert!(logout_can_match(Some("user@corp.example"), &[]));
        assert!(logout_can_match(None, &[index]));
    }

    #[test]
    fn the_logout_issue_instant_window_is_two_minutes() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("ts");
        assert!(logout_issue_instant_acceptable(now, now));
        assert!(logout_issue_instant_acceptable(
            now - time::Duration::minutes(2),
            now
        ));
        assert!(!logout_issue_instant_acceptable(
            now - time::Duration::minutes(2) - time::Duration::seconds(1),
            now
        ));
        assert!(logout_issue_instant_acceptable(
            now + time::Duration::minutes(2),
            now
        ));
        assert!(!logout_issue_instant_acceptable(
            now + time::Duration::minutes(2) + time::Duration::seconds(1),
            now
        ));
    }

    /// A signed request from a compliant IdP is accepted, and the answer is a Success
    /// LogoutResponse correlated to the request — unsigned, because this SP has no key.
    #[test]
    fn a_signed_logout_request_is_received_and_answered_with_success() {
        use risaml::{LogoutSigning, StartSlo};

        let sp = test_sp();
        let idp = test_idp_descriptor();
        let sp_descriptor = test_sp_descriptor(&sp);
        let idp_facade = test_idp_facade();
        let subject = risaml::LogoutSubject::with_session_index(
            NameId::new("user@corp.example", None),
            SessionIndex::try_new("_s1").expect("index"),
        );
        let started = idp_facade
            .start_slo(
                &sp_descriptor,
                subject,
                StartSlo::redirect().signing(LogoutSigning::Sign),
            )
            .expect("the signed LogoutRequest");
        let url = started
            .outbound
            .redirect_url()
            .expect("redirect")
            .to_owned();
        let query = url
            .split_once('?')
            .map(|(_, query)| query.to_owned())
            .expect("a query string");

        let received = sp
            .receive_slo(
                &idp,
                BrowserInput::<LogoutRequest>::redirect(query),
                slo_validation(),
            )
            .expect("the SP accepts the signed LogoutRequest");
        assert_eq!(
            received.message().name_id().map(NameId::value),
            Some("user@corp.example")
        );
        assert_eq!(
            received
                .message()
                .session_indexes()
                .iter()
                .map(SessionIndex::as_str)
                .collect::<Vec<_>>(),
            vec!["_s1"]
        );

        let context = logout_response_context(
            &sp,
            &idp,
            received.message(),
            received.relay_state(),
            Binding::Post,
        )
        .expect("the LogoutResponse renders");
        let xml = String::from_utf8(
            BASE64
                .decode(context.context.as_bytes())
                .expect("base64-encoded XML"),
        )
        .expect("utf-8 XML");
        assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:status:Success"));
        assert!(xml.contains(&format!(
            "InResponseTo=\"{}\"",
            received.message().id().as_str()
        )));

        // The Redirect answer is what the HTTP handler returns when the IdP declares it.
        let redirect_context = logout_response_context(
            &sp,
            &idp,
            received.message(),
            received.relay_state(),
            Binding::Redirect,
        )
        .expect("the Redirect LogoutResponse renders");
        assert!(
            Outbound::<LogoutResponse>::try_from(redirect_context)
                .expect("the Redirect action")
                .redirect_url()
                .expect("a redirect URL")
                .contains("SAMLResponse=")
        );
    }

    /// A request whose bytes no longer match the detached signature must be refused.
    #[test]
    fn a_tampered_logout_request_signature_is_refused() {
        use risaml::{LogoutSigning, StartSlo};

        let sp = test_sp();
        let idp = test_idp_descriptor();
        let sp_descriptor = test_sp_descriptor(&sp);
        let idp_facade = test_idp_facade();
        let subject = risaml::LogoutSubject::with_session_index(
            NameId::new("user@corp.example", None),
            SessionIndex::try_new("_s1").expect("index"),
        );
        let started = idp_facade
            .start_slo(
                &sp_descriptor,
                subject,
                StartSlo::post().signing(LogoutSigning::Sign),
            )
            .expect("the signed LogoutRequest");
        let fields = started
            .outbound
            .post_form()
            .expect("the POST form")
            .fields()
            .to_vec();
        let original = fields
            .iter()
            .find(|field| field.name() == "SAMLRequest")
            .expect("the SAMLRequest field")
            .value()
            .to_owned();
        let mut tampered = original.clone();
        let index = tampered.len() / 2;
        let replacement = if &tampered[index..index + 1] == "A" {
            "B"
        } else {
            "A"
        };
        tampered.replace_range(index..index + 1, replacement);
        assert_ne!(tampered, original);

        assert!(
            sp.receive_slo(
                &idp,
                BrowserInput::<LogoutRequest>::post(vec![FormField::new(
                    "SAMLRequest",
                    tampered.as_str(),
                )]),
                slo_validation(),
            )
            .is_err(),
            "a signature that no longer covers the bytes must be refused"
        );
    }
}
