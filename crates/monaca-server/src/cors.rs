//! Per-application CORS for the protocol endpoints — `docs/contracts/m0.md` §6.1, §6.2.
//!
//! A browser application starts a flow from its own origin, so the browser needs the tenant's
//! protocol responses to be readable there. Which origins are readable is configured on each
//! application, but a preflight carries no `client_id`: the only set the server can decide from is
//! the union of every application's `cors_allowed_origins` in the tenant. That union is the gate
//! this middleware applies to `/t/{tenant}/…` and the tenant discovery document.
//!
//! A static `CorsLayer` cannot express this: the list is per tenant, mutable at runtime, and read
//! from PostgreSQL. The middleware therefore answers the preflight itself (the router has no
//! `OPTIONS` route), and decorates ordinary responses after the handler ran. Unregistered origins
//! are left without the headers — the browser blocks the read — rather than failing the request,
//! which is what the CORS protocol expects. `/v1` and `/internal` are deliberately out of scope:
//! the console reaches them same-origin through the gateway.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::clients::normalise_origin;
use crate::state::AppState;

/// The protocol surface uses `GET` for authorize/userinfo/JWKS and `POST` for everything else.
const ALLOW_METHODS: &str = "GET, POST, OPTIONS";
/// What a request may carry when the browser did not name the headers it intends to send.
const ALLOW_HEADERS: &str = "authorization, content-type, dpop";
/// How long a browser may cache one preflight answer.
const MAX_AGE: &str = "600";

/// The tenant CORS middleware; see the module comment for the rules.
pub async fn tenant_cors(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .and_then(normalise_origin);
    let slug = tenant_slug(request.uri().path());
    let (Some(origin), Some(slug)) = (origin, slug) else {
        return next.run(request).await;
    };

    let allowed = match state.tenant(slug).await {
        Ok(tenant) => match state.store.tenant_cors_origins(&tenant).await {
            Ok(origins) => origins.iter().any(|registered| registered == &origin),
            Err(err) => {
                tracing::warn!(%err, "could not read the tenant's CORS origins");
                false
            }
        },
        // The route below reports the missing tenant; CORS has nothing to add here.
        Err(_) => false,
    };

    let preflight = is_preflight(&request);
    if !allowed {
        let mut response = if preflight {
            StatusCode::NO_CONTENT.into_response()
        } else {
            next.run(request).await
        };
        // Even a refusal varies by origin: a shared cache must not hand this response to another
        // origin that *is* registered.
        response
            .headers_mut()
            .append(header::VARY, HeaderValue::from_static("Origin"));
        return response;
    }

    if preflight {
        let mut response = StatusCode::NO_CONTENT.into_response();
        let requested = request
            .headers()
            .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static(ALLOW_HEADERS));
        let allow_origin = HeaderValue::from_str(&origin).expect("a normalized origin is ASCII");
        let headers = response.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin);
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static(ALLOW_METHODS),
        );
        headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, requested);
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static(MAX_AGE),
        );
        headers.append(header::VARY, HeaderValue::from_static("Origin"));
        headers.append(
            header::VARY,
            HeaderValue::from_static("Access-Control-Request-Headers"),
        );
        return response;
    }

    let mut response = next.run(request).await;
    let allow_origin = HeaderValue::from_str(&origin).expect("a normalized origin is ASCII");
    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin);
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    headers.append(header::VARY, HeaderValue::from_static("Origin"));
    response
}

/// A CORS preflight: `OPTIONS` plus the method the browser wants to send.
fn is_preflight(request: &Request) -> bool {
    request.method() == Method::OPTIONS
        && request
            .headers()
            .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
}

/// The tenant a protocol path addresses, or `None` for every other audience.
fn tenant_slug(path: &str) -> Option<&str> {
    if let Some(rest) = path.strip_prefix("/t/") {
        return rest.split('/').next().filter(|slug| !slug.is_empty());
    }
    path.strip_prefix("/.well-known/oauth-authorization-server/t/")
        .filter(|slug| !slug.is_empty() && !slug.contains('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_protocol_paths_name_a_tenant() {
        assert_eq!(tenant_slug("/t/demo/oauth2/token"), Some("demo"));
        assert_eq!(tenant_slug("/t/demo"), Some("demo"));
        assert_eq!(
            tenant_slug("/.well-known/oauth-authorization-server/t/demo"),
            Some("demo")
        );
        assert_eq!(tenant_slug("/t/"), None);
        assert_eq!(tenant_slug("/v1/clients"), None);
        assert_eq!(tenant_slug("/internal/mail"), None);
        assert_eq!(tenant_slug("/healthz"), None);
        assert_eq!(
            tenant_slug("/.well-known/oauth-authorization-server/t/demo/extra"),
            None
        );
    }

    #[test]
    fn a_preflight_is_options_with_a_requested_method() {
        let preflight = Request::builder()
            .method(Method::OPTIONS)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .body(axum::body::Body::empty())
            .expect("request");
        assert!(is_preflight(&preflight));

        let plain_options = Request::builder()
            .method(Method::OPTIONS)
            .body(axum::body::Body::empty())
            .expect("request");
        assert!(!is_preflight(&plain_options));

        let get = Request::builder()
            .method(Method::GET)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .body(axum::body::Body::empty())
            .expect("request");
        assert!(!is_preflight(&get));
    }
}
