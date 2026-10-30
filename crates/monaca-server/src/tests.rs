//! Router tests — `docs/contracts/m0.md` §12 step 1.
//!
//! These drive a state-free router through `tower::ServiceExt::oneshot`, so no socket is bound and
//! no database is required. The protocol and management handlers need PostgreSQL and are covered
//! by `scripts/e2e/skeleton.ts` against a running server; what belongs here is the surface that
//! must answer before any dependency is reachable.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use tower::ServiceExt as _;

/// The two endpoints that need no state.
fn app() -> Router {
    Router::new()
        .route("/healthz", get(crate::routes::healthz))
        .route("/version", get(crate::routes::version))
}

/// Read a response body as JSON.
async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("the body is readable");
    serde_json::from_slice(&bytes).expect("the body is JSON")
}

/// `GET /healthz` answers `200 {"status":"ok"}` — §6.1 and §12 step 1.
#[tokio::test]
async fn healthz_answers_ok() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("the router responds");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await,
        serde_json::json!({"status": "ok"})
    );
}

/// The gateway's `/healthz` adds a `service` member; the server's does not — §6.1 vs §9.
#[tokio::test]
async fn healthz_does_not_name_a_service() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("the router responds");

    let body = json_body(response).await;
    assert!(
        body.get("service").is_none(),
        "the server's healthz has no `service` member"
    );
    assert_eq!(
        body.as_object().expect("an object").len(),
        1,
        "only `status` is present"
    );
}

#[tokio::test]
async fn version_reports_the_binary() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/version")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("the router responds");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["name"], "monaca-server");
    assert!(body["version"].as_str().expect("version").contains('.'));
}

/// An unrouted path is a 404, not a panic or a 500.
#[tokio::test]
async fn an_unknown_path_is_not_found() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/nope")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("the router responds");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// The OpenAPI document describes both stage-0 endpoints — §10.1's codegen contract.
#[test]
fn the_openapi_document_covers_the_stage_0_routes() {
    let document = crate::routes::openapi_document();
    let json = document.to_json().expect("the document serializes");
    let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    let paths = value["paths"].as_object().expect("paths is an object");
    assert!(
        paths.contains_key("/healthz"),
        "the document must describe /healthz"
    );
    assert!(
        paths.contains_key("/version"),
        "the document must describe /version"
    );
    assert!(
        paths["/healthz"].get("get").is_some(),
        "/healthz must be a GET"
    );
    assert!(
        paths["/version"].get("get").is_some(),
        "/version must be a GET"
    );
}

/// The generated document is valid OpenAPI 3.x and names the service.
#[test]
fn the_openapi_document_has_the_expected_envelope() {
    let document = crate::routes::openapi_document();
    let value: serde_json::Value =
        serde_json::from_str(&document.to_json().expect("serializes")).expect("valid JSON");

    assert!(
        value["openapi"].as_str().expect("openapi").starts_with('3'),
        "expected an OpenAPI 3.x document, got {}",
        value["openapi"]
    );
    assert_eq!(value["info"]["title"], "Monaca");
    assert_eq!(value["info"]["version"], env!("CARGO_PKG_VERSION"));
}

/// Both documented responses carry a schema, so the SDK generator has something to emit.
#[test]
fn the_documented_responses_have_schemas() {
    let document = crate::routes::openapi_document();
    let value: serde_json::Value =
        serde_json::from_str(&document.to_json().expect("serializes")).expect("valid JSON");

    for path in ["/healthz", "/version"] {
        let content = &value["paths"][path]["get"]["responses"]["200"]["content"];
        let media = content
            .as_object()
            .unwrap_or_else(|| panic!("{path} 200 must have content"));
        assert!(
            media.contains_key("application/json"),
            "{path} 200 must be application/json"
        );
    }
}
