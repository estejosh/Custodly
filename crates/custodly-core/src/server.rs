//! The HTTP side of `policy()` (`docs/BOUNDARY.md`): the one route
//! Ferryman calls into Custodly. `custodly-cli`'s `serve` subcommand binds
//! this and runs it; kept here, not there, so it can be exercised in
//! tests with `tower::ServiceExt::oneshot` the way `ferryman-server`
//! already tests its own routes, rather than only over a real socket.
//!
//! House rule from `START-HERE.md` still applies: this is not the CLI end
//! users are told never to touch. It is infrastructure a Ferryman
//! deployment calls, not a flow a person runs commands through.

use axum::{
    Json, Router,
    extract::Query,
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::policy;

#[derive(Debug, Deserialize)]
struct PolicyQuery {
    provider: String,
    scope: String,
}

async fn policy_handler(Query(query): Query<PolicyQuery>) -> Json<Value> {
    let response = policy::evaluate(&query.provider, &query.scope);
    Json(json!({
        "tier": response.tier,
        "requires": response.requires,
        "contract_version": crate::CONTRACT_VERSION,
    }))
}

async fn health() -> Json<Value> {
    Json(json!({"status": "ok", "contract_version": crate::CONTRACT_VERSION}))
}

/// Build the router. No state: `policy()` is a pure function of its query
/// string, so there is nothing to share across requests yet.
#[must_use]
pub fn app() -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/boundary/policy", get(policy_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn policy_route_scores_a_known_provider_and_scope() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/v1/boundary/policy?provider=github&scope=repo:read")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_success());
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["tier"], 0);
        assert_eq!(body["requires"], serde_json::json!([]));
        assert_eq!(body["contract_version"], crate::CONTRACT_VERSION);
    }

    #[tokio::test]
    async fn policy_route_fails_closed_for_an_unknown_provider() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/v1/boundary/policy?provider=stripe&scope=charges:read")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response.status().is_success());
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["tier"], 2);
    }

    #[tokio::test]
    async fn healthz_reports_ok() {
        let response = app()
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(response.status().is_success());
    }
}
