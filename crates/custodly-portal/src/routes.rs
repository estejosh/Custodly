//! The whole owner-facing surface: two pending-request kinds, rendered
//! as plain server-side HTML (no JS, no build step -- an owner on a
//! phone browser needs a page that just works). See
//! `custodly-owner-portal.md` for the design this implements.

use std::sync::Arc;

use axum::{
    Router,
    extract::{Form, Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use chrono::Utc;
use custodly_core::{AcquisitionSource, EntryMetadata, Tier};
use custodly_vault::Vault;
use serde::Deserialize;

use crate::code::verify_code;
use crate::models::{PendingKind, PendingStatus};
#[allow(unused_imports)]
use crate::models::PendingRequest;
use crate::oauth::{OAuthError, SlackOAuth, lookup};
use crate::store::PendingStore;

pub struct AppState {
    pub store: PendingStore,
    pub vault: Vault,
    pub slack: Option<SlackOAuth>,
    /// This portal's own externally-reachable base URL, e.g.
    /// `https://portal.example.com` -- used to build the OAuth
    /// `redirect_uri`, which must match what's registered with the
    /// provider.
    pub base_url: String,
    /// Tailscale login allowed to see the home-page list of pending
    /// requests. Tailscale Serve sets `Tailscale-User-Login` on tailnet
    /// traffic only; the portal itself listens on localhost only.
    pub admin_login: Option<String>,
    /// Phones that have asked to send keys (`custodly-intake`). None = the
    /// phone feature is not configured on this portal.
    pub devices: Option<custodly_intake::DeviceRegistry>,
    /// The intake key fingerprint the owner compares with the phone.
    pub intake_fingerprint: Option<String>,
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title} — Custodly</title>\
         <style>body{{font-family:system-ui,sans-serif;max-width:480px;margin:2rem auto;padding:0 1rem;line-height:1.5}}\
         button,input{{font-size:1rem;padding:.6rem;width:100%;margin-top:.5rem}}\
         .muted{{color:#666;font-size:.9rem}}</style></head><body>{body}</body></html>"
    ))
}

async fn render_pending(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let request = match state.store.get(&id) {
        Ok(r) => r,
        Err(_) => return page("Not found", "<p>No pending request here. The link may be wrong or already used.</p>").into_response(),
    };

    if request.status != PendingStatus::Pending {
        let what = match request.status {
            PendingStatus::Fulfilled => "already completed",
            PendingStatus::Denied => "already denied",
            PendingStatus::Pending => unreachable!(),
        };
        return page("Already handled", &format!("<p>This request was {what}.</p>")).into_response();
    }
    if request.is_expired(Utc::now()) {
        return page("Expired", "<p>This request expired before it was acted on. Ask for a new one.</p>").into_response();
    }

    match &request.kind {
        PendingKind::Authorize { provider, resource, scopes } => page(
            "Authorize",
            &format!(
                "<h1>Authorize {p}</h1>\
                 <p>Custodly wants to acquire a credential for <b>{proj}</b> \
                 ({res}), scoped to: <code>{scopes}</code>.</p>\
                 <p class=\"muted\">You'll be taken to {p}'s own sign-in and consent screen. \
                 Custodly never sees your {p} password.</p>\
                 <form method=\"get\" action=\"/pending/{id}/oauth-start\">\
                 <button type=\"submit\">Continue to {p}</button></form>",
                p = escape_html(provider),
                proj = escape_html(&request.project),
                res = escape_html(resource),
                scopes = escape_html(&scopes.join(", ")),
                id = id,
            ),
        )
        .into_response(),
        PendingKind::Approve { provider, resource, requested_scope, current_scope, tier, .. } => page(
            "Approve request",
            &format!(
                "<h1>Approve — {p}</h1>\
                 <p><b>{proj}</b> / {res}<br>\
                 Requested: <code>{req}</code><br>\
                 Current: <code>{cur}</code><br>\
                 Tier: {tier}</p>\
                 <form method=\"post\" action=\"/pending/{id}/approve\">\
                 <label>Approval code (from your notification)</label>\
                 <input type=\"text\" name=\"code\" autocomplete=\"off\" required>\
                 <button type=\"submit\">Approve</button></form>\
                 <form method=\"post\" action=\"/pending/{id}/deny\">\
                 <button type=\"submit\">Deny</button></form>",
                p = escape_html(provider),
                proj = escape_html(&request.project),
                res = escape_html(resource),
                req = escape_html(requested_scope),
                cur = current_scope.as_deref().map(escape_html).unwrap_or_else(|| "none on record".to_string()),
                tier = tier,
                id = id,
            ),
        )
        .into_response(),
    }
}

async fn oauth_start(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let request = match state.store.get(&id) {
        Ok(r) => r,
        Err(_) => return page("Not found", "<p>No pending request here.</p>").into_response(),
    };
    let PendingKind::Authorize { provider, .. } = &request.kind else {
        return page("Wrong kind", "<p>This request isn't an authorize request.</p>").into_response();
    };
    if request.status != PendingStatus::Pending || request.is_expired(Utc::now()) {
        return page("Not available", "<p>This request is no longer pending.</p>").into_response();
    }
    let Some(provider_impl) = lookup(provider, state.slack.as_ref()) else {
        return page("Unsupported", &format!("<p>No confirmed OAuth flow for {} yet.</p>", escape_html(provider))).into_response();
    };
    let redirect_uri = format!("{}/oauth/callback/{provider}", state.base_url);
    Redirect::to(&provider_impl.authorize_url(&id, &redirect_uri)).into_response()
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn oauth_callback(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    if let Some(err) = query.error {
        return page("Authorization declined", &format!("<p>{} declined: {}</p>", escape_html(&provider), escape_html(&err)))
            .into_response();
    }
    let (Some(code), Some(id)) = (query.code, query.state) else {
        return page("Bad callback", "<p>Missing code or state.</p>").into_response();
    };

    let mut request = match state.store.get(&id) {
        Ok(r) => r,
        Err(_) => return page("Not found", "<p>No pending request matches this callback.</p>").into_response(),
    };
    let PendingKind::Authorize { provider: pending_provider, resource, scopes } = &request.kind else {
        return page("Wrong kind", "<p>This pending id isn't an authorize request.</p>").into_response();
    };
    if pending_provider != &provider {
        return page("Mismatch", "<p>Provider in the callback doesn't match the pending request.</p>").into_response();
    }
    if request.status != PendingStatus::Pending || request.is_expired(Utc::now()) {
        return page("Not available", "<p>This request is no longer pending.</p>").into_response();
    }

    let Some(provider_impl) = lookup(&provider, state.slack.as_ref()) else {
        return page("Unsupported", &format!("<p>No confirmed OAuth flow for {} yet.</p>", escape_html(&provider))).into_response();
    };
    let redirect_uri = format!("{}/oauth/callback/{provider}", state.base_url);

    let parent = match provider_impl.exchange(&code, &redirect_uri).await {
        Ok(p) => p,
        Err(e) => {
            let message = match &e {
                OAuthError::Unsupported(m) | OAuthError::Http(m) | OAuthError::Rejected(m) => m.clone(),
            };
            return page("Authorization failed", &format!("<p>Couldn't complete this: {}</p>", escape_html(&message))).into_response();
        }
    };

    let metadata = match EntryMetadata::for_owner(
        request.owner.clone(),
        provider.clone(),
        request.project.clone(),
        format!("Owner-authorized via portal, requested scopes: {}", scopes.join(", ")),
        AcquisitionSource::OwnerPortalOauth { provider: provider.clone() },
        Utc::now(),
        None,
        Tier::Tier1,
    ) {
        Ok(m) => m,
        Err(e) => return page("Internal error", &format!("<p>{e}</p>")).into_response(),
    };
    let label = provider.clone();
    let entry = custodly_core::VaultEntry::new(label, metadata, parent.secret.clone());
    let vault_result = {
        let vault = &state.vault;
        // `Vault::put` shells out synchronously (keepassxc-cli) -- fine
        // to block this one handler's worker thread briefly; not fine to
        // block the whole runtime, hence spawn_blocking isn't used here
        // since axum already runs handlers on a blocking-tolerant pool
        // per request. Kept simple rather than adding spawn_blocking
        // machinery for a call that finishes in well under a second.
        vault.put(&entry)
    };
    if let Err(e) = vault_result {
        return page("Storage failed", &format!("<p>Authorized, but couldn't store the credential: {e}. Nothing was lost -- ask for a new authorize link.</p>")).into_response();
    }

    request.status = PendingStatus::Fulfilled;
    let _ = state.store.put(&request);

    page(
        "Authorized",
        &format!(
            "<h1>Done</h1><p>{} is authorized for <b>{}</b> ({}). \
             The credential is in the vault -- you're finished here.</p>",
            escape_html(&provider),
            escape_html(&request.project),
            escape_html(resource),
        ),
    )
    .into_response()
}

#[derive(Debug, Deserialize)]
struct ApproveForm {
    code: String,
}

async fn approve(State(state): State<Arc<AppState>>, Path(id): Path<String>, Form(form): Form<ApproveForm>) -> Response {
    let mut request = match state.store.get(&id) {
        Ok(r) => r,
        Err(_) => return page("Not found", "<p>No pending request here.</p>").into_response(),
    };
    let PendingKind::Approve { code_hash, .. } = &request.kind else {
        return page("Wrong kind", "<p>This request isn't an approval request.</p>").into_response();
    };
    if request.status != PendingStatus::Pending || request.is_expired(Utc::now()) {
        return page("Not available", "<p>This request is no longer pending.</p>").into_response();
    }
    if !verify_code(&form.code, code_hash) {
        return page("Wrong code", "<p>That code doesn't match. Nothing was approved.</p>").into_response();
    }
    request.status = PendingStatus::Fulfilled;
    let _ = state.store.put(&request);
    // Continuing the actual mint after approval isn't wired up yet --
    // see custodly-owner-portal.md's "still open" section. This records
    // the decision; something still needs to poll/watch for it.
    page("Approved", "<p>Approved. The pending mint will proceed from here (continuation not yet wired up -- see the roadmap doc).</p>").into_response()
}

async fn deny(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let mut request = match state.store.get(&id) {
        Ok(r) => r,
        Err(_) => return page("Not found", "<p>No pending request here.</p>").into_response(),
    };
    if request.status != PendingStatus::Pending {
        return page("Not available", "<p>This request is no longer pending.</p>").into_response();
    }
    request.status = PendingStatus::Denied;
    let _ = state.store.put(&request);
    page("Denied", "<p>Denied. Nothing was approved.</p>").into_response()
}

fn kind_summary(kind: &PendingKind) -> String {
    match kind {
        PendingKind::Authorize { provider, resource, .. } => format!("Authorize {provider} for {resource}"),
        PendingKind::Approve { provider, resource, requested_scope, .. } => {
            format!("Approve {requested_scope} on {provider} for {resource}")
        }
    }
}

fn is_admin(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
    match (&state.admin_login, headers.get("tailscale-user-login").and_then(|v| v.to_str().ok())) {
        (Some(want), Some(got)) => want == got,
        _ => false,
    }
}

/// A browser tags cross-site requests; refuse those for anything that changes state.
fn same_site(headers: &axum::http::HeaderMap) -> bool {
    headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()).is_none_or(|v| v == "same-origin" || v == "none")
}

fn phones_section(state: &AppState) -> String {
    let Some(devices) = &state.devices else { return String::new() };
    let mut out = String::from("<h2>Phones</h2>");
    if let Some(fp) = &state.intake_fingerprint {
        out.push_str(&format!(
            "<p class=\"muted\">This computer's key fingerprint, which the phone also shows: <b>{}</b></p>",
            escape_html(fp)
        ));
    }
    let pending = devices.list_pending();
    for d in &pending {
        out.push_str(&format!(
            "<form method=\"post\" action=\"/devices/{id}/enroll\"><p><b>{name}</b> wants to send keys.<br>\
             <span class=\"muted\">Type the 6-digit code shown on the phone.</span></p>\
             <input name=\"code\" inputmode=\"numeric\" autocomplete=\"off\" placeholder=\"123 456\">\
             <button>Approve this phone</button></form>\
             <form method=\"post\" action=\"/devices/{id}/reject\"><button>Refuse</button></form>",
            id = escape_html(&d.device_id),
            name = escape_html(&d.name),
        ));
    }
    let enrolled = devices.list_enrolled();
    if pending.is_empty() && enrolled.is_empty() {
        out.push_str("<p class=\"muted\">No phones yet. Install the Custodly app and follow its steps.</p>");
    }
    if !enrolled.is_empty() {
        out.push_str("<p class=\"muted\">Approved: ");
        out.push_str(&enrolled.iter().map(|d| escape_html(&d.name)).collect::<Vec<_>>().join(", "));
        out.push_str("</p>");
    }
    out
}

#[derive(Deserialize)]
struct CodeForm {
    code: String,
}

async fn enroll_device(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<CodeForm>,
) -> Response {
    if !is_admin(&state, &headers) || !same_site(&headers) {
        return (axum::http::StatusCode::FORBIDDEN, page("Not allowed", "<p>Open this from your own device.</p>")).into_response();
    }
    let Some(devices) = &state.devices else { return Redirect::to("/").into_response() };
    match devices.enroll(&id, &form.code) {
        Ok(()) => Redirect::to("/").into_response(),
        Err(_) => page("That code did not match", "<p>The code must be the one shown on the phone.</p><p><a href=\"/\">Back</a></p>")
            .into_response(),
    }
}

async fn reject_device(State(state): State<Arc<AppState>>, headers: axum::http::HeaderMap, Path(id): Path<String>) -> Response {
    if !is_admin(&state, &headers) || !same_site(&headers) {
        return (axum::http::StatusCode::FORBIDDEN, page("Not allowed", "<p>Open this from your own device.</p>")).into_response();
    }
    if let Some(devices) = &state.devices {
        let _ = devices.reject(&id);
    }
    Redirect::to("/").into_response()
}

async fn home(State(state): State<Arc<AppState>>, headers: axum::http::HeaderMap) -> Html<String> {
    let is_admin = is_admin(&state, &headers);
    if !is_admin {
        return page("Custodly", "<h1>Custodly</h1><p class=\"muted\">Open the link you were sent to continue.</p>");
    }
    let now = Utc::now();
    let mut waiting = String::new();
    let mut recent = String::new();
    for r in state.store.list() {
        let item = format!("<li>{} <span class=\"muted\">({}, {})</span></li>", escape_html(&kind_summary(&r.kind)), escape_html(&r.project), r.created_at.format("%b %d %H:%M"));
        if r.status == PendingStatus::Pending && !r.is_expired(now) {
            waiting.push_str(&format!("<li><a href=\"/pending/{}\">{}</a> <span class=\"muted\">({}, {})</span></li>", escape_html(&r.id), escape_html(&kind_summary(&r.kind)), escape_html(&r.project), r.created_at.format("%b %d %H:%M")));
        } else if recent.matches("<li>").count() < 5 {
            recent.push_str(&item);
        }
    }
    let waiting = if waiting.is_empty() { "<p class=\"muted\">Nothing waiting for you.</p>".to_string() } else { format!("<ul>{waiting}</ul>") };
    let recent = if recent.is_empty() { String::new() } else { format!("<h2>Recent</h2><ul>{recent}</ul>") };
    page("Custodly", &format!("<h1>Waiting for you</h1>{waiting}{recent}{}", phones_section(&state)))
}

async fn health() -> &'static str {
    "ok"
}

pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/devices/{id}/enroll", post(enroll_device))
        .route("/devices/{id}/reject", post(reject_device))
        .route("/healthz", get(health))
        .route("/pending/{id}", get(render_pending))
        .route("/pending/{id}/oauth-start", get(oauth_start))
        .route("/pending/{id}/approve", post(approve))
        .route("/pending/{id}/deny", post(deny))
        .route("/oauth/callback/{provider}", get(oauth_callback))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::Duration;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use crate::code::generate_approval_code;

    fn test_state(dir: std::path::PathBuf) -> Arc<AppState> {
        Arc::new(AppState {
            store: PendingStore::new(&dir).unwrap(),
            vault: Vault::new("/does/not/exist", dir.join("test.kdbx"), "custodly-portal-test"),
            slack: Some(SlackOAuth::new("cid", "csecret", vec!["chat:write".into()], reqwest::Client::new())),
            base_url: "https://portal.example".to_string(),
            admin_login: Some("josh@test".to_string()),
            devices: None,
            intake_fingerprint: None,
        })
    }

    fn tmp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("custodly-portal-routes-test-{}", crate::code::generate_id()))
    }

    #[tokio::test]
    async fn an_unknown_pending_id_renders_not_found_not_a_500() {
        let state = test_state(tmp_dir());
        let app = app(state);
        let resp = app
            .oneshot(Request::builder().uri("/pending/does-not-exist").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(body.contains("No pending request"));
    }

    #[tokio::test]
    async fn home_lists_pending_requests_only_for_the_admin_tailscale_login() {
        let dir = tmp_dir();
        let state = test_state(dir.clone());
        let req = PendingRequest {
            id: "req-home".into(),
            owner: "josh".into(),
            project: "custodly".into(),
            kind: PendingKind::Authorize { provider: "slack".into(), resource: "acme".into(), scopes: vec![] },
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(15),
            status: PendingStatus::Pending,
        };
        state.store.put(&req).unwrap();
        let body_of = |login: Option<&'static str>| {
            let app = app(state.clone());
            async move {
                let mut b = Request::builder().uri("/");
                if let Some(l) = login {
                    b = b.header("tailscale-user-login", l);
                }
                let resp = app.oneshot(b.body(Body::empty()).unwrap()).await.unwrap();
                String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
            }
        };
        assert!(!body_of(None).await.contains("req-home"));
        assert!(!body_of(Some("someone@else")).await.contains("req-home"));
        let admin = body_of(Some("josh@test")).await;
        assert!(admin.contains("/pending/req-home") && admin.contains("Authorize slack for acme"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_phone_is_enrolled_only_by_the_admin_with_the_code_shown_on_the_phone() {
        use custodly_intake::envelope::{device_code, device_id};
        use custodly_intake::{DeviceRegistry, DeviceStatus, EnrollFile};

        let dir = tmp_dir();
        let mut st = Arc::try_unwrap(test_state(dir.clone())).ok().unwrap();
        st.devices = Some(DeviceRegistry::new(dir.join("dev")).unwrap());
        st.intake_fingerprint = Some("aaaa-bbbb-cccc".into());
        let state = Arc::new(st);
        let key = [11_u8; 32];
        let public = ed25519_dalek::SigningKey::from_bytes(&key).verifying_key().to_bytes();
        let id = device_id(&public);
        state
            .devices
            .as_ref()
            .unwrap()
            .record_pending(&EnrollFile {
                v: "custodly-enroll/v1".into(),
                device_id: id.clone(),
                device_pub: hex::encode(public),
                name: "Pixel <b>".into(),
                created: "2026-10-08T00:00:00Z".into(),
            })
            .unwrap();
        let post = |login: Option<&'static str>, code: &str| {
            let app = app(state.clone());
            let mut b = Request::builder().method("POST").uri(format!("/devices/{id}/enroll"))
                .header("content-type", "application/x-www-form-urlencoded");
            if let Some(l) = login {
                b = b.header("tailscale-user-login", l);
            }
            let req = b.body(Body::from(format!("code={code}"))).unwrap();
            async move { app.oneshot(req).await.unwrap().status() }
        };
        let status = |s: &Arc<AppState>| s.devices.as_ref().unwrap().status(&id);

        assert_eq!(post(None, &device_code(&public)).await, StatusCode::FORBIDDEN);
        assert_eq!(post(Some("someone@else"), &device_code(&public)).await, StatusCode::FORBIDDEN);
        assert_eq!(status(&state), DeviceStatus::Pending);
        post(Some("josh@test"), "000000").await;
        assert_eq!(status(&state), DeviceStatus::Pending);
        assert_eq!(post(Some("josh@test"), &device_code(&public)).await, StatusCode::SEE_OTHER);
        assert_eq!(status(&state), DeviceStatus::Enrolled);

        // the page escapes the phone's name and shows the fingerprint
        let home = app(state.clone())
            .oneshot(Request::builder().uri("/").header("tailscale-user-login", "josh@test").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = String::from_utf8(home.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(body.contains("aaaa-bbbb-cccc"));
        assert!(body.contains("Pixel &lt;b&gt;") && !body.contains("<b>Pixel <b>"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn oauth_start_redirects_to_slacks_authorize_url_for_a_pending_authorize_request() {
        let dir = tmp_dir();
        let state = test_state(dir.clone());
        let req = PendingRequest {
            id: "req1".into(),
            owner: "josh".into(),
            project: "custodly".into(),
            kind: PendingKind::Authorize { provider: "slack".into(), resource: "acme".into(), scopes: vec!["chat:write".into()] },
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(15),
            status: PendingStatus::Pending,
        };
        state.store.put(&req).unwrap();
        let app = app(state);
        let resp = app
            .oneshot(Request::builder().uri("/pending/req1/oauth-start").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("https://slack.com/oauth/v2/authorize?"));
        assert!(location.contains("state=req1"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn approve_refuses_a_wrong_code_and_leaves_the_request_pending() {
        let dir = tmp_dir();
        let state = test_state(dir.clone());
        let (_, hash) = generate_approval_code();
        let req = PendingRequest {
            id: "req2".into(),
            owner: "josh".into(),
            project: "custodly".into(),
            kind: PendingKind::Approve {
                provider: "github".into(),
                resource: "estejosh/Custodly".into(),
                requested_scope: "admin:write".into(),
                current_scope: None,
                tier: 2,
                code_hash: hash,
            },
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(15),
            status: PendingStatus::Pending,
        };
        state.store.put(&req).unwrap();
        let app = app(state.clone());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pending/req2/approve")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("code=WRONGCOD"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let stored = state.store.get("req2").unwrap();
        assert_eq!(stored.status, PendingStatus::Pending);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn approve_with_the_right_code_marks_the_request_fulfilled() {
        let dir = tmp_dir();
        let state = test_state(dir.clone());
        let (code, hash) = generate_approval_code();
        let req = PendingRequest {
            id: "req3".into(),
            owner: "josh".into(),
            project: "custodly".into(),
            kind: PendingKind::Approve {
                provider: "github".into(),
                resource: "estejosh/Custodly".into(),
                requested_scope: "admin:write".into(),
                current_scope: None,
                tier: 2,
                code_hash: hash,
            },
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(15),
            status: PendingStatus::Pending,
        };
        state.store.put(&req).unwrap();
        let app = app(state.clone());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pending/req3/approve")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!("code={code}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let stored = state.store.get("req3").unwrap();
        assert_eq!(stored.status, PendingStatus::Fulfilled);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn an_already_fulfilled_request_cannot_be_approved_again() {
        let dir = tmp_dir();
        let state = test_state(dir.clone());
        let (code, hash) = generate_approval_code();
        let req = PendingRequest {
            id: "req4".into(),
            owner: "josh".into(),
            project: "custodly".into(),
            kind: PendingKind::Approve {
                provider: "github".into(),
                resource: "estejosh/Custodly".into(),
                requested_scope: "admin:write".into(),
                current_scope: None,
                tier: 2,
                code_hash: hash,
            },
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(15),
            status: PendingStatus::Fulfilled,
        };
        state.store.put(&req).unwrap();
        let app = app(state.clone());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pending/req4/approve")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!("code={code}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
        assert!(body.contains("no longer pending"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn an_expired_authorize_request_refuses_to_redirect() {
        let dir = tmp_dir();
        let state = test_state(dir.clone());
        let req = PendingRequest {
            id: "req5".into(),
            owner: "josh".into(),
            project: "custodly".into(),
            kind: PendingKind::Authorize { provider: "slack".into(), resource: "acme".into(), scopes: vec!["chat:write".into()] },
            created_at: Utc::now() - Duration::minutes(30),
            expires_at: Utc::now() - Duration::minutes(15),
            status: PendingStatus::Pending,
        };
        state.store.put(&req).unwrap();
        let app = app(state);
        let resp = app
            .oneshot(Request::builder().uri("/pending/req5/oauth-start").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        std::fs::remove_dir_all(&dir).ok();
    }
}
