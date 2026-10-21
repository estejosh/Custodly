//! `custodly-portal` binary. `serve` binds the owner-facing web surface;
//! `create-pending-authorize` is a dev-only helper to hand-create a
//! pending request for testing, standing in for the real n8n caller
//! this doesn't have yet (`custodly-owner-portal.md`, "still open").
//! Same house rule as `custodly-cli`: this is infrastructure, not the
//! interface end users touch -- the interface *is* the web pages this
//! binary serves.

use std::path::PathBuf;

use chrono::Utc;
use clap::{Parser, Subcommand};
use custodly_portal::{AppState, PendingKind, PendingRequest, PendingStatus, PendingStore, SlackOAuth, app};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bind the owner portal's HTTP listener.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8879")]
        listen: std::net::SocketAddr,
        /// This portal's own externally-reachable base URL -- must match
        /// what's registered as the OAuth redirect URI with each
        /// provider (e.g. `https://portal.example.com`).
        #[arg(long, env = "CUSTODLY_PORTAL_BASE_URL")]
        base_url: String,
        #[arg(long, env = "CUSTODLY_PORTAL_PENDING_DIR")]
        pending_dir: PathBuf,
        #[arg(long, env = "CUSTODLY_VAULT_PATH")]
        vault: PathBuf,
        #[arg(long, env = "CUSTODLY_KEEPASSXC_CLI", default_value = "C:\\Program Files\\KeePassXC\\keepassxc-cli.exe")]
        cli_path: PathBuf,
        #[arg(long, env = "CUSTODLY_KEYRING_NAME", default_value = "custodly-working-vault")]
        keyring_name: String,
        /// Slack app client id -- omit to run without Slack authorize
        /// support (every other route still works).
        #[arg(long, env = "CUSTODLY_SLACK_CLIENT_ID")]
        slack_client_id: Option<String>,
        #[arg(long, env = "CUSTODLY_SLACK_CLIENT_SECRET")]
        slack_client_secret: Option<String>,
        /// Repeatable, e.g. `--slack-bot-scope chat:write --slack-bot-scope channels:read`.
        #[arg(long = "slack-bot-scope")]
        slack_bot_scopes: Vec<String>,
        /// Tailscale login (e.g. `you@github`) allowed to see pending requests on the home page.
        #[arg(long, env = "CUSTODLY_PORTAL_ADMIN_LOGIN")]
        admin_login: Option<String>,
        /// The phone-intake state directory (the `state_dir` in intake.json). When set,
        /// the home page lists phones waiting to be approved.
        #[arg(long, env = "CUSTODLY_INTAKE_STATE_DIR")]
        intake_state_dir: Option<PathBuf>,
        /// Credential-store name of the intake key (`intake_key_name` in intake.json).
        #[arg(long, env = "CUSTODLY_INTAKE_KEY_NAME", default_value = "default")]
        intake_key_name: String,
    },
    /// Dev-only: hand-create a pending "Authorize" request and print its
    /// link, so the portal can be exercised without a real caller yet.
    CreatePendingAuthorize {
        #[arg(long, env = "CUSTODLY_PORTAL_PENDING_DIR")]
        pending_dir: PathBuf,
        #[arg(long, env = "CUSTODLY_PORTAL_BASE_URL")]
        base_url: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        project: String,
        #[arg(long)]
        provider: String,
        #[arg(long)]
        resource: String,
        #[arg(long = "scope", required = true)]
        scopes: Vec<String>,
        #[arg(long, default_value_t = 30)]
        ttl_minutes: i64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            listen,
            base_url,
            pending_dir,
            vault,
            cli_path,
            keyring_name,
            slack_client_id,
            slack_client_secret,
            slack_bot_scopes,
            admin_login,
            intake_state_dir,
            intake_key_name,
        } => {
            let slack = match (slack_client_id, slack_client_secret) {
                (Some(id), Some(secret)) => {
                    Some(SlackOAuth::new(id, secret, slack_bot_scopes, reqwest::Client::new()))
                }
                _ => {
                    tracing::warn!("no Slack client id/secret configured -- /oauth/callback/slack will refuse everything");
                    None
                }
            };
            let (devices, intake_fingerprint) = match intake_state_dir {
                Some(dir) => {
                    let key = custodly_intake::IntakeKey::load_or_create(&intake_key_name)?;
                    (
                        Some(custodly_intake::DeviceRegistry::new(dir.join("devices"))?),
                        Some(custodly_intake::envelope::fingerprint(&key.public())),
                    )
                }
                None => (None, None),
            };
            let state = std::sync::Arc::new(AppState {
                store: PendingStore::new(pending_dir)?,
                vault: custodly_vault::Vault::new(cli_path, vault, keyring_name),
                slack,
                base_url,
                admin_login,
                devices,
                intake_fingerprint,
            });
            let listener = tokio::net::TcpListener::bind(listen).await?;
            tracing::info!(address = %listen, "custodly-portal listening");
            axum::serve(listener, app(state)).await?;
            Ok(())
        }
        Command::CreatePendingAuthorize { pending_dir, base_url, owner, project, provider, resource, scopes, ttl_minutes } => {
            let store = PendingStore::new(pending_dir)?;
            let id = custodly_portal::code::generate_id();
            let request = PendingRequest {
                id: id.clone(),
                owner,
                project,
                kind: PendingKind::Authorize { provider, resource, scopes },
                created_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::minutes(ttl_minutes),
                status: PendingStatus::Pending,
            };
            store.put(&request)?;
            println!("{base_url}/pending/{id}");
            Ok(())
        }
    }
}
