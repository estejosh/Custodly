//! Custodly CLI entry point.
//!
//! **Not a shipped end-user CLI.** `START-HERE.md`'s house rules are
//! explicit that end users never touch a command line -- the real
//! interfaces are n8n workflows and the dashboard. This binary exists so
//! the workspace builds end to end, so there is somewhere to run
//! `custodly-core`/`custodly-vault`/`custodly-github` from a shell during
//! development, and for the two subcommands below that are real
//! infrastructure, not end-user surface:
//! - `serve`: binds `custodly-core::server` -- the `policy()` half of
//!   `boundary/v1` (`docs/BOUNDARY.md`).
//! - `mint-github`: runs the Track 1 pilot end to end -- mint an
//!   installation token, verify it, deposit it. This is what an n8n
//!   workflow will eventually call in place of a human running this by
//!   hand; it exists here first so the pipeline can be proven with a
//!   real GitHub App before anything gets built on top of it.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use custodly_core::{AcquisitionSource, EntryMetadata, Tier, VaultEntry};
use custodly_github::{AppCredentials, RequestedGrant, mint_installation_token};
use custodly_vault::Vault;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the `policy()` HTTP listener Ferryman calls into.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8878")]
        listen: std::net::SocketAddr,
    },
    /// Mint a GitHub App installation access token and deposit it into
    /// `working.kdbx`. The App's private key is read from stdin (PEM),
    /// never a flag or env var, so it never lands in shell history or a
    /// process list -- same rule `custodly-vault` already follows for
    /// the vault's own password.
    ///
    /// Example:
    /// `custodly mint-github --app-id 123456 --installation-id 789 \
    ///    --permission contents:read --project redaktly \
    ///    --label github-pat < app-private-key.pem`
    MintGithub {
        #[arg(long, env = "CUSTODLY_GITHUB_APP_ID")]
        app_id: u64,
        #[arg(long)]
        installation_id: u64,
        /// `resource:level`, e.g. `contents:read`. Repeatable -- pass
        /// one `--permission` per resource. Ask for the least this
        /// credential actually needs; GitHub will not grant more than
        /// the App's own installation permits, and this crate refuses
        /// to store a token that comes back broader than requested.
        #[arg(long = "permission", value_parser = parse_permission, required = true)]
        permissions: Vec<(String, String)>,
        /// Restrict to specific repositories by GitHub's numeric id.
        /// Omit to request every repository the installation covers.
        #[arg(long = "repository-id")]
        repository_ids: Vec<u64>,
        /// Which project this credential is for, e.g. "redaktly" --
        /// becomes the vault group and must be non-empty
        /// (`EntryMetadata::new` refuses an empty one).
        #[arg(long)]
        project: String,
        /// Short name for this credential within its project, e.g.
        /// "github-pat".
        #[arg(long)]
        label: String,
        #[arg(long, env = "CUSTODLY_VAULT_PATH")]
        vault: PathBuf,
        #[arg(long, env = "CUSTODLY_KEEPASSXC_CLI", default_value = "C:\\Program Files\\KeePassXC\\keepassxc-cli.exe")]
        cli_path: PathBuf,
        #[arg(long, env = "CUSTODLY_KEYRING_NAME", default_value = "custodly-working-vault")]
        keyring_name: String,
    },
}

/// Parse a `--permission` value of the form `resource:level`.
fn parse_permission(raw: &str) -> Result<(String, String), String> {
    let (resource, level) = raw
        .split_once(':')
        .ok_or_else(|| format!("expected resource:level, got {raw:?}"))?;
    if resource.is_empty() || level.is_empty() {
        return Err(format!("expected resource:level, got {raw:?}"));
    }
    Ok((resource.to_string(), level.to_string()))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Serve { listen }) => {
            let listener = tokio::net::TcpListener::bind(listen).await?;
            tracing::info!(address=%listen, "custodly policy() listener starting");
            axum::serve(listener, custodly_core::server::app()).await?;
            Ok(())
        }
        Some(Command::MintGithub {
            app_id,
            installation_id,
            permissions,
            repository_ids,
            project,
            label,
            vault,
            cli_path,
            keyring_name,
        }) => {
            let mut private_key_pem = String::new();
            std::io::stdin()
                .read_to_string(&mut private_key_pem)
                .map_err(|e| anyhow::anyhow!("reading the App private key from stdin: {e}"))?;
            if private_key_pem.trim().is_empty() {
                anyhow::bail!(
                    "no private key on stdin -- pipe the App's PEM in, e.g. `custodly mint-github ... < app-key.pem`"
                );
            }

            let app = AppCredentials { app_id, private_key_pem };
            let grant = RequestedGrant {
                installation_id,
                permissions: permissions.into_iter().collect::<BTreeMap<_, _>>(),
                repository_ids: if repository_ids.is_empty() { None } else { Some(repository_ids) },
            };

            let client = reqwest::Client::new();
            let minted = mint_installation_token(&client, &app, &grant).await?;
            tracing::info!(
                tier = ?minted.tier,
                scope = %minted.scope_string,
                expires_at = %minted.expires_at,
                "minted and verified installation token"
            );

            let source_description =
                format!("GitHub App installation token, app {app_id}, installation {installation_id}, {}", minted.scope_string);
            let metadata = EntryMetadata::new(
                "github",
                project,
                source_description,
                AcquisitionSource::GithubAppInstallationToken,
                chrono::Utc::now(),
                Some(minted.expires_at),
                minted.tier,
            )?;
            let entry = VaultEntry::new(label.clone(), metadata, minted.token);
            let store = Vault::new(cli_path, vault, keyring_name);
            store.put(&entry)?;

            println!(
                "deposited {}/{} (tier {}, expires {})",
                entry.metadata.project,
                label,
                match entry.metadata.tier {
                    Tier::Tier0 => 0,
                    Tier::Tier1 => 1,
                    Tier::Tier2 => 2,
                },
                entry.metadata.expires_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
            );
            Ok(())
        }
        None => {
            eprintln!(
                "custodly: no subcommand given ({}). See docs/mvp-scope.md for what's decided \
                 and docs/START-HERE.md's order of work for what's next. Run `custodly serve` to \
                 start the policy() listener, or `custodly mint-github --help` for the Track 1 \
                 pilot.",
                custodly_core::CONTRACT_VERSION
            );
            std::process::exit(1);
        }
    }
}
