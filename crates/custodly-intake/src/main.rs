use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use custodly_intake::{Config, Intake, IntakeKey, ProjectDeliver};

#[derive(Parser)]
#[command(name = "custodly-intake", about = "Receives keys from the Custodly phone app")]
struct Cli {
    /// Path to intake.json.
    #[arg(long, env = "CUSTODLY_INTAKE_CONFIG")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Watch the sync folder and process what arrives.
    Run,
    /// Print the key fingerprint to compare with the phone, and device counts.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let cli = Cli::parse();
    let cfg: Config = serde_json::from_slice(
        &std::fs::read(&cli.config).with_context(|| format!("reading {}", cli.config.display()))?,
    )
    .context("parsing the config file")?;
    let key = IntakeKey::load_or_create(&cfg.intake_key_name)?;
    let vault = custodly_vault::Vault::new(cfg.keepassxc_cli.clone(), cfg.vault_path.clone(), cfg.keyring_name.clone());
    let intake = Intake::new(cfg, key, vault, ProjectDeliver)?;
    match cli.command {
        Command::Status => {
            println!("intake key fingerprint: {}", intake.fingerprint());
            println!("phones waiting to be enrolled: {}", intake.devices().list_pending().len());
            println!("phones enrolled: {}", intake.devices().list_enrolled().len());
            Ok(())
        }
        Command::Run => {
            tracing::info!(fingerprint = %intake.fingerprint(), "custodly-intake running");
            loop {
                match intake.tick(chrono::Utc::now()).await {
                    Ok(r) if r != custodly_intake::TickReport::default() => tracing::info!(?r, "tick"),
                    Ok(_) => {}
                    Err(e) => tracing::error!(error = %e, "tick failed"),
                }
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_secs(5)) => {}
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                }
            }
        }
    }
}