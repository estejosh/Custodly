//! Custodly CLI entry point.
//!
//! **Not a shipped end-user CLI.** `START-HERE.md`'s house rules are
//! explicit that end users never touch a command line -- the real
//! interfaces are n8n workflows and the dashboard. This binary exists so
//! the workspace builds end to end and so there is somewhere to run
//! `custodly-core` from a shell during development, including the one
//! subcommand below that is real infrastructure (a deployment operator
//! runs it, not an end user): `serve`, which binds `custodly-core::server`
//! -- the `policy()` half of `boundary/v1` (`docs/BOUNDARY.md`).

use clap::{Parser, Subcommand};

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
        None => {
            eprintln!(
                "custodly: not implemented yet ({}). See docs/mvp-scope.md for what's decided \
                 and docs/START-HERE.md's order of work for what's next. Run `custodly serve` \
                 to start the policy() listener.",
                custodly_core::CONTRACT_VERSION
            );
            std::process::exit(1);
        }
    }
}
