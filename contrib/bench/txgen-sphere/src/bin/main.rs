use clap::{Parser, Subcommand};
use eyre::Result;
use txgen_sphere::{
    auth_token_map::{run_auth_token_map, AuthTokenMapArgs},
    SphereAdapter,
};

#[derive(Parser)]
#[command(name = "txgen-sphere", about = "Sphere transaction generator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(flatten)]
    Txgen(txgen_cli::Command),
    /// Generate or refresh an Arc Sphere private-RPC authorization-token map
    AuthTokenMap(AuthTokenMapArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Txgen(command) => txgen_cli::run_command(SphereAdapter, command).await,
        Command::AuthTokenMap(args) => run_auth_token_map(args).await,
    }
}
