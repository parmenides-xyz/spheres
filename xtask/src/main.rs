//! xtask is a Swiss army knife of tools that help with running and testing spheres.
use crate::{
    benchmark_results::BenchmarkResults,
    deposit::Deposit,
    sphere_info::SphereInfoCmd,
    generate_p2p_key::GenerateP2pKey,
};
use clap::Parser as _;
use eyre::Context;

mod admin;
mod benchmark_results;
mod deposit;
mod sphere_utils;
mod sphere_info;
mod generate_p2p_key;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    let args = Args::parse();
    match args.action {
        Action::BenchmarkResults(args) => args.run().wrap_err("failed to render benchmark results"),
        Action::SphereInfo(args) => args.run().await.wrap_err("failed to fetch sphere info"),
        Action::Deposit(args) => args.run().await.wrap_err("failed to send deposit"),
        Action::GenerateP2pKey(args) => args.run().wrap_err("failed to generate P2P key"),
    }
}

#[derive(Debug, clap::Parser)]
#[command(author)]
#[command(version)]
#[command(about)]
#[command(long_about = None)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, clap::Subcommand)]
enum Action {
    BenchmarkResults(BenchmarkResults),
    GenerateP2pKey(GenerateP2pKey),
    Deposit(Deposit),
    SphereInfo(SphereInfoCmd),
}
