use std::path::PathBuf;

use clap::Parser;
use nx_proxy::{run_proxy, ProxyConfig};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(name = "nx_proxy")]
#[command(
    about = "Defensive UDP mitigation proxy with strict packet validation, anomaly filtering, and smurf/MMR detection"
)]
struct Args {
    #[arg(long, default_value = "config/dev.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = ProxyConfig::from_file(&args.config)?;

    let shutdown = CancellationToken::new();
    let signal_shutdown = shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_shutdown.cancel();
        }
    });

    run_proxy(config, shutdown).await
}
