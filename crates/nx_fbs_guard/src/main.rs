use std::net::SocketAddr;

use clap::{Parser, ValueEnum};
use nx_fbs_guard::{run_fbs_guard, CriticalOverflowPolicy, FbsGuardConfig};
use nx_metrics::ProxyMetrics;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(name = "nx_fbs_guard")]
#[command(about = "RLBot v5 FlatBuffers TCP guard with bounded queueing")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:23235")]
    listen: SocketAddr,

    #[arg(long, default_value = "127.0.0.1:23234")]
    upstream: SocketAddr,

    #[arg(long, default_value_t = 65_535)]
    max_frame_bytes: usize,

    #[arg(long, default_value_t = 512)]
    telemetry_queue_capacity: usize,

    #[arg(long, default_value_t = 64)]
    critical_queue_capacity: usize,

    #[arg(long, value_enum, default_value_t = CriticalOverflowArg::DropNewest)]
    critical_overflow_policy: CriticalOverflowArg,

    #[arg(long)]
    writer_delay_millis: Option<u64>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CriticalOverflowArg {
    DropNewest,
    Block,
}

impl From<CriticalOverflowArg> for CriticalOverflowPolicy {
    fn from(value: CriticalOverflowArg) -> Self {
        match value {
            CriticalOverflowArg::DropNewest => CriticalOverflowPolicy::DropNewest,
            CriticalOverflowArg::Block => CriticalOverflowPolicy::Block,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = FbsGuardConfig {
        listen_addr: args.listen,
        upstream_addr: args.upstream,
        max_frame_bytes: args.max_frame_bytes,
        telemetry_queue_capacity: args.telemetry_queue_capacity,
        critical_queue_capacity: args.critical_queue_capacity,
        critical_overflow_policy: args.critical_overflow_policy.into(),
        writer_delay_millis: args.writer_delay_millis.unwrap_or(0),
    };

    let metrics = ProxyMetrics::new("nx_fbs_guard")?;

    let shutdown = CancellationToken::new();
    let signal_shutdown = shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_shutdown.cancel();
        }
    });

    run_fbs_guard(config, metrics, shutdown).await
}
