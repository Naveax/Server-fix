use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use clap::Parser;
use nx_proxy::packet::build_checksum_packet;
use nx_proxy::ProxyConfig;
use rand::Rng;
use tokio::net::UdpSocket;
use tokio::time::MissedTickBehavior;

#[derive(Debug, Parser)]
#[command(name = "nx_packet_manip_sim")]
#[command(
    about = "Loopback-safe packet manipulation simulator for validating strict checksum/length enforcement"
)]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value = "127.0.0.1:7000")]
    target: SocketAddr,
    #[arg(long, default_value_t = 2_000)]
    pps: u32,
    #[arg(long, default_value_t = 5)]
    duration_secs: u64,
    #[arg(long, default_value_t = 0.5)]
    invalid_ratio: f64,
    #[arg(long, default_value_t = false)]
    allow_non_local: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.pps == 0 {
        bail!("pps must be > 0");
    }
    if args.duration_secs == 0 {
        bail!("duration_secs must be > 0");
    }
    if !(0.0..=1.0).contains(&args.invalid_ratio) {
        bail!("invalid_ratio must be in range [0, 1]");
    }

    let allow_non_local_from_config = if let Some(path) = &args.config {
        ProxyConfig::from_file(path)
            .with_context(|| format!("failed to read simulator config {}", path.display()))?
            .flood_sim
            .allow_non_local
    } else {
        false
    };
    let allow_non_local = args.allow_non_local || allow_non_local_from_config;
    if !allow_non_local && !args.target.ip().is_loopback() {
        bail!(
            "refusing non-loopback target {} without --allow-non-local",
            args.target
        );
    }

    let bind_addr = if args.target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind sender socket on {bind_addr}"))?;
    socket
        .connect(args.target)
        .await
        .with_context(|| format!("failed to connect to target {}", args.target))?;

    let mut rng = rand::thread_rng();
    let total_packets = (args.pps as u64).saturating_mul(args.duration_secs);
    let tick_nanos = (1_000_000_000u64 / (args.pps as u64)).max(1);
    let mut ticker = tokio::time::interval(Duration::from_nanos(tick_nanos));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut sent = 0u64;
    let mut invalid_sent = 0u64;
    let mut send_errors = 0u64;
    let started = Instant::now();

    while sent < total_packets {
        ticker.tick().await;

        let logical_payload = format!(
            "SYNC:{}|MMR:{}|DATA",
            rng.gen_range(-250..=250),
            rng.gen_range(900..=2100)
        );
        let mut packet = build_checksum_packet(logical_payload.as_bytes());

        if rng.gen_bool(args.invalid_ratio) {
            invalid_sent = invalid_sent.saturating_add(1);
            if rng.gen_bool(0.5) {
                // Corrupt checksum.
                if packet.len() >= 8 {
                    packet[6] ^= 0x3C;
                }
            } else if packet.len() >= 4 {
                // Corrupt declared length.
                packet[0] ^= 0x01;
            }
        }

        match socket.send(&packet).await {
            Ok(_) => sent = sent.saturating_add(1),
            Err(_) => send_errors = send_errors.saturating_add(1),
        }
    }

    let elapsed = started.elapsed().as_secs_f64().max(1e-9);
    let achieved_pps = sent as f64 / elapsed;
    println!(
        "nx_packet_manip_sim target={} sent={} invalid_sent={} errors={} elapsed_s={:.3} achieved_pps={:.0} allow_non_local={}",
        args.target, sent, invalid_sent, send_errors, elapsed, achieved_pps, allow_non_local
    );

    Ok(())
}
