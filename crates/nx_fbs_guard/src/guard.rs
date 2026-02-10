use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use flume::{Receiver, Sender, TrySendError};
use nx_metrics::ProxyMetrics;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

use crate::codec::{
    classify_frame, read_frame, write_frame, FrameClass, FrameDirection, FrameReadError, ReadFrame,
};
use crate::config::{CriticalOverflowPolicy, FbsGuardConfig};

pub async fn run_fbs_guard(
    config: FbsGuardConfig,
    metrics: ProxyMetrics,
    shutdown: CancellationToken,
) -> Result<()> {
    config.validate()?;

    let listener = TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("failed to bind FBS guard on {}", config.listen_addr))?;

    let listen_addr = listener
        .local_addr()
        .context("failed to read FBS guard listen addr")?;

    println!(
        "nx_fbs_guard listening on {}, upstream {}",
        listen_addr, config.upstream_addr
    );

    let mut gc_tick = tokio::time::interval(Duration::from_secs(60));
    gc_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut sessions: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                break;
            }
            _ = gc_tick.tick() => {
                while sessions.try_join_next().is_some() {}
            }
            accepted = listener.accept() => {
                let (client, client_addr) = match accepted {
                    Ok(v) => v,
                    Err(_) => {
                        metrics.record_fbs_frame_drop("accept_error");
                        continue;
                    }
                };

                let session_config = config.clone();
                let session_metrics = metrics.clone();
                let session_shutdown = shutdown.child_token();

                sessions.spawn(async move {
                    if let Err(err) = run_session(client, client_addr, session_config, session_metrics, session_shutdown).await {
                        eprintln!("nx_fbs_guard session error: {err}");
                    }
                });
            }
        }
    }

    shutdown.cancel();
    while sessions.join_next().await.is_some() {}

    Ok(())
}

async fn run_session(
    client_stream: TcpStream,
    _client_addr: SocketAddr,
    config: FbsGuardConfig,
    metrics: ProxyMetrics,
    shutdown: CancellationToken,
) -> Result<()> {
    let upstream_stream = TcpStream::connect(config.upstream_addr)
        .await
        .with_context(|| {
            format!(
                "failed to connect upstream FlatBuffers peer {}",
                config.upstream_addr
            )
        })?;

    client_stream
        .set_nodelay(true)
        .context("set_nodelay failed for client stream")?;
    upstream_stream
        .set_nodelay(true)
        .context("set_nodelay failed for upstream stream")?;

    let (client_read, client_write) = client_stream.into_split();
    let (upstream_read, upstream_write) = upstream_stream.into_split();

    let (c2u_critical_tx, c2u_critical_rx) = flume::bounded(config.critical_queue_capacity);
    let (c2u_telemetry_tx, c2u_telemetry_rx) = flume::bounded(config.telemetry_queue_capacity);
    let c2u_telemetry_tap = c2u_telemetry_rx.clone();

    let (u2c_critical_tx, u2c_critical_rx) = flume::bounded(config.critical_queue_capacity);
    let (u2c_telemetry_tx, u2c_telemetry_rx) = flume::bounded(config.telemetry_queue_capacity);
    let u2c_telemetry_tap = u2c_telemetry_rx.clone();

    let session_shutdown = shutdown.child_token();
    let writer_delay = Duration::from_millis(config.writer_delay_millis);
    let mut tasks = JoinSet::new();

    tasks.spawn(read_loop(
        client_read,
        c2u_critical_tx,
        c2u_telemetry_tx,
        c2u_telemetry_tap,
        FrameDirection::InterfaceToCore,
        config.max_frame_bytes,
        config.critical_overflow_policy,
        metrics.clone(),
        session_shutdown.child_token(),
    ));

    tasks.spawn(write_loop(
        upstream_write,
        c2u_critical_rx,
        c2u_telemetry_rx,
        metrics.clone(),
        writer_delay,
        session_shutdown.child_token(),
    ));

    tasks.spawn(read_loop(
        upstream_read,
        u2c_critical_tx,
        u2c_telemetry_tx,
        u2c_telemetry_tap,
        FrameDirection::CoreToInterface,
        config.max_frame_bytes,
        config.critical_overflow_policy,
        metrics.clone(),
        session_shutdown.child_token(),
    ));

    tasks.spawn(write_loop(
        client_write,
        u2c_critical_rx,
        u2c_telemetry_rx,
        metrics,
        writer_delay,
        session_shutdown.child_token(),
    ));

    tokio::select! {
        _ = shutdown.cancelled() => {}
        _ = tasks.join_next() => {}
    }

    session_shutdown.cancel();
    while tasks.join_next().await.is_some() {}

    Ok(())
}

// Read-loop wiring is explicit to keep call sites and ownership boundaries clear.
#[allow(clippy::too_many_arguments)]
async fn read_loop<R>(
    mut reader: R,
    critical_tx: Sender<Vec<u8>>,
    telemetry_tx: Sender<Vec<u8>>,
    telemetry_tap_rx: Receiver<Vec<u8>>,
    direction: FrameDirection,
    max_frame_bytes: usize,
    critical_policy: CriticalOverflowPolicy,
    metrics: ProxyMetrics,
    shutdown: CancellationToken,
) where
    R: AsyncRead + Unpin,
{
    loop {
        let read_result = tokio::select! {
            _ = shutdown.cancelled() => break,
            result = read_frame(&mut reader, max_frame_bytes) => result,
        };

        let frame = match read_result {
            Ok(ReadFrame::EndOfStream) => break,
            Ok(ReadFrame::Frame(frame)) => frame,
            Err(FrameReadError::LengthZero) => {
                metrics.record_fbs_frame_drop("frame_length_zero");
                break;
            }
            Err(FrameReadError::Oversized { .. }) => {
                metrics.record_fbs_frame_drop("frame_too_large");
                break;
            }
            Err(FrameReadError::Incomplete) => {
                metrics.record_fbs_frame_drop("frame_incomplete");
                break;
            }
            Err(FrameReadError::Io(_)) => {
                metrics.record_fbs_frame_drop("frame_read_io");
                break;
            }
        };

        let class = classify_frame(&frame, direction);

        match enqueue_frame(
            frame,
            class,
            &critical_tx,
            &telemetry_tx,
            &telemetry_tap_rx,
            critical_policy,
        )
        .await
        {
            QueueOutcome::Enqueued => {}
            QueueOutcome::Dropped { reason } => {
                metrics.record_fbs_frame_drop(reason);
                metrics.record_fbs_queue_full();
            }
            QueueOutcome::DroppedOldestEnqueued { reason } => {
                metrics.record_fbs_frame_drop(reason);
                metrics.record_fbs_queue_full();
            }
            QueueOutcome::Disconnected => {
                metrics.record_fbs_frame_drop("queue_disconnected");
                break;
            }
        }
    }
}

async fn write_loop<W>(
    mut writer: W,
    critical_rx: Receiver<Vec<u8>>,
    telemetry_rx: Receiver<Vec<u8>>,
    metrics: ProxyMetrics,
    writer_delay: Duration,
    shutdown: CancellationToken,
) where
    W: AsyncWrite + Unpin,
{
    loop {
        let Some(frame) = recv_prioritized(&critical_rx, &telemetry_rx, &shutdown).await else {
            break;
        };

        if write_frame(&mut writer, &frame).await.is_err() {
            metrics.record_fbs_frame_drop("frame_write_io");
            break;
        }

        metrics.record_fbs_frame_forwarded();
        if !writer_delay.is_zero() {
            tokio::time::sleep(writer_delay).await;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueueOutcome {
    Enqueued,
    Dropped { reason: &'static str },
    DroppedOldestEnqueued { reason: &'static str },
    Disconnected,
}

async fn enqueue_frame(
    frame: Vec<u8>,
    class: FrameClass,
    critical_tx: &Sender<Vec<u8>>,
    telemetry_tx: &Sender<Vec<u8>>,
    telemetry_tap_rx: &Receiver<Vec<u8>>,
    critical_policy: CriticalOverflowPolicy,
) -> QueueOutcome {
    match class {
        FrameClass::Telemetry => match telemetry_tx.try_send(frame) {
            Ok(_) => QueueOutcome::Enqueued,
            Err(TrySendError::Disconnected(_)) => QueueOutcome::Disconnected,
            Err(TrySendError::Full(frame)) => {
                let _ = telemetry_tap_rx.try_recv();
                match telemetry_tx.try_send(frame) {
                    Ok(_) => QueueOutcome::DroppedOldestEnqueued {
                        reason: "queue_full_telemetry",
                    },
                    Err(TrySendError::Full(_)) => QueueOutcome::Dropped {
                        reason: "queue_full_telemetry",
                    },
                    Err(TrySendError::Disconnected(_)) => QueueOutcome::Disconnected,
                }
            }
        },
        FrameClass::Critical => match critical_policy {
            CriticalOverflowPolicy::DropNewest => match critical_tx.try_send(frame) {
                Ok(_) => QueueOutcome::Enqueued,
                Err(TrySendError::Disconnected(_)) => QueueOutcome::Disconnected,
                Err(TrySendError::Full(_)) => QueueOutcome::Dropped {
                    reason: "queue_full_critical",
                },
            },
            CriticalOverflowPolicy::Block => match critical_tx.send_async(frame).await {
                Ok(_) => QueueOutcome::Enqueued,
                Err(_) => QueueOutcome::Disconnected,
            },
        },
    }
}

async fn recv_prioritized(
    critical_rx: &Receiver<Vec<u8>>,
    telemetry_rx: &Receiver<Vec<u8>>,
    shutdown: &CancellationToken,
) -> Option<Vec<u8>> {
    loop {
        if let Ok(frame) = critical_rx.try_recv() {
            return Some(frame);
        }

        if critical_rx.is_disconnected() && telemetry_rx.is_disconnected() {
            return None;
        }

        tokio::select! {
            _ = shutdown.cancelled() => return None,
            recv = critical_rx.recv_async() => {
                match recv {
                    Ok(frame) => return Some(frame),
                    Err(_) => {
                        if telemetry_rx.is_disconnected() {
                            return None;
                        }
                    }
                }
            }
            recv = telemetry_rx.recv_async() => {
                match recv {
                    Ok(frame) => return Some(frame),
                    Err(_) => {
                        if critical_rx.is_disconnected() {
                            return None;
                        }
                    }
                }
            }
        }
    }
}
