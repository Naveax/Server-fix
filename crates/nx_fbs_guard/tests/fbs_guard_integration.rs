use std::net::SocketAddr;
use std::time::Duration;

use nx_fbs_guard::config::{CriticalOverflowPolicy, FbsGuardConfig};
use nx_fbs_guard::run_fbs_guard;
use nx_metrics::ProxyMetrics;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const INTERFACE_MESSAGE_PLAYER_INPUT: u8 = 4;
const INTERFACE_MESSAGE_RENDER_GROUP: u8 = 6;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn guard_survives_overload_and_reports_controlled_drops() {
    let upstream_shutdown = CancellationToken::new();
    let (upstream_addr, upstream_task) = spawn_slow_echo_upstream(upstream_shutdown.clone()).await;

    let guard_addr = pick_free_tcp_addr();
    let metrics = ProxyMetrics::new("nx_fbs_guard_test").expect("metrics init");

    let config = FbsGuardConfig {
        listen_addr: guard_addr,
        upstream_addr,
        max_frame_bytes: 1024,
        telemetry_queue_capacity: 8,
        critical_queue_capacity: 4,
        critical_overflow_policy: CriticalOverflowPolicy::DropNewest,
        writer_delay_millis: 10,
    };

    let guard_shutdown = CancellationToken::new();
    let guard_task = {
        let metrics = metrics.clone();
        let shutdown = guard_shutdown.clone();
        tokio::spawn(async move { run_fbs_guard(config, metrics, shutdown).await })
    };

    tokio::time::sleep(Duration::from_millis(200)).await;

    let stream = TcpStream::connect(guard_addr)
        .await
        .expect("connect to guard");
    let (mut client_read, mut client_write) = stream.into_split();

    // Overload interface->core critical path to force queue pressure and controlled dropping.
    for i in 0..160u16 {
        let payload = [0x02, (i & 0xff) as u8, ((i >> 8) & 0xff) as u8];
        write_frame_u16(&mut client_write, &payload)
            .await
            .expect("write telemetry frame");
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!guard_task.is_finished(), "guard unexpectedly crashed");

    // Session should remain alive after pressure; a later write should succeed.
    write_frame_u16(&mut client_write, &[0x01, 0xaa])
        .await
        .expect("write post-pressure control frame");

    let first_response = timeout(
        Duration::from_secs(3),
        read_frame_u16(&mut client_read, 1024),
    )
    .await
    .expect("timeout waiting for response")
    .expect("frame read should not error")
    .expect("expected a response frame");

    assert!(
        !first_response.is_empty(),
        "expected non-empty response frame"
    );

    let snapshot = metrics.snapshot().expect("snapshot metrics");
    let dropped_critical = metric_counter_with_reason(
        &snapshot,
        "nx_fbs_guard_test_fbs_frames_dropped_total",
        "queue_full_critical",
    );
    let queue_full_total = metric_counter(&snapshot, "nx_fbs_guard_test_fbs_queue_full_total");
    let forwarded_total = metric_counter(&snapshot, "nx_fbs_guard_test_fbs_frames_forwarded_total");

    assert!(
        dropped_critical > 0,
        "expected controlled critical drops, metrics: {snapshot}"
    );
    assert!(
        queue_full_total > 0,
        "expected queue-full events, metrics: {snapshot}"
    );
    assert!(
        forwarded_total > 0,
        "expected some forwarded frames, metrics: {snapshot}"
    );

    guard_shutdown.cancel();
    let guard_result = guard_task.await.expect("join guard task");
    assert!(
        guard_result.is_ok(),
        "guard returned error: {guard_result:?}"
    );

    upstream_shutdown.cancel();
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn render_spam_drops_telemetry_but_player_input_advances() {
    let upstream_shutdown = CancellationToken::new();
    let (upstream_addr, upstream_task) = spawn_slow_echo_upstream(upstream_shutdown.clone()).await;

    let guard_addr = pick_free_tcp_addr();
    let metrics = ProxyMetrics::new("nx_fbs_guard_render_spam").expect("metrics init");

    let config = FbsGuardConfig {
        listen_addr: guard_addr,
        upstream_addr,
        max_frame_bytes: 1024,
        telemetry_queue_capacity: 4,
        critical_queue_capacity: 4,
        critical_overflow_policy: CriticalOverflowPolicy::DropNewest,
        writer_delay_millis: 10,
    };

    let guard_shutdown = CancellationToken::new();
    let guard_task = {
        let metrics = metrics.clone();
        let shutdown = guard_shutdown.clone();
        tokio::spawn(async move { run_fbs_guard(config, metrics, shutdown).await })
    };

    tokio::time::sleep(Duration::from_millis(200)).await;

    let stream = TcpStream::connect(guard_addr)
        .await
        .expect("connect to guard");
    let (mut client_read, mut client_write) = stream.into_split();

    let render_payload = build_message_packet_with_message_type(INTERFACE_MESSAGE_RENDER_GROUP);
    let player_input_payload =
        build_message_packet_with_message_type(INTERFACE_MESSAGE_PLAYER_INPUT);

    for _ in 0..200 {
        write_frame_u16(&mut client_write, &render_payload)
            .await
            .expect("write render frame");
    }
    write_frame_u16(&mut client_write, &player_input_payload)
        .await
        .expect("write player input");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    let mut saw_player_input = false;
    while tokio::time::Instant::now() < deadline {
        let read = timeout(
            Duration::from_millis(250),
            read_frame_u16(&mut client_read, 1024),
        )
        .await;
        let frame = match read {
            Ok(Ok(Some(payload))) => payload,
            Ok(Ok(None)) => break,
            Ok(Err(_)) => break,
            Err(_) => continue,
        };

        if frame == player_input_payload {
            saw_player_input = true;
            break;
        }
    }

    assert!(
        saw_player_input,
        "player input did not advance through guard under render spam"
    );

    let snapshot = metrics.snapshot().expect("snapshot metrics");
    let dropped_telemetry = metric_counter_with_reason(
        &snapshot,
        "nx_fbs_guard_render_spam_fbs_frames_dropped_total",
        "queue_full_telemetry",
    );
    assert!(
        dropped_telemetry > 0,
        "expected render telemetry drops under spam, snapshot: {snapshot}"
    );

    guard_shutdown.cancel();
    let guard_result = guard_task.await.expect("join guard task");
    assert!(
        guard_result.is_ok(),
        "guard returned error: {guard_result:?}"
    );

    upstream_shutdown.cancel();
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn guard_closes_session_on_oversized_frame() {
    let upstream_shutdown = CancellationToken::new();
    let (upstream_addr, upstream_task) = spawn_slow_echo_upstream(upstream_shutdown.clone()).await;

    let guard_addr = pick_free_tcp_addr();
    let metrics = ProxyMetrics::new("nx_fbs_guard_oversize").expect("metrics init");

    let config = FbsGuardConfig {
        listen_addr: guard_addr,
        upstream_addr,
        max_frame_bytes: 64,
        telemetry_queue_capacity: 8,
        critical_queue_capacity: 4,
        critical_overflow_policy: CriticalOverflowPolicy::DropNewest,
        writer_delay_millis: 0,
    };

    let guard_shutdown = CancellationToken::new();
    let guard_task = {
        let metrics = metrics.clone();
        let shutdown = guard_shutdown.clone();
        tokio::spawn(async move { run_fbs_guard(config, metrics, shutdown).await })
    };

    tokio::time::sleep(Duration::from_millis(200)).await;

    let stream = TcpStream::connect(guard_addr)
        .await
        .expect("connect to guard");
    let (mut client_read, mut client_write) = stream.into_split();

    let oversized_payload = vec![0x33; 65];
    write_frame_u16(&mut client_write, &oversized_payload)
        .await
        .expect("write oversized frame");

    let close_result = timeout(
        Duration::from_secs(3),
        read_frame_u16(&mut client_read, 1024),
    )
    .await
    .expect("timeout waiting for close");
    assert!(
        close_result.is_err() || close_result.ok().flatten().is_none(),
        "expected guard to close session after oversized frame"
    );
    assert!(
        !guard_task.is_finished(),
        "guard listener unexpectedly crashed"
    );

    let snapshot = metrics.snapshot().expect("snapshot metrics");
    let dropped_too_large = metric_counter_with_reason(
        &snapshot,
        "nx_fbs_guard_oversize_fbs_frames_dropped_total",
        "frame_too_large",
    );
    assert!(
        dropped_too_large > 0,
        "expected oversized-drop metrics, snapshot: {snapshot}"
    );

    guard_shutdown.cancel();
    let guard_result = guard_task.await.expect("join guard task");
    assert!(
        guard_result.is_ok(),
        "guard returned error: {guard_result:?}"
    );

    upstream_shutdown.cancel();
    let _ = upstream_task.await;
}

fn metric_counter(snapshot: &str, metric_name: &str) -> u64 {
    snapshot
        .lines()
        .find_map(|line| {
            let prefix = format!("{metric_name} ");
            line.strip_prefix(&prefix)
                .and_then(|raw| raw.parse::<u64>().ok())
        })
        .unwrap_or(0)
}

fn metric_counter_with_reason(snapshot: &str, metric_name: &str, reason: &str) -> u64 {
    let prefix = format!("{metric_name}{{reason=\"{reason}\"}} ");
    snapshot
        .lines()
        .find_map(|line| {
            line.strip_prefix(&prefix)
                .and_then(|raw| raw.parse::<u64>().ok())
        })
        .unwrap_or(0)
}

fn pick_free_tcp_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve TCP port");
    listener.local_addr().expect("reserved addr")
}

async fn spawn_slow_echo_upstream(shutdown: CancellationToken) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let addr = listener.local_addr().expect("upstream local addr");

    let task = tokio::spawn(async move {
        let (mut stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                read = read_frame_u16(&mut stream, 4096) => {
                    match read {
                        Ok(Some(payload)) => {
                            tokio::time::sleep(Duration::from_millis(25)).await;
                            if write_frame_u16(&mut stream, &payload).await.is_err() {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            }
        }
    });

    (addr, task)
}

async fn write_frame_u16<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let len = u16::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

async fn read_frame_u16<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_frame_bytes: usize,
) -> io::Result<Option<Vec<u8>>> {
    let Some(declared_bytes) = read_length_prefix_u16(reader).await? else {
        return Ok(None);
    };

    if declared_bytes == 0 || declared_bytes > max_frame_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }

    let mut payload = vec![0u8; declared_bytes];
    reader.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

async fn read_length_prefix_u16<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<usize>> {
    let mut header = [0u8; 2];
    let mut read = 0usize;
    while read < header.len() {
        let n = reader.read(&mut header[read..]).await?;
        if n == 0 {
            if read == 0 {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete length prefix",
            ));
        }
        read += n;
    }

    Ok(Some(u16::from_be_bytes(header) as usize))
}

fn build_message_packet_with_message_type(message_type: u8) -> Vec<u8> {
    let mut buf = vec![0u8; 24];

    // Root uoffset points to table start.
    buf[0..4].copy_from_slice(&12u32.to_le_bytes());

    // Vtable at offset 4, table at offset 12.
    buf[4..6].copy_from_slice(&8u16.to_le_bytes()); // vtable size
    buf[6..8].copy_from_slice(&12u16.to_le_bytes()); // object size
    buf[8..10].copy_from_slice(&4u16.to_le_bytes()); // message_type field offset
    buf[10..12].copy_from_slice(&8u16.to_le_bytes()); // message union field offset

    // Table body.
    buf[12..16].copy_from_slice(&8i32.to_le_bytes()); // vtable back-offset
    buf[16] = message_type; // message_type field

    // union object offset is left as 0 (not needed for classification)

    buf
}
