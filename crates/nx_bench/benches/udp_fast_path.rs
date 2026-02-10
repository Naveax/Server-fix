use std::net::UdpSocket;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::time::Instant;

use nx_netio::{MsgBuf, RecvBatchState};

const PACKETS: usize = 20_000;
const BATCH: usize = 32;

fn main() {
    let fallback_pps = bench_fallback_pps();
    println!("fallback_recv_from_pps={fallback_pps:.0}");

    #[cfg(target_os = "linux")]
    {
        let mmsg_pps = bench_mmsg_pps();
        println!("mmsg_recvmmsg_pps={mmsg_pps:.0}");
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!("mmsg_recvmmsg_pps=unsupported");
    }

    let (p50_us, p99_us) = bench_queue_latency_us();
    println!("enqueue_forward_latency_p50_us={p50_us:.2}");
    println!("enqueue_forward_latency_p99_us={p99_us:.2}");
}

fn bench_fallback_pps() -> f64 {
    let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
    let recv_addr = recv_socket.local_addr().expect("recv addr");
    let send_socket = UdpSocket::bind("127.0.0.1:0").expect("bind send");
    send_socket.connect(recv_addr).expect("connect send");

    let payload = [0u8; 64];
    let mut recv_buf = [0u8; 1500];

    let start = Instant::now();
    for _ in 0..PACKETS {
        send_socket.send(&payload).expect("send");
        let _ = recv_socket.recv_from(&mut recv_buf).expect("recv");
    }
    let elapsed = start.elapsed().as_secs_f64();
    PACKETS as f64 / elapsed.max(1e-9)
}

#[cfg(target_os = "linux")]
fn bench_mmsg_pps() -> f64 {
    let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
    let recv_addr = recv_socket.local_addr().expect("recv addr");
    let send_socket = UdpSocket::bind("127.0.0.1:0").expect("bind send");
    send_socket.connect(recv_addr).expect("connect send");

    let payload = [0u8; 64];
    let mut msg_bufs = (0..BATCH)
        .map(|_| MsgBuf::with_capacity(1500))
        .collect::<Vec<_>>();
    let mut recv_state = RecvBatchState::new(BATCH);
    let recv_fd = recv_socket.as_raw_fd();

    let start = Instant::now();
    let mut received = 0usize;
    while received < PACKETS {
        let to_send = (PACKETS - received).min(BATCH);
        for _ in 0..to_send {
            send_socket.send(&payload).expect("send");
        }

        let mut got = 0usize;
        while got < to_send {
            let n = nx_netio::recv_batch_with_state(recv_fd, &mut msg_bufs, &mut recv_state)
                .expect("recvmmsg");
            got += n;
        }
        received += got;
    }

    let elapsed = start.elapsed().as_secs_f64();
    PACKETS as f64 / elapsed.max(1e-9)
}

fn bench_queue_latency_us() -> (f64, f64) {
    let (tx, rx) = flume::bounded::<Instant>(1024);
    let (ack_tx, ack_rx) = flume::bounded::<Instant>(1024);

    let worker = std::thread::spawn(move || {
        while let Ok(sent_at) = rx.recv() {
            let _ = ack_tx.send(sent_at);
        }
    });

    let mut latencies_us = Vec::with_capacity(10_000);
    for _ in 0..10_000 {
        let sent_at = Instant::now();
        tx.send(sent_at).expect("queue send");
        let echoed = ack_rx.recv().expect("queue recv");
        latencies_us.push(echoed.elapsed().as_secs_f64() * 1_000_000.0);
    }

    drop(tx);
    let _ = worker.join();

    latencies_us.sort_by(|a, b| a.partial_cmp(b).expect("valid float compare"));
    let p50 = percentile(&latencies_us, 0.50);
    let p99 = percentile(&latencies_us, 0.99);
    (p50, p99)
}

fn percentile(samples: &[f64], p: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let idx = ((samples.len() - 1) as f64 * p).round() as usize;
    samples[idx.min(samples.len() - 1)]
}
