use std::net::SocketAddr;

use clap::Parser;
use tokio::net::UdpSocket;

#[derive(Debug, Parser)]
#[command(name = "nx_echo_upstream")]
#[command(about = "Benign UDP echo server for local proxy testing")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7001")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let socket = UdpSocket::bind(args.listen).await?;
    println!("nx_echo_upstream listening on {}", socket.local_addr()?);

    let mut buf = vec![0u8; 65_535];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        socket.send_to(&buf[..len], peer).await?;
    }
}
