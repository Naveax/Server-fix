use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use tokio::net::UdpSocket;

#[cfg(unix)]
pub type SocketFd = std::os::fd::RawFd;
#[cfg(not(unix))]
pub type SocketFd = i32;

#[derive(Debug, Clone)]
pub struct MsgBuf {
    storage: Vec<u8>,
    len: usize,
    addr: SocketAddr,
}

impl MsgBuf {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            storage: vec![0u8; capacity],
            len: 0,
            addr: SocketAddr::from(([0, 0, 0, 0], 0)),
        }
    }

    pub fn reset(&mut self) {
        self.len = 0;
        self.addr = SocketAddr::from(([0, 0, 0, 0], 0));
    }

    pub fn payload(&self) -> &[u8] {
        &self.storage[..self.len]
    }

    pub fn payload_mut_full(&mut self) -> &mut [u8] {
        &mut self.storage
    }

    pub fn set_len(&mut self, len: usize) {
        self.len = len.min(self.storage.len());
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn set_addr(&mut self, addr: SocketAddr) {
        self.addr = addr;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DatagramRef<'a> {
    pub payload: &'a [u8],
    pub addr: SocketAddr,
}

#[derive(Debug, Default)]
pub struct RecvBatchState {
    #[cfg(all(target_os = "linux", feature = "mmsg"))]
    iovecs: Vec<libc::iovec>,
    #[cfg(all(target_os = "linux", feature = "mmsg"))]
    addrs: Vec<libc::sockaddr_storage>,
    #[cfg(all(target_os = "linux", feature = "mmsg"))]
    hdrs: Vec<libc::mmsghdr>,
}

#[cfg(all(target_os = "linux", feature = "mmsg"))]
unsafe impl Send for RecvBatchState {}

impl RecvBatchState {
    pub fn new(capacity: usize) -> Self {
        #[cfg(all(target_os = "linux", feature = "mmsg"))]
        {
            let mut state = Self::default();
            state.ensure_capacity(capacity);
            state
        }
        #[cfg(not(all(target_os = "linux", feature = "mmsg")))]
        {
            let _ = capacity;
            Self::default()
        }
    }

    #[cfg(all(target_os = "linux", feature = "mmsg"))]
    fn ensure_capacity(&mut self, needed: usize) {
        if self.iovecs.len() < needed {
            self.iovecs.resize_with(needed, || libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            });
            self.addrs
                .resize_with(needed, || unsafe { std::mem::zeroed() });
            self.hdrs
                .resize_with(needed, || unsafe { std::mem::zeroed() });
        }
    }
}

#[derive(Debug, Default)]
pub struct SendBatchState {
    #[cfg(all(target_os = "linux", feature = "mmsg"))]
    iovecs: Vec<libc::iovec>,
    #[cfg(all(target_os = "linux", feature = "mmsg"))]
    addrs: Vec<libc::sockaddr_storage>,
    #[cfg(all(target_os = "linux", feature = "mmsg"))]
    hdrs: Vec<libc::mmsghdr>,
}

#[cfg(all(target_os = "linux", feature = "mmsg"))]
unsafe impl Send for SendBatchState {}

impl SendBatchState {
    pub fn new(capacity: usize) -> Self {
        #[cfg(all(target_os = "linux", feature = "mmsg"))]
        {
            let mut state = Self::default();
            state.ensure_capacity(capacity);
            state
        }
        #[cfg(not(all(target_os = "linux", feature = "mmsg")))]
        {
            let _ = capacity;
            Self::default()
        }
    }

    #[cfg(all(target_os = "linux", feature = "mmsg"))]
    fn ensure_capacity(&mut self, needed: usize) {
        if self.iovecs.len() < needed {
            self.iovecs.resize_with(needed, || libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            });
            self.addrs
                .resize_with(needed, || unsafe { std::mem::zeroed() });
            self.hdrs
                .resize_with(needed, || unsafe { std::mem::zeroed() });
        }
    }
}

pub async fn recv_batch_tokio(socket: &UdpSocket, bufs: &mut [MsgBuf]) -> io::Result<usize> {
    if bufs.is_empty() {
        return Ok(0);
    }

    for buf in bufs.iter_mut() {
        buf.reset();
    }

    let first = &mut bufs[0];
    let (len, addr) = socket.recv_from(first.payload_mut_full()).await?;
    first.set_len(len);
    first.set_addr(addr);

    let mut count = 1usize;
    while count < bufs.len() {
        let next = &mut bufs[count];
        match socket.try_recv_from(next.payload_mut_full()) {
            Ok((len, addr)) => {
                next.set_len(len);
                next.set_addr(addr);
                count += 1;
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
            Err(err) => return Err(err),
        }
    }

    Ok(count)
}

pub async fn send_batch_tokio(
    socket: &UdpSocket,
    packets: &[DatagramRef<'_>],
) -> io::Result<usize> {
    let mut sent = 0usize;
    for packet in packets {
        socket.send_to(packet.payload, packet.addr).await?;
        sent += 1;
    }
    Ok(sent)
}

pub fn recv_batch(fd: SocketFd, bufs: &mut [MsgBuf]) -> io::Result<usize> {
    let mut state = RecvBatchState::new(bufs.len());
    recv_batch_with_state(fd, bufs, &mut state)
}

pub fn send_batch(fd: SocketFd, packets: &[DatagramRef<'_>]) -> io::Result<usize> {
    let mut state = SendBatchState::new(packets.len());
    send_batch_with_state(fd, packets, &mut state)
}

#[cfg(all(target_os = "linux", feature = "mmsg"))]
pub fn recv_batch_with_state(
    fd: SocketFd,
    bufs: &mut [MsgBuf],
    state: &mut RecvBatchState,
) -> io::Result<usize> {
    if bufs.is_empty() {
        return Ok(0);
    }

    state.ensure_capacity(bufs.len());
    for (index, msg) in bufs.iter_mut().enumerate() {
        msg.reset();
        state.addrs[index] = unsafe { std::mem::zeroed() };
        state.iovecs[index] = libc::iovec {
            iov_base: msg.payload_mut_full().as_mut_ptr().cast(),
            iov_len: msg.payload_mut_full().len(),
        };
        state.hdrs[index] = libc::mmsghdr {
            msg_hdr: libc::msghdr {
                msg_name: (&mut state.addrs[index] as *mut libc::sockaddr_storage).cast(),
                msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
                msg_iov: &mut state.iovecs[index] as *mut libc::iovec,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            msg_len: 0,
        };
    }

    let recv_count = unsafe {
        libc::recvmmsg(
            fd,
            state.hdrs.as_mut_ptr(),
            bufs.len() as u32,
            0,
            std::ptr::null_mut(),
        )
    };
    if recv_count < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        return Err(err);
    }

    let recv_count = recv_count as usize;
    for (index, buf) in bufs.iter_mut().enumerate().take(recv_count) {
        let msg_len = state.hdrs[index].msg_len as usize;
        buf.set_len(msg_len);
        let addr = sockaddr_storage_to_addr(
            &state.addrs[index],
            state.hdrs[index].msg_hdr.msg_namelen as usize,
        )?;
        buf.set_addr(addr);
    }

    Ok(recv_count)
}

#[cfg(not(all(target_os = "linux", feature = "mmsg")))]
pub fn recv_batch_with_state(
    fd: SocketFd,
    bufs: &mut [MsgBuf],
    state: &mut RecvBatchState,
) -> io::Result<usize> {
    let _ = (fd, bufs, state);
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "recvmmsg is unavailable on this target or feature set",
    ))
}

#[cfg(all(target_os = "linux", feature = "mmsg"))]
pub fn send_batch_with_state(
    fd: SocketFd,
    packets: &[DatagramRef<'_>],
    state: &mut SendBatchState,
) -> io::Result<usize> {
    if packets.is_empty() {
        return Ok(0);
    }

    state.ensure_capacity(packets.len());
    for (index, packet) in packets.iter().enumerate() {
        state.iovecs[index] = libc::iovec {
            iov_base: packet.payload.as_ptr().cast_mut().cast(),
            iov_len: packet.payload.len(),
        };
        let namelen = socket_addr_to_storage(packet.addr, &mut state.addrs[index]);
        state.hdrs[index] = libc::mmsghdr {
            msg_hdr: libc::msghdr {
                msg_name: (&mut state.addrs[index] as *mut libc::sockaddr_storage).cast(),
                msg_namelen: namelen,
                msg_iov: &mut state.iovecs[index] as *mut libc::iovec,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            msg_len: 0,
        };
    }

    let sent = unsafe { libc::sendmmsg(fd, state.hdrs.as_mut_ptr(), packets.len() as u32, 0) };
    if sent < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        return Err(err);
    }
    Ok(sent as usize)
}

#[cfg(not(all(target_os = "linux", feature = "mmsg")))]
pub fn send_batch_with_state(
    fd: SocketFd,
    packets: &[DatagramRef<'_>],
    state: &mut SendBatchState,
) -> io::Result<usize> {
    let _ = (fd, packets, state);
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "sendmmsg is unavailable on this target or feature set",
    ))
}

#[cfg(all(target_os = "linux", feature = "mmsg"))]
fn socket_addr_to_storage(
    addr: SocketAddr,
    storage: &mut libc::sockaddr_storage,
) -> libc::socklen_t {
    unsafe {
        std::ptr::write_bytes(
            storage as *mut libc::sockaddr_storage as *mut u8,
            0,
            std::mem::size_of::<libc::sockaddr_storage>(),
        );
    }

    match addr {
        SocketAddr::V4(addr_v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr_v4.port().to_be(),
                sin_addr: libc::in_addr {
                    // `sockaddr_in` stores the IPv4 bytes in network order.
                    // `from_ne_bytes` ensures the in-memory byte sequence matches
                    // the octets on both little- and big-endian hosts.
                    s_addr: u32::from_ne_bytes(addr_v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::write(
                    storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in,
                    sin,
                );
            }
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(addr_v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr_v6.port().to_be(),
                sin6_flowinfo: addr_v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr_v6.ip().octets(),
                },
                sin6_scope_id: addr_v6.scope_id(),
            };
            unsafe {
                std::ptr::write(
                    storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6,
                    sin6,
                );
            }
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

#[cfg(all(target_os = "linux", feature = "mmsg"))]
fn sockaddr_storage_to_addr(
    storage: &libc::sockaddr_storage,
    namelen: usize,
) -> io::Result<SocketAddr> {
    let family = storage.ss_family as i32;
    match family {
        libc::AF_INET => {
            if namelen < std::mem::size_of::<libc::sockaddr_in>() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid sockaddr_in size",
                ));
            }
            let sin: libc::sockaddr_in =
                unsafe { *(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            if namelen < std::mem::size_of::<libc::sockaddr_in6>() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid sockaddr_in6 size",
                ));
            }
            let sin6: libc::sockaddr_in6 =
                unsafe { *(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported address family",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(target_os = "linux", feature = "mmsg"))]
    #[test]
    fn ipv4_sockaddr_round_trip() {
        let addr: SocketAddr = "127.0.0.1:4242".parse().expect("valid ipv4 addr");
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let len = socket_addr_to_storage(addr, &mut storage);
        let decoded =
            sockaddr_storage_to_addr(&storage, len as usize).expect("decode sockaddr storage");
        assert_eq!(decoded, addr);
    }

    #[cfg(all(target_os = "linux", feature = "mmsg"))]
    #[test]
    fn ipv6_sockaddr_round_trip() {
        let addr: SocketAddr = "[::1]:5151".parse().expect("valid ipv6 addr");
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let len = socket_addr_to_storage(addr, &mut storage);
        let decoded =
            sockaddr_storage_to_addr(&storage, len as usize).expect("decode sockaddr storage");
        assert_eq!(decoded, addr);
    }
}
