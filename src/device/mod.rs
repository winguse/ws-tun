use crate::device::tun::TunSocket;
use std::future::Future;
use std::os::unix::io::AsRawFd;
use std::pin::Pin;
use std::task::Poll::{Pending, Ready};
use std::task::{Context, Poll};

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[path = "tun_darwin.rs"]
pub mod tun;

#[cfg(target_os = "linux")]
#[path = "tun_linux.rs"]
pub mod tun;

pub mod allowed_ips;

#[derive(Debug)]
pub enum Error {
    Socket(String),
    Bind(String),
    FCntl(String),
    EventQueue(String),
    IOCtl(String),
    Connect(String),
    SetSockOpt(String),
    InvalidTunnelName,
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    GetSockOpt(String),
    GetSockName(String),
    UDPRead(i32),
    #[cfg(target_os = "linux")]
    Timer(String),
    IfaceRead(i32),
    DropPrivileges(String),
    ApiSocket(std::io::Error),
}

// The trait satisfied by tunnel device implementations.
pub trait Tun: 'static + AsRawFd + Sized + Send + Sync {
    fn new(name: &str) -> Result<Self, Error>;
    fn set_non_blocking(self) -> Result<Self, Error>;

    fn name(&self) -> Result<String, Error>;
    fn mtu(&self) -> Result<usize, Error>;

    fn write4(&self, src: &[u8]) -> usize;
    fn write6(&self, src: &[u8]) -> usize;
    fn read<'a>(&self, dst: &'a mut [u8]) -> Result<usize, Error>;
}

pub struct TunRead<'a> {
    tun: &'a TunSocket,
    dst: &'a mut [u8],
}

impl<'a> TunRead<'a> {
    pub fn read(&mut self) -> Result<usize, Error> {
        self.tun.read(&mut self.dst)
    }
}

pub fn tun_read<'a>(tun: &'a TunSocket, dst: &'a mut [u8]) -> TunRead<'a> {
    TunRead { tun, dst }
}

impl<'a> Future for TunRead<'a> {
    type Output = Result<usize, Error>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.read() {
            Ok(len) => Ready(Ok(len)),
            Err(Error::IfaceRead(errno)) => {
                let ek = std::io::Error::from_raw_os_error(errno).kind();
                if ek == std::io::ErrorKind::Interrupted || ek == std::io::ErrorKind::WouldBlock {
                    // cx.waker().wake(); // what's this?
                    Pending
                } else {
                    Ready(Err(Error::IfaceRead(errno)))
                }
            }
            Err(e) => Ready(Err(e)),
        }
    }
}
