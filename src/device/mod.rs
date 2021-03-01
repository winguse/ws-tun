use std::os::unix::io::AsRawFd;

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
    fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error>;
}
