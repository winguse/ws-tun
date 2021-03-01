#[cfg(not(any(target_os = "windows", target_os = "android")))]
pub mod device;

pub mod logger;
pub mod utils;
