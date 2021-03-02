use std::fmt;
use std::fmt::Formatter;
use std::net::IpAddr;
use std::str::FromStr;

use tokio::process::Command;

pub const IPV4_MIN_HEADER_SIZE: usize = 20;
pub const IPV4_LEN_OFF: usize = 2;
pub const IPV4_SRC_IP_OFF: usize = 12;
pub const IPV4_DST_IP_OFF: usize = 16;
pub const IPV4_IP_SZ: usize = 4;

pub const IPV6_MIN_HEADER_SIZE: usize = 40;
pub const IPV6_LEN_OFF: usize = 4;
pub const IPV6_SRC_IP_OFF: usize = 8;
pub const IPV6_DST_IP_OFF: usize = 24;
pub const IPV6_IP_SZ: usize = 16;

pub const IP_LEN_SZ: usize = 2;

#[inline(always)]
pub fn make_array<A, T>(slice: &[T]) -> A
where
    A: Sized + Default + AsMut<[T]> + std::borrow::Borrow<[T]>,
    T: Copy,
{
    let mut arr: A = Default::default();
    let arr_len = arr.borrow().len();
    <A as AsMut<[T]>>::as_mut(&mut arr).copy_from_slice(&slice[0..arr_len]);
    arr
}

fn read_ip_packet(packet: &[u8], source: bool) -> Result<IpAddr, String> {
    if packet.len() == 0 {
        return Err(String::from("empty packet"));
    }
    match packet[0] >> 4 {
        4 if packet.len() >= IPV4_MIN_HEADER_SIZE => {
            let off = if source {
                IPV4_SRC_IP_OFF
            } else {
                IPV4_DST_IP_OFF
            };
            let addr_bytes: [u8; IPV4_IP_SZ] = make_array(&packet[off..]);
            Ok(IpAddr::from(addr_bytes))
        }
        6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
            let off = if source {
                IPV6_SRC_IP_OFF
            } else {
                IPV6_DST_IP_OFF
            };
            let addr_bytes: [u8; IPV6_IP_SZ] = make_array(&packet[off..]);
            Ok(IpAddr::from(addr_bytes))
        }
        _ => Err(String::from("invalid packet")),
    }
}

pub fn read_src_ip(packet: &[u8]) -> Result<IpAddr, String> {
    read_ip_packet(packet, true)
}

pub fn read_dst_ip(packet: &[u8]) -> Result<IpAddr, String> {
    read_ip_packet(packet, false)
}

#[derive(Copy, Clone, Debug)]
pub struct AllowedIP {
    pub addr: IpAddr,
    pub cidr: u8,
}

fn compare_bytes(len: u8, a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut c = len;
    for i in 0..a.len() {
        if c == 0 {
            break;
        }
        let s = if c <= 0 {
            break;
        } else if c >= 8 {
            0
        } else {
            8 - c
        };
        if (a[i] >> s) != (b[i] >> s) {
            return false;
        }
        if c <= 8 {
            break;
        }
        c -= 8;
    }
    true
}

fn reset_by_mask(cidr: u8, bytes: &mut [u8]) {
    let total_bits = bytes.len() << 3; // * 8
    for pos in cidr as usize..total_bits {
        let i = pos >> 3;
        let b = 7 - (pos & 7);
        let m = 1u8 << b;
        bytes[i] &= !m;
    }
}

fn set_by_mask(cidr: u8, bytes: &mut [u8]) {
    let total_bits = bytes.len() << 3; // * 8
    for pos in cidr as usize..total_bits {
        let i = pos >> 3;
        let b = 7 - (pos & 7);
        let m = 1u8 << b;
        bytes[i] |= !m;
    }
}

impl AllowedIP {
    pub fn unify(&mut self) {
        self.addr = match self.addr {
            IpAddr::V4(ip) => {
                let mut bytes = ip.octets();
                reset_by_mask(self.cidr, &mut bytes);
                IpAddr::from(bytes)
            }
            IpAddr::V6(ip) => {
                let mut bytes = ip.octets();
                reset_by_mask(self.cidr, &mut bytes);
                IpAddr::from(bytes)
            }
        };
    }

    pub fn has(&self, other: &IpAddr) -> bool {
        match (self.addr, other) {
            (IpAddr::V4(a), IpAddr::V4(b)) => compare_bytes(self.cidr, &a.octets(), &b.octets()),
            (IpAddr::V6(a), IpAddr::V6(b)) => compare_bytes(self.cidr, &a.octets(), &b.octets()),
            _ => false,
        }
    }

    pub fn last_valid_ip(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(ip) => {
                let mut bytes = ip.octets();
                set_by_mask(self.cidr, &mut bytes);
                IpAddr::from(bytes)
            }
            IpAddr::V6(ip) => {
                let mut bytes = ip.octets();
                set_by_mask(self.cidr, &mut bytes);
                IpAddr::from(bytes)
            }
        }
    }
}

#[test]
fn get_last_ip_correctly() {
    let net: AllowedIP = "192.168.123.55/24".parse().unwrap();
    let expected: IpAddr = "192.168.123.255".parse().unwrap();
    assert_eq!(net.last_valid_ip(), expected)
}

#[test]
fn judge_inside_range_correctly() {
    fn test(range_str: &str, ip_str: &str, expected: bool) {
        let range: AllowedIP = range_str.parse().unwrap();
        let ip: IpAddr = ip_str.parse().unwrap();
        assert_eq!(
            range.has(&ip),
            expected,
            "{} has {} should be {}",
            range_str,
            ip_str,
            expected
        );
    }

    test("192.168.123.0/24", "192.168.123.0", true);
    test("192.168.123.0/24", "192.168.123.1", true);
    test("192.168.123.0/24", "192.168.123.255", true);
    test("192.168.123.0/24", "192.168.124.0", false);
    test("192.168.0.0/23", "192.168.1.0", true);
    test("192.168.1.0/23", "192.168.0.0", true);
    test("192.168.0.0/23", "192.168.2.0", false);
}

#[test]
fn new_net_address_correctly() {
    let net = AllowedIP {
        addr: "192.168.123.45".parse().unwrap(),
        cidr: 24,
    };
    let expected: IpAddr = "192.168.123.0".parse().unwrap();
    assert_eq!(net.addr, expected);
}

pub fn add_one(bytes: &mut [u8]) {
    for i in (0..bytes.len()).rev() {
        if bytes[i] == 0xff {
            bytes[i] = 0;
        } else {
            bytes[i] += 1;
            break;
        }
    }
}

pub fn next_ip_of(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let mut bytes = v4.octets();
            add_one(&mut bytes);
            IpAddr::from(bytes)
        }
        IpAddr::V6(v6) => {
            let mut bytes = v6.octets();
            add_one(&mut bytes);
            IpAddr::from(bytes)
        }
    }
}

#[test]
fn next_ip_of_correctly() {
    fn test(a: &str, b: &str) {
        let result = next_ip_of(&a.parse().unwrap());
        let expected: IpAddr = b.parse().unwrap();
        assert_eq!(result, expected);
    }

    test("192.168.123.0", "192.168.123.1");
    test("192.168.123.255", "192.168.124.0");
    test("192.168.255.255", "192.169.0.0");
}

impl fmt::Display for AllowedIP {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.cidr)
    }
}

impl FromStr for AllowedIP {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: Vec<&str> = s.split('/').collect();
        if ip.len() != 2 {
            return Err("Invalid IP format".to_owned());
        }

        let (addr, cidr) = (ip[0].parse::<IpAddr>(), ip[1].parse::<u8>());
        match (addr, cidr) {
            (Ok(addr @ IpAddr::V4(_)), Ok(cidr)) if cidr <= 32 => Ok(AllowedIP { addr, cidr }),
            (Ok(addr @ IpAddr::V6(_)), Ok(cidr)) if cidr <= 128 => Ok(AllowedIP { addr, cidr }),
            _ => Err("Invalid IP format".to_owned()),
        }
    }
}

#[test]
fn net_address_display_and_parse() {
    let mut net: AllowedIP = "192.168.32.43/24".parse().unwrap();
    let ip: IpAddr = "192.168.32.43".parse().unwrap();
    assert_eq!(net.addr, ip);
    assert_eq!(net.to_string(), "192.168.32.43/24");

    net.unify();
    let ip: IpAddr = "192.168.32.0".parse().unwrap();
    assert_eq!(net.addr, ip);
    assert_eq!(net.to_string(), "192.168.32.0/24");
}

pub struct IfConfig {
    pub mtu: usize,
    pub addresses: Vec<AllowedIP>,
    pub routes: Vec<AllowedIP>,
}

fn vec_address_to_str(addresses: &Vec<AllowedIP>) -> String {
    addresses
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<String>>()
        .join(",")
}

fn str_to_vec_address(str: &str) -> Result<Vec<AllowedIP>, String> {
    let mut res: Vec<AllowedIP> = vec![];
    if str.len() > 0 {
        for item in str.split(",") {
            match item.parse() {
                Ok(addr) => {
                    res.push(addr);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }
    Ok(res)
}

impl FromStr for IfConfig {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut splits = s.split(";");
        match (splits.next(), splits.next(), splits.next()) {
            (Some(mtu_str), Some(addresses_str), Some(route_str)) => {
                let mtu: usize = match mtu_str.parse() {
                    Ok(v) => v,
                    Err(e) => return Err(e.to_string()),
                };
                let addresses = match str_to_vec_address(addresses_str) {
                    Ok(v) => v,
                    Err(e) => return Err(e),
                };
                let routes = match str_to_vec_address(route_str) {
                    Ok(v) => v,
                    Err(e) => return Err(e),
                };
                Ok(IfConfig {
                    mtu,
                    addresses,
                    routes,
                })
            }
            _ => return Err(format!("invalid IfConfig str: {}", s)),
        }
    }
}

impl fmt::Display for IfConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{};{};{}",
            self.mtu,
            vec_address_to_str(&self.addresses),
            vec_address_to_str(&self.routes)
        )
    }
}

#[test]
fn if_config_string_and_parse() {
    fn test(input: &str) {
        let parsed: IfConfig = input.parse().unwrap();
        let to_str = parsed.to_string();
        assert_eq!(input, to_str)
    }
    test("1234;192.168.12.34/24,192.168.13.34/24;192.168.14.34/24,192.168.15.34/24");
    test("1234;192.168.12.34/24,192.168.13.34/24;");
}

impl IfConfig {
    #[cfg(any(target_os = "linux"))]
    pub async fn setup_tun(&self, tun_name: &str) {
        for addr in &self.addresses {
            Command::new("ip")
                .args(&["address", "add", &addr.to_string(), "dev", &tun_name])
                .status()
                .await
                .expect("failed to assign ip to tunnel");
        }
        Command::new("ip")
            .args(&[
                "link",
                "set",
                "mtu",
                &format!("{}", self.mtu),
                "up",
                "dev",
                &tun_name,
            ])
            .status()
            .await
            .expect("failed to start the tunnel");
        for route in &self.routes {
            Command::new("ip")
                .args(&["route", "add", &route.to_string(), "dev", &tun_name])
                .status()
                .await
                .expect("failed to add route");
        }
    }

    #[cfg(any(target_os = "macos"))]
    pub async fn setup_tun(&self, tun_name: &str) {
        for addr in &self.addresses {
            match addr.addr {
                IpAddr::V4(v4) => {
                    Command::new("ifconfig")
                        .args(&[tun_name, &addr.to_string(), &v4.to_string(), "alias"])
                        .status()
                        .await
                        .expect("failed to assign ip to tunnel");
                }
                IpAddr::V6(v6) => {
                    Command::new("ifconfig")
                        .args(&[
                            tun_name,
                            "inet6",
                            &v6.to_string(),
                            "prefixlen",
                            &format!("{}", addr.cidr),
                            "alias",
                        ])
                        .status()
                        .await
                        .expect("failed to assign ipv6 to tunnel");
                }
            }
        }
        Command::new("ifconfig")
            .args(&[tun_name, "up", "mtu", &format!("{}", self.mtu)])
            .status()
            .await
            .expect("failed to start the tunnel");
        for route in &self.routes {
            let inet_flag = match route.addr {
                IpAddr::V4(_) => "-inet",
                IpAddr::V6(_) => "-inet6",
            };

            Command::new("route")
                .args(&[
                    "-q",
                    "-n",
                    "add",
                    inet_flag,
                    &route.to_string(),
                    "-interface",
                    &tun_name,
                ])
                .status()
                .await
                .expect("failed to add route");
        }
    }
}
