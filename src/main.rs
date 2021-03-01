use std::net::{IpAddr, SocketAddr};

use clap::{crate_description, crate_name, crate_version, value_t, App, Arg};
use futures_util::stream::SplitSink;
use futures_util::stream::SplitStream;
use futures_util::{SinkExt, StreamExt};
use log::LevelFilter;
use log::{debug, error, info, warn};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    accept_async, connect_async, tungstenite::protocol::Message, WebSocketStream,
};

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use ws_tun::device::allowed_ips::AllowedIps;
use ws_tun::device::tun::TunSocket;
use ws_tun::device::Tun;
use ws_tun::logger;
use ws_tun::utils::{next_ip_of, read_dst_ip, read_src_ip, AllowedIP, IfConfig};

const MAX_PACKET_SIZE: usize = (1 << 16) - 1;

struct ClientInfo {
    ws_write: RwLock<SplitSink<WebSocketStream<TcpStream>, Message>>,
    peer_addr: SocketAddr,
}

async fn server_ws_to_tun(
    tun: Arc<TunSocket>,
    mut read: SplitStream<WebSocketStream<TcpStream>>,
    client_ip: IpAddr,
    allowed_ips: AllowedIps<()>,
    route_table: Arc<RwLock<HashMap<IpAddr, ClientInfo>>>,
) {
    loop {
        match read.next().await {
            None => break,
            Some(Ok(Message::Text(_txt))) => {}
            Some(Ok(Message::Binary(bin))) => match read_src_ip(&bin) {
                Ok(addr) if allowed_ips.find(addr).is_some() => {
                    if addr.is_ipv4() {
                        tun.write4(&bin);
                    } else {
                        tun.write6(&bin);
                    }
                }
                Ok(addr) => warn!("drop source packet from {}", addr),
                Err(_) => break,
            },
            Some(Ok(Message::Ping(_bin))) => {}
            Some(Ok(Message::Pong(_bin))) => {}
            Some(Ok(Message::Close(_))) => break,
            Some(Err(_)) => break,
        }
    }
    match route_table.write().await.remove(&client_ip) {
        None => warn!("removing client error, the item doesn't exist"),
        Some(info) => info!("client {} terminated", info.peer_addr),
    }
}

async fn server_tun_to_ws(
    tun: Arc<TunSocket>,
    route_table: Arc<RwLock<HashMap<IpAddr, ClientInfo>>>,
) {
    let mut buf = [0u8; MAX_PACKET_SIZE];
    loop {
        match tun.read(&mut buf) {
            Ok(bin) => {
                match read_dst_ip(bin) {
                    Ok(ip) => match route_table.read().await.get(&ip) {
                        Some(info) => {
                            match info
                                .ws_write
                                .write()
                                .await
                                .send(Message::Binary(Vec::from(bin)))
                                .await
                            {
                                Ok(_) => {}
                                Err(e) => error!("error while sending data to {}: {}", ip, e),
                            }
                        }
                        None => debug!("destination {} is not found", ip),
                    },
                    Err(msg) => {
                        error!("failed to parse ip from received packet: {}", msg);
                    }
                };
            }
            Err(_) => {
                break;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    log::set_logger(&logger::LOGGER).unwrap();
    log::set_max_level(LevelFilter::Info);

    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .arg(
            Arg::with_name("tun")
                .short("t")
                .long("tun")
                .value_name("TUN_NAME")
                .help("tun name. in macOS, it should be utun[0-9]+. default utun")
                .default_value("utun")
                .required(false),
        )
        .arg(
            Arg::with_name("server-url")
                .short("s")
                .long("server-url")
                .value_name("SERVER_URL")
                .help("the URL of server to listening on (<Bind IP>:<Port>, e.g.: 127.0.0.1:8080) or client connecting to (e.g.: ws://127.0.0.1:8080/path, wss://foo.com/path).")
                .required(true),
        )
        .arg(
            Arg::with_name("subnet")
                .short("n")
                .long("subnet")
                .value_name("SUBNET")
                .help("(server option) the subnet server is working on. server will use the first address.")
                .default_value("172.27.0.1/24")
                .required(false),
        )
        .arg(
            Arg::with_name("mtu")
                .short("m")
                .long("mtu")
                .value_name("MTU")
                .help("(server option) max transfer unit")
                .default_value("1400")
                .required(false),
        )
        .arg(
            Arg::with_name("max-client")
                .short("x")
                .long("max-client")
                .value_name("MAX_NUMBER_OF_CLIENTS")
                .help("(server option) max number of clients connected at the same time")
                .default_value("32")
                .required(false),
        )
        .get_matches();

    let tun_name = matches.value_of("tun").unwrap_or("utun");
    let server_url = matches
        .value_of("server-url")
        .expect("server url is required.");
    let mut subnet =
        value_t!(matches.value_of("subnet"), AllowedIP).expect("should be a valid subnet config");
    subnet.unify();
    let subnet = subnet;
    let mtu = value_t!(matches.value_of("mtu"), usize).expect("should be a valid mtu config");
    let max_client = value_t!(matches.value_of("max-client"), usize)
        .expect("should be a valid number of max-client config");
    let is_client_mode = server_url.starts_with("ws");

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        ws_tun::device::tun::parse_utun_name(&tun_name)
            .expect("macOS tun name should be utun[0-9]+.");
    }

    let tun = Arc::new(TunSocket::new(tun_name).unwrap());
    println!("mtu {}", tun.mtu().unwrap());

    if is_client_mode {
        let (ws_stream, _) = connect_async(server_url)
            .await
            .expect("should connect to server success");
        let (mut write, mut read) = ws_stream.split();
        match read.next().await {
            Some(Ok(Message::Text(init))) => {
                let if_config: IfConfig = init
                    .parse()
                    .expect("should parse server if config correctly");
                if_config.setup_tun(tun_name).await;
            }
            _ => {
                error!("unexpected response from server, expecting text message for setup tun interface");
                return;
            }
        }
        let tun_read = tun.clone();
        tokio::spawn(async move {
            let mut allowed_ips: AllowedIps<()> = Default::default();
            allowed_ips.insert("0.0.0.0/0".parse().unwrap(), 0, ());
            allowed_ips.insert("0::/0".parse().unwrap(), 0, ());
            loop {
                match read.next().await {
                    None => break,
                    Some(Ok(Message::Text(_txt))) => {}
                    Some(Ok(Message::Binary(bin))) => match read_src_ip(&bin) {
                        Ok(addr) if allowed_ips.find(addr).is_some() => {
                            if addr.is_ipv4() {
                                tun.write4(&bin);
                            } else {
                                tun.write6(&bin);
                            }
                        }
                        Ok(addr) => warn!("drop source packet from {}", addr),
                        Err(_) => break,
                    },
                    Some(Ok(Message::Ping(_bin))) => {}
                    Some(Ok(Message::Pong(_bin))) => {}
                    Some(Ok(Message::Close(_))) => break,
                    Some(Err(_)) => break,
                }
            }
        });
        tokio::spawn(async move {
            let mut buf = [0u8; MAX_PACKET_SIZE];
            loop {
                match tun_read.read(&mut buf) {
                    Ok(bin) => match write.send(Message::Binary(Vec::from(bin))).await {
                        Ok(_) => {}
                        Err(_) => {
                            break;
                        }
                    },
                    Err(_) => {
                        break;
                    }
                }
            }
        });
    } else {
        let listener = TcpListener::bind(&server_url)
            .await
            .expect("should bind server tcp listener successfully");
        info!("Listening on: {}", server_url);

        let server_ip = next_ip_of(&subnet.addr);

        let if_config = IfConfig {
            mtu,
            addresses: vec![AllowedIP {
                addr: server_ip,
                cidr: subnet.cidr,
            }],
            routes: vec![],
        };
        if_config.setup_tun(tun_name).await;

        let route_table: Arc<RwLock<HashMap<IpAddr, ClientInfo>>> =
            Arc::new(RwLock::new(HashMap::new()));

        tokio::spawn(server_tun_to_ws(tun.clone(), route_table.clone()));

        let allocation_start_ip = next_ip_of(&server_ip);
        let allocation_end_ip = subnet.last_valid_ip();
        let mut previous_allocated_ip = server_ip;

        while let Ok((stream, _)) = listener.accept().await {
            let peer_addr = stream
                .peer_addr()
                .expect("connected streams should have a peer address");
            info!("Peer address: {}", peer_addr);

            let ws_stream = accept_async(stream)
                .await
                .expect("Error during the websocket handshake occurred");

            let (mut ws_write, ws_read) = ws_stream.split();

            let new_ip = {
                let mut writable_table = route_table.write().await;
                if writable_table.len() > max_client {
                    warn!(
                        "max client number {} reached, the client will be disconnected.",
                        max_client
                    );
                    continue;
                }
                let mut new_ip: IpAddr;
                loop {
                    new_ip = next_ip_of(&previous_allocated_ip);
                    if new_ip == allocation_end_ip {
                        new_ip = allocation_start_ip;
                    }
                    if !writable_table.contains_key(&new_ip) {
                        break;
                    }
                }
                previous_allocated_ip = new_ip;
                let net_addr = AllowedIP {
                    addr: new_ip,
                    cidr: subnet.cidr,
                };
                let if_config = IfConfig {
                    mtu,
                    addresses: vec![net_addr],
                    routes: vec![],
                };
                match ws_write.send(Message::Text(if_config.to_string())).await {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("failed to send if config to client: {}", e);
                        continue;
                    }
                }
                writable_table.insert(
                    net_addr.addr,
                    ClientInfo {
                        peer_addr,
                        ws_write: RwLock::new(ws_write),
                    },
                );
                new_ip
            };
            let new_ip_length = if new_ip.is_ipv4() { 32 } else { 128 };

            let mut allowed_ips: AllowedIps<()> = Default::default();
            allowed_ips.insert(new_ip, new_ip_length, ());
            tokio::spawn(server_ws_to_tun(
                tun.clone(),
                ws_read,
                new_ip,
                allowed_ips,
                route_table.clone(),
            ));
        }
    }

    ()
}
