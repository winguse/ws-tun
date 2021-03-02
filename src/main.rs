use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use clap::{crate_description, crate_name, crate_version, value_t, App, Arg};
use futures_util::stream::SplitSink;
use futures_util::stream::SplitStream;
use futures_util::{SinkExt, StreamExt};
use log::LevelFilter;
use log::{debug, error, info, warn};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::{
    accept_async, connect_async, tungstenite::protocol::Message, WebSocketStream,
};

use ws_tun::device::allowed_ips::AllowedIps;
use ws_tun::device::tun::TunSocket;
use ws_tun::device::Tun;
use ws_tun::logger;
use ws_tun::utils::{next_ip_of, read_dst_ip, read_src_ip, AllowedIP, IfConfig};

const MAX_PACKET_SIZE: usize = (1 << 16) - 1;

struct ClientInfo {
    ws_write: RwLock<SplitSink<WebSocketStream<TcpStream>, Message>>,
    remote_addr: SocketAddr,
}

enum ClientTask {
    WS,
    TUN,
}

async fn server_ws_to_tun(
    tun: Arc<TunSocket>,
    mut read: SplitStream<WebSocketStream<TcpStream>>,
    client_ip: IpAddr,
    allowed_ips: AllowedIps<()>,
    route_table: Arc<RwLock<HashMap<IpAddr, ClientInfo>>>,
) {
    loop {
        debug!("server ws: wait for packet");
        match read.next().await {
            None => break,
            Some(Ok(Message::Text(_txt))) => {}
            Some(Ok(Message::Binary(bin))) => match read_src_ip(&bin) {
                Ok(addr) if allowed_ips.find(addr).is_some() => {
                    debug!("got ws from {}", addr);
                    if addr.is_ipv4() {
                        tun.write4(&bin);
                    } else {
                        tun.write6(&bin);
                    }
                }
                Ok(addr) => warn!("server ws: drop source packet from {}", addr),
                Err(_) => break,
            },
            Some(Ok(Message::Ping(_bin))) => {}
            Some(Ok(Message::Pong(_bin))) => {}
            Some(Ok(Message::Close(_))) => break,
            Some(Err(_)) => break,
        }
    }
    match route_table.write().await.remove(&client_ip) {
        None => warn!("server ws: removing client error, the item doesn't exist"),
        Some(info) => info!("server ws: client {} terminated", info.remote_addr),
    }
}

async fn server_tun_to_ws(
    mut tun_read_rx: Receiver<Vec<u8>>,
    route_table: Arc<RwLock<HashMap<IpAddr, ClientInfo>>>,
    tun_tx: Sender<ClientTask>,
) {
    loop {
        debug!("server tun: wait for packet");
        match tun_read_rx.recv().await {
            None => {
                error!("server tun: receive nothing");
                break;
            }
            Some(bin) => {
                match read_dst_ip(&bin) {
                    Ok(ip) => match route_table.read().await.get(&ip) {
                        Some(info) => {
                            match info
                                .ws_write
                                .write()
                                .await
                                .send(Message::Binary(Vec::from(bin)))
                                .await
                            {
                                Ok(_) => debug!("server tun: sending data to {}", ip),
                                Err(e) => error!("error while sending data to {}: {}", ip, e),
                            }
                        }
                        None => info!("destination {} is not found, dropped", ip),
                    },
                    Err(msg) => {
                        error!("failed to parse ip from received packet: {}", msg);
                    }
                };
            }
        }
    }
    info!("server tun: exit");
    let _ = tun_tx.send(ClientTask::TUN).await;
}

#[tokio::main]
async fn main() {
    log::set_logger(&logger::LOGGER).unwrap();
    log::set_max_level(LevelFilter::Info);

    let matches = {
        App::new(crate_name!())
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
            .get_matches()
    };

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
    let tun_name = tun.name().expect("should get tun name success");
    info!("name: {}, mtu: {}", tun_name, tun.mtu().unwrap());

    let (tun_tx, ws_tx, mut ch_rx) = {
        let (tx, rx) = mpsc::channel(1);
        (tx.clone(), tx, rx)
    };

    let (tun_read_tx, mut tun_read_rx) = mpsc::channel(1);
    let tun_read = tun.clone();
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        loop {
            match tun_read.read(&mut buf) {
                Ok(bin) => {
                    let msg = Vec::from(bin);
                    match tun_read_tx.blocking_send(msg) {
                        Ok(_) => {}
                        Err(_) => {
                            error!("error while sending tun read");
                        }
                    }
                }
                Err(_) => error!("error while reading tun"),
            }
        }
    });

    if is_client_mode {
        info!("connecting to {}", server_url);
        let (ws_stream, _) = connect_async(server_url)
            .await
            .expect("should connect to server success");
        info!("client connected");
        let (mut write, mut read) = ws_stream.split();
        match read.next().await {
            Some(Ok(Message::Text(init))) => {
                info!("server config: {}", init);
                let if_config: IfConfig = init
                    .parse()
                    .expect("should parse server if config correctly");
                if_config.setup_tun(tun_name.as_str()).await;
            }
            _ => {
                error!("unexpected response from server, expecting text message for setup tun interface");
                return;
            }
        }

        let client_ws_task = tokio::task::spawn(async move {
            let mut allowed_ips: AllowedIps<()> = Default::default();
            allowed_ips.insert("0.0.0.0".parse().unwrap(), 0, ());
            allowed_ips.insert("0::".parse().unwrap(), 0, ());
            loop {
                debug!("client ws: wait for packet");
                match read.next().await {
                    None => break,
                    Some(Ok(Message::Text(_txt))) => {}
                    Some(Ok(Message::Binary(bin))) => match read_src_ip(&bin) {
                        Ok(addr) if allowed_ips.find(addr).is_some() => {
                            debug!("client ws: got package from {}", addr);
                            if addr.is_ipv4() {
                                tun.write4(&bin);
                            } else {
                                tun.write6(&bin);
                            }
                        }
                        Ok(addr) => warn!("client ws: drop source packet from {}", addr),
                        Err(_) => break,
                    },
                    Some(Ok(Message::Ping(_bin))) => {}
                    Some(Ok(Message::Pong(_bin))) => {}
                    Some(Ok(Message::Close(_))) => break,
                    Some(Err(_)) => break,
                }
            }
            info!("client ws: exit");
            let _ = ws_tx.send(ClientTask::WS).await;
        });
        let client_tun_task = tokio::task::spawn(async move {
            loop {
                debug!("client tun: wait for tun package");
                match tun_read_rx.recv().await {
                    None => {
                        error!("client tun: receive nothing");
                        break;
                    }
                    Some(bin) => match write.send(Message::Binary(Vec::from(bin))).await {
                        Ok(_) => debug!("client tun: send to ws"),
                        Err(_) => break,
                    },
                }
            }
            info!("client tun: exit");
            let _ = tun_tx.send(ClientTask::TUN).await;
        });
        match ch_rx.recv().await.expect("should receive exit task id") {
            ClientTask::WS => client_tun_task.abort(),
            ClientTask::TUN => client_ws_task.abort(),
        }
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
        if_config.setup_tun(tun_name.as_str()).await;

        let route_table: Arc<RwLock<HashMap<IpAddr, ClientInfo>>> =
            Arc::new(RwLock::new(HashMap::new()));

        let server_tun_task =
            tokio::task::spawn(server_tun_to_ws(tun_read_rx, route_table.clone(), tun_tx));

        let allocation_start_ip = next_ip_of(&server_ip);
        let allocation_end_ip = subnet.last_valid_ip();
        let mut previous_allocated_ip = server_ip;

        info!("Server IP: {}", server_ip);
        info!("IP pool: {} ~ {}", allocation_start_ip, allocation_end_ip);

        let server_ws_task = tokio::task::spawn(async move {
            let _ = ws_tx; // we are not using this for now, as the loop never exist itself
            loop {
                let tcp_stream = match listener.accept().await {
                    Ok((stream, _)) => stream,
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                        continue;
                    }
                };
                debug!("accepted connection");
                let remote_addr = match tcp_stream.peer_addr() {
                    Ok(remote_addr) => {
                        info!("Peer address: {}", remote_addr);
                        remote_addr
                    }
                    Err(e) => {
                        error!("Failed to get peer addr: {}", e);
                        continue;
                    }
                };
                debug!("accepting websocket..");

                let ws_stream = match accept_async(tcp_stream).await {
                    Ok(ws_stream) => ws_stream,
                    Err(e) => {
                        error!("Failed to accept web socket stream: {}", e);
                        continue;
                    }
                };

                let (mut ws_write, ws_read) = ws_stream.split();

                info!("generating ip for the client");

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
                        routes: vec![net_addr],
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
                            remote_addr,
                            ws_write: RwLock::new(ws_write),
                        },
                    );
                    new_ip
                };
                let new_ip_length = if new_ip.is_ipv4() { 32 } else { 128 };

                info!("client ip: {}", new_ip);

                let mut allowed_ips: AllowedIps<()> = Default::default();
                allowed_ips.insert(new_ip, new_ip_length, ());
                tokio::task::spawn(server_ws_to_tun(
                    tun.clone(),
                    ws_read,
                    new_ip,
                    allowed_ips,
                    route_table.clone(),
                ));
            }
            // Never be here for now
            // info!("server ws: exit");
            // let _ = ws_tx.send(ClientTask::WS).await;
        });
        match ch_rx.recv().await.expect("should receive exit task id") {
            ClientTask::WS => server_tun_task.abort(),
            ClientTask::TUN => server_ws_task.abort(),
        }
    }

    ()
}
