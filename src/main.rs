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
use tokio::select;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::spawn;
use tokio::time::{sleep, Duration};
use tokio_tungstenite::{
    accept_async, connect_async, tungstenite::protocol::Message, WebSocketStream,
};
use tokio_util::sync::CancellationToken;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use ws_tun::device::allowed_ips::AllowedIps;
use ws_tun::device::tun::TunSocket;
use ws_tun::device::{AsyncTun, Tun};
use ws_tun::logger;
use ws_tun::utils::{next_ip_of, read_dst_ip, read_src_ip, AllowedIP, IfConfig};

const MAX_PACKET_SIZE: usize = (1 << 16) - 1;

struct ClientInfo {
    ws_write: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
    remote_addr: SocketAddr,
}

/// server handle client web socket connection
async fn server_ws_to_tun(
    tun: Arc<AsyncTun>,
    mut read: SplitStream<WebSocketStream<TcpStream>>,
    client_ip: IpAddr,
    allowed_ips: AllowedIps<()>,
    route_table: Arc<RwLock<HashMap<IpAddr, ClientInfo>>>,
    exit_token: CancellationToken,
) {
    loop {
        debug!("server ws: wait for packet");
        select! {
            _ = exit_token.cancelled() => {
                info!("server ws -> tun exit because receive cancel");
                break;
            }
            res = read.next() => {
                match res {
                    None => break,
                    Some(Ok(Message::Text(_txt))) => {}
                    Some(Ok(Message::Binary(bin))) => match read_src_ip(&bin) {
                        Ok(addr) if allowed_ips.find(addr).is_some() => {
                            debug!("got ws from {}", addr);
                            if addr.is_ipv4() {
                                tun.inner.get_ref().write4(&bin);
                            } else {
                                tun.inner.get_ref().write6(&bin);
                            }
                        }
                        Ok(addr) => warn!("server ws: drop source packet from {}", addr),
                        Err(_) => break,
                    },
                    Some(Ok(Message::Ping(_bin))) => { /* the lib already handled response */ }
                    Some(Ok(Message::Pong(_bin))) => {}
                    Some(Ok(Message::Close(_))) => break,
                    Some(Err(_)) => break,
                }
            }
        }
    }
    match route_table.write().await.remove(&client_ip) {
        None => warn!("server ws: removing client error, the item doesn't exist"),
        Some(info) => info!("server ws: client {} terminated", info.remote_addr),
    }
}

/// server handle package from tun and send to valid destination web socket
async fn server_tun_to_ws(
    mut tun_read_rx: Receiver<Vec<u8>>,
    route_table: Arc<RwLock<HashMap<IpAddr, ClientInfo>>>,
    exit_token: CancellationToken,
) {
    loop {
        debug!("server tun: wait for packet");
        select! {
            _ = exit_token.cancelled() => {
                info!("server tun -> ws exit because receive cancel");
                break;
            }
            res = tun_read_rx.recv() => {
                match res {
                    None => {
                        error!("server tun: receive nothing, exit..");
                        break;
                    }
                    Some(bin) => {
                        match read_dst_ip(&bin) {
                            Ok(ip) => match route_table.read().await.get(&ip) {
                                Some(info) => {
                                    match info
                                        .ws_write
                                        .lock()
                                        .await
                                        .send(Message::Binary(Vec::from(bin)))
                                        .await
                                    {
                                        Ok(_) => debug!("server tun: sending data to {}", ip),
                                        Err(e) => error!("error while sending data to {}: {}", ip, e),
                                    }
                                }
                                None => {
                                    info!("from {} to destination {} is not found, dropped", read_src_ip(&bin).expect("should read ip success"), ip)
                                },
                            },
                            Err(msg) => {
                                error!("failed to parse ip from received packet: {}", msg);
                            }
                        };
                    }
                }
            }
        }
    }
    if !exit_token.is_cancelled() {
        exit_token.cancel();
    }
}

/// the tun reader
/// read the tun package and send to channel
async fn tun_reader(
    async_tun_read: Arc<AsyncTun>,
    sender: Sender<Vec<u8>>,
    exit_token: CancellationToken,
) {
    let mut buf = [0u8; MAX_PACKET_SIZE];
    loop {
        select! {
            _ = exit_token.cancelled() => {
                break;
            }
            res = async_tun_read.read(&mut buf) => {
                match res {
                    Ok(len) => {
                        let msg = Vec::from(&buf[..len]);
                        match sender.send(msg).await {
                            Ok(_) => {}
                            Err(_) => {
                                error!("error while sending tun read");
                            }
                        }
                    }
                    Err(_) => error!("error while reading tun"),
                }
            }
        }
    }
}

/// return the micro seconds from unix epoch
fn get_time() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("should get time success")
        .as_micros()
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
            .arg(
                Arg::with_name("close-timeout")
                    .short("c")
                    .long("close-timeout")
                    .value_name("CLOSE_TIMEOUT")
                    .help("timeout before killing tasks not exit")
                    .default_value("5")
                    .required(false),
            )
            .arg(
                Arg::with_name("hart-beat")
                    .short("h")
                    .long("hard-beat")
                    .value_name("HEART_BEAT")
                    .help("the interval of seconds between sending ping/pong when there is no message, only implemented in client as for now.")
                    .default_value("25")
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
    let close_timeout = value_t!(matches.value_of("close-timeout"), u64)
        .expect("should be a valid number of close-timeout");
    let heart_beat = value_t!(matches.value_of("hart-beat"), u64)
        .expect("should be a valid number of hart-beat");
    let is_client_mode = server_url.starts_with("ws");

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        ws_tun::device::tun::parse_utun_name(&tun_name)
            .expect("macOS tun name should be utun[0-9]+.");
    }

    let exit_token = CancellationToken::new();

    let raw_tun = TunSocket::new(tun_name)
        .expect("create tun success")
        .set_non_blocking()
        .expect("should set non blocked success");

    let tun = Arc::new(AsyncTun::new(raw_tun));

    let tun_name = tun
        .inner
        .get_ref()
        .name()
        .expect("should get tun name success");
    info!(
        "name: {}, mtu: {}",
        tun_name,
        tun.inner.get_ref().mtu().unwrap()
    );

    let tasks = Arc::new(RwLock::new(Vec::new()));

    {
        // create ctrl c task
        let ctrl_exit_token = exit_token.clone();
        tasks.write().await.push(spawn(async move {
            select! {
                _ = ctrl_exit_token.cancelled() => {info!("ctrl-c listener exit because of canceled")},
                _ = tokio::signal::ctrl_c() => {
                    info!("got ctrl-c signal");
                    ctrl_exit_token.cancel();
                },
            }
        }));
    }

    let (tun_read_tx, mut tun_read_rx) = mpsc::channel(1);

    {
        // create tun reader task
        tasks.write().await.push(spawn(tun_reader(
            tun.clone(),
            tun_read_tx,
            exit_token.clone(),
        )));
    }

    if is_client_mode {
        info!("connecting to {}", server_url);
        let (ws_stream, _) = connect_async(server_url)
            .await
            .expect("should connect to server success");
        info!("client connected");
        let (write, mut read) = ws_stream.split();
        let wrapped_write = Arc::new(Mutex::new(write));
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

        {
            // create client task for reading web socket
            let client_ws_exit = exit_token.clone();
            tasks.write().await.push(spawn(async move {
                let mut allowed_ips: AllowedIps<()> = Default::default();
                allowed_ips.insert("0.0.0.0".parse().unwrap(), 0, ());
                allowed_ips.insert("0::".parse().unwrap(), 0, ());
                loop {
                    debug!("client ws: wait for packet");
                    select! {
                        _ = client_ws_exit.cancelled() => {
                            info!("client ws reader exit because of canceled");
                            break;
                        },
                        res = read.next() => {
                            match res {
                                None => {
                                    warn!("client ws read nothing, exit..");
                                    break;
                                },
                                Some(Ok(Message::Text(_txt))) => {}
                                Some(Ok(Message::Binary(bin))) => match read_src_ip(&bin) {
                                    Ok(addr) if allowed_ips.find(addr).is_some() => {
                                        debug!("client ws: got package from {}", addr);
                                        if addr.is_ipv4() {
                                            tun.inner.get_ref().write4(&bin);
                                        } else {
                                            tun.inner.get_ref().write6(&bin);
                                        }
                                    }
                                    Ok(addr) => warn!("client ws: drop source packet from {} to {}", addr, read_dst_ip(&bin).expect("read dest success")),
                                    Err(_) => break,
                                },
                                Some(Ok(Message::Ping(_bin))) => { /* no need to do, the lib will return pong */ }
                                Some(Ok(Message::Pong(bin))) => {
                                    if bin.len() == 16 {
                                        let dt = get_time() - bin.as_slice().read_u128::<BigEndian>().expect("");
                                        info!("received pong, latency: {} micro seconds", dt);
                                    }
                                }
                                Some(Ok(Message::Close(_))) => break,
                                Some(Err(_)) => break,
                            }
                        }
                    }
                }
                info!("client ws: exit");
                if !client_ws_exit.is_cancelled() {
                    client_ws_exit.cancel();
                }
            }));
        }
        {
            // create client task for read tun
            let client_tun_exit_token = exit_token.clone();
            tasks.write().await.push(spawn(async move {
                loop {
                    debug!("client tun: wait for tun package");
                    select! {
                        _ = client_tun_exit_token.cancelled() => {
                            info!("client tun reader exit because of canceled");
                            break;
                        },
                        _ = sleep(Duration::from_secs(heart_beat)) => {
                            debug!("sending hart beat");
                            let mut wtr = Vec::new();
                            wtr.write_u128::<BigEndian>(get_time()).expect("write ts success");
                            let _ = wrapped_write.lock().await.send(Message::Ping(wtr)).await;
                        },
                        res = tun_read_rx.recv() => {
                            match res {
                                None => {
                                    error!("client tun: receive nothing");
                                    break;
                                }
                                Some(bin) => match wrapped_write.lock().await.send(Message::Binary(Vec::from(bin))).await {
                                    Ok(_) => debug!("client tun: send to ws"),
                                    Err(_) => break,
                                },
                            }
                        }
                    }
                }
                info!("client tun: exit");
                if !client_tun_exit_token.is_cancelled() {
                    client_tun_exit_token.cancel();
                }
            }));
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

        tasks.write().await.push(spawn(server_tun_to_ws(
            tun_read_rx,
            route_table.clone(),
            exit_token.clone(),
        )));

        let allocation_start_ip = next_ip_of(&server_ip);
        let allocation_end_ip = subnet.last_valid_ip();

        info!("Server IP: {}", server_ip);
        info!("IP pool: {} ~ {}", allocation_start_ip, allocation_end_ip);

        {
            let server_ws_exit_token = exit_token.clone();
            let server_conn_tasks = tasks.clone();
            tasks.write().await.push(spawn(async move {
                loop {
                    select! {
                        _ = server_ws_exit_token.cancelled() => {
                            info!("server ws main loop exit because receive cancel");
                            break;
                        }
                        res = listener.accept() => {
                            let tcp_stream = match res {
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
                                let mut new_ip: IpAddr = allocation_start_ip;
                                loop {
                                    if !writable_table.contains_key(&new_ip) {
                                        break;
                                    }
                                    new_ip = next_ip_of(&new_ip);
                                    if new_ip == allocation_end_ip {
                                        new_ip = allocation_start_ip;
                                    }
                                }
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
                                let current_ws_write = Arc::new(Mutex::new(ws_write));
                                writable_table.insert(
                                    new_ip,
                                    ClientInfo {
                                        remote_addr,
                                        ws_write: current_ws_write.clone(),
                                    },
                                );
                                new_ip
                            };
                            let new_ip_length = if new_ip.is_ipv4() { 32 } else { 128 };

                            info!("client ip: {}", new_ip);

                            let mut allowed_ips: AllowedIps<()> = Default::default();
                            allowed_ips.insert(new_ip, new_ip_length, ());
                            {
                                server_conn_tasks.write().await.push(
                                    spawn(server_ws_to_tun(
                                        tun.clone(),
                                        ws_read,
                                        new_ip,
                                        allowed_ips,
                                        route_table.clone(),
                                        server_ws_exit_token.clone(),
                                    ))
                                );
                            }
                        }
                    }
                }
            }));
        }
    }

    let _ = exit_token.cancelled().await;
    info!("waiting {} seconds for tasks exiting", close_timeout);
    sleep(Duration::from_secs(close_timeout)).await;
    info!("killing running task");
    {
        let task_list = tasks.read().await;
        for i in 0..task_list.len() {
            task_list[i].abort();
        }
    }
    info!("exit");

    ()
}
