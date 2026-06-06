// LAN discovery + UDP/TCP messaging backend for the Tauri app.
//
// Discovery uses a UDP multicast group so every peer on the LAN (and multiple
// instances on the same host, for testing) hears each other's "beacon".
// Direct messages are sent either over TCP (connection per message) or as a
// single UDP datagram, to the port the peer advertised in its beacon.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tauri::{AppHandle, Emitter, Manager, State};

const MCAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 98);
const DISCOVERY_PORT: u16 = 45678;
const BEACON_INTERVAL: Duration = Duration::from_secs(2);
const PEER_TIMEOUT_SECS: u64 = 8; // drop peers we haven't heard from in this long

/// Our own identity, advertised in every beacon and shown in the UI.
#[derive(Clone, Serialize)]
struct Identity {
    node_id: String,
    name: String,
    ip: String,
    tcp_port: u16,
    udp_port: u16,
}

/// What we broadcast on the multicast group.
#[derive(Serialize, Deserialize)]
struct Beacon {
    node_id: String,
    name: String,
    tcp_port: u16,
    udp_port: u16,
}

/// A discovered peer, kept in the shared peer table and sent to the UI.
#[derive(Clone, Serialize)]
struct Peer {
    node_id: String,
    name: String,
    ip: String,
    tcp_port: u16,
    udp_port: u16,
    last_seen: u64,
}

/// Wire format for an actual chat message (TCP body or UDP datagram).
#[derive(Serialize, Deserialize)]
struct WireMessage {
    from: String,
    text: String,
}

/// What we hand to the UI when a message arrives.
#[derive(Clone, Serialize)]
struct IncomingMessage {
    from: String,
    ip: String,
    protocol: String,
    text: String,
    ts: u64,
}

type PeerMap = Arc<Mutex<HashMap<String, Peer>>>;

struct AppState {
    identity: Identity,
    peers: PeerMap,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Best-effort local LAN IP (no traffic is actually sent).
fn local_ip() -> String {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            Ok(s.local_addr()?.ip().to_string())
        })
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}

/// Create a UDP socket bound to the multicast port, joined to the group, with
/// address/port reuse so several instances on one machine can all listen.
///
/// Joins the group on *every* IPv4 interface, so we still receive a peer's
/// beacons on a multi-homed machine (Wi-Fi + Ethernet + VPN) where the default
/// interface might not be the one the LAN traffic arrives on.
fn bind_multicast() -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    let addr: SocketAddr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), DISCOVERY_PORT);
    socket.bind(&addr.into())?;

    let mut joined = Vec::new();
    match if_addrs::get_if_addrs() {
        Ok(ifaces) => {
            for iface in ifaces {
                if iface.is_loopback() {
                    continue;
                }
                if let std::net::IpAddr::V4(v4) = iface.ip() {
                    if socket.join_multicast_v4(&MCAST_GROUP, &v4).is_ok() {
                        joined.push(format!("{}={}", iface.name, v4));
                    }
                }
            }
        }
        Err(e) => eprintln!("[disco] get_if_addrs failed: {e}"),
    }
    if joined.is_empty() {
        socket.join_multicast_v4(&MCAST_GROUP, &Ipv4Addr::UNSPECIFIED)?;
        eprintln!("[disco] joined {MCAST_GROUP} on default interface (INADDR_ANY)");
    } else {
        eprintln!(
            "[disco] joined {MCAST_GROUP}:{DISCOVERY_PORT} on [{}]",
            joined.join(", ")
        );
    }
    socket.set_multicast_loop_v4(true)?;
    Ok(socket.into())
}

/// Push the current peer list to the UI.
fn emit_peers(app: &AppHandle, peers: &PeerMap) {
    let list: Vec<Peer> = peers.lock().unwrap().values().cloned().collect();
    let _ = app.emit("peers-updated", list);
}

/// Receive beacons, update the peer table, and emit changes.
fn discovery_recv_loop(app: AppHandle, socket: UdpSocket, peers: PeerMap, my_id: String) {
    let mut buf = [0u8; 2048];
    loop {
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[disco] recv error: {e}");
                continue;
            }
        };
        let beacon: Beacon = match serde_json::from_slice(&buf[..len]) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[disco] rx {len}B from {src}: not a beacon ({e})");
                continue;
            }
        };
        if beacon.node_id == my_id {
            continue; // ignore our own beacons (received via multicast loopback)
        }
        let peer = Peer {
            node_id: beacon.node_id.clone(),
            name: beacon.name.clone(),
            ip: src.ip().to_string(),
            tcp_port: beacon.tcp_port,
            udp_port: beacon.udp_port,
            last_seen: now_secs(),
        };
        let is_new = {
            let mut map = peers.lock().unwrap();
            map.insert(beacon.node_id.clone(), peer).is_none()
        };
        if is_new {
            eprintln!(
                "[disco] NEW peer '{}' @ {} (tcp {}, udp {})",
                beacon.name,
                src.ip(),
                beacon.tcp_port,
                beacon.udp_port
            );
        }
        emit_peers(&app, &peers);
    }
}

/// Periodically broadcast our beacon to the multicast group.
fn beacon_send_loop(socket: UdpSocket, identity: Identity) {
    let beacon = Beacon {
        node_id: identity.node_id.clone(),
        name: identity.name.clone(),
        tcp_port: identity.tcp_port,
        udp_port: identity.udp_port,
    };
    let payload = serde_json::to_vec(&beacon).unwrap();
    let dst = SocketAddr::new(MCAST_GROUP.into(), DISCOVERY_PORT);
    eprintln!(
        "[disco] beaconing as '{}' -> {}:{} every {}s",
        identity.name,
        MCAST_GROUP,
        DISCOVERY_PORT,
        BEACON_INTERVAL.as_secs()
    );
    loop {
        if let Err(e) = socket.send_to(&payload, dst) {
            eprintln!("[disco] beacon send error: {e}");
        }
        std::thread::sleep(BEACON_INTERVAL);
    }
}

/// Drop peers we haven't heard from in a while and refresh the UI.
fn prune_loop(app: AppHandle, peers: PeerMap) {
    loop {
        std::thread::sleep(Duration::from_secs(2));
        let removed = {
            let mut map = peers.lock().unwrap();
            let before = map.len();
            let cutoff = now_secs().saturating_sub(PEER_TIMEOUT_SECS);
            map.retain(|_, p| p.last_seen >= cutoff);
            before != map.len()
        };
        if removed {
            emit_peers(&app, &peers);
        }
    }
}

/// Accept TCP connections; each connection delivers one message.
fn tcp_recv_loop(app: AppHandle, listener: TcpListener) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let app = app.clone();
        std::thread::spawn(move || {
            let ip = stream
                .peer_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_default();
            let mut buf = Vec::new();
            if stream.read_to_end(&mut buf).is_err() {
                return;
            }
            if let Ok(msg) = serde_json::from_slice::<WireMessage>(&buf) {
                eprintln!("[msg] TCP from {} ({}): {}", msg.from, ip, msg.text);
                let _ = app.emit(
                    "message-received",
                    IncomingMessage {
                        from: msg.from,
                        ip,
                        protocol: "TCP".into(),
                        text: msg.text,
                        ts: now_secs(),
                    },
                );
            }
        });
    }
}

/// Receive direct UDP datagrams (one message per datagram).
fn udp_recv_loop(app: AppHandle, socket: UdpSocket) {
    let mut buf = [0u8; 65535];
    loop {
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Ok(msg) = serde_json::from_slice::<WireMessage>(&buf[..len]) {
            eprintln!("[msg] UDP from {} ({}): {}", msg.from, src.ip(), msg.text);
            let _ = app.emit(
                "message-received",
                IncomingMessage {
                    from: msg.from,
                    ip: src.ip().to_string(),
                    protocol: "UDP".into(),
                    text: msg.text,
                    ts: now_secs(),
                },
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_identity(state: State<AppState>) -> Identity {
    state.identity.clone()
}

#[tauri::command]
fn get_peers(state: State<AppState>) -> Vec<Peer> {
    state.peers.lock().unwrap().values().cloned().collect()
}

#[tauri::command]
fn set_display_name(name: String, state: State<AppState>, app: AppHandle) -> Result<(), String> {
    // Identity is immutable in state; we just emit the change for the UI to use
    // on the next beacon cycle. For simplicity we keep the boot name on the wire,
    // but reflect the chosen name in outgoing messages via a managed override.
    *app.state::<NameOverride>().0.lock().unwrap() = Some(name);
    let _ = state; // identity name stays as the advertised hostname
    Ok(())
}

/// Optional user-chosen display name used as the "from" on outgoing messages.
struct NameOverride(Mutex<Option<String>>);

#[tauri::command]
fn send_message(
    node_id: String,
    protocol: String,
    text: String,
    state: State<AppState>,
    app: AppHandle,
) -> Result<(), String> {
    let peer = state
        .peers
        .lock()
        .unwrap()
        .get(&node_id)
        .cloned()
        .ok_or_else(|| "peer not found (it may have gone offline)".to_string())?;

    let from = app
        .state::<NameOverride>()
        .0
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| state.identity.name.clone());

    let payload = serde_json::to_vec(&WireMessage { from, text }).map_err(|e| e.to_string())?;

    match protocol.to_uppercase().as_str() {
        "TCP" => {
            let addr = SocketAddr::new(peer.ip.parse().map_err(|_| "bad peer ip")?, peer.tcp_port);
            let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("TCP connect failed: {e}"))?;
            stream
                .write_all(&payload)
                .map_err(|e| format!("TCP send failed: {e}"))?;
            // Closing the write half signals end-of-message to the receiver.
            stream
                .shutdown(std::net::Shutdown::Write)
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        "UDP" => {
            let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
            let addr = SocketAddr::new(peer.ip.parse().map_err(|_| "bad peer ip")?, peer.udp_port);
            socket
                .send_to(&payload, addr)
                .map_err(|e| format!("UDP send failed: {e}"))?;
            Ok(())
        }
        other => Err(format!("unknown protocol: {other}")),
    }
}

fn start_networking(app: &AppHandle) -> std::io::Result<AppState> {
    let node_id = uuid::Uuid::new_v4().to_string();
    let name = gethostname::gethostname().to_string_lossy().to_string();

    // TCP listener on an ephemeral port; advertise the real port we got.
    let tcp_listener = TcpListener::bind("0.0.0.0:0")?;
    let tcp_port = tcp_listener.local_addr()?.port();

    // UDP socket for direct messages, also on an ephemeral advertised port.
    let udp_msg_socket = UdpSocket::bind("0.0.0.0:0")?;
    let udp_port = udp_msg_socket.local_addr()?.port();

    let identity = Identity {
        node_id: node_id.clone(),
        name,
        ip: local_ip(),
        tcp_port,
        udp_port,
    };
    eprintln!(
        "[net] identity name='{}' ip={} tcp={} udp={} id={}",
        identity.name, identity.ip, identity.tcp_port, identity.udp_port, identity.node_id
    );

    let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));

    // Discovery: one socket shared for sending beacons and receiving them.
    let disco_recv = bind_multicast()?;
    let disco_send = disco_recv.try_clone()?;

    {
        let app = app.clone();
        let peers = peers.clone();
        let my_id = node_id.clone();
        std::thread::spawn(move || discovery_recv_loop(app, disco_recv, peers, my_id));
    }
    {
        let identity = identity.clone();
        std::thread::spawn(move || beacon_send_loop(disco_send, identity));
    }
    {
        let app = app.clone();
        let peers = peers.clone();
        std::thread::spawn(move || prune_loop(app, peers));
    }
    {
        let app = app.clone();
        std::thread::spawn(move || tcp_recv_loop(app, tcp_listener));
    }
    {
        let app = app.clone();
        std::thread::spawn(move || udp_recv_loop(app, udp_msg_socket));
    }

    Ok(AppState { identity, peers })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(NameOverride(Mutex::new(None)))
        .setup(|app| {
            let handle = app.handle().clone();
            match start_networking(&handle) {
                Ok(state) => {
                    app.manage(state);
                }
                Err(e) => {
                    eprintln!("failed to start networking: {e}");
                    return Err(Box::new(e));
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_identity,
            get_peers,
            set_display_name,
            send_message
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
