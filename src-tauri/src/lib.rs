// my-domain desktop backend.
//
// Discovery:
//   * Registry (default): after login, register this device and fetch the user's
//     other devices from the server. Re-register on network change. No polling.
//   * LAN scan (manual): UDP multicast/broadcast/unicast beacons on demand.
// Messaging (all peer-to-peer, end-to-end encrypted):
//   * UDP / TCP — direct datagram / connection per message (LAN).
//   * WebSocket — a persistent LAN connection; whichever side can reach the
//     other "triggers" it, then messages flow both ways over the one socket.
// E2EE: a user passphrase ("encryption key") → Argon2id → XChaCha20-Poly1305.
// The server is a directory only; it never sees plaintext or keys.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tauri::{AppHandle, Emitter, Manager, State};
use tungstenite::client::IntoClientRequest;
use tungstenite::Message as WsMessage;

const MCAST_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 98);
const DISCOVERY_PORT: u16 = 45678;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize)]
struct Identity {
    node_id: String,
    name: String,
    ip: String,
    tcp_port: u16,
    udp_port: u16,
    ws_port: u16,
}

#[derive(Serialize, Deserialize)]
struct Beacon {
    node_id: String,
    name: String,
    tcp_port: u16,
    udp_port: u16,
    ws_port: u16,
    #[serde(default)]
    reply: bool,
}

#[derive(Clone, Serialize)]
struct Peer {
    node_id: String,
    name: String,
    ip: String,
    tcp_port: u16,
    udp_port: u16,
    ws_port: u16,
    /// "registry" | "lan" | "manual"
    source: String,
}

/// Decrypted message body.
#[derive(Serialize, Deserialize)]
struct Plaintext {
    from: String,
    text: String,
}

/// Encrypted on-the-wire envelope (TCP/UDP body, and WS `msg` frames).
#[derive(Serialize, Deserialize)]
struct Envelope {
    nonce: String,
    ciphertext: String,
}

#[derive(Clone, Serialize)]
struct IncomingMessage {
    from: String,
    ip: String,
    protocol: String,
    text: String,
    ts: u64,
    ok: bool,
}

/// WebSocket frames.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
enum WsFrame {
    #[serde(rename = "hello")]
    Hello { node_id: String, name: String },
    #[serde(rename = "msg")]
    Msg { nonce: String, ciphertext: String },
}

type PeerMap = Arc<Mutex<HashMap<String, Peer>>>;
type KeyHolder = Arc<Mutex<Option<[u8; 32]>>>;
/// node_id -> (connection id, outgoing-frame sender). One entry per peer; a
/// duplicate connection to an already-connected peer is dropped.
type WsConns = Arc<Mutex<HashMap<String, (u64, mpsc::Sender<String>)>>>;

static WS_CONN_SEQ: AtomicU64 = AtomicU64::new(1);

/// Auth + encryption-key session. Empty until the user logs in / sets a key.
struct Session {
    server_url: Mutex<Option<String>>,
    token: Mutex<Option<String>>,
    username: Mutex<Option<String>>,
    key: KeyHolder,
}

struct AppState {
    identity: Arc<Mutex<Identity>>,
    peers: PeerMap,
    disco_send: Arc<UdpSocket>,
    ws_conns: WsConns,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// End-to-end encryption
// ---------------------------------------------------------------------------

/// Derive the 32-byte message key from the user's passphrase. Salt is bound to
/// the username so the same passphrase yields the same key on all the user's
/// devices (and differs between users).
fn derive_key(passphrase: &str, username: &str) -> Option<[u8; 32]> {
    let salt = format!("my-domain-e2ee:{username}");
    let mut key = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt.as_bytes(), &mut key)
        .ok()?;
    Some(key)
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Option<Envelope> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).ok()?;
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher.encrypt(XNonce::from_slice(&nonce), plaintext).ok()?;
    Some(Envelope {
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ct),
    })
}

fn decrypt(key: &[u8; 32], env: &Envelope) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).ok()?;
    let nonce = STANDARD.decode(&env.nonce).ok()?;
    if nonce.len() != 24 {
        return None;
    }
    let ct = STANDARD.decode(&env.ciphertext).ok()?;
    cipher.decrypt(XNonce::from_slice(&nonce), ct.as_ref()).ok()
}

/// Turn an incoming encrypted envelope into a UI message, decrypting if we hold
/// a key. Undecryptable messages are surfaced (not silently dropped).
fn envelope_to_message(key: &KeyHolder, env: &Envelope, ip: String, protocol: &str) -> IncomingMessage {
    let guard = key.lock().unwrap();
    if let Some(k) = guard.as_ref() {
        if let Some(pt) = decrypt(k, env) {
            if let Ok(msg) = serde_json::from_slice::<Plaintext>(&pt) {
                return IncomingMessage {
                    from: msg.from,
                    ip,
                    protocol: protocol.into(),
                    text: msg.text,
                    ts: now_secs(),
                    ok: true,
                };
            }
        }
    }
    IncomingMessage {
        from: "(unknown)".into(),
        ip,
        protocol: protocol.into(),
        text: "🔒 message could not be decrypted (wrong encryption key)".into(),
        ts: now_secs(),
        ok: false,
    }
}

// ---------------------------------------------------------------------------
// Registry (HTTP) client
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenResp {
    token: String,
    username: String,
}

#[derive(Deserialize)]
struct RegistryDevice {
    node_id: String,
    name: String,
    ip: String,
    tcp_port: u16,
    udp_port: u16,
    #[serde(default)]
    ws_port: u16,
}

/// Normalize a user-entered server URL to just `scheme://host[:port]`, dropping
/// any path/query so pasting a full endpoint (e.g. `.../auth/login`) doesn't get
/// the path appended twice.
fn base(url: &str) -> String {
    let u = url.trim().trim_end_matches('/');
    match u.find("://") {
        Some(i) => {
            let host_start = i + 3;
            let host_end = u[host_start..]
                .find('/')
                .map(|j| host_start + j)
                .unwrap_or(u.len());
            u[..host_end].to_string()
        }
        None => u.to_string(),
    }
}

fn http_err(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, r) => r
            .into_json::<serde_json::Value>()
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
            .unwrap_or_else(|| format!("server returned HTTP {code}")),
        other => other.to_string(),
    }
}

fn auth_call(url: &str, path: &str, username: &str, password: &str) -> Result<TokenResp, String> {
    ureq::post(&format!("{}{}", base(url), path))
        .timeout(Duration::from_secs(10))
        .send_json(serde_json::json!({ "username": username, "password": password }))
        .map_err(http_err)?
        .into_json::<TokenResp>()
        .map_err(|e| e.to_string())
}

fn verify_password_call(url: &str, username: &str, password: &str) -> Result<bool, String> {
    match ureq::post(&format!("{}/auth/verify", base(url)))
        .timeout(Duration::from_secs(10))
        .send_json(serde_json::json!({ "username": username, "password": password }))
    {
        Ok(_) => Ok(true),
        Err(ureq::Error::Status(401, _)) => Ok(false),
        Err(e) => Err(http_err(e)),
    }
}

fn registry_register(url: &str, token: &str, id: &Identity) -> Result<(), String> {
    ureq::post(&format!("{}/devices/register", base(url)))
        .timeout(Duration::from_secs(10))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(serde_json::json!({
            "node_id": id.node_id,
            "name": id.name,
            "ip": id.ip,
            "tcp_port": id.tcp_port,
            "udp_port": id.udp_port,
            "ws_port": id.ws_port,
        }))
        .map_err(http_err)?;
    Ok(())
}

fn registry_fetch(url: &str, token: &str, exclude: &str) -> Result<Vec<RegistryDevice>, String> {
    ureq::get(&format!("{}/devices?exclude={}", base(url), exclude))
        .timeout(Duration::from_secs(10))
        .set("Authorization", &format!("Bearer {token}"))
        .call()
        .map_err(http_err)?
        .into_json::<Vec<RegistryDevice>>()
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Peer table helpers
// ---------------------------------------------------------------------------

fn emit_peers(app: &AppHandle, peers: &PeerMap) {
    let list: Vec<Peer> = peers.lock().unwrap().values().cloned().collect();
    let _ = app.emit("peers-updated", list);
}

/// Replace all registry-sourced peers with a freshly fetched set.
fn apply_registry_peers(app: &AppHandle, peers: &PeerMap, devices: Vec<RegistryDevice>) {
    {
        let mut map = peers.lock().unwrap();
        map.retain(|_, p| p.source != "registry");
        for d in devices {
            map.insert(
                d.node_id.clone(),
                Peer {
                    node_id: d.node_id,
                    name: d.name,
                    ip: d.ip,
                    tcp_port: d.tcp_port,
                    udp_port: d.udp_port,
                    ws_port: d.ws_port,
                    source: "registry".into(),
                },
            );
        }
    }
    emit_peers(app, peers);
}

// ---------------------------------------------------------------------------
// LAN discovery (manual)
// ---------------------------------------------------------------------------

fn local_ip() -> String {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            Ok(s.local_addr()?.ip().to_string())
        })
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}

fn bind_multicast() -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), DISCOVERY_PORT).into())?;
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            if let std::net::IpAddr::V4(v4) = iface.ip() {
                let _ = socket.join_multicast_v4(&MCAST_GROUP, &v4);
            }
        }
    }
    let _ = socket.join_multicast_v4(&MCAST_GROUP, &Ipv4Addr::UNSPECIFIED);
    socket.set_multicast_loop_v4(true)?;
    Ok(socket.into())
}

/// Targets for a LAN announce: multicast + broadcast + /24 unicast sweep.
fn lan_targets() -> Vec<SocketAddr> {
    let mut v = vec![
        SocketAddr::new(MCAST_GROUP.into(), DISCOVERY_PORT),
        SocketAddr::new(Ipv4Addr::BROADCAST.into(), DISCOVERY_PORT),
    ];
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            if let if_addrs::IfAddr::V4(v4) = iface.addr {
                if let Some(bc) = v4.broadcast {
                    v.push(SocketAddr::new(bc.into(), DISCOVERY_PORT));
                }
                let o = v4.ip.octets();
                for host in 1..=254u8 {
                    if host == o[3] {
                        continue;
                    }
                    v.push(SocketAddr::new(
                        Ipv4Addr::new(o[0], o[1], o[2], host).into(),
                        DISCOVERY_PORT,
                    ));
                }
            }
        }
    }
    v
}

fn send_beacon(socket: &UdpSocket, id: &Identity, reply: bool, to: &[SocketAddr]) {
    let beacon = Beacon {
        node_id: id.node_id.clone(),
        name: id.name.clone(),
        tcp_port: id.tcp_port,
        udp_port: id.udp_port,
        ws_port: id.ws_port,
        reply,
    };
    if let Ok(payload) = serde_json::to_vec(&beacon) {
        for dst in to {
            let _ = socket.send_to(&payload, dst);
        }
    }
}

/// Always-listening receiver. On an announce, record the peer and reply once
/// (unicast) so a single "Scan LAN" press discovers both directions.
fn discovery_recv_loop(
    app: AppHandle,
    recv: UdpSocket,
    send: Arc<UdpSocket>,
    peers: PeerMap,
    identity: Arc<Mutex<Identity>>,
) {
    let mut buf = [0u8; 2048];
    loop {
        let (len, src) = match recv.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let beacon: Beacon = match serde_json::from_slice(&buf[..len]) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let my_id = identity.lock().unwrap().node_id.clone();
        if beacon.node_id == my_id {
            continue;
        }
        let is_new = {
            let mut map = peers.lock().unwrap();
            let existed = map.contains_key(&beacon.node_id);
            map.insert(
                beacon.node_id.clone(),
                Peer {
                    node_id: beacon.node_id.clone(),
                    name: beacon.name.clone(),
                    ip: src.ip().to_string(),
                    tcp_port: beacon.tcp_port,
                    udp_port: beacon.udp_port,
                    ws_port: beacon.ws_port,
                    source: "lan".into(),
                },
            );
            !existed
        };
        if is_new {
            eprintln!("[disco] LAN peer '{}' @ {}", beacon.name, src.ip());
        }
        emit_peers(&app, &peers);
        // Reply to announces (not to replies) so the scanner is discovered too.
        if !beacon.reply {
            let id = identity.lock().unwrap().clone();
            send_beacon(&send, &id, true, &[SocketAddr::new(src.ip(), DISCOVERY_PORT)]);
        }
    }
}

// ---------------------------------------------------------------------------
// Messaging — UDP / TCP direct
// ---------------------------------------------------------------------------

fn tcp_recv_loop(app: AppHandle, listener: TcpListener, key: KeyHolder) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let app = app.clone();
        let key = key.clone();
        std::thread::spawn(move || {
            let ip = stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
            let mut buf = Vec::new();
            if stream.read_to_end(&mut buf).is_err() {
                return;
            }
            if let Ok(env) = serde_json::from_slice::<Envelope>(&buf) {
                let _ = app.emit("message-received", envelope_to_message(&key, &env, ip, "TCP"));
            }
        });
    }
}

fn udp_recv_loop(app: AppHandle, socket: UdpSocket, key: KeyHolder) {
    let mut buf = [0u8; 65535];
    loop {
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Ok(env) = serde_json::from_slice::<Envelope>(&buf[..len]) {
            let _ = app.emit(
                "message-received",
                envelope_to_message(&key, &env, src.ip().to_string(), "UDP"),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Messaging — WebSocket (LAN, persistent, bidirectional)
// ---------------------------------------------------------------------------

fn ws_server_loop(app: AppHandle, listener: TcpListener, ctx: WsCtx) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
        if let Ok(ws) = tungstenite::accept(stream) {
            let app = app.clone();
            let ctx = ctx.clone();
            std::thread::spawn(move || handle_ws_conn(app, ws, ctx));
        }
    }
}

#[derive(Clone)]
struct WsCtx {
    identity: Arc<Mutex<Identity>>,
    key: KeyHolder,
    conns: WsConns,
}

fn handle_ws_conn<S: Read + Write>(app: AppHandle, mut ws: tungstenite::WebSocket<S>, ctx: WsCtx) {
    // Announce ourselves.
    {
        let id = ctx.identity.lock().unwrap();
        let hello = serde_json::to_string(&WsFrame::Hello {
            node_id: id.node_id.clone(),
            name: id.name.clone(),
        })
        .unwrap_or_default();
        let _ = ws.send(WsMessage::Text(hello));
    }
    let (tx, rx) = mpsc::channel::<String>();
    let my_conn_id = WS_CONN_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut peer_id: Option<String> = None;

    loop {
        match ws.read() {
            Ok(WsMessage::Text(t)) => {
                if let Ok(frame) = serde_json::from_str::<WsFrame>(&t) {
                    match frame {
                        WsFrame::Hello { node_id, .. } => {
                            // One socket per peer: if we already have a connection
                            // to this node (it dialed us, or we dialed it), drop
                            // this duplicate.
                            let mut guard = ctx.conns.lock().unwrap();
                            if guard.contains_key(&node_id) {
                                break;
                            }
                            guard.insert(node_id.clone(), (my_conn_id, tx.clone()));
                            drop(guard);
                            let _ = app.emit("ws-connected", &node_id);
                            peer_id = Some(node_id);
                        }
                        WsFrame::Msg { nonce, ciphertext } => {
                            let env = Envelope { nonce, ciphertext };
                            let _ = app.emit(
                                "message-received",
                                envelope_to_message(&ctx.key, &env, String::new(), "WS"),
                            );
                        }
                    }
                }
            }
            Ok(WsMessage::Close(_)) => break,
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(_) => break,
        }
        // Flush any queued outgoing frames.
        let mut dead = false;
        while let Ok(out) = rx.try_recv() {
            if ws.send(WsMessage::Text(out)).is_err() {
                dead = true;
                break;
            }
        }
        if dead {
            break;
        }
    }
    // Only remove our own entry (a newer connection may have replaced it).
    if let Some(pid) = peer_id {
        let mut g = ctx.conns.lock().unwrap();
        if g.get(&pid).map(|(id, _)| *id == my_conn_id).unwrap_or(false) {
            g.remove(&pid);
            drop(g);
            let _ = app.emit("ws-disconnected", &pid);
        }
    }
}

/// Dial a peer's WebSocket listener (the "trigger"). The spawned handler
/// registers the connection once hellos are exchanged.
fn ws_connect(app: &AppHandle, ctx: WsCtx, ip: &str, ws_port: u16) -> Result<(), String> {
    let addr: Ipv4Addr = ip.parse().map_err(|_| "bad peer ip")?;
    let stream = TcpStream::connect_timeout(
        &SocketAddr::new(addr.into(), ws_port),
        Duration::from_secs(4),
    )
    .map_err(|e| format!("WS connect failed: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| e.to_string())?;
    let req = format!("ws://{ip}:{ws_port}/")
        .into_client_request()
        .map_err(|e| e.to_string())?;
    let (ws, _resp) = tungstenite::client(req, stream).map_err(|e| format!("WS handshake failed: {e}"))?;
    let app = app.clone();
    std::thread::spawn(move || handle_ws_conn(app, ws, ctx));
    Ok(())
}

// ---------------------------------------------------------------------------
// Session persistence (server_url + username only)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
struct SavedSession {
    server_url: String,
    username: String,
}

fn session_path(app: &AppHandle) -> Option<std::path::PathBuf> {
    let dir = app.path().app_config_dir().ok()?;
    let _ = std::fs::create_dir_all(&dir);
    Some(dir.join("session.json"))
}

fn load_saved(app: &AppHandle) -> SavedSession {
    session_path(app)
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_saved(app: &AppHandle, s: &SavedSession) {
    if let Some(p) = session_path(app) {
        if let Ok(bytes) = serde_json::to_vec_pretty(s) {
            let _ = std::fs::write(p, bytes);
        }
    }
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_identity(state: State<AppState>) -> Identity {
    state.identity.lock().unwrap().clone()
}

#[tauri::command]
fn get_peers(state: State<AppState>) -> Vec<Peer> {
    state.peers.lock().unwrap().values().cloned().collect()
}

#[tauri::command]
fn get_saved_session(app: AppHandle) -> SavedSession {
    load_saved(&app)
}

#[tauri::command]
fn is_ready(session: State<Session>) -> bool {
    session.token.lock().unwrap().is_some() && session.key.lock().unwrap().is_some()
}

#[tauri::command]
fn session_info(session: State<Session>) -> serde_json::Value {
    serde_json::json!({
        "username": session.username.lock().unwrap().clone(),
        "server_url": session.server_url.lock().unwrap().clone(),
        "has_key": session.key.lock().unwrap().is_some(),
    })
}

fn do_auth(
    path: &str,
    server_url: String,
    username: String,
    password: String,
    session: &Session,
    app: &AppHandle,
) -> Result<(), String> {
    if server_url.trim().is_empty() {
        return Err("server URL is required".into());
    }
    let resp = auth_call(&server_url, path, username.trim(), &password)?;
    *session.server_url.lock().unwrap() = Some(base(&server_url));
    *session.token.lock().unwrap() = Some(resp.token);
    *session.username.lock().unwrap() = Some(resp.username.clone());
    save_saved(
        app,
        &SavedSession {
            server_url: base(&server_url),
            username: resp.username,
        },
    );
    Ok(())
}

#[tauri::command]
fn auth_register(
    server_url: String,
    username: String,
    password: String,
    session: State<Session>,
    app: AppHandle,
) -> Result<(), String> {
    do_auth("/auth/register", server_url, username, password, &session, &app)
}

#[tauri::command]
fn auth_login(
    server_url: String,
    username: String,
    password: String,
    session: State<Session>,
    app: AppHandle,
) -> Result<(), String> {
    do_auth("/auth/login", server_url, username, password, &session, &app)
}

#[tauri::command]
fn set_encryption_key(passphrase: String, session: State<Session>) -> Result<(), String> {
    let username = session
        .username
        .lock()
        .unwrap()
        .clone()
        .ok_or("log in first")?;
    if passphrase.trim().is_empty() {
        return Err("encryption key is required".into());
    }
    let key = derive_key(&passphrase, &username).ok_or("failed to derive key")?;
    *session.key.lock().unwrap() = Some(key);
    Ok(())
}

#[tauri::command]
fn update_encryption_key(
    new_passphrase: String,
    password: String,
    session: State<Session>,
) -> Result<(), String> {
    let username = session.username.lock().unwrap().clone().ok_or("log in first")?;
    let url = session.server_url.lock().unwrap().clone().ok_or("no server")?;
    if !verify_password_call(&url, &username, &password)? {
        return Err("incorrect password".into());
    }
    if new_passphrase.trim().is_empty() {
        return Err("new encryption key is required".into());
    }
    let key = derive_key(&new_passphrase, &username).ok_or("failed to derive key")?;
    *session.key.lock().unwrap() = Some(key);
    Ok(())
}

#[tauri::command]
fn generate_key() -> String {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

#[tauri::command]
fn logout(session: State<Session>) {
    *session.token.lock().unwrap() = None;
    *session.key.lock().unwrap() = None;
}

/// Register this device with the registry and refresh the peer list.
#[tauri::command]
fn refresh_from_server(state: State<AppState>, session: State<Session>, app: AppHandle) -> Result<(), String> {
    let url = session.server_url.lock().unwrap().clone().ok_or("not logged in")?;
    let token = session.token.lock().unwrap().clone().ok_or("not logged in")?;
    let id = state.identity.lock().unwrap().clone();
    registry_register(&url, &token, &id)?;
    let devices = registry_fetch(&url, &token, &id.node_id)?;
    apply_registry_peers(&app, &state.peers, devices);
    Ok(())
}

#[tauri::command]
fn scan_lan(state: State<AppState>) {
    let id = state.identity.lock().unwrap().clone();
    let socket = state.disco_send.clone();
    let targets = lan_targets();
    // A few announce bursts over a couple of seconds.
    std::thread::spawn(move || {
        for _ in 0..3 {
            send_beacon(&socket, &id, false, &targets);
            std::thread::sleep(Duration::from_millis(700));
        }
    });
}

#[tauri::command]
fn connect_ws(node_id: String, state: State<AppState>, session: State<Session>, app: AppHandle) -> Result<(), String> {
    let peer = state
        .peers
        .lock()
        .unwrap()
        .get(&node_id)
        .cloned()
        .ok_or("peer not found")?;
    if peer.ws_port == 0 {
        return Err("peer has no WebSocket port".into());
    }
    // Reuse an existing connection instead of opening a second socket.
    if state.ws_conns.lock().unwrap().contains_key(&node_id) {
        return Ok(());
    }
    let ctx = WsCtx {
        identity: state.identity.clone(),
        key: session.key.clone(),
        conns: state.ws_conns.clone(),
    };
    ws_connect(&app, ctx, &peer.ip, peer.ws_port)
}

#[tauri::command]
fn send_message(
    node_id: String,
    protocol: String,
    text: String,
    state: State<AppState>,
    session: State<Session>,
) -> Result<(), String> {
    let key = session.key.lock().unwrap().ok_or("set your encryption key first")?;
    let from = session
        .username
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| state.identity.lock().unwrap().name.clone());

    let plaintext = serde_json::to_vec(&Plaintext { from, text }).map_err(|e| e.to_string())?;
    let env = encrypt(&key, &plaintext).ok_or("encryption failed")?;
    let body = serde_json::to_vec(&env).map_err(|e| e.to_string())?;

    let proto = protocol.to_uppercase();
    if proto == "WS" {
        let frame = serde_json::to_string(&WsFrame::Msg {
            nonce: env.nonce.clone(),
            ciphertext: env.ciphertext.clone(),
        })
        .map_err(|e| e.to_string())?;
        let sender = state
            .ws_conns
            .lock()
            .unwrap()
            .get(&node_id)
            .map(|(_, s)| s.clone())
            .ok_or("no WebSocket connection — trigger 'Connect (WS)' first")?;
        sender.send(frame).map_err(|_| "WebSocket connection closed".to_string())?;
        return Ok(());
    }

    let peer = state
        .peers
        .lock()
        .unwrap()
        .get(&node_id)
        .cloned()
        .ok_or("peer not found")?;
    let ip: Ipv4Addr = peer.ip.parse().map_err(|_| "bad peer ip")?;
    match proto.as_str() {
        "TCP" => {
            let addr = SocketAddr::new(ip.into(), peer.tcp_port);
            let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
                .map_err(|e| format!("TCP connect failed: {e}"))?;
            stream.write_all(&body).map_err(|e| format!("TCP send failed: {e}"))?;
            stream.shutdown(std::net::Shutdown::Write).map_err(|e| e.to_string())?;
            Ok(())
        }
        "UDP" => {
            let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
            socket
                .send_to(&body, SocketAddr::new(ip.into(), peer.udp_port))
                .map_err(|e| format!("UDP send failed: {e}"))?;
            Ok(())
        }
        other => Err(format!("unknown protocol: {other}")),
    }
}

#[tauri::command]
fn add_manual_peer(
    name: String,
    ip: String,
    tcp_port: u16,
    udp_port: u16,
    ws_port: u16,
    state: State<AppState>,
    app: AppHandle,
) -> Result<(), String> {
    let parsed: Ipv4Addr = ip.trim().parse().map_err(|_| format!("invalid IPv4: {ip}"))?;
    let node_id = format!("manual:{parsed}");
    let display = if name.trim().is_empty() {
        parsed.to_string()
    } else {
        name.trim().to_string()
    };
    state.peers.lock().unwrap().insert(
        node_id.clone(),
        Peer {
            node_id,
            name: display,
            ip: parsed.to_string(),
            tcp_port,
            udp_port,
            ws_port,
            source: "manual".into(),
        },
    );
    emit_peers(&app, &state.peers);
    Ok(())
}

#[tauri::command]
fn remove_peer(node_id: String, state: State<AppState>, app: AppHandle) {
    state.peers.lock().unwrap().remove(&node_id);
    emit_peers(&app, &state.peers);
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

fn start_networking(app: &AppHandle, key: KeyHolder) -> std::io::Result<AppState> {
    let node_id = uuid::Uuid::new_v4().to_string();
    let name = gethostname::gethostname().to_string_lossy().to_string();

    let tcp_listener = TcpListener::bind("0.0.0.0:0")?;
    let tcp_port = tcp_listener.local_addr()?.port();
    let udp_msg_socket = UdpSocket::bind("0.0.0.0:0")?;
    let udp_port = udp_msg_socket.local_addr()?.port();
    let ws_listener = TcpListener::bind("0.0.0.0:0")?;
    let ws_port = ws_listener.local_addr()?.port();

    let identity = Arc::new(Mutex::new(Identity {
        node_id,
        name,
        ip: local_ip(),
        tcp_port,
        udp_port,
        ws_port,
    }));
    eprintln!("[net] {:?}", identity.lock().unwrap().clone().node_id);

    let peers: PeerMap = Arc::new(Mutex::new(HashMap::new()));
    let ws_conns: WsConns = Arc::new(Mutex::new(HashMap::new()));

    let disco_recv = bind_multicast()?;
    let disco_send: Arc<UdpSocket> = Arc::new(disco_recv.try_clone()?);

    // LAN discovery receiver (always listening; only beacons on manual scan).
    {
        let app = app.clone();
        let send = disco_send.clone();
        let peers = peers.clone();
        let identity = identity.clone();
        std::thread::spawn(move || discovery_recv_loop(app, disco_recv, send, peers, identity));
    }
    // Direct messaging receivers.
    {
        let app = app.clone();
        let key = key.clone();
        std::thread::spawn(move || tcp_recv_loop(app, tcp_listener, key));
    }
    {
        let app = app.clone();
        let key = key.clone();
        std::thread::spawn(move || udp_recv_loop(app, udp_msg_socket, key));
    }
    // WebSocket listener.
    {
        let app = app.clone();
        let ctx = WsCtx {
            identity: identity.clone(),
            key: key.clone(),
            conns: ws_conns.clone(),
        };
        std::thread::spawn(move || ws_server_loop(app, ws_listener, ctx));
    }
    // Network-change watcher: update advertised IP (re-register is user/Refresh driven).
    {
        let identity = identity.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            let current = local_ip();
            let mut id = identity.lock().unwrap();
            if id.ip != current {
                eprintln!("[net] ip changed {} -> {}", id.ip, current);
                id.ip = current;
            }
        });
    }

    Ok(AppState {
        identity,
        peers,
        disco_send,
        ws_conns,
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let key: KeyHolder = Arc::new(Mutex::new(None));
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(Session {
            server_url: Mutex::new(None),
            token: Mutex::new(None),
            username: Mutex::new(None),
            key: key.clone(),
        })
        .setup(move |app| {
            let handle = app.handle().clone();
            match start_networking(&handle, key.clone()) {
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
            get_saved_session,
            is_ready,
            session_info,
            auth_register,
            auth_login,
            set_encryption_key,
            update_encryption_key,
            generate_key,
            logout,
            refresh_from_server,
            scan_lan,
            connect_ws,
            send_message,
            add_manual_peer,
            remove_peer
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
