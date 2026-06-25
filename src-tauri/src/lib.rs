// my-domain desktop backend — a thin Tauri adapter over the shared `mdcore`
// Engine. Platform specifics (machine id, hostname, interface enumeration,
// clipboard, session persistence) are implemented here; all networking,
// crypto, discovery, and messaging live in `mdcore`.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tauri::{AppHandle, Emitter, Manager, State};

use mdcore::capabilities::Clipboard;
use mdcore::engine::{Engine, FirewallStatus, SavedSession, SessionInfo};
use mdcore::events::{CoreEvent, EventSink};
use mdcore::model::{Identity, Peer};
use mdcore::platform::{IfaceMode, Platform};

type Eng = Engine<DesktopPlatform>;

// ---------------------------------------------------------------------------
// Platform implementation
// ---------------------------------------------------------------------------

/// System clipboard via arboard (a fresh handle per call, as before).
struct DesktopClipboard;

impl Clipboard for DesktopClipboard {
    fn get(&self) -> Option<String> {
        arboard::Clipboard::new().ok().and_then(|mut c| c.get_text().ok())
    }
    fn set(&self, text: &str) {
        if let Ok(mut c) = arboard::Clipboard::new() {
            let _ = c.set_text(text.to_owned());
        }
    }
}

struct DesktopPlatform {
    app: AppHandle,
    clipboard: DesktopClipboard,
}

impl DesktopPlatform {
    /// `~/.config/<id>/session.json` — a flat `{key: value}` JSON map.
    fn config_file(&self) -> Option<PathBuf> {
        let dir = self.app.path().app_config_dir().ok()?;
        let _ = std::fs::create_dir_all(&dir);
        Some(dir.join("session.json"))
    }

    fn read_map(&self) -> serde_json::Map<String, serde_json::Value> {
        self.config_file()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
}

/// Optional test suffix (`TEST=foo npm run tauri dev`) so several instances on
/// one machine register as distinct devices instead of clobbering the same
/// machine-uid row. Trimmed; empty/unset => no suffix.
fn test_suffix() -> Option<String> {
    std::env::var("TEST").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

impl Platform for DesktopPlatform {
    fn device_id(&self) -> String {
        let base = machine_uid::get().unwrap_or_default();
        match test_suffix() {
            Some(suffix) => format!("{base}-{suffix}"),
            None => base,
        }
    }

    fn device_name(&self) -> String {
        let base = gethostname::gethostname().to_string_lossy().to_string();
        match test_suffix() {
            Some(suffix) => format!("{base} [{suffix}]"),
            None => base,
        }
    }

    fn platform_kind(&self) -> &'static str {
        "desktop"
    }

    fn iface_mode(&self) -> IfaceMode {
        let mut v4_addrs = Vec::new();
        if let Ok(ifaces) = if_addrs::get_if_addrs() {
            for iface in ifaces {
                if iface.is_loopback() {
                    continue;
                }
                if let IpAddr::V4(v4) = iface.ip() {
                    v4_addrs.push(v4);
                }
            }
        }
        IfaceMode::All { v4_addrs }
    }

    fn kv_get(&self, key: &str) -> Option<String> {
        self.read_map()
            .get(key)
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    fn kv_set(&self, key: &str, value: &str) {
        let mut map = self.read_map();
        map.insert(key.to_string(), serde_json::Value::String(value.to_string()));
        if let Some(p) = self.config_file() {
            if let Ok(bytes) = serde_json::to_vec_pretty(&map) {
                let _ = std::fs::write(p, bytes);
            }
        }
    }

    fn clipboard(&self) -> Option<&dyn Clipboard> {
        Some(&self.clipboard)
    }
}

// ---------------------------------------------------------------------------
// Event sink — bridge core events to the existing Tauri event names/payloads.
// ---------------------------------------------------------------------------

struct TauriSink {
    app: AppHandle,
}

impl EventSink for TauriSink {
    fn emit(&self, ev: CoreEvent) {
        match ev {
            CoreEvent::PeersUpdated { peers } => {
                let _ = self.app.emit("peers-updated", peers);
            }
            CoreEvent::MessageReceived(msg) => {
                let _ = self.app.emit("message-received", msg);
            }
            CoreEvent::WsConnected { node_id } => {
                let _ = self.app.emit("ws-connected", node_id);
            }
            CoreEvent::WsDisconnected { node_id } => {
                let _ = self.app.emit("ws-disconnected", node_id);
            }
            CoreEvent::Clipboard { from, ip, protocol, action } => {
                let _ = self.app.emit(
                    "clipboard-event",
                    serde_json::json!({ "from": from, "ip": ip, "protocol": protocol, "action": action }),
                );
            }
            CoreEvent::Notification { from, title, body, app } => {
                let _ = self.app.emit(
                    "notification-event",
                    serde_json::json!({ "from": from, "title": title, "body": body, "app": app }),
                );
            }
            CoreEvent::CallNotification { from, caller, number, state } => {
                let _ = self.app.emit(
                    "call-notification-event",
                    serde_json::json!({ "from": from, "caller": caller, "number": number, "state": state }),
                );
            }
            CoreEvent::CallHistory { from, entries } => {
                let _ = self.app.emit(
                    "call-history-event",
                    serde_json::json!({ "from": from, "entries": entries }),
                );
            }
            CoreEvent::AppsList { from, apps, subscribed } => {
                let _ = self.app.emit(
                    "apps-list-event",
                    serde_json::json!({ "from": from, "apps": apps, "subscribed": subscribed }),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tauri commands (thin wrappers over the Engine)
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_identity(engine: State<Eng>) -> Identity {
    engine.identity()
}

#[tauri::command]
fn get_peers(engine: State<Eng>) -> Vec<Peer> {
    engine.get_peers()
}

#[tauri::command]
fn get_saved_session(engine: State<Eng>) -> SavedSession {
    engine.saved_session()
}

#[tauri::command]
fn is_ready(engine: State<Eng>) -> bool {
    engine.is_ready()
}

#[tauri::command]
fn session_info(engine: State<Eng>) -> SessionInfo {
    engine.session_info()
}

#[tauri::command]
fn auth_register(server_url: String, username: String, password: String, engine: State<Eng>) -> Result<(), String> {
    engine.auth_register(&server_url, &username, &password)
}

#[tauri::command]
fn auth_login(server_url: String, username: String, password: String, engine: State<Eng>) -> Result<(), String> {
    engine.auth_login(&server_url, &username, &password)
}

#[tauri::command]
fn set_encryption_key(passphrase: String, engine: State<Eng>) -> Result<(), String> {
    engine.set_encryption_key(&passphrase)
}

#[tauri::command]
fn update_encryption_key(new_passphrase: String, password: String, engine: State<Eng>) -> Result<(), String> {
    engine.update_encryption_key(&new_passphrase, &password)
}

#[tauri::command]
fn generate_key(engine: State<Eng>) -> String {
    engine.generate_key()
}

#[tauri::command]
fn logout(engine: State<Eng>) {
    engine.logout()
}

#[tauri::command]
fn refresh_from_server(engine: State<Eng>) -> Result<(), String> {
    engine.refresh_from_server()
}

#[tauri::command]
fn scan_lan(engine: State<Eng>) {
    engine.scan_lan()
}

#[tauri::command]
fn connect_ws(node_id: String, engine: State<Eng>) -> Result<(), String> {
    engine.connect_ws(&node_id)
}

#[tauri::command]
fn send_message(node_id: String, protocol: String, text: String, engine: State<Eng>) -> Result<(), String> {
    engine.send(&node_id, &protocol, &text)
}

#[tauri::command]
fn enable_clipboard_sync(engine: State<Eng>) {
    engine.enable_clipboard_sync()
}

#[tauri::command]
fn disable_clipboard_sync(engine: State<Eng>) {
    engine.disable_clipboard_sync()
}

#[tauri::command]
fn clipboard_sync_enabled(engine: State<Eng>) -> bool {
    engine.clipboard_sync_enabled()
}

#[tauri::command]
fn get_clipboard(node_id: String, engine: State<Eng>) -> Result<String, String> {
    engine.get_clipboard(&node_id)
}

#[tauri::command]
fn add_manual_peer(
    name: String,
    ip: String,
    tcp_port: u16,
    udp_port: u16,
    ws_port: u16,
    engine: State<Eng>,
) -> Result<(), String> {
    engine.add_manual_peer(&name, &ip, tcp_port, udp_port, ws_port)
}

#[tauri::command]
fn remove_peer(node_id: String, engine: State<Eng>) {
    engine.remove_peer(&node_id)
}

#[tauri::command]
fn share_notification(title: String, body: String, app: Option<String>, engine: State<Eng>) {
    engine.share_notification(&title, &body, app.as_deref())
}

#[tauri::command]
fn share_call_notification(caller: String, number: Option<String>, state: String, engine: State<Eng>) {
    engine.share_call_notification(&caller, number.as_deref(), &state)
}

#[tauri::command]
fn share_call_history(entries_json: String, engine: State<Eng>) {
    engine.share_call_history(&entries_json)
}

// --- signaling / connection setup ---

#[tauri::command]
fn connect(node_id: String, engine: State<Eng>) -> Result<(), String> {
    engine.connect(&node_id)
}

#[tauri::command]
fn firewall_check(engine: State<Eng>) -> Result<FirewallStatus, String> {
    engine.firewall_check()
}

#[tauri::command]
fn update_ws_open(open: bool, engine: State<Eng>) -> Result<(), String> {
    engine.update_ws_open(open)
}

/// Feed an inbound signal (when a desktop signal channel — e.g. SSE — is wired).
#[tauri::command]
fn on_signal(from: String, payload: String, engine: State<Eng>) {
    engine.on_signal(&from, &payload)
}

// --- app-notification pub/sub (consumer side) ---

#[tauri::command]
fn request_apps(node_id: String, engine: State<Eng>) -> Result<(), String> {
    engine.request_apps(&node_id)
}

#[tauri::command]
fn subscribe_apps(node_id: String, apps_json: String, engine: State<Eng>) -> Result<(), String> {
    engine.subscribe_apps(&node_id, &apps_json)
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(move |app| {
            let handle = app.handle().clone();
            let platform = DesktopPlatform {
                app: handle.clone(),
                clipboard: DesktopClipboard,
            };
            let sink: Arc<dyn EventSink> = Arc::new(TauriSink { app: handle.clone() });
            match Engine::start(platform, sink) {
                Ok(engine) => {
                    app.manage(engine);
                }
                Err(e) => {
                    eprintln!("failed to start networking: {e}");
                    return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e)));
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
            enable_clipboard_sync,
            disable_clipboard_sync,
            clipboard_sync_enabled,
            get_clipboard,
            add_manual_peer,
            remove_peer,
            share_notification,
            share_call_notification,
            share_call_history,
            connect,
            firewall_check,
            update_ws_open,
            on_signal,
            request_apps,
            subscribe_apps
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
