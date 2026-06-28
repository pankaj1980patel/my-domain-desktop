// Desktop FCM receiver.
//
// The desktop has no Firebase SDK (it is a native process, not a browser or an
// Android app), so we use `fcm_receiver_rs`, which registers with FCM the way a
// web/Android client would — GCM check-in + register, then a persistent MTalk
// (mcs) connection to mtalk.google.com:5228 — and delivers data messages.
//
// This mirrors the Android `FirebaseMessagingService` path: obtain a token,
// publish it to the registry (via the Engine's `fcm_token()` + a refresh), and
// feed inbound signals into `Engine::on_signal`, which drives the responder side
// of the connection ladder.
//
// Credentials (all overridable by env; the two public web-config values fall
// back to the project defaults):
//   MYDOMAIN_FCM_API_KEY     (public web apiKey)        — default baked in
//   MYDOMAIN_FCM_PROJECT_ID  (Firebase project id)      — default baked in
//   MYDOMAIN_FCM_APP_ID      (1:NNN:web:xxxx / android)  — REQUIRED
//   MYDOMAIN_FCM_VAPID_KEY   (Web Push public key)       — REQUIRED
// Missing APP_ID or VAPID_KEY => the receiver is disabled (logged once), exactly
// like the server skips FCM when its service-account is absent.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};

use fcm_receiver_rs::client::FcmClient;

use crate::Eng;

/// Mirror an FCM lifecycle/message line to the frontend debug panel. `kind` is
/// one of "token" | "message" | "error" | "info"; the panel renders errors red.
fn emit_fcm(app: &AppHandle, kind: &str, from: &str, text: &str) {
    let _ = app.emit(
        "fcm-event",
        serde_json::json!({ "kind": kind, "from": from, "text": text }),
    );
}

/// Truncate a string for a one-line log entry.
fn preview(s: &str) -> String {
    if s.chars().count() > 160 {
        format!("{}…", s.chars().take(160).collect::<String>())
    } else {
        s.to_string()
    }
}

/// Public web-config defaults for the `my-domain-c0c36` Firebase project. None
/// of these are secrets — the web SDK ships them to every browser, and the VAPID
/// value is the *public* push key (its private half stays on the server). Baking
/// them means every desktop install can receive push signals out of the box; a
/// `fcm_config.json` or env var still overrides any of them per machine.
const DEFAULT_API_KEY: &str = "AIzaSyC15ftHcLqR3kaSp9iFWJQTyOaByEeLves";
const DEFAULT_PROJECT_ID: &str = "my-domain-c0c36";
const DEFAULT_APP_ID: &str = "1:744722246836:web:11fa725b96ced3ecebfbe1";
const DEFAULT_VAPID_KEY: &str =
    "BGENRpf8b_hvgMPaQ45OJZfjL6_l6-iwVTmYXqJrk0Fn0KcSy_sIX3XcISIBb9ijFkjEoz3uguOHBrkDFy51zxs";

struct FcmConfig {
    api_key: String,
    app_id: String,
    project_id: String,
    vapid_key: String,
}

impl FcmConfig {
    /// Env first, then `<config>/fcm_config.json`, then defaults for the public
    /// values. Returns `None` (receiver disabled) if app_id or vapid_key is unset.
    fn load(config_dir: &Path) -> Option<FcmConfig> {
        let file: FileConfig = std::fs::read(config_dir.join("fcm_config.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();

        let pick = |env: &str, from_file: &str, default: &str| -> String {
            std::env::var(env)
                .ok()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| Some(from_file.to_string()).filter(|s| !s.trim().is_empty()))
                .unwrap_or_else(|| default.to_string())
        };

        let cfg = FcmConfig {
            api_key: pick("MYDOMAIN_FCM_API_KEY", &file.api_key, DEFAULT_API_KEY),
            app_id: pick("MYDOMAIN_FCM_APP_ID", &file.app_id, DEFAULT_APP_ID),
            project_id: pick("MYDOMAIN_FCM_PROJECT_ID", &file.project_id, DEFAULT_PROJECT_ID),
            vapid_key: pick("MYDOMAIN_FCM_VAPID_KEY", &file.vapid_key, DEFAULT_VAPID_KEY),
        };
        if cfg.app_id.trim().is_empty() || cfg.vapid_key.trim().is_empty() {
            return None;
        }
        Some(cfg)
    }
}

#[derive(Deserialize, Default)]
struct FileConfig {
    #[serde(default)]
    api_key: String,
    #[serde(default)]
    app_id: String,
    #[serde(default)]
    project_id: String,
    #[serde(default)]
    vapid_key: String,
}

/// Persisted registration so we keep the same FCM token (and MTalk identity)
/// across restarts — re-registering would orphan the old token on the server.
#[derive(Serialize, Deserialize)]
struct Creds {
    fcm_token: String,
    gcm_token: String,
    android_id: u64,
    security_token: u64,
    private_key_base64: String,
    auth_secret_base64: String,
}

/// Start the FCM receiver in a background thread. No-op (with a log line) if the
/// required credentials are absent.
pub fn spawn(app: AppHandle, token_cell: Arc<Mutex<Option<String>>>) {
    let config_dir = match app.path().app_config_dir() {
        Ok(d) => {
            let _ = std::fs::create_dir_all(&d);
            d
        }
        Err(e) => {
            eprintln!("[fcm] disabled: no config dir: {e}");
            return;
        }
    };
    let Some(cfg) = FcmConfig::load(&config_dir) else {
        eprintln!(
            "[fcm] disabled: set MYDOMAIN_FCM_APP_ID and MYDOMAIN_FCM_VAPID_KEY \
             (env or {}/fcm_config.json) to receive push signals on desktop",
            config_dir.display()
        );
        return;
    };

    std::thread::spawn(move || {
        if let Err(e) = run(app, token_cell, cfg, config_dir.join("fcm_creds.json")) {
            eprintln!("[fcm] receiver stopped: {e}");
        }
    });
}

fn run(
    app: AppHandle,
    token_cell: Arc<Mutex<Option<String>>>,
    cfg: FcmConfig,
    creds_path: PathBuf,
) -> Result<(), String> {
    let mut client =
        FcmClient::new(cfg.api_key, cfg.app_id, cfg.project_id).map_err(|e| e.to_string())?;
    client.vapid_key = cfg.vapid_key;

    // Inbound data message -> Engine::on_signal. The data fields set by the
    // server (server/src/signal.rs) are `type`, `from`, `to`, `payload`.
    let handle = app.clone();
    client.on_data_message = Some(Arc::new(move |payload: Vec<u8>| {
        match extract_signal(&payload) {
            Some((from, sig)) => {
                // Self-test pong: the server echoes our ping as `selfping:<sid>`.
                // Receiving it proves the full push path works; don't forward it
                // to the Engine (it isn't a real Signal).
                if let Some(sid) = sig.strip_prefix("selfping:") {
                    emit_fcm(&handle, "info", &from, &format!("self-test pong received — FCM round-trip OK ✓ ({sid})"));
                } else {
                    emit_fcm(&handle, "message", &from, &preview(&sig));
                    if let Some(engine) = handle.try_state::<Eng>() {
                        engine.on_signal(&from, &sig);
                    }
                }
            }
            None => {
                let raw = String::from_utf8_lossy(&payload);
                emit_fcm(&handle, "message", "", &format!("unparsed payload: {}", preview(&raw)));
            }
        }
    }));

    // Reuse a persisted registration if we have one; otherwise register fresh.
    let token = match load_creds(&creds_path) {
        Some(creds) => {
            client.android_id = creds.android_id;
            client.security_token = creds.security_token;
            client.gcm_token = Some(creds.gcm_token);
            client.fcm_token = Some(creds.fcm_token.clone());
            client
                .load_keys(&creds.private_key_base64, &creds.auth_secret_base64)
                .map_err(|e| e.to_string())?;
            creds.fcm_token
        }
        None => {
            let (private_key_base64, auth_secret_base64) =
                client.create_new_keys().map_err(|e| e.to_string())?;
            client
                .load_keys(&private_key_base64, &auth_secret_base64)
                .map_err(|e| e.to_string())?;
            let (fcm_token, gcm_token, android_id, security_token) =
                client.register().map_err(|e| e.to_string())?;
            save_creds(
                &creds_path,
                &Creds {
                    fcm_token: fcm_token.clone(),
                    gcm_token,
                    android_id,
                    security_token,
                    private_key_base64,
                    auth_secret_base64,
                },
            );
            fcm_token
        }
    };

    // Publish the token: the Platform now reports it, and a refresh pushes it to
    // the registry. If we aren't logged in yet, the refresh is a no-op; the
    // frontend refreshes again after login, by which point `fcm_token()` is set.
    let token_preview: String = token.chars().take(12).collect();
    emit_fcm(&app, "token", "", &format!("FCM token acquired ({token_preview}…)"));
    *token_cell.lock().unwrap() = Some(token);
    if let Some(engine) = app.try_state::<Eng>() {
        let _ = engine.refresh_from_server();
    }

    // Listen forever; reconnect with a fixed backoff on any drop.
    loop {
        emit_fcm(&app, "info", "", "MTalk connected — listening for push signals");
        if let Err(e) = client.start_listening() {
            emit_fcm(&app, "error", "", &format!("listen ended: {e}; reconnecting in 10s"));
            eprintln!("[fcm] listen ended: {e}; reconnecting in 10s");
        }
        std::thread::sleep(Duration::from_secs(10));
    }
}

/// Pull `(from, payload)` out of a decrypted data message. The data fields may
/// arrive at the top level or nested under a `data` object depending on how FCM
/// packages the web-push body, so check both.
fn extract_signal(bytes: &[u8]) -> Option<(String, String)> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let obj = v
        .get("data")
        .and_then(|d| d.as_object())
        .or_else(|| v.as_object())?;
    // `from` is an FCM-reserved data key, so the server sends the sender id as
    // `sender`; accept the legacy `from` too for forward/backward compatibility.
    let from = obj
        .get("sender")
        .or_else(|| obj.get("from"))
        .and_then(|v| v.as_str())?
        .to_string();
    let payload = obj.get("payload")?.as_str()?.to_string();
    Some((from, payload))
}

fn load_creds(path: &Path) -> Option<Creds> {
    let creds: Creds = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())?;
    if creds.android_id == 0
        || creds.security_token == 0
        || creds.private_key_base64.is_empty()
        || creds.auth_secret_base64.is_empty()
        || creds.fcm_token.is_empty()
    {
        return None;
    }
    Some(creds)
}

fn save_creds(path: &Path, creds: &Creds) {
    if let Ok(bytes) = serde_json::to_vec_pretty(creds) {
        let _ = std::fs::write(path, bytes);
    }
}
