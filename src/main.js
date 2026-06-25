const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const el = (id) => document.getElementById(id);
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ---------- state ----------
let peers = [];
const connected = new Set(); // node_ids with a live WebSocket
let selected = null; // selected node_id
let view = "empty"; // empty | device | settings
let identity = null;
const activity = []; // { node?, dir, name, ip, protocol, text, ok, ts }

// ---------- helpers ----------
function setStatus(id, msg, ok) {
  const s = el(id);
  if (!s) return;
  s.textContent = msg || "";
  s.className = "status " + (ok ? "ok" : msg ? "err" : "");
}
let toastTimer;
function toast(msg) {
  const t = el("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 2200);
}
const selectedPeer = () => peers.find((p) => p.node_id === selected) || null;
const avatarText = (name) => (name || "?").trim().charAt(0).toUpperCase() || "?";

// ---------- auth ----------
async function onAuth(e, isRegister) {
  if (e) e.preventDefault();
  const server = el("a-server").value.trim();
  const user = el("a-user").value.trim();
  const pass = el("a-pass").value;
  const key = el("a-key").value;
  if (!server || !user || !pass || !key) return setStatus("a-status", "All fields are required.", false);
  setStatus("a-status", "Connecting…", true);
  try {
    await invoke(isRegister ? "auth_register" : "auth_login", { serverUrl: server, username: user, password: pass });
    await invoke("set_encryption_key", { passphrase: key });
    await enterApp();
  } catch (err) {
    setStatus("a-status", String(err), false);
  }
}

async function enterApp() {
  el("login").classList.add("hidden");
  el("app").classList.remove("hidden");
  identity = await invoke("get_identity");
  el("me-name").textContent = identity.name;
  const info = await invoke("session_info");
  el("set-who").textContent = `${info.username ?? ""} @ ${info.server_url ?? ""}`;
  el("acct-line").textContent = `Signed in as ${info.username ?? "?"} · ${info.server_url ?? ""}`;
  renderMeDetails();
  try { await invoke("refresh_from_server"); } catch (e) { console.warn(e); }
  await loadPeers();
  await refreshClipToggle();
}

function renderMeDetails() {
  if (!identity) return;
  el("me-details").innerHTML = `
    <dt>Name</dt><dd>${esc(identity.name)}</dd>
    <dt>IP</dt><dd>${esc(identity.ip)}</dd>
    <dt>TCP</dt><dd>${identity.tcp_port}</dd>
    <dt>UDP</dt><dd>${identity.udp_port}</dd>
    <dt>WS</dt><dd>${identity.ws_port}</dd>
    <dt>Node</dt><dd>${esc(identity.node_id)}</dd>`;
}

// ---------- peers / sidebar ----------
async function loadPeers() {
  try { peers = await invoke("get_peers"); renderDevices(); } catch (e) { console.error(e); }
}

function renderDevices() {
  const list = el("device-list");
  if (!peers.length) {
    list.innerHTML = '<li class="empty">No devices yet.<br/>Scan LAN or Refresh.</li>';
  } else {
    list.innerHTML = peers
      .map((p) => {
        const isConn = connected.has(p.node_id);
        const dotCls = isConn ? "connected" : "online";
        return `<li class="device ${p.node_id === selected ? "active" : ""}" data-id="${esc(p.node_id)}">
          <span class="avatar">${esc(avatarText(p.name))}</span>
          <span class="info">
            <span class="nm"><span class="dot ${dotCls}"></span><strong>${esc(p.name)}</strong></span>
            <span class="sub">${esc(p.ip)} · <span class="badge src-${esc(p.source)}">${esc(p.source)}</span></span>
          </span>
        </li>`;
      })
      .join("");
  }
  if (selected && view === "device") renderDevice();
}

function selectDevice(id) {
  selected = id;
  view = "device";
  el("nav-settings").classList.remove("active");
  showView();
  renderDevices();
  renderDevice();
}

function showView() {
  el("view-empty").classList.toggle("hidden", view !== "empty");
  el("view-device").classList.toggle("hidden", view !== "device");
  el("view-settings").classList.toggle("hidden", view !== "settings");
}

// ---------- device view ----------
function renderDevice() {
  const p = selectedPeer();
  if (!p) { view = "empty"; showView(); return; }
  const isConn = connected.has(p.node_id);
  el("dv-avatar").textContent = avatarText(p.name);
  el("dv-name").textContent = p.name;
  el("dv-sub").textContent = `${p.ip} · tcp ${p.tcp_port} · udp ${p.udp_port} · ws ${p.ws_port}`;
  const status = el("dv-status");
  status.textContent = isConn ? "connected" : "online";
  status.className = "pill " + (isConn ? "connected" : "online");
  const cbtn = el("btn-connect");
  cbtn.textContent = isConn ? "Connected ✓" : "Connect";
  cbtn.disabled = isConn || !p.ws_port;
  el("btn-remove").classList.toggle("hidden", p.source !== "manual");
  renderThread();
}

function relevant(entry, p) {
  return entry.node === p.node_id || entry.ip === p.ip || entry.name === p.name;
}

function renderThread() {
  const p = selectedPeer();
  const t = el("thread");
  const items = activity.filter((e) => relevant(e, p));
  if (!items.length) { t.innerHTML = '<li class="empty">No activity yet.</li>'; return; }
  t.innerHTML = items
    .map(
      (e) => `<li class="entry ${e.dir} ${e.ok ? "" : "bad"}">
        <div class="entry-head">
          <span class="badge ${esc((e.protocol || "").toLowerCase())}">${esc(e.protocol || "")}</span>
          <span>${e.dir === "in" ? "from" : "to"} <strong>${esc(e.name || "peer")}</strong></span>
        </div>
        <div class="entry-text">${esc(e.text)}</div>
      </li>`
    )
    .join("");
}

function logActivity(entry) {
  activity.unshift({ ok: true, ts: Date.now(), ...entry });
  if (activity.length > 500) activity.pop();
  if (view === "device") renderThread();
}

// ---------- actions ----------
async function onSend(e) {
  e.preventDefault();
  const p = selectedPeer();
  if (!p) return;
  const protocol = document.querySelector('input[name="proto"]:checked').value;
  const text = el("msg-input").value.trim();
  if (!text) return setStatus("send-status", "Message is empty.", false);
  el("send-btn").disabled = true;
  try {
    if (protocol === "WS") {
      await invoke("connect_ws", { nodeId: p.node_id });
      await new Promise((r) => setTimeout(r, 400));
    }
    try {
      await invoke("send_message", { nodeId: p.node_id, protocol, text });
    } catch (err) {
      if (protocol === "WS" && String(err).includes("no WebSocket")) {
        await new Promise((r) => setTimeout(r, 600));
        await invoke("send_message", { nodeId: p.node_id, protocol, text });
      } else throw err;
    }
    logActivity({ node: p.node_id, dir: "out", name: p.name, ip: p.ip, protocol, text });
    el("msg-input").value = "";
    setStatus("send-status", `Sent over ${protocol}.`, true);
  } catch (err) {
    setStatus("send-status", String(err), false);
  } finally {
    el("send-btn").disabled = false;
  }
}

async function refreshClipToggle() {
  const on = await invoke("clipboard_sync_enabled");
  el("clip-toggle").setAttribute("aria-checked", on ? "true" : "false");
}
async function onClipToggle() {
  const on = await invoke("clipboard_sync_enabled");
  await invoke(on ? "disable_clipboard_sync" : "enable_clipboard_sync");
  await refreshClipToggle();
  toast(on ? "Clipboard auto-sync off" : "Clipboard auto-sync on");
}
async function onClipGet() {
  const p = selectedPeer();
  if (!p) return;
  el("clip-get-btn").disabled = true;
  setStatus("clip-status", "Requesting…", true);
  try {
    const text = await invoke("get_clipboard", { nodeId: p.node_id });
    setStatus("clip-status", "Copied to your clipboard.", true);
    logActivity({ node: p.node_id, dir: "in", name: p.name, ip: p.ip, protocol: "CLIP", text: `📋 ${text}` });
  } catch (err) {
    setStatus("clip-status", String(err), false);
  } finally {
    el("clip-get-btn").disabled = false;
  }
}

async function onNotif(e) {
  e.preventDefault();
  const title = el("n-title").value.trim();
  const body = el("n-body").value.trim();
  if (!title) return setStatus("notif-status", "Title required.", false);
  try {
    await invoke("share_notification", { title, body, app: "my-domain" });
    setStatus("notif-status", "Notification sent to your devices.", true);
    el("n-title").value = el("n-body").value = "";
  } catch (err) {
    setStatus("notif-status", String(err), false);
  }
}

// ---------- settings ----------
function openSettings() {
  view = "settings";
  selected = null;
  el("nav-settings").classList.add("active");
  showView();
  renderDevices();
}
async function onUpdateKey(e) {
  e.preventDefault();
  const key = el("s-key").value, pass = el("s-pass").value;
  if (!key || !pass) return setStatus("s-status", "Both fields required.", false);
  try {
    await invoke("update_encryption_key", { newPassphrase: key, password: pass });
    setStatus("s-status", "Encryption key updated.", true);
    el("s-key").value = el("s-pass").value = "";
  } catch (err) {
    setStatus("s-status", String(err), false);
  }
}
async function onFirewall() {
  setStatus("fw-status", "Checking…", true);
  try {
    const fs = await invoke("firewall_check");
    const out = fs.outbound_ok ? "outbound OK" : "outbound BLOCKED";
    const inb = fs.inbound_blocked ? "inbound blocked (needs relay)" : "inbound reachable";
    setStatus("fw-status", `${out} · ${inb}`, fs.outbound_ok);
  } catch (err) {
    setStatus("fw-status", String(err), false);
  }
}

// ---------- manual add ----------
function openAdd() { el("modal-add").classList.remove("hidden"); }
function closeAdd() { el("modal-add").classList.add("hidden"); setStatus("manual-status", "", false); }
async function onAddManual(e) {
  e.preventDefault();
  const name = el("m-name").value.trim();
  const ip = el("m-ip").value.trim();
  const tcpPort = parseInt(el("m-tcp").value, 10) || 0;
  const udpPort = parseInt(el("m-udp").value, 10) || 0;
  const wsPort = parseInt(el("m-ws").value, 10) || 0;
  if (!ip) return setStatus("manual-status", "Enter an IP.", false);
  try {
    await invoke("add_manual_peer", { name, ip, tcpPort, udpPort, wsPort });
    await loadPeers();
    el("m-name").value = el("m-ip").value = el("m-tcp").value = el("m-udp").value = el("m-ws").value = "";
    closeAdd();
    toast(`Added ${ip}`);
  } catch (err) {
    setStatus("manual-status", String(err), false);
  }
}

// ---------- init ----------
async function init() {
  const saved = await invoke("get_saved_session");
  if (saved.server_url) el("a-server").value = saved.server_url;
  if (saved.username) el("a-user").value = saved.username;

  el("login-form").addEventListener("submit", (e) => onAuth(e, false));
  el("a-register").addEventListener("click", (e) => onAuth(e, true));
  el("a-genkey").addEventListener("click", async () => { el("a-key").value = await invoke("generate_key"); });

  // sidebar
  el("device-list").addEventListener("click", (e) => {
    const row = e.target.closest(".device");
    if (row) selectDevice(row.dataset.id);
  });
  el("btn-scan").addEventListener("click", () => { invoke("scan_lan"); toast("Scanning LAN…"); });
  el("btn-refresh").addEventListener("click", async () => { try { await invoke("refresh_from_server"); toast("Refreshed"); } catch (e) { toast(String(e)); } });
  el("btn-add").addEventListener("click", openAdd);
  el("nav-settings").addEventListener("click", openSettings);

  // device view
  el("send-form").addEventListener("submit", onSend);
  el("clip-toggle").addEventListener("click", onClipToggle);
  el("clip-get-btn").addEventListener("click", onClipGet);
  el("notif-form").addEventListener("submit", onNotif);
  el("clear-log").addEventListener("click", () => { const p = selectedPeer(); for (let i = activity.length - 1; i >= 0; i--) if (relevant(activity[i], p)) activity.splice(i, 1); renderThread(); });
  el("btn-connect").addEventListener("click", async () => {
    const p = selectedPeer(); if (!p) return;
    el("btn-connect").textContent = "Connecting…";
    try { await invoke("connect_ws", { nodeId: p.node_id }); } catch (err) { toast(String(err)); renderDevice(); }
  });
  el("btn-remove").addEventListener("click", async () => {
    const p = selectedPeer(); if (!p) return;
    await invoke("remove_peer", { nodeId: p.node_id });
    selected = null; view = "empty"; showView();
    await loadPeers();
  });

  // settings
  el("settings-form").addEventListener("submit", onUpdateKey);
  el("s-genkey").addEventListener("click", async () => { el("s-key").value = await invoke("generate_key"); });
  el("btn-firewall").addEventListener("click", onFirewall);
  el("s-logout").addEventListener("click", async () => { await invoke("logout"); location.reload(); });

  // modal
  el("manual-form").addEventListener("submit", onAddManual);
  el("m-cancel").addEventListener("click", closeAdd);
  el("modal-add").addEventListener("click", (e) => { if (e.target.id === "modal-add") closeAdd(); });

  // events
  await listen("peers-updated", (ev) => { peers = ev.payload; renderDevices(); });
  await listen("ws-connected", (ev) => { connected.add(ev.payload); renderDevices(); if (view === "device") renderDevice(); });
  await listen("ws-disconnected", (ev) => { connected.delete(ev.payload); renderDevices(); if (view === "device") renderDevice(); });
  await listen("message-received", (ev) => {
    const m = ev.payload;
    logActivity({ dir: "in", name: m.from, ip: m.ip, protocol: m.protocol, text: m.text, ok: m.ok });
  });
  await listen("clipboard-event", (ev) => {
    const m = ev.payload;
    logActivity({ dir: "in", name: m.from, ip: m.ip, protocol: "CLIP", text: "📋 Clipboard synced" });
  });
  await listen("notification-event", (ev) => {
    const m = ev.payload;
    logActivity({ dir: "in", name: m.from, protocol: "NOTIF", text: `🔔 ${m.title}${m.body ? " — " + m.body : ""}` });
    toast(`🔔 ${m.title}`);
  });
  await listen("call-notification-event", (ev) => {
    const m = ev.payload;
    logActivity({ dir: "in", name: m.from, protocol: "CALL", text: `📞 ${m.caller || ""} (${m.state})` });
  });
  await listen("call-history-event", (ev) => {
    const m = ev.payload;
    logActivity({ dir: "in", name: m.from, protocol: "CALL", text: "📞 Call history synced" });
  });
}

window.addEventListener("DOMContentLoaded", init);
