const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

let peers = [];
const el = (id) => document.getElementById(id);
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function setStatus(id, msg, ok) {
  const s = el(id);
  if (!s) return;
  s.textContent = msg;
  s.className = "status " + (ok ? "ok" : msg ? "err" : "");
}

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
    await invoke(isRegister ? "auth_register" : "auth_login", {
      serverUrl: server,
      username: user,
      password: pass,
    });
    await invoke("set_encryption_key", { passphrase: key });
    await enterApp();
  } catch (err) {
    setStatus("a-status", String(err), false);
  }
}

async function enterApp() {
  el("auth").classList.add("hidden");
  el("app").classList.remove("hidden");
  const id = await invoke("get_identity");
  el("me-line").textContent = `${id.name} · ${id.ip} · tcp ${id.tcp_port} · udp ${id.udp_port} · ws ${id.ws_port}`;
  const info = await invoke("session_info");
  el("set-who").textContent = `${info.username ?? ""} @ ${info.server_url ?? ""}`;
  try { await invoke("refresh_from_server"); } catch (e) { console.warn(e); }
  await loadPeers();
}

// ---------- peers ----------
async function loadPeers() {
  try { peers = await invoke("get_peers"); render(); } catch (e) { console.error(e); }
}

function render() {
  el("peer-count").textContent = peers.length;
  const list = el("peer-list");
  if (!peers.length) {
    list.innerHTML = '<li class="empty">No peers yet — Refresh (registry) or Scan LAN.</li>';
  } else {
    list.innerHTML = peers
      .map(
        (p) => `<li class="peer">
          <div class="peer-meta">
            <strong>${esc(p.name)} <span class="badge src-${esc(p.source)}">${esc(p.source)}</span></strong>
            <span class="muted small">${esc(p.ip)} · tcp ${p.tcp_port} · udp ${p.udp_port} · ws ${p.ws_port}</span>
          </div>
          <div class="peer-actions">
            ${p.ws_port ? `<button class="ws-btn" data-id="${esc(p.node_id)}">Connect WS</button>` : ""}
            ${p.source === "manual" ? `<button class="remove" data-id="${esc(p.node_id)}">✕</button>` : ""}
          </div>
        </li>`
      )
      .join("");
  }
  const sel = el("peer-select");
  const prev = sel.value;
  sel.innerHTML = peers.map((p) => `<option value="${esc(p.node_id)}">${esc(p.name)} (${esc(p.ip)})</option>`).join("");
  if (peers.some((p) => p.node_id === prev)) sel.value = prev;
}

function addLog({ dir, peer, ip, protocol, text, ok = true }) {
  const log = el("log");
  if (log.querySelector(".empty")) log.innerHTML = "";
  const li = document.createElement("li");
  li.className = `entry ${dir} ${ok ? "" : "bad"}`;
  li.innerHTML = `<div class="entry-head">
      <span class="badge ${protocol.toLowerCase()}">${protocol}</span>
      <span>${dir === "in" ? "from" : "to"} <strong>${esc(peer)}</strong></span>
      <span class="muted small">${esc(ip || "")}</span>
    </div><div class="entry-text">${esc(text)}</div>`;
  log.prepend(li);
}

// ---------- send ----------
async function onSend(e) {
  e.preventDefault();
  const node_id = el("peer-select").value;
  const protocol = document.querySelector('input[name="proto"]:checked').value;
  const text = el("msg-input").value.trim();
  if (!node_id) return setStatus("send-status", "Pick a peer.", false);
  if (!text) return setStatus("send-status", "Message is empty.", false);
  const peer = peers.find((p) => p.node_id === node_id);
  el("send-btn").disabled = true;
  try {
    if (protocol === "WS") {
      await invoke("connect_ws", { nodeId: node_id });
      await new Promise((r) => setTimeout(r, 400));
    }
    try {
      await invoke("send_message", { nodeId: node_id, protocol, text });
    } catch (err) {
      if (protocol === "WS" && String(err).includes("no WebSocket")) {
        await new Promise((r) => setTimeout(r, 600));
        await invoke("send_message", { nodeId: node_id, protocol, text });
      } else throw err;
    }
    addLog({ dir: "out", peer: peer ? peer.name : "peer", ip: peer ? peer.ip : "", protocol, text });
    el("msg-input").value = "";
    setStatus("send-status", `Sent over ${protocol}.`, true);
  } catch (err) {
    setStatus("send-status", String(err), false);
  } finally {
    el("send-btn").disabled = false;
  }
}

// ---------- init ----------
async function init() {
  const saved = await invoke("get_saved_session");
  if (saved.server_url) el("a-server").value = saved.server_url;
  if (saved.username) el("a-user").value = saved.username;

  el("auth-form").addEventListener("submit", (e) => onAuth(e, false));
  el("a-register").addEventListener("click", (e) => onAuth(e, true));
  el("a-genkey").addEventListener("click", async () => { el("a-key").value = await invoke("generate_key"); });

  el("send-form").addEventListener("submit", onSend);
  el("clear-log").addEventListener("click", () => { el("log").innerHTML = '<li class="empty">No messages yet.</li>'; });
  el("btn-refresh").addEventListener("click", async () => { try { await invoke("refresh_from_server"); } catch (e) { alert(e); } });
  el("btn-scan").addEventListener("click", () => invoke("scan_lan"));
  el("btn-settings").addEventListener("click", () => el("settings").classList.remove("hidden"));

  el("manual-form").addEventListener("submit", onAddManual);
  el("peer-list").addEventListener("click", async (e) => {
    const ws = e.target.closest(".ws-btn");
    const rm = e.target.closest(".remove");
    if (ws) { try { await invoke("connect_ws", { nodeId: ws.dataset.id }); ws.textContent = "WS ✓"; } catch (err) { alert(err); } }
    if (rm) { await invoke("remove_peer", { nodeId: rm.dataset.id }); await loadPeers(); }
  });

  // settings
  el("s-genkey").addEventListener("click", async () => { el("s-key").value = await invoke("generate_key"); });
  el("s-close").addEventListener("click", () => el("settings").classList.add("hidden"));
  el("settings-form").addEventListener("submit", onUpdateKey);
  el("s-logout").addEventListener("click", async () => {
    await invoke("logout");
    location.reload();
  });

  await listen("peers-updated", (ev) => { peers = ev.payload; render(); });
  await listen("message-received", (ev) => {
    const m = ev.payload;
    addLog({ dir: "in", peer: m.from, ip: m.ip, protocol: m.protocol, text: m.text, ok: m.ok });
  });
}

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
    setStatus("manual-status", `Added ${ip}.`, true);
  } catch (err) {
    setStatus("manual-status", String(err), false);
  }
}

async function onUpdateKey(e) {
  e.preventDefault();
  const key = el("s-key").value;
  const pass = el("s-pass").value;
  if (!key || !pass) return setStatus("s-status", "Both fields required.", false);
  try {
    await invoke("update_encryption_key", { newPassphrase: key, password: pass });
    setStatus("s-status", "Encryption key updated.", true);
    el("s-key").value = el("s-pass").value = "";
  } catch (err) {
    setStatus("s-status", String(err), false);
  }
}

window.addEventListener("DOMContentLoaded", init);
