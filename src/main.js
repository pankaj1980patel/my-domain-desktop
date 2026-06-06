const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

let peers = []; // current peer list from the backend

const el = (id) => document.getElementById(id);

function fmtTime(tsSecs) {
  const d = new Date(tsSecs * 1000);
  return d.toLocaleTimeString();
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function renderPeers() {
  const list = el("peer-list");
  const select = el("peer-select");
  el("peer-count").textContent = peers.length;

  // Peer cards
  if (peers.length === 0) {
    list.innerHTML = '<li class="empty" id="peer-empty">Searching the LAN for other devices…</li>';
  } else {
    list.innerHTML = peers
      .map(
        (p) => `
        <li class="peer">
          <span class="dot online"></span>
          <div class="peer-meta">
            <strong>${escapeHtml(p.name)}</strong>
            <span class="muted small">${escapeHtml(p.ip)} · tcp ${p.tcp_port} · udp ${p.udp_port}</span>
          </div>
        </li>`
      )
      .join("");
  }

  // Keep the dropdown in sync, preserving the current selection if possible.
  const prev = select.value;
  select.innerHTML = peers
    .map((p) => `<option value="${p.node_id}">${escapeHtml(p.name)} (${escapeHtml(p.ip)})</option>`)
    .join("");
  if (peers.some((p) => p.node_id === prev)) select.value = prev;
}

function addLogEntry({ direction, peer, ip, protocol, text, ts }) {
  const log = el("log");
  if (log.querySelector(".empty")) log.innerHTML = "";
  const li = document.createElement("li");
  li.className = `entry ${direction}`;
  li.innerHTML = `
    <div class="entry-head">
      <span class="badge ${protocol.toLowerCase()}">${protocol}</span>
      <span class="dir">${direction === "in" ? "from" : "to"} <strong>${escapeHtml(peer)}</strong></span>
      <span class="muted small">${escapeHtml(ip || "")}</span>
      <span class="muted small time">${fmtTime(ts)}</span>
    </div>
    <div class="entry-text">${escapeHtml(text)}</div>`;
  log.prepend(li);
}

function setStatus(msg, ok) {
  const s = el("send-status");
  s.textContent = msg;
  s.className = "status " + (ok ? "ok" : "err");
  if (msg) setTimeout(() => { if (s.textContent === msg) s.textContent = ""; }, 4000);
}

async function refreshPeers() {
  try {
    peers = await invoke("get_peers");
    renderPeers();
  } catch (e) {
    console.error(e);
  }
}

async function init() {
  // Show our own identity.
  try {
    const me = await invoke("get_identity");
    el("me-name").textContent = me.name;
    el("me-ip").textContent = `${me.ip} · tcp ${me.tcp_port} · udp ${me.udp_port}`;
  } catch (e) {
    el("me-name").textContent = "error starting network";
    console.error(e);
  }

  await refreshPeers();

  // Live updates pushed from Rust.
  await listen("peers-updated", (event) => {
    peers = event.payload;
    renderPeers();
  });

  await listen("message-received", (event) => {
    const m = event.payload;
    addLogEntry({
      direction: "in",
      peer: m.from,
      ip: m.ip,
      protocol: m.protocol,
      text: m.text,
      ts: m.ts,
    });
  });

  // Fallback poll in case an event is missed.
  setInterval(refreshPeers, 5000);

  el("send-form").addEventListener("submit", onSend);
  el("clear-log").addEventListener("click", () => {
    el("log").innerHTML = '<li class="empty">No messages yet.</li>';
  });
}

async function onSend(e) {
  e.preventDefault();
  const node_id = el("peer-select").value;
  const protocol = document.querySelector('input[name="proto"]:checked').value;
  const text = el("msg-input").value.trim();

  if (!node_id) return setStatus("Pick a peer first.", false);
  if (!text) return setStatus("Message is empty.", false);

  const peer = peers.find((p) => p.node_id === node_id);
  el("send-btn").disabled = true;
  try {
    await invoke("send_message", { nodeId: node_id, protocol, text });
    addLogEntry({
      direction: "out",
      peer: peer ? peer.name : "peer",
      ip: peer ? peer.ip : "",
      protocol,
      text,
      ts: Math.floor(Date.now() / 1000),
    });
    el("msg-input").value = "";
    setStatus(`Sent over ${protocol}.`, true);
  } catch (err) {
    setStatus(String(err), false);
  } finally {
    el("send-btn").disabled = false;
  }
}

window.addEventListener("DOMContentLoaded", init);
