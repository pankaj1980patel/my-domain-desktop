# LAN Messenger (Tauri + Rust)

A desktop app that discovers other devices on your local network and lets you
send them messages over **UDP** or **TCP**.

## How it works

- **Discovery** — every instance joins the UDP multicast group `239.255.42.98:45678`
  and broadcasts a small JSON *beacon* every 2 seconds (node id, hostname, and the
  TCP/UDP ports it listens on). Peers that go quiet for 8 seconds are dropped.
  Multicast + `SO_REUSEPORT` means you can also run several instances on one machine
  to test.
- **Messaging** — each instance opens a TCP listener and a UDP socket on ephemeral
  ports (advertised in its beacon). Sending over **TCP** opens a short connection per
  message; sending over **UDP** fires a single datagram.
- The Rust backend (`src-tauri/src/lib.rs`) emits `peers-updated` and
  `message-received` events to the web UI (`src/main.js`), and exposes the commands
  `get_identity`, `get_peers`, `send_message`, and `set_display_name`.

## Run

```bash
npm install
npm run tauri dev      # development
npm run tauri build    # production bundle
```

To test discovery on a single machine, launch two instances — each appears in the
other's **Peers** list. To test across devices, run it on two machines on the same
LAN/Wi-Fi (the network must allow UDP multicast; some guest/corporate networks block it).

## Project layout

- `src-tauri/src/lib.rs` — discovery, TCP/UDP send & receive, Tauri commands.
- `src/index.html`, `src/main.js`, `src/styles.css` — the UI.
- `src-tauri/tauri.conf.json` — Tauri config (`withGlobalTauri` enabled for vanilla JS).
