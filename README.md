<div align="center">
  <img src="WiFiCatcher/web/static/img/logo-wordmark.png" alt="WiFiCatcher" width="420"/>
  <p><em>A simplified tool for fast Wi-Fi penetration testing, and an easy starting point for beginners.</em></p>
</div>

## Quick start

```bash
git clone https://github.com/0xPR3ST1JH0NN7/WiFiCatcher
cd WiFiCatcher

# system tools used for live capture + deauth
sudo apt install aircrack-ng tshark

# python dependencies (the app runs from this venv)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Run

The app **always runs unprivileged** — never as root:

```bash
.venv/bin/python -m WiFiCatcher      # http://127.0.0.1:8000
```

Press **Enter** (or Ctrl+C) in the terminal to stop. Import & replay work out of
the box. **Live capture and deauth** need the privileged helper (below); the app
itself never touches the radio.

## Live capture — the privileged helper

The operations that need root (monitor mode, `airodump-ng`, `aireplay-ng`, EAP)
run in a small **helper daemon**, so the web app never runs as root. Install it
once as a systemd **socket-activated** service:

```bash
sudo ./packaging/install-helper.sh
# then log out/in so your user joins the 'wificatcher' group
```

systemd listens on a unix socket and starts the helper **on demand** when the app
needs the radio, stopping it again when idle — no root process runs the rest of
the time, and there is no password prompt. The app auto-detects it (you'll see
`privileged helper reachable` at startup). Check it with
`systemctl status wc-privhelper.socket` (a `.service` shown as `inactive (dead)`
while unused is normal).

### Development (no systemd)

Run the helper on demand yourself and point the app at its socket:

```bash
# terminal 1 — the helper (root)
sudo .venv/bin/python -m WiFiCatcher.privileged \
     --socket /tmp/wc-priv.sock --peer-uid "$(id -u)"

# terminal 2 — the app (your user)
WIFICATCHER_PRIV_SOCKET=/tmp/wc-priv.sock .venv/bin/python -m WiFiCatcher
```

## What it does

- **Graph & table views.** Every access point, client and association is laid out as an interactive map, or a sortable, searchable table when the scan gets crowded. Futhermore, you can filter by type, encryption or channel.
- **Import & replay.** Load a saved `airodump-ng` CSV to explore a past scan, or replay it node by node as if it were being discovered live. (no root needed)
- **Live capture.** Stream a live capture and watch the map build in real time, with per-AP detail like signal, channel, vendor and WPS.
- **Deauth & handshake capture.** Fire targeted deauthentication frames at a client or AP (shown as a pulse on the graph): any WPA handshake that follows is detected and flagged automatically.
- **WPA2-Enterprise.** Spots 802.1X networks, inspects and exports the RADIUS server certificate, and enumerates which EAP methods a network accepts.

## Replay

Already captured a scan? Import it and hit **Replay** to watch the whole thing rebuild itself node by node — access points, clients and their associations popping into place one after another, exactly as they appeared when the scan first ran. It's an easy way to revisit a past session, or to get a feel for how WiFiCatcher lays things out before you ever take it into the field. Everything runs locally from the saved file, so it stays fully offline: no wireless adapter, no root, nothing to set up.

https://github.com/user-attachments/assets/7aba55f7-ad56-42dd-82a5-8492b734425f

## Live capture

This mode talks to the radio, so it needs root — start it with `sudo`. Pick a wireless adapter and, if it's a managed one, WiFiCatcher switches it into monitor mode for you automatically, then quietly restores it when you stop, so you're never left resetting the interface by hand. From there you can narrow the scan to a specific channel or band, add a few filters if you want, and hit **Start live capture** to watch the map fill in live as frames come in.

https://github.com/user-attachments/assets/d780571b-aa86-4b80-aa67-9d963e6e6c24

> ⚠️ Use WiFiCatcher only on networks you own or are authorized to test.

## Authors

[@0xPR3ST1JH0NN7](https://github.com/0xPR3ST1JH0NN7), [@tvasari](https://github.com/tvasari)
