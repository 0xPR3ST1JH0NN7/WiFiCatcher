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

# python dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Run

Run without `sudo` for offline use, or with `sudo` to unlock live capture:

```bash
.venv/bin/python -m WiFiCatcher                    # http://127.0.0.1:8000  (offline: import & replay)
         OR
sudo .venv/bin/python -m WiFiCatcher      # also enables live capture + deauth
```

Press **Enter** (or Ctrl+C) in the terminal to stop.

> **Using `sudo` with a virtualenv?** `sudo` resets `PATH` and runs the *system*
> Python, so a plain `sudo python3 -m WiFiCatcher` won't see packages you
> installed into `.venv` (you'll get `missing required: python-multipart` even
> though `pip install` succeeded). Point `sudo` at the venv's own interpreter —
> `sudo .venv/bin/python -m WiFiCatcher` — or preserve your environment with
> `sudo -E env "PATH=$PATH" python3 -m WiFiCatcher`.

## What it does

- **Graph & table views.** Every access point, client and association is laid out as an interactive map, or a sortable, searchable table when the scan gets crowded. Futhermore, you can filter by type, encryption or channel.
- **Import & replay.** Load a saved `airodump-ng` CSV to explore a past scan, or replay it node by node as if it were being discovered live. (no root needed)
- **Live capture.** Stream a live capture and watch the map build in real time, with per-AP detail like signal, channel, vendor and WPS.
- **Deauth & handshake capture.** Fire targeted deauthentication frames at a client or AP (shown as a pulse on the graph): any WPA handshake that follows is detected and flagged automatically.
- **WPA2-Enterprise.** Spots 802.1X networks, inspects and exports the RADIUS server certificate, and enumerates which EAP methods a network accepts.

## Replay

Import a saved capture, then hit **Replay** to watch the whole scan rebuild node by node, as if it were being discovered live. Fully offline: no radio, no root.

https://github.com/user-attachments/assets/7aba55f7-ad56-42dd-82a5-8492b734425f

## Live capture

Needs root (`sudo`). Pick a wireless adapter; a managed one is switched to monitor mode automatically and restored when you stop. Set a channel, band or filters, then **Start live capture**.

https://github.com/user-attachments/assets/d780571b-aa86-4b80-aa67-9d963e6e6c24

> ⚠️ Use WiFiCatcher only on networks you own or are authorized to test.

## Authors

[@0xPR3ST1JH0NN7](https://github.com/0xPR3ST1JH0NN7), [@tvasari](https://github.com/tvasari)
