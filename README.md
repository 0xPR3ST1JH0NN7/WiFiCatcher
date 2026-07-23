<div align="center">
  <img src="WiFiCatcher/web/static/img/logo-wordmark.png" alt="WiFiCatcher" width="420"/>
  <p><em>A simplified tool for fast Wi-Fi assessment.</em></p>
</div>

## Hardware Requirements

Live capture and deauthentication attacks require a compatible Wi-Fi adapter that supports monitor mode and packet injection. Standard built-in laptop adapters may not support these features.

## Quick start

```bash
git clone [https://github.com/0xPR3ST1JH0NN7/WiFiCatcher](https://github.com/0xPR3ST1JH0NN7/WiFiCatcher)
cd WiFiCatcher

# linux dependencies
sudo apt install aircrack-ng tshark zenity

# python dependencies (the app runs from this venv)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# installing the service
sudo ./packaging/install-helper.sh
```

## Run

Start the app.
```bash
.venv/bin/python -m WiFiCatcher                 # [http://127.0.0.1:8000](http://127.0.0.1:8000)
```

Press Enter (or Ctrl+C) in the terminal to stop. WiFiCatcher checks for the helper at startup and prints privileged helper reachable when it is ready. If it is missing, it refuses to start and points you at the installer above. Live capture and deauth go through the helper. Systemd starts it on demand when the app needs the radio and stops it when idle, with no password prompt. Import and replay run entirely inside the unprivileged app.

## What it does

- **Graph & table views**. Every access point, client and association is laid out as an interactive map, or a sortable, searchable table when the scan gets crowded. Furthermore, you can filter by type, encryption or channel.

- **Replay**. Load a saved airodump-ng CSV to explore a past scan, or replay it node by node as if it were being discovered live.

- **Live capture**. Stream a live capture and watch the map build in real time, with per-AP detail like signal, channel, vendor and WPS.

- **Deauth & handshake capture**. Fire targeted deauthentication frames at a client or AP (shown as a pulse on the graph). Any WPA handshake that follows is detected and flagged automatically.

- **WPA2-Enterprise**. Spots 802.1X networks, inspects and exports the RADIUS server certificate, and enumerates which EAP methods a network accepts.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

> ⚠️ Use WiFiCatcher only on networks you own or are authorized to test.

## Authors

[@0xPR3ST1JH0NN7](https://github.com/0xPR3ST1JH0NN7), [@tvasari](https://github.com/tvasari)
