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

- **Replay**. Load a saved airodump-ng CSV to explore a past scan, or replay it node by node as if it were being discovered live (no root needed).

- **Live capture**. Stream a live capture and watch the map build in real time, with per-AP detail like signal, channel, vendor and WPS.

- **Deauth & handshake capture**. Fire targeted deauthentication frames at a client or AP (shown as a pulse on the graph). Any WPA handshake that follows is detected and flagged automatically.

- **WPA2-Enterprise**. Spots 802.1X networks, inspects and exports the RADIUS server certificate, and enumerates which EAP methods a network accepts.

## Replay

Already captured a scan? Import it and hit Replay to watch the whole thing rebuild itself node by node. Access points, clients and their associations pop into place one after another exactly as they appeared when the scan first ran. It is an easy way to revisit a past session or to get a feel for how WiFiCatcher lays things out before you ever take it into the field. Everything runs locally from the saved file, so it stays fully offline and requires no wireless adapter, no root, and nothing to set up.

https://github.com/user-attachments/assets/7aba55f7-ad56-42dd-82a5-8492b734425f

## Live capture

This mode talks to the radio, so it runs through the privileged helper (installed in the Quick start) while the app itself stays unprivileged. Pick a wireless adapter and, if it is a managed one, WiFiCatcher switches it into monitor mode for you automatically, then quietly restores it when you stop, so you are never left resetting the interface by hand. From there you can narrow the scan to a specific channel or band, add a few filters if you want, and hit Start live capture to watch the map fill in live as frames come in.

> ⚠️ Use WiFiCatcher only on networks you own or are authorized to test.

## Troubleshooting
If you experience issues putting your adapter into monitor mode, network managers running in the background might be interfering. You can resolve these conflicts by running sudo airmon-ng check kill before starting a live capture.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Authors

[@0xPR3ST1JH0NN7](https://github.com/0xPR3ST1JH0NN7), [@tvasari](https://github.com/tvasari)
