<div align="center">
  <img src="wifihound/web/static/img/logo.png" alt="WiFiHound" width="130"/>

  # WiFiHound

  **Interactive graph analysis for WiFi reconnaissance data.**
</div>

WiFiHound turns `airodump-ng` output into an explorable graph of access points,
clients and their associations. Import a past scan and replay it, or run a live
capture and watch the map build in real time.

## Features

* Graph UI with access points in red, clients in blue, associations as edges.
* Search and filters by type, encryption and channel.
* Offline vendor lookup from the OUI database.
* Two ways to build the map: replay an imported capture, or live capture a real
  `airodump-ng` stream.

## Install

WiFiHound needs Python 3.8 or newer, so use `python3` and `pip3` (a bare `pip`
on an old system can still point at Python 2).

```bash
git clone https://github.com/0xPR3ST1JH0NN7/WiFiHound
cd WiFiHound
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python3 -m wifihound        # opens http://127.0.0.1:8000
sudo python3 -m wifihound   # also enables live radio capture
```

Click **Import capture** and pick an `airodump-ng` CSV
(`airodump-ng -w scan --output-format csv wlan0mon`).

## Replay

Importing a capture gives you the full graph of a past scan. In the **Replay**
panel press **Replay capture** to watch it rebuild node by node, as if it were
being discovered live. It runs fully offline, with no radio and no root.

![Replay in action](docs/replay.gif)

## Live capture

The **Live capture** panel streams a real `airodump-ng` capture and maps the
network as it appears. It needs root, so run with `sudo`. Pick a wireless
interface from the list of detected adapters; a managed one is switched to
monitor mode automatically and restored when you stop. You can also set a
channel, protocol, WPS and an ESSID or BSSID filter.

![Live capture in action](docs/live-capture.gif)

> Use WiFiHound only on networks you own or are authorized to test.

## Authors

* [@0xPR3ST1JH0NN7](https://github.com/0xPR3ST1JH0NN7)
* [@tvasari](https://github.com/tvasari)
