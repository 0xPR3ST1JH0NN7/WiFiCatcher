<div align="center">
  <img src="wifihound/web/static/img/logo.svg" alt="WiFiHound" width="130"/>

  # WiFiHound

  **Interactive graph analysis for WiFi reconnaissance data.**
</div>

---

WiFiHound builds on the `aircrack-ng` suite and turns it into an explorable graph
of access points, clients and their associations, with live capture on top.
Import a CSV to analyze a past scan, or run a live capture and watch the network
map build in real time, deauth included.

- **Graph UI**: APs (red) and clients (blue) as nodes, associations as edges.
- **Explore**: search, filter (type, encryption, channel), node details, context actions.
- **Vendor enrichment** from the OUI, fully offline.
- **Live capture**: replay a loaded CSV, or stream a real `airodump-ng` capture over WebSocket.
- **Offensive** (opt in): deauth an AP or a single client during a live capture.

## Install

```bash
git clone https://github.com/0xPR3ST1JH0NN7/WiFiHound
cd WiFiHound
pip install -r requirements.txt
```

## Usage

```bash
python -m wifihound                  # opens http://127.0.0.1:8000
sudo python -m wifihound             # also unlocks live radio capture + deauth
```

There is one way to run it. Offline analysis and replay work unprivileged;
live radio capture and deauth turn on automatically when you start it with
**sudo** (root). No special flags.

Click **Import capture** and pick an `airodump-ng` CSV
(`airodump-ng -w scan --output-format csv wlan0mon`).

**Live capture** (sidebar, *Live capture* panel):

- **Replay**: import a CSV, then *Start live* to reveal it node by node. No privileges needed.
- **airodump**: stream a real capture. Choose interface, channel, protocol
  (WEP / WPA2 / WPA3 / Open), WPS, and an optional ESSID or BSSID filter.
  Needs root (run with sudo) and a monitor mode interface. WPA handshakes
  captured during the session (e.g. from a deauth) are flagged on the AP with a 🔑.

The reveal / poll speed is set by the *Interval* field.

## Offensive operations

Deauthentication runs `aireplay-ng -0 <count> -a <AP> [-c <client>]` on the live
capture interface. It is **only available while an airodump capture is running on
a fixed channel** (aireplay can reach the AP only on the interface's channel),
and stays behind its guardrails: requires root (run with sudo), confirmed per
action, with capped bursts and logging.

> ⚠️ Use only on networks you own or are explicitly authorized to test.
> Unauthorized deauthentication is illegal in most jurisdictions.

## Tests

```bash
pytest
```

## Authors

- [@0xPR3ST1JH0NN7](https://github.com/0xPR3ST1JH0NN7)
- [@tvasari](https://github.com/tvasari)
