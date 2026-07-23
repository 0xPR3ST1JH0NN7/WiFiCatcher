<div align="center">
  <img src="WiFiCatcher/web/static/img/logo-wordmark.png" alt="WiFiCatcher" width="420"/>
  <p><em>A simplified tool for fast Wi-Fi assessment.</em></p>
</div>

## Hardware requirements

Live capture and deauthentication need a Wi-Fi adapter that supports monitor mode and packet injection. Many built-in laptop adapters do not, so a compatible external adapter is usually the safe choice. Import and replay work on any machine, since they read a capture file rather than the radio.

## Quick start

```bash
git clone https://github.com/0xPR3ST1JH0NN7/WiFiCatcher
cd WiFiCatcher

# system dependencies
sudo apt install aircrack-ng tshark zenity

# python dependencies (the app runs from this venv)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# install the privileged warden (once)
sudo ./packaging/install-warden.sh
```

## Run

```bash
.venv/bin/python -m WiFiCatcher      # http://127.0.0.1:8000
```

Open the printed address in your browser and you are ready to go. Live capture and deauth run through the privileged warden, so WiFiCatcher checks that it is reachable at startup and won't run without it, pointing you back at the installer above if it is missing. Press Enter (or Ctrl+C) in the terminal to stop.

## What it does

WiFiCatcher is built around three ways of working. Whichever you use, the results share the same views: an interactive graph of every access point, client and association, a sortable and searchable table for when the scan gets crowded, per-node details, and filters by type, encryption or channel.

### Live capture

Point it at a wireless interface and watch the map build in real time as access points and clients appear, each one carrying its signal, channel, vendor, encryption, cipher, auth and WPS state. From here you can fire targeted deauthentication frames at a client or an AP (shown as a pulse on the graph); any WPA handshake that follows is detected and flagged automatically.

### Replay

Load a saved airodump-ng CSV to go back over a past scan. Step through it node by node, as if it were being discovered live, or jump straight to the full picture. Handy for reviewing a capture away from the radio.

### Enterprise (802.1X)

For WPA-Enterprise networks, WiFiCatcher singles out the 802.1X access points, reads and exports the RADIUS server certificate, pulls EAP Response/Identity usernames (often `DOMAIN\user`) out of the traffic, and enumerates which EAP methods a network accepts.

For any selected AP, the attack-paths view then lays out the exploitation routes that fit its security type.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Authors

[@0xPR3ST1JH0NN7](https://github.com/0xPR3ST1JH0NN7), [@tvasari](https://github.com/tvasari)

## Disclaimer

WiFiCatcher is for authorized security testing and education only. Use it exclusively on networks you own or have explicit permission to test. It is provided as is, without warranty of any kind; the authors accept no responsibility or liability for any misuse or damage. You alone are responsible for complying with all applicable laws.
