<div align="center">
  <img src="WiFiCatcher/web/static/img/logo-wordmark.png" alt="WiFiCatcher" width="380"/>
  <p><em>A simplified tool for a fast Wi-Fi assessment, and an easy starting point for beginners.</em></p>
</div>

WiFiCatcher is an open-source tool for Wi-Fi reconnaissance. From a functional standpoint, the project is built on tools already established in the pentesting field, such as `airodump-ng`, `aireplay-ng`, `tshark` and `EAP_buster`. Instead of a traditional scrolling wall of text, the network is turned into an interactive map. Every access point and every client becomes a node, and every client-AP association becomes an edge.

> 📖 A full write-up of the project is available on my website: **[the WiFiCatcher article](https://williamprestigiovanni.com/article/2026/07/26/wificatcher/)**.

<div align="center">
  <img src="assets/hero.png" alt="WiFiCatcher graph view" width="760"/>
</div>

## 🏗️ Architecture

The application is split into two separate components. The main WiFiCatcher app always runs with the permissions of the user who starts it. The few operations that require root access are handed off to a small separate service called the warden. You install it once as a systemd socket-activated service, and from then on the operating system starts it on demand only when network hardware access is truly needed. This ensures the main application never has to run as root.

## 📡 Hardware requirements

To fully utilize the live capture and deauthentication features, you will need a compatible Wi-Fi adapter that explicitly supports both monitor mode and packet injection. On the other hand, all the remaining functionalities are completely hardware-independent. Since they rely on reading pre-existing capture files, you can run them on any standard machine without requiring specialized networking equipment.

## 📥 Installation

```bash
git clone https://github.com/0xPR3ST1JH0NN7/WiFiCatcher
cd WiFiCatcher

# system tools
sudo apt install aircrack-ng tshark wpasupplicant

# Python dependencies (the app runs from this venv)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# install the privileged warden (once)
sudo ./packaging/install-warden.sh
```

## ▶️ Run

```bash
.venv/bin/python -m WiFiCatcher      # http://127.0.0.1:8000
```

## ✨ What it does

WiFiCatcher is built around three ways of working. Whichever you use, the results share the same views: an interactive graph, a sortable and searchable table for busier scans, per-node details, and filters by type, encryption or channel.

### 📶 Live capture

Point it at a wireless interface and watch the map build in real time as access points and clients appear, each carrying its signal, channel, vendor, encryption, cipher, auth and WPS state. You handle the reconnaissance, fire targeted deauthentication at a client or an AP, and follow the attack paths suggested for each technology. Any WPA handshake that follows a deauth is detected and flagged automatically, and on WPA-Enterprise networks you watch RADIUS server certificates and captured domain users appear live.

### ⏯️ Replay

Load a saved `airodump-ng` CSV to go back over a past scan offline. Step through it node by node as if it were being discovered live, or jump straight to the full picture, with the same graph, table, details and attack paths as a live session.

### 🏢 Enterprise (802.1X)

For WPA-Enterprise networks WiFiCatcher gives you three tools: export the RADIUS server certificate, read usernames from a capture (such as `DOMAIN\user`), and run the EAP-method enumeration to see which methods a network accepts, followed live as they are tried.

## ⚖️ License

Licensed under the MIT License. See [LICENSE](LICENSE). The MIT license covers WiFiCatcher's own code only.

## 📦 Third-party software

WiFiCatcher drives several well-known external tools. You install those yourself and WiFiCatcher runs them as separate programs, so their licenses stay with them. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the full list.

## 👥 Authors

[@0xPR3ST1JH0NN7](https://github.com/0xPR3ST1JH0NN7), [@tvasari](https://github.com/tvasari)

## ⚠️ Disclaimer

WiFiCatcher is for authorized security testing and education only. Use it exclusively on networks you own or have explicit permission to test. It is provided as is, without warranty of any kind; the authors accept no responsibility or liability for any misuse or damage. You alone are responsible for complying with all applicable laws.
