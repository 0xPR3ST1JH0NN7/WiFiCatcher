# Sample captures

Ready-made airodump-ng CSV files to try WiFiCatcher without a Wi-Fi adapter.
All networks, devices and MAC addresses are fictitious; the MAC prefixes belong
to real vendors so the *Vendor* field is filled in.

## How to open one

1. Start the app: `python -m WiFiCatcher`
2. Open the **Replay** panel and click **Import capture**.
3. Pick a file from this folder. Click **Replay capture** to watch the map build
   node by node, or explore the full graph straight away.

## Files

| File | Networks inside | AP icon |
|---|---|---|
| `all-networks.csv` | One of every type below, plus a hidden network | all of them |
| `open.csv` | Open | white waves |
| `wep.csv` | WEP | green waves |
| `wpa-wpa2-psk.csv` | WPA/WPA2-PSK, including a legacy WPA/TKIP router and a hidden network | red waves |
| `wpa2-wpa3-transition.csv` | WPA2/WPA3 transition mode | blue waves |
| `wpa3-sae.csv` | WPA3-SAE | blue waves |
| `wpa3-owe.csv` | WPA3-OWE, plus an OWE transition-mode pair (an open network and its hidden OWE twin) | teal waves with an open padlock |
| `wpa2-enterprise.csv` | WPA2-Enterprise (802.1X) | purple waves |

Each file also contains associated clients and at least one unassociated client
that probes for a known network name.
