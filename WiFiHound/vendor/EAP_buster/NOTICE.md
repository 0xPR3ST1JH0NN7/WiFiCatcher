# EAP_buster (vendored)

This directory contains a verbatim copy of **EAP_buster** by BlackArrow, bundled
with WiFiHound so EAP method enumeration works out of the box (no separate
install). WiFiHound runs it from a temporary copy, so the files here are never
modified at runtime.

* Upstream: https://github.com/blackarrowsec/EAP_buster
* Author: Miguel Amat (BlackArrow / Tarlogic)
* License: MIT (see `LICENSE`)

Only `EAP_buster.sh` and the `EAP_config/` wpa_supplicant templates are included;
the upstream documentation images are omitted. EAP enumeration still requires
`wpa_supplicant` on the host.
