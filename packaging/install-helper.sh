#!/usr/bin/env bash
#
# Install the WiFiCatcher privileged helper as a systemd socket-activated
# service. Run once, as root, from the repository root:
#
#     sudo ./packaging/install-helper.sh [INSTALL_DIR] [APP_USER]
#
# INSTALL_DIR defaults to the current checkout; APP_USER to the invoking user.
# After this, the app runs unprivileged and the helper is started on demand.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="${1:-$REPO_DIR}"
APP_USER="${2:-${SUDO_USER:-$(id -un)}}"
UNIT_DIR="/etc/systemd/system"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

VENV_PY="$INSTALL_DIR/.venv/bin/python"
if [[ ! -x "$VENV_PY" ]]; then
  echo "No venv python at $VENV_PY — create it first:" >&2
  echo "  cd $INSTALL_DIR && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi

echo "[*] install dir : $INSTALL_DIR"
echo "[*] app user    : $APP_USER"

# 1) group that is allowed to talk to the helper socket
groupadd -f wificatcher
usermod -aG wificatcher "$APP_USER"

# 2) install the units, pointing ExecStart at the real install dir
install -m 0644 "$REPO_DIR/packaging/systemd/wc-privhelper.socket" "$UNIT_DIR/"
sed -e "s#/opt/wificatcher/.venv/bin/python#$VENV_PY#g" \
    -e "s#/opt/wificatcher#$INSTALL_DIR#g" \
    "$REPO_DIR/packaging/systemd/wc-privhelper.service" > "$UNIT_DIR/wc-privhelper.service"
chmod 0644 "$UNIT_DIR/wc-privhelper.service"

# 3) enable the socket (starts listening now + at every boot; the service is
#    started on demand, not at boot)
systemctl daemon-reload
systemctl enable --now wc-privhelper.socket

echo "[*] done. Helper socket is listening; the service starts on first use."
echo "    Log out/in so '$APP_USER' picks up the 'wificatcher' group, then run:"
echo "      cd $INSTALL_DIR && .venv/bin/python -m WiFiCatcher"
