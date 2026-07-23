#!/usr/bin/env bash
#
# Install the WiFiCatcher privileged warden as a systemd socket-activated
# service. Run once, as root, from the repository root:
#
#     sudo ./packaging/install-warden.sh [INSTALL_DIR] [APP_USER]
#
# INSTALL_DIR defaults to the current checkout; APP_USER to the invoking user.
# After this, the app runs unprivileged and the warden is started on demand.
# The socket is owned by APP_USER (mode 0600), so only that user can reach it.
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
  echo "No venv python at $VENV_PY. Create it first:" >&2
  echo "  cd $INSTALL_DIR && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi

APP_UID="$(id -u "$APP_USER")"
echo "[*] install dir : $INSTALL_DIR"
echo "[*] app user    : $APP_USER (uid $APP_UID)"

# Socket owned by the app user only (no shared group).
sed -e "s#APP_USER#$APP_USER#g" \
    "$REPO_DIR/packaging/systemd/wc-privwarden.socket" > "$UNIT_DIR/wc-privwarden.socket"

# Service: real venv python + install dir, and pin the app uid as a second gate.
sed -e "s#/opt/wificatcher/.venv/bin/python#$VENV_PY#g" \
    -e "s#/opt/wificatcher#$INSTALL_DIR#g" \
    -e "s#APP_UID#$APP_UID#g" \
    "$REPO_DIR/packaging/systemd/wc-privwarden.service" > "$UNIT_DIR/wc-privwarden.service"

chmod 0644 "$UNIT_DIR/wc-privwarden.socket" "$UNIT_DIR/wc-privwarden.service"

# Apply the units and (re)bind the socket. A plain "enable --now" does NOT
# restart an already-running socket, so on a re-install it would keep a stale
# binding (old path / no open fd) and never create the new socket file. restart
# forces the new config to take effect; reset-failed clears any prior failure.
systemctl daemon-reload
systemctl reset-failed wc-privwarden.socket wc-privwarden.service 2>/dev/null || true
systemctl enable wc-privwarden.socket
systemctl restart wc-privwarden.socket

echo "[*] done. Just run the app:"
echo "      cd $INSTALL_DIR && .venv/bin/python -m WiFiCatcher"
