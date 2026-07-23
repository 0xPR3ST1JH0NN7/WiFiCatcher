"""Entry point for the privileged warden daemon.

    sudo python -m WiFiCatcher.privileged --socket /tmp/wc-priv.sock   # dev
    (under systemd socket activation the socket is passed as fd 3 instead)
"""

from WiFiCatcher.privileged.server import main

if __name__ == "__main__":
    raise SystemExit(main())
