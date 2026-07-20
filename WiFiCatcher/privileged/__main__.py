"""Entry point for the privileged helper daemon.

    sudo python -m WiFiCatcher.privileged --socket /run/wificatcher/priv.sock
    (under systemd socket activation the socket is passed as fd 3 instead)
"""

from WiFiCatcher.privileged.server import main

if __name__ == "__main__":
    raise SystemExit(main())
