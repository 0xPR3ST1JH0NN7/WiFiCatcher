"""Command-line entry point. Runs the app unprivileged; live capture/deauth go
through a privileged warden that must be installed and reachable. ``stop`` shuts
a running server down gracefully; ``--debug`` enables verbose logging.
"""

from __future__ import annotations

import argparse
import os
import signal
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

from WiFiCatcher import __version__, preflight

# ANSI colors, used only when writing to a real terminal.
_RED = "\033[91m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _paint(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if sys.stdout.isatty() else text


def _banner() -> str:
    try:
        return (Path(__file__).parent / "banner.txt").read_text(encoding="utf-8")
    except OSError:
        return "WiFiCatcher\n"


def print_banner() -> None:
    sys.stdout.write(_paint(_banner(), _RED))
    sys.stdout.write(_paint(f"  WiFi recon, mapped.  v{__version__}\n\n", _DIM))


def _install_stdin_quit() -> None:
    """Stop the server on Enter/EOF: a daemon thread raises SIGINT (uvicorn's
    clean-shutdown path). Only attached on a real TTY, so headless runs are unaffected.
    """
    if not (sys.stdin and sys.stdin.isatty()):
        return

    def _watch() -> None:
        try:
            sys.stdin.readline()
        except Exception:
            return
        os.kill(os.getpid(), signal.SIGINT)

    threading.Thread(target=_watch, daemon=True).start()


def _open_browser_when_ready(host: str, port: int, url: str) -> None:
    """Open the browser only once the server accepts connections; opening before
    uvicorn binds the port shows a 'connection refused' page.
    """
    connect_host = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host

    def _wait() -> None:
        for _ in range(150):  # ~30s ceiling, then open regardless
            try:
                with socket.create_connection((connect_host, port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.2)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=_wait, daemon=True).start()


def _serve(args: argparse.Namespace) -> int:
    print_banner()
    print(_paint("For authorized security testing only. Use exclusively on networks you own "
                 "or have explicit permission to test.", _DIM))
    print(_paint("Provided as is, without warranty. The authors accept no liability for "
                 "misuse or any damage.", _DIM))

    # Verify required tools/libraries are present; a missing dependency aborts
    # here with a clear message rather than crashing later.
    if not preflight.run():
        return 1

    try:
        import uvicorn
    except ImportError:
        print("[!] uvicorn is not installed. Run: pip install -r requirements.txt",
              file=sys.stderr)
        return 1

    # The warden is required; don't start a crippled session without it.
    from WiFiCatcher.privileged import warden_available
    if not warden_available():
        print(_paint("[!] cannot start: the privileged warden is not reachable.",
                     _RED))
        print(_paint("    Install it once, then launch again:", _DIM))
        print(_paint("      sudo ./packaging/install-warden.sh", _DIM))
        return 1
    print(_paint("[*] privileged warden reachable: live radio capture and deauth "
                 "are available.", _DIM))

    url = f"http://{args.host}:{args.port}"
    print(_paint(f"[*] listening on {url}", _DIM))
    print(_paint("[*] press Enter (or Ctrl+C) here to stop. "
                 "NetworkManager is restarted on exit.", _DIM))
    if args.debug:
        print(_paint("[*] debug mode: verbose request logging enabled.", _DIM))

    if not args.reload:
        _install_stdin_quit()

    if not args.no_browser:
        _open_browser_when_ready(args.host, args.port, url)

    # Quiet by default; --debug restores per-request and framework logs.
    uvicorn.run(
        "WiFiCatcher.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="debug" if args.debug else "warning",
        access_log=args.debug,
        # Don't hang on a lingering live-capture WebSocket when shutting down.
        timeout_graceful_shutdown=5,
    )
    return 0


def _stop(args: argparse.Namespace) -> int:
    """Ask a running WiFiCatcher server to shut down gracefully (no Ctrl+C)."""
    import urllib.request

    url = f"http://{args.host}:{args.port}/api/shutdown"
    # Talk straight to the local server; never route this through an HTTP proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        req = urllib.request.Request(url, data=b"", method="POST")
        with opener.open(req, timeout=5) as resp:
            resp.read()
    except Exception as exc:
        print(f"[!] no running WiFiCatcher server at {args.host}:{args.port} ({exc})",
              file=sys.stderr)
        return 1
    print(_paint(f"[*] shutdown requested; {args.host}:{args.port} is stopping.", _DIM))
    return 0


def _add_serve_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--no-browser", action="store_true",
                   help="Do not auto-open the browser.")
    # Development-only auto-reload; hidden from --help to keep it uncluttered.
    p.add_argument("--reload", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--debug", action="store_true",
                   help="Verbose logging: framework and per-request logs.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="WiFiCatcher",
        description="Interactive graph analysis for WiFi recon data.",
    )
    parser.add_argument("--version", action="version",
                        version=f"WiFiCatcher {__version__}")
    _add_serve_flags(parser)

    # Running the app is the default action; the only subcommand is 'stop'.
    sub = parser.add_subparsers(dest="command")
    stop = sub.add_parser(
        "stop", help="Tell a running server to shut down gracefully (no Ctrl+C).")
    stop.add_argument("--host", default="127.0.0.1")
    stop.add_argument("--port", type=int, default=8000)
    stop.set_defaults(func=_stop)

    parser.set_defaults(func=_serve)  # running the app is the default action
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
