"""Live capture sources.

A *source* yields successive :class:`~WiFiCatcher.models.Scan` snapshots. The
:class:`CaptureController` polls a source and streams the resulting graph diffs
to the browser.

Two sources ship today:

* :class:`ReplaySource` re-feeds a static airodump CSV as if it were being
  discovered live. It needs no privileges or hardware, so it works everywhere
  and powers the demo / test path.
* :class:`AirodumpSource` spawns a real ``airodump-ng`` and tails its rotating
  CSV. It touches radio hardware, so it is guardrailed exactly like the
  offensive operations (authorized use, root, monitor-mode interface).
"""

from __future__ import annotations

import asyncio
import glob
import math
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from typing import Optional

from WiFiCatcher.capture.interfaces import MonitorHandle, restore_managed_mode
from WiFiCatcher.models import Scan
from WiFiCatcher.parsers.airodump_csv import AirodumpCsvParser


class Source:
    """Base class: produce a Scan snapshot each time it is read."""

    async def start(self) -> None:
        pass

    async def read(self) -> Optional[Scan]:
        """Return the current Scan, or None if nothing is available yet."""
        raise NotImplementedError

    async def stop(self) -> None:
        pass


class ReplaySource(Source):
    """Reveal a static scan progressively to simulate live discovery."""

    def __init__(self, scan: Scan, steps: int = 6):
        self._snapshots = self._build(scan, max(1, steps))
        self._tick = 0

    @classmethod
    def from_csv(cls, text: str, filename: str = "", steps: int = 6) -> "ReplaySource":
        scan = AirodumpCsvParser().parse(text, filename)
        return cls(scan, steps=steps)

    @staticmethod
    def _build(scan: Scan, steps: int) -> list[Scan]:
        aps, clients = scan.access_points, scan.clients
        snapshots: list[Scan] = []
        for t in range(1, steps + 1):
            ka = math.ceil(len(aps) * t / steps)
            kc = math.ceil(len(clients) * t / steps)
            snapshots.append(Scan(
                access_points=list(aps[:ka]),
                clients=list(clients[:kc]),
                source=scan.source,
                format=scan.format,
            ))
        # Guarantee at least the full scan as the final, stable snapshot.
        snapshots.append(Scan(access_points=list(aps), clients=list(clients),
                              source=scan.source, format=scan.format))
        return snapshots

    async def read(self) -> Optional[Scan]:
        snap = self._snapshots[min(self._tick, len(self._snapshots) - 1)]
        self._tick += 1
        return snap


# airodump-ng --band letters: 'a' = 5 GHz, 'b'/'g' = 2.4 GHz.
_BAND_FLAGS = {"2.4": "bg", "5": "a", "both": "abg"}


class AirodumpSource(Source):
    """Spawn airodump-ng and tail its rotating CSV (authorized use only).

    Capture can be narrowed with the usual airodump-ng filters: a fixed channel
    (``-c``), a band (``--band`` for 2.4 GHz / 5 GHz / both), encryption suite
    (``--encrypt``), and a specific ESSID (``--essid``) or BSSID (``--bssid``).
    When ``save`` is set the capture files are kept under ``./captures`` instead
    of being discarded on stop.
    """

    def __init__(self, interface: str, channel: Optional[str] = None,
                 band: Optional[str] = None, encrypt: Optional[str] = None,
                 essid: Optional[str] = None,
                 bssid: Optional[str] = None,
                 monitor: Optional[MonitorHandle] = None, save: bool = False,
                 save_dir: Optional[str] = None):
        self.interface = interface
        self.channel = channel
        self.band = band             # "2.4" | "5" | "both"
        self.encrypt = encrypt        # WEP | WPA2 | WPA3 | OPN ...
        self.essid = essid
        self.bssid = bssid
        self.save = save
        # Folder to keep the capture in when ``save`` is on; ``None`` -> ./captures.
        self.save_dir = save_dir
        # Directory holding the kept capture once stop() runs (None if discarded).
        self.saved_path: Optional[str] = None
        # When we enabled monitor mode for this capture, this handle lets stop()
        # put the interface back to managed mode automatically.
        self._monitor = monitor
        self._proc: Optional[subprocess.Popen] = None
        self._dir: Optional[str] = None
        self._parser = AirodumpCsvParser()

    def build_command(self, prefix: str) -> list[str]:
        # pcap is written alongside the CSV so handshakes can be detected.
        cmd = ["airodump-ng", "--output-format", "pcap,csv", "-w", prefix]
        if self.channel:
            # A fixed channel already pins the band; --band would conflict.
            cmd += ["-c", str(self.channel)]
        elif self.band in _BAND_FLAGS:
            cmd += ["--band", _BAND_FLAGS[self.band]]
        if self.encrypt:
            cmd += ["--encrypt", str(self.encrypt)]
        if self.bssid:
            cmd += ["--bssid", str(self.bssid)]
        if self.essid:
            cmd += ["--essid", str(self.essid)]
        cmd.append(self.interface)
        return cmd

    async def start(self) -> None:
        if self.save:
            # Keep the capture in a readable folder: the one the user chose, or a
            # git-ignored ./captures subfolder by default.
            base = self.save_dir or os.path.join(os.getcwd(), "captures")
            os.makedirs(base, exist_ok=True)
            self._dir = tempfile.mkdtemp(
                prefix="capture-" + time.strftime("%Y%m%d-%H%M%S") + "-", dir=base)
        else:
            self._dir = tempfile.mkdtemp(prefix="WiFiCatcher-cap-")
        prefix = os.path.join(self._dir, "cap")
        # airodump-ng runs until terminated; it rewrites cap-01.csv ~once/sec.
        self._proc = subprocess.Popen(
            self.build_command(prefix),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def _latest_csv(self) -> Optional[str]:
        if not self._dir:
            return None
        files = sorted(glob.glob(os.path.join(self._dir, "cap-*.csv")))
        return files[-1] if files else None

    def latest_cap(self) -> Optional[str]:
        """Newest pcap file, used for handshake detection."""
        if not self._dir:
            return None
        files = sorted(glob.glob(os.path.join(self._dir, "cap-*.cap")))
        return files[-1] if files else None

    async def read(self) -> Optional[Scan]:
        path = self._latest_csv()
        if not path:
            return None
        try:
            with open(path, "r", encoding="utf-8-sig", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            return None
        if not text.strip():
            return None
        return self._parser.parse(text, os.path.basename(path))

    async def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self._proc.wait(timeout=5))
            except Exception:
                self._proc.kill()
        self._proc = None
        if self._dir and os.path.isdir(self._dir):
            if self.save:
                self.saved_path = self._dir   # keep it; report the location
            else:
                shutil.rmtree(self._dir, ignore_errors=True)
        self._dir = None
        # Return the radio to managed mode if we put it into monitor mode.
        if self._monitor is not None:
            monitor, self._monitor = self._monitor, None
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: restore_managed_mode(monitor))
            except Exception:
                pass


class HelperAirodumpSource(Source):
    """Live capture driven by the privileged helper.

    The app is unprivileged, so it does not run airodump-ng itself: it opens a
    ``capture.stream`` on the helper socket. The helper (root) enables monitor
    mode, runs airodump-ng, and streams CSV snapshots back; closing the socket in
    :meth:`stop` tells it to kill airodump and restore managed mode.

    ``interface`` is filled in from the helper's first event (the monitor
    interface), so deauth can target it. Handshake/WPS detection needs the pcap,
    which lives on the helper, so :meth:`latest_cap` returns ``None`` for now.
    """

    def __init__(self, interface: str, channel: Optional[str] = None,
                 band: Optional[str] = None, encrypt: Optional[str] = None,
                 essid: Optional[str] = None, bssid: Optional[str] = None,
                 save: bool = False, save_dir: Optional[str] = None,
                 save_name: Optional[str] = None, acknowledged: bool = True):
        # The interface the user picked; becomes the monitor interface once the
        # helper reports it back (that is what the controller/deauth read).
        self.interface: Optional[str] = interface
        self.channel = channel
        # Where the helper kept the capture, reported in its first event.
        self.saved_path: Optional[str] = None
        self._params = {
            "iface": interface, "channel": channel, "band": band,
            "encrypt": encrypt, "essid": essid, "bssid": bssid,
            "save": save, "save_dir": save_dir, "save_name": save_name,
            "acknowledged": acknowledged,
        }
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._latest = ""
        self._handshakes: set[str] = set()
        self._wps: dict[str, dict] = {}
        self._deauth: list = []
        self._certs: dict[str, list] = {}
        self._lock = threading.Lock()
        self._parser = AirodumpCsvParser()

    def _connect_and_handshake(self) -> None:
        from WiFiCatcher.privileged import PrivUnavailable, client
        from WiFiCatcher.privileged.protocol import recv_message, send_message
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        try:
            sock.connect(client.socket_path())
        except OSError as exc:
            sock.close()
            raise PrivUnavailable(f"helper unreachable: {exc}") from exc
        send_message(sock, {"op": "capture.stream", "params": self._params})
        first = recv_message(sock)
        if isinstance(first, dict) and "event" in first:
            ev = first["event"]
            if ev.get("monitor_interface"):
                self.interface = ev["monitor_interface"]
            if ev.get("save_path"):
                self.saved_path = ev["save_path"]
        elif isinstance(first, dict) and not first.get("ok", True):
            sock.close()
            raise PrivUnavailable(first.get("error", "capture refused"))
        sock.settimeout(None)
        self._sock = sock

    def _reader(self) -> None:
        from WiFiCatcher.privileged.protocol import ProtocolError, recv_message
        while self._sock is not None:
            try:
                msg = recv_message(self._sock)
            except (ProtocolError, OSError):
                break
            if not isinstance(msg, dict):
                break
            event = msg.get("event")
            if event and "csv" in event:
                with self._lock:
                    self._latest = event["csv"]
            elif event and "handshake" in event:
                bssid = (event["handshake"] or {}).get("bssid")
                if bssid:
                    with self._lock:
                        self._handshakes.add(bssid)
            elif event and "wps" in event:
                with self._lock:
                    self._wps.update(event["wps"] or {})
            elif event and "deauth" in event:
                with self._lock:
                    self._deauth.extend(event["deauth"] or [])
            elif event and "cert" in event:
                with self._lock:
                    self._certs.update(event["cert"] or {})
            elif "ok" in msg or msg.get("done"):
                break

    async def start(self) -> None:
        await asyncio.get_event_loop().run_in_executor(
            None, self._connect_and_handshake)
        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()

    async def read(self) -> Optional[Scan]:
        with self._lock:
            text = self._latest
        if not text.strip():
            return None
        return self._parser.parse(text, "live.csv")

    def latest_cap(self) -> Optional[str]:
        return None                      # the pcap lives on the helper

    def handshake_bssids(self) -> set[str]:
        """BSSIDs the helper has reported a captured handshake for so far."""
        with self._lock:
            return set(self._handshakes)

    def wps_info(self) -> dict[str, dict]:
        """Per-BSSID WPS info ({version, locked}) the helper has reported so far."""
        with self._lock:
            return dict(self._wps)

    def drain_deauth(self) -> list:
        """Return and clear deauth/disassoc events received since the last call.

        Each is ``{"client": mac|None, "bssid": mac, "broadcast": bool}``; the
        controller consumes these to suppress torn-down associations.
        """
        with self._lock:
            out, self._deauth = self._deauth, []
            return out

    def certs_info(self) -> dict:
        """Per-BSSID RADIUS/EAP server certificates the helper has parsed so far."""
        with self._lock:
            return dict(self._certs)

    async def stop(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            # Closing the socket ends the helper's stream: it kills airodump and
            # restores managed mode on its side.
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


class HelperHandshakeWatcher:
    """Adapts a :class:`HelperAirodumpSource`'s streamed handshake events to the
    controller's ``poll()`` interface (the helper does the tshark detection)."""

    def __init__(self, source: "HelperAirodumpSource") -> None:
        self._source = source

    def poll(self) -> set[str]:
        return self._source.handshake_bssids()


class HelperWpsWatcher:
    """Adapts a :class:`HelperAirodumpSource`'s streamed WPS events to the
    controller's ``poll()`` interface (the helper does the tshark detection)."""

    def __init__(self, source: "HelperAirodumpSource") -> None:
        self._source = source

    def poll(self) -> dict[str, dict]:
        return self._source.wps_info()
