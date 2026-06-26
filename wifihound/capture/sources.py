"""Live capture sources.

A *source* yields successive :class:`~wifihound.models.Scan` snapshots. The
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
import subprocess
import tempfile
from typing import Optional

from wifihound.models import Scan
from wifihound.parsers.airodump_csv import AirodumpCsvParser


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


class AirodumpSource(Source):
    """Spawn airodump-ng and tail its rotating CSV (authorized use only).

    Capture can be narrowed with the usual airodump-ng filters: a fixed channel
    (``-c``), encryption suite (``--encrypt``), WPS info (``--wps``), and a
    specific ESSID (``--essid``) or BSSID (``--bssid``).
    """

    def __init__(self, interface: str, channel: Optional[str] = None,
                 encrypt: Optional[str] = None, wps: bool = False,
                 essid: Optional[str] = None, bssid: Optional[str] = None):
        self.interface = interface
        self.channel = channel
        self.encrypt = encrypt        # WEP | WPA2 | WPA3 | OPN ...
        self.wps = wps
        self.essid = essid
        self.bssid = bssid
        self._proc: Optional[subprocess.Popen] = None
        self._dir: Optional[str] = None
        self._parser = AirodumpCsvParser()

    def build_command(self, prefix: str) -> list[str]:
        cmd = ["airodump-ng", "--output-format", "csv", "-w", prefix]
        if self.channel:
            cmd += ["-c", str(self.channel)]
        if self.encrypt:
            cmd += ["--encrypt", str(self.encrypt)]
        if self.wps:
            cmd += ["--wps"]
        if self.bssid:
            cmd += ["--bssid", str(self.bssid)]
        if self.essid:
            cmd += ["--essid", str(self.essid)]
        cmd.append(self.interface)
        return cmd

    async def start(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="wifihound-cap-")
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
            shutil.rmtree(self._dir, ignore_errors=True)
        self._dir = None
