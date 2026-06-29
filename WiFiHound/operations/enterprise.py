"""WPA2-Enterprise (802.1X) assessment helpers.

Two authorized-testing features for enterprise networks:

* **RADIUS server certificate extraction** from a capture's ``.cap``/``.pcap``.
  This only *reads a file* (no radio), so it carries no privilege gate, just a
  dependency check, exactly like WPA handshake detection. It prefers
  ``pcapFilter.sh -C`` when present and otherwise drives ``tshark`` directly,
  decoding the X.509 certificate(s) with :mod:`cryptography`.

* **EAP-method enumeration** via ``EAP_buster.sh``. That script performs *real*
  802.1X authentication attempts against a live AP (it takes the interface to
  managed mode itself), so it gets the full offensive guardrails: root and an
  explicit per-request acknowledgement.

The parsing helpers (``parse_eap_buster``, ``parse_certificates_*``) are pure
and unit-tested; the subprocess calls are best-effort and degrade with a clear
:class:`OperationError` when a tool is missing.

Authorized use only: run these against networks you own or are explicitly
permitted to assess.
"""

from __future__ import annotations

import binascii
import glob
import logging
import os
import re
import shutil
import subprocess
import tempfile

from WiFiHound.models import normalize_mac
from WiFiHound.operations.base import (
    OperationError,
    require_authorization,
    require_tools,
)

logger = logging.getLogger("WiFiHound.operations.enterprise")

try:  # certificate decoding needs `cryptography`; degrade clearly if absent
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as _serialization
    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - exercised only without the dep
    x509 = None
    _serialization = None
    _HAVE_CRYPTO = False

# EAP_buster is vendored under the package (operations/../vendor/EAP_buster) so
# enumeration works out of the box; WIFIHOUND_EAP_BUSTER can still override it.
_BUNDLED_EAP_BUSTER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "vendor", "EAP_buster", "EAP_buster.sh")
EAP_BUSTER = os.environ.get("WIFIHOUND_EAP_BUSTER") or _BUNDLED_EAP_BUSTER
CERT_TIMEOUT = 120              # tshark TLS reassembly over a big cap is slow
EAP_BUSTER_TIMEOUT = 15 * 60    # ~20s/method x ~18 methods; hung well past this

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# "not supported" must precede "supported": the former contains the latter.
_VERDICT_RE = re.compile(r"^(?P<status>not supported|supported)\s+=>\s+(?P<method>\S.*?)\s*$")
_PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)
# Reject control chars in the EAP identity; keep it a bounded, printable string.
_IDENTITY_RE = re.compile(r"^[^\x00-\x1f]{1,128}$")

# EAP_buster.sh declares this list; methods without a shipped .conf are not
# actually probed, so we report them as "maybe" (untested), never "no".
EAP_METHODS = [
    "EAP-TLS", "EAP-PEAP_MSCHAPv2", "EAP-PEAP_TLS", "EAP-PEAP_GTC",
    "EAP-PEAP_OTP", "EAP-PEAP_MD5-Challenge", "EAP-TTLS_EAP-MD5-Challenge",
    "EAP-TTLS_EAP-GTC", "EAP-TTLS_EAP-OTP", "EAP-TTLS_EAP-MSCHAPv2",
    "EAP-TTLS_EAP-TLS", "EAP-TTLS_MSCHAPv2", "EAP-TTLS_MSCHAP",
    "EAP-TTLS_PAP", "EAP-TTLS_CHAP", "EAP-SIM", "EAP-AKA", "EAP-PSK",
    "EAP-PAX", "EAP-SAKE", "EAP-IKEv2", "EAP-GPSK", "LEAP",
    "EAP-FAST_MSCHAPv2", "EAP-FAST_GTC", "EAP-FAST_OTP",
]


# --------------------------------------------------------------- EAP parsing
def parse_eap_buster(stdout: str, mark_untested_as_maybe: bool = True) -> list[dict]:
    """Parse ``EAP_buster.sh`` output into ``[{"method", "supported"}]``.

    ``supported`` is ``"yes"`` / ``"no"`` for methods the tool actually probed.
    ``"maybe"`` is **synthetic**: it never comes from the tool, it marks methods
    in :data:`EAP_METHODS` the run did not report on (e.g. ones with no shipped
    config). The tool colours lines and rewrites a progress line with ``\\r``;
    we keep only the text after the last carriage return and strip ANSI codes.
    """
    results: list[dict] = []
    seen: set[str] = set()
    for raw in stdout.splitlines():
        line = _ANSI_RE.sub("", raw.split("\r")[-1]).strip()
        if not line:
            continue
        match = _VERDICT_RE.match(line)
        if not match:
            continue  # banner / warning / progress remnants
        method = match.group("method").strip()
        if method in seen:
            continue
        seen.add(method)
        results.append({
            "method": method,
            "supported": "yes" if match.group("status") == "supported" else "no",
        })
    if mark_untested_as_maybe:
        for method in EAP_METHODS:
            if method not in seen:
                results.append({"method": method, "supported": "maybe"})
    return results


# -------------------------------------------------------- certificate parsing
def _validity(cert) -> tuple[str, str]:
    # cryptography >= 42 exposes tz-aware *_utc; older versions have naive UTC.
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    return not_before.isoformat(), not_after.isoformat()


def _cert_to_dict(cert) -> dict:
    not_before, not_after = _validity(cert)
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": not_before,
        "not_after": not_after,
        "serial": format(cert.serial_number, "x"),
    }


def parse_certificates_from_der_list(der_blobs: list[bytes]) -> list[dict]:
    """Decode raw DER certificate blobs into structured dicts, leaf first.

    The leaf (server) certificate is the one whose subject differs from its
    issuer; it is sorted first so callers can read ``certs[0]`` as the RADIUS
    server certificate.
    """
    if not _HAVE_CRYPTO:
        raise OperationError(
            "Certificate parsing needs the 'cryptography' package "
            "(pip install cryptography).")
    certs = []
    for der in der_blobs:
        try:
            certs.append(x509.load_der_x509_certificate(der))
        except (ValueError, TypeError):
            continue
    certs.sort(key=lambda c: c.subject == c.issuer)  # leaf (subj != iss) first
    return [_cert_to_dict(c) for c in certs]


def hexfields_to_der(field_output: str) -> list[bytes]:
    """Turn a ``tls.handshake.certificate`` ``-T fields`` dump into DER blobs.

    tshark prints the field as colon-separated hex, one packet per line, with
    commas joining multiple certificates inside a packet. Bad tokens are skipped.
    """
    blobs: list[bytes] = []
    for token in field_output.split():
        for chunk in token.split(","):
            hexed = chunk.replace(":", "").strip()
            if not hexed:
                continue
            try:
                blobs.append(binascii.unhexlify(hexed))
            except (binascii.Error, ValueError):
                continue
    return blobs


def parse_certificates_from_pem_text(text: str) -> list[dict]:
    """Scrape ``-----BEGIN CERTIFICATE-----`` blocks from text and decode them."""
    if not _HAVE_CRYPTO:
        raise OperationError(
            "Certificate parsing needs the 'cryptography' package "
            "(pip install cryptography).")
    ders: list[bytes] = []
    for pem in _PEM_RE.findall(text):
        try:
            cert = x509.load_pem_x509_certificate(pem.encode())
            ders.append(cert.public_bytes(_serialization.Encoding.DER))
        except (ValueError, TypeError):
            continue
    return parse_certificates_from_der_list(ders)


# ------------------------------------------------------------- cert extraction
def extract_radius_cert(cap_path: str, ap_bssid: str | None = None,
                        prefer_pcapfilter: bool = True,
                        dry_run: bool = False) -> dict:
    """Pull the RADIUS/EAP server certificate(s) out of a capture file.

    Read-only: no radio, no root. Uses ``pcapFilter.sh -C`` when available,
    otherwise ``tshark``. ``ap_bssid`` scopes the search to one AP
    (``wlan.sa == BSSID``). Returns ``status: "empty"`` (not an error) when the
    capture contains no certificate (truncated capture, non-enterprise AP, or a
    TLS 1.3 handshake that encrypts the certificate).
    """
    if not cap_path or not os.path.isfile(cap_path):
        raise OperationError("Capture file not found.")
    bssid = normalize_mac(ap_bssid) if ap_bssid else None
    if ap_bssid and not bssid:
        raise OperationError("Invalid AP BSSID.")

    use_pf = prefer_pcapfilter and shutil.which("pcapFilter.sh") is not None
    if use_pf:
        require_tools("pcapFilter.sh", "tshark",
                      hint="Install pcapFilter.sh and Wireshark/tshark.")
        cmd = ["pcapFilter.sh", "-f", cap_path, "-C"]
    else:
        require_tools("tshark", hint="Install Wireshark/tshark.")
        disp = "tls.handshake.type == 11"
        if bssid:
            disp += f" && wlan.sa == {bssid}"
        cmd = ["tshark", "-r", cap_path, "-Y", disp,
               "-T", "fields", "-e", "tls.handshake.certificate",
               "-E", "occurrence=a",
               "-o", "tls.desegment_ssl_records:TRUE",
               "-o", "tls.desegment_ssl_application_data:TRUE"]

    backend = "pcapfilter" if use_pf else "tshark"
    logger.info("Cert extraction (%s): %s", backend, " ".join(cmd))
    if dry_run:
        return {"status": "dry-run", "backend": backend, "command": cmd}

    started = _now()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=CERT_TIMEOUT, check=False)
    except FileNotFoundError as exc:
        raise OperationError(str(exc)) from exc
    except subprocess.TimeoutExpired as exc:
        raise OperationError(
            "Certificate extraction timed out; scope it to one AP (BSSID) to "
            "shrink the work.") from exc

    if use_pf:
        # pcapFilter writes raw DER to /tmp/certs/; decode those (most reliable),
        # falling back to scraping the PEM it prints. Only read files it just
        # wrote, to avoid stale certs from a previous run.
        ders = []
        for der_file in sorted(glob.glob("/tmp/certs/*")):
            try:
                if os.path.getmtime(der_file) + 1 < started:
                    continue
                with open(der_file, "rb") as fh:
                    ders.append(fh.read())
            except OSError:
                continue
        certs = (parse_certificates_from_der_list(ders)
                 or parse_certificates_from_pem_text(proc.stdout))
    else:
        certs = parse_certificates_from_der_list(hexfields_to_der(proc.stdout))

    return {
        "status": "ok" if certs else "empty",
        "backend": backend,
        "command": cmd,
        "returncode": proc.returncode,
        "certificates": certs,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
    }


# --------------------------------------------------------- EAP enumeration
def enumerate_eap_methods(interface: str, essid: str, identity: str,
                          script_path: str = EAP_BUSTER,
                          acknowledged: bool = False,
                          dry_run: bool = False) -> dict:
    """Enumerate the EAP methods an enterprise AP accepts, via ``EAP_buster.sh``.

    Active 802.1X authentication against a live AP, so it needs root and an
    explicit acknowledgement. The script **takes the interface to managed mode
    itself**, so do not pass an interface you need to keep in monitor mode.
    Long-running (several minutes). Returns a ``methods`` list from
    :func:`parse_eap_buster`.
    """
    require_authorization(acknowledged)            # root + acknowledged
    require_tools("wpa_supplicant",
                  hint="Install wpa_supplicant (apt install wpasupplicant).")
    if not os.path.isfile(script_path):
        raise OperationError(f"EAP_buster.sh was not found at {script_path}.")

    if not interface or not interface.strip():
        raise OperationError("A wireless interface is required.")
    interface = interface.strip()
    if not essid or not essid.strip():
        raise OperationError("An ESSID is required.")
    if not identity or not _IDENTITY_RE.match(identity):
        raise OperationError(
            "A legitimate EAP identity is required (e.g. 'DOMAIN\\\\user'); "
            "anonymous identities give unreliable results.")

    # Positional order is fixed: <ESSID> <IDENTITY> <INTERFACE>.
    cmd = [script_path, essid, identity, interface]
    # Audit at INFO so it stays off the default terminal (shown with --debug).
    logger.info("EAP enumeration requested: %s", " ".join(cmd))
    if dry_run:
        return {"status": "dry-run", "command": cmd}

    # EAP_buster generates certs, per-ESSID logs and edits its config files in
    # place, so run it from a private copy. The bundled tool stays pristine and
    # nothing is left behind in the package directory.
    src_dir = os.path.dirname(os.path.abspath(script_path))
    workdir = tempfile.mkdtemp(prefix="wifihound-eap-")
    try:
        run_dir = os.path.join(workdir, "EAP_buster")
        shutil.copytree(src_dir, run_dir)
        run_script = os.path.join(run_dir, os.path.basename(script_path))
        os.chmod(run_script, 0o755)
        try:
            proc = subprocess.run(
                [run_script, essid, identity, interface],
                capture_output=True, text=True,
                timeout=EAP_BUSTER_TIMEOUT, check=False)
        except FileNotFoundError as exc:
            raise OperationError(str(exc)) from exc
        except subprocess.TimeoutExpired as exc:
            raise OperationError(
                "EAP_buster timed out; the AP/RADIUS may be rate-limiting or "
                "the interface is stuck.") from exc
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    methods = parse_eap_buster(proc.stdout, mark_untested_as_maybe=True)
    return {
        "status": "ok" if proc.returncode == 0 else "error",
        "command": cmd,
        "returncode": proc.returncode,
        "essid": essid,
        "identity": identity,
        "methods": methods,
        "stdout": proc.stdout[-8000:],
        "stderr": proc.stderr[-4000:],
    }


def _now() -> float:
    import time
    return time.time()
