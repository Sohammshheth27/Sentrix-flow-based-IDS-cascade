"""Device type fingerprinting (Option A + B)"""
from __future__ import annotations

import json
import logging
import socket
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from enum import Enum

from ip_classifier import get_classifier
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("device_classifier")

# ═══════════════════════════════════════════════════════════════
#  DEVICE CLASSES + EVIDENCE WEIGHTS
# ═══════════════════════════════════════════════════════════════

class DeviceClass(str, Enum):
    LAPTOP          = "laptop"
    PHONE           = "phone"
    PERSONAL_MOBILE = "personal_mobile"
    PRINTER         = "printer"
    CAMERA          = "camera"
    ROUTER          = "router"
    SWITCH          = "switch"
    NAS             = "nas"
    VOIP            = "voip"
    IOT             = "iot"
    SERVER          = "server"
    UNKNOWN         = "unknown"

# ═══════════════════════════════════════════════════════════════
#  PORT → EVIDENCE MAP
# ═══════════════════════════════════════════════════════════════
#
# Keyed by destination port. When a flow sends traffic TO that port
# on some IP, the IP is inferred to be SERVING that service. The
# weight reflects how discriminative the port is; "a device on port
# 9100 is almost certainly a printer" is a strong signal, "a device
# with port 443 open" is a very weak one.

PORT_EVIDENCE: Dict[int, Tuple[DeviceClass, float, str]] = {
    # printers; extremely discriminative
    9100: (DeviceClass.PRINTER, 0.90, "JetDirect"),
    515:  (DeviceClass.PRINTER, 0.85, "LPD"),
    631:  (DeviceClass.PRINTER, 0.55, "IPP/CUPS"),
    # cameras; also very discriminative
    554:  (DeviceClass.CAMERA,  0.90, "RTSP"),
    322:  (DeviceClass.CAMERA,  0.60, "RTSPS"),
    8554: (DeviceClass.CAMERA,  0.55, "RTSP-alt"),
    37777:(DeviceClass.CAMERA,  0.85, "Dahua"),
    34567:(DeviceClass.CAMERA,  0.80, "Hikvision"),
    # VoIP
    5060: (DeviceClass.VOIP,    0.88, "SIP"),
    5061: (DeviceClass.VOIP,    0.88, "SIPS"),
    2000: (DeviceClass.VOIP,    0.55, "SCCP (Cisco)"),
    # NAS / storage
    2049: (DeviceClass.NAS,     0.75, "NFS"),
    548:  (DeviceClass.NAS,     0.75, "AFP"),
    5000: (DeviceClass.NAS,     0.50, "Synology-HTTP"),
    5001: (DeviceClass.NAS,     0.50, "Synology-HTTPS"),
    # File sharing; could be laptop or NAS, weak signal
    445:  (DeviceClass.LAPTOP,  0.20, "SMB"),
    139:  (DeviceClass.LAPTOP,  0.20, "NetBIOS-SSN"),
    137:  (DeviceClass.LAPTOP,  0.15, "NetBIOS-NS"),
    # Remote admin; router/server signal
    22:   (DeviceClass.SERVER,  0.30, "SSH"),
    23:   (DeviceClass.ROUTER,  0.55, "Telnet"),
    # Management
    161:  (DeviceClass.ROUTER,  0.35, "SNMP"),
    162:  (DeviceClass.ROUTER,  0.30, "SNMP-trap"),
    # Web; super weak. Almost everything has 80/443.
    80:   (DeviceClass.UNKNOWN, 0.05, "HTTP"),
    443:  (DeviceClass.UNKNOWN, 0.05, "HTTPS"),
    8080: (DeviceClass.UNKNOWN, 0.08, "HTTP-alt"),
    8443: (DeviceClass.UNKNOWN, 0.08, "HTTPS-alt"),
    # DNS / DHCP; infrastructure
    53:   (DeviceClass.ROUTER,  0.15, "DNS"),
    67:   (DeviceClass.ROUTER,  0.40, "DHCP-server"),
    # Email (servers)
    25:   (DeviceClass.SERVER,  0.45, "SMTP"),
    587:  (DeviceClass.SERVER,  0.30, "SMTP-sub"),
    143:  (DeviceClass.SERVER,  0.40, "IMAP"),
    993:  (DeviceClass.SERVER,  0.40, "IMAPS"),
    110:  (DeviceClass.SERVER,  0.40, "POP3"),
    995:  (DeviceClass.SERVER,  0.40, "POP3S"),
    # Databases (servers)
    1433: (DeviceClass.SERVER,  0.55, "MSSQL"),
    3306: (DeviceClass.SERVER,  0.55, "MySQL"),
    5432: (DeviceClass.SERVER,  0.55, "PostgreSQL"),
    27017:(DeviceClass.SERVER,  0.50, "MongoDB"),
    # Remote desktop
    3389: (DeviceClass.LAPTOP,  0.35, "RDP"),
    5900: (DeviceClass.LAPTOP,  0.30, "VNC"),
    # IoT / smart home cloud cues
    1883: (DeviceClass.IOT,     0.60, "MQTT"),
    8883: (DeviceClass.IOT,     0.60, "MQTT-TLS"),
    5683: (DeviceClass.IOT,     0.65, "CoAP"),
    # mDNS / SSDP; discovery (weak, nearly everything broadcasts some)
    5353: (DeviceClass.UNKNOWN, 0.05, "mDNS"),
    1900: (DeviceClass.UNKNOWN, 0.05, "SSDP"),
    # Time
    123:  (DeviceClass.UNKNOWN, 0.02, "NTP"),
    # Proxy / tunneling
    3128: (DeviceClass.SERVER,  0.40, "Squid"),
    1080: (DeviceClass.SERVER,  0.30, "SOCKS"),
}

# ═══════════════════════════════════════════════════════════════
#  OUI DATABASE
# ═══════════════════════════════════════════════════════════════
#
# Abbreviated IEEE OUI → vendor lookup. Covers the vendors most
# likely to show up in an office network. Key is the first 3 bytes
# of the MAC in uppercase no-delimiter form. Users can extend with
# the full IEEE CSV (~30 000 entries) if they want wider coverage.

OUI_DB: Dict[str, str] = {
    # Apple
    "3C0754": "Apple", "F0B479": "Apple", "A8667F": "Apple",
    "7CD1C3": "Apple", "B817C2": "Apple", "28CFE9": "Apple",
    "14BD61": "Apple", "F82793": "Apple", "485A3F": "Apple",
    # Dell
    "F8BC12": "Dell", "001422": "Dell", "E4F04C": "Dell",
    "00188B": "Dell", "50F535": "Dell", "A41F72": "Dell",
    # HP / Hewlett-Packard
    "A0481C": "Hewlett-Packard", "E4E749": "Hewlett-Packard",
    "08002B": "DEC/HP-legacy",   "001E0B": "Hewlett-Packard",
    "EC9A74": "Hewlett-Packard", "FCA8A3": "Hewlett-Packard",
    # Lenovo
    "6CE85C": "Lenovo", "28D244": "Lenovo", "F0DEF1": "Lenovo",
    "506B4B": "Lenovo",
    # Microsoft (Surface / Xbox)
    "7C1E52": "Microsoft", "00155D": "Microsoft-Hyper-V",
    # Intel (NICs)
    "A0369F": "Intel", "00248C": "Intel", "7085C2": "Intel",
    # Cisco; networking
    "00000C": "Cisco", "001E7A": "Cisco", "00265A": "Cisco",
    "E4AA5D": "Cisco", "503DE5": "Cisco", "1C1D86": "Cisco",
    # Cisco Meraki
    "E0CB4E": "Cisco-Meraki", "884AEA": "Cisco-Meraki",
    # Aruba / HPE Networking
    "005056": "VMware",  # intentional; Vmware vNIC
    "9C1C12": "Aruba",  "4C1A3D": "Aruba",
    # Juniper
    "2C6BF5": "Juniper", "4CFB43": "Juniper",
    # Ubiquiti
    "24A43C": "Ubiquiti", "802AA8": "Ubiquiti", "44D9E7": "Ubiquiti",
    "04184A": "Ubiquiti",
    # MikroTik
    "4C5E0C": "MikroTik", "6C3B6B": "MikroTik", "D4CA6D": "MikroTik",
    # Fortinet
    "00090F": "Fortinet", "900D66": "Fortinet",
    # Palo Alto
    "F89D0D": "Palo-Alto", "6C23B9": "Palo-Alto",
    # Hikvision; cameras
    "4C3D5B": "Hikvision", "C0F699": "Hikvision", "44194F": "Hikvision",
    "ACB966": "Hikvision", "E0CA3C": "Hikvision",
    # Dahua; cameras
    "901A69": "Dahua", "14A7A5": "Dahua", "3CEF8C": "Dahua",
    "A0BD1D": "Dahua",
    # Axis; cameras
    "00408C": "Axis", "ACCC8E": "Axis", "B8A44F": "Axis",
    # Hanwha / Samsung Techwin; cameras
    "009048": "Hanwha",
    # Canon; printers
    "001E8F": "Canon", "6CF37F": "Canon", "D48564": "Canon",
    # Epson; printers
    "0000E0": "Epson", "6805CA": "Epson", "20BBC0": "Epson",
    # Brother; printers
    "30055C": "Brother", "008092": "Brother",
    # Lexmark; printers
    "00040F": "Lexmark", "0021B7": "Lexmark",
    # Ricoh
    "00261F": "Ricoh", "04B301": "Ricoh",
    # Synology; NAS
    "0011322": "Synology", "001132": "Synology",
    # QNAP; NAS
    "245EBE": "QNAP", "0008A1": "QNAP",
    # Sonos; audio IoT
    "B8E937": "Sonos", "54A050": "Sonos",
    # Amazon; Alexa / Fire / Kindle
    "38F73D": "Amazon", "74C246": "Amazon", "08E39D": "Amazon",
    "447DA5": "Amazon",
    # Google; Nest / Chromecast / Home
    "F4F5D8": "Google", "6466B3": "Google", "6C56E0": "Google",
    "3C5AB4": "Google",
    # Samsung (phones/TVs)
    "8CF5A3": "Samsung", "2CAE2B": "Samsung", "08EE8B": "Samsung",
    # Xiaomi (phones/IoT); dominant in Indian BYOD
    "F48B32": "Xiaomi", "50EC50": "Xiaomi", "8CBE1D": "Xiaomi",
    "64CC2E": "Xiaomi", "9C2EA1": "Xiaomi",
    # OnePlus; common in Indian offices
    "94652D": "OnePlus", "C0EEFB": "OnePlus",
    # Oppo / Realme; high market share in India
    "A45E60": "Oppo", "E89309": "Oppo", "2CAACA": "Realme",
    # Vivo; top 3 in Indian mobile market
    "4C6641": "Vivo", "5893D8": "Vivo",
    # Motorola (Lenovo mobile)
    "28A183": "Motorola-Mobile", "C8E07E": "Motorola-Mobile",
    # Huawei / Honor
    "E0191D": "Huawei", "2842CA": "Huawei", "0018D2": "Huawei",
    # Raspberry Pi Foundation
    "B827EB": "Raspberry-Pi", "DCA632": "Raspberry-Pi",
    "E45F01": "Raspberry-Pi",
    # Polycom; VoIP
    "0004F2": "Polycom", "64167F": "Polycom",
    # Yealink; VoIP
    "001565": "Yealink", "249AD8": "Yealink",
    # Roku
    "B0A737": "Roku", "DC3A5E": "Roku",
}

# Vendors that strongly imply a specific device class
VENDOR_CLASS_HINT: Dict[str, DeviceClass] = {
    "Apple": DeviceClass.LAPTOP,  # could be phone too; port signals differentiate
    "Dell": DeviceClass.LAPTOP,
    "Hewlett-Packard": DeviceClass.LAPTOP,
    "Lenovo": DeviceClass.LAPTOP,
    "Microsoft": DeviceClass.LAPTOP,
    "Cisco": DeviceClass.ROUTER,
    "Cisco-Meraki": DeviceClass.ROUTER,
    "Aruba": DeviceClass.ROUTER,
    "Juniper": DeviceClass.ROUTER,
    "Ubiquiti": DeviceClass.ROUTER,
    "MikroTik": DeviceClass.ROUTER,
    "Fortinet": DeviceClass.ROUTER,
    "Palo-Alto": DeviceClass.ROUTER,
    "Hikvision": DeviceClass.CAMERA,
    "Dahua": DeviceClass.CAMERA,
    "Axis": DeviceClass.CAMERA,
    "Hanwha": DeviceClass.CAMERA,
    "Canon": DeviceClass.PRINTER,
    "Epson": DeviceClass.PRINTER,
    "Brother": DeviceClass.PRINTER,
    "Lexmark": DeviceClass.PRINTER,
    "Ricoh": DeviceClass.PRINTER,
    "Synology": DeviceClass.NAS,
    "QNAP": DeviceClass.NAS,
    "Sonos": DeviceClass.IOT,
    "Amazon": DeviceClass.IOT,
    "Google": DeviceClass.IOT,
    "Samsung": DeviceClass.PERSONAL_MOBILE,
    "Xiaomi": DeviceClass.PERSONAL_MOBILE,
    "OnePlus": DeviceClass.PERSONAL_MOBILE,
    "Oppo": DeviceClass.PERSONAL_MOBILE,
    "Realme": DeviceClass.PERSONAL_MOBILE,
    "Vivo": DeviceClass.PERSONAL_MOBILE,
    "Motorola-Mobile": DeviceClass.PERSONAL_MOBILE,
    "Huawei": DeviceClass.PERSONAL_MOBILE,
    "Raspberry-Pi": DeviceClass.SERVER,
    "Polycom": DeviceClass.VOIP,
    "Yealink": DeviceClass.VOIP,
    "Roku": DeviceClass.IOT,
}

# ═══════════════════════════════════════════════════════════════
#  DHCP FINGERPRINTS
# ═══════════════════════════════════════════════════════════════
#
# Common DHCP Option 55 parameter request lists. Real Fingerbank has
# thousands; this covers the major OSes / device families.
# Key is the comma-joined option list as string.

DHCP_FINGERPRINTS: Dict[str, Tuple[str, DeviceClass]] = {
    "1,15,3,6,44,46,47,31,33,121,249,43":      ("Windows 7/8",       DeviceClass.LAPTOP),
    "1,3,6,15,31,33,43,44,46,47,119,121,249,252,207": ("Windows 10/11", DeviceClass.LAPTOP),
    "1,3,6,15,119,252,95,44,46":                ("macOS",              DeviceClass.LAPTOP),
    "1,3,6,15,119,252":                         ("iOS",                DeviceClass.PERSONAL_MOBILE),
    "1,121,3,6,15,26,28,51,58,59,43":           ("Android",            DeviceClass.PERSONAL_MOBILE),
    "1,3,6,12,15,28,42,43,66,150":              ("VoIP phone",         DeviceClass.VOIP),
    "1,3,6,12,15,17,23,28,29,31,33,40,41,42":   ("Linux generic",      DeviceClass.SERVER),
    "1,3,28,6,15,44,47":                        ("IP camera",          DeviceClass.CAMERA),
    "1,6,15,44,3,33,150,43":                    ("Printer",            DeviceClass.PRINTER),
}

# ═══════════════════════════════════════════════════════════════
#  DEVICE EVIDENCE RECORD
# ═══════════════════════════════════════════════════════════════

@dataclass
class DeviceEvidence:
    ip: str
    class_scores: Dict[DeviceClass, float] = field(default_factory=dict)
    vendor_hint: Optional[str] = None
    model_hint: Optional[str] = None
    os_hint: Optional[str] = None
    sources: List[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_updated: float = 0.0
    flow_count: int = 0
    observed_ports: Dict[int, int] = field(default_factory=dict)
    snmp_probed_at: Optional[float] = None
    snmp_sysdescr: Optional[str] = None
    _seen_signals: Set[Tuple[str, str]] = field(default_factory=set)

    def add_signal(self, dev_class: DeviceClass, weight: float,
                   signal_key: str, source_label: str) -> None:
        """
        Vote once per unique (class, signal_key) pair. Repeated
        observations of the SAME signal key don't inflate the score.
        """
        key = (dev_class.value, signal_key)
        if key in self._seen_signals:
            return
        self._seen_signals.add(key)
        self.class_scores[dev_class] = self.class_scores.get(dev_class, 0.0) + weight
        if source_label not in self.sources:
            self.sources.append(source_label)

    def best_class(self) -> Tuple[DeviceClass, float]:
        if not self.class_scores:
            return DeviceClass.UNKNOWN, 0.0
        # Drop UNKNOWN from the "best" selection; it's a catch-all bucket,
        # not a useful classification.
        candidates = {k: v for k, v in self.class_scores.items()
                      if k != DeviceClass.UNKNOWN}
        if not candidates:
            return DeviceClass.UNKNOWN, 0.0
        best_cls = max(candidates.items(), key=lambda x: x[1])
        total = sum(candidates.values())
        conf = best_cls[1] / total if total > 0 else 0.0
        return best_cls[0], conf

# ═══════════════════════════════════════════════════════════════
#  SNMP GET sysDescr.0; hand-rolled BER over stdlib UDP
# ═══════════════════════════════════════════════════════════════
#
# SNMPv2c packet layout:
#   SEQUENCE {
#     INTEGER version (1)
#     OCTET STRING community
#     [0] IMPLICIT GetRequest {
#       INTEGER request-id
#       INTEGER 0   -- error-status
#       INTEGER 0   -- error-index
#       SEQUENCE {
#         SEQUENCE {  -- one varbind
#           OID 1.3.6.1.2.1.1.1.0
#           NULL
#         }
#       }
#     }
#   }

def _ber_length(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    if n < 256:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xff, n & 0xff])

def _ber_integer(v: int) -> bytes:
    if v == 0:
        body = b"\x00"
    else:
        bs: List[int] = []
        n = v
        while n > 0:
            bs.append(n & 0xff)
            n >>= 8
        bs.reverse()
        if bs[0] & 0x80:
            bs.insert(0, 0)
        body = bytes(bs)
    return b"\x02" + _ber_length(len(body)) + body

def _ber_octet_string(s: bytes) -> bytes:
    return b"\x04" + _ber_length(len(s)) + s

def _ber_null() -> bytes:
    return b"\x05\x00"

def _ber_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    if len(parts) < 2:
        raise ValueError("OID too short")
    out: List[int] = [parts[0] * 40 + parts[1]]
    for p in parts[2:]:
        if p < 128:
            out.append(p)
        else:
            # base-128 with continuation bit
            stack: List[int] = []
            n = p
            while n > 0:
                stack.append(n & 0x7f)
                n >>= 7
            stack.reverse()
            for i in range(len(stack) - 1):
                stack[i] |= 0x80
            out.extend(stack)
    body = bytes(out)
    return b"\x06" + _ber_length(len(body)) + body

def _ber_sequence(content: bytes) -> bytes:
    return b"\x30" + _ber_length(len(content)) + content

def _ber_get_request(content: bytes) -> bytes:
    # Context [0] constructed = 0xA0
    return b"\xA0" + _ber_length(len(content)) + content

def _build_snmp_get_sysdescr(community: str = "public",
                              request_id: int = 1) -> bytes:
    oid = _ber_oid("1.3.6.1.2.1.1.1.0")
    varbind = _ber_sequence(oid + _ber_null())
    varbinds = _ber_sequence(varbind)
    pdu = _ber_get_request(
        _ber_integer(request_id)
        + _ber_integer(0)   # error-status
        + _ber_integer(0)   # error-index
        + varbinds
    )
    msg = _ber_sequence(
        _ber_integer(1)     # SNMPv2c
        + _ber_octet_string(community.encode("ascii"))
        + pdu
    )
    return msg

def _ber_read_length(data: bytes, pos: int) -> Tuple[int, int]:
    first = data[pos]
    if first < 128:
        return first, pos + 1
    n = first & 0x7f
    length = 0
    for i in range(n):
        length = (length << 8) | data[pos + 1 + i]
    return length, pos + 1 + n

def _ber_skip(data: bytes, pos: int) -> int:
    pos += 1  # tag
    length, pos = _ber_read_length(data, pos)
    return pos + length

def _parse_snmp_sysdescr_response(data: bytes) -> Optional[str]:
    """
    Walk the BER tree and return the first OCTET STRING inside the
    varbinds section. Returns None on any parse error.
    """
    try:
        if not data or data[0] != 0x30:
            return None
        pos = 1
        _, pos = _ber_read_length(data, pos)     # skip outer length
        pos = _ber_skip(data, pos)                # skip version
        pos = _ber_skip(data, pos)                # skip community
        # PDU; expect GetResponse (0xA2)
        if data[pos] != 0xA2:
            return None
        pos += 1
        _, pos = _ber_read_length(data, pos)
        pos = _ber_skip(data, pos)                # skip request-id
        pos = _ber_skip(data, pos)                # skip error-status
        pos = _ber_skip(data, pos)                # skip error-index
        # VarBinds sequence
        if data[pos] != 0x30:
            return None
        pos += 1
        _, pos = _ber_read_length(data, pos)
        # First varbind (SEQUENCE)
        if data[pos] != 0x30:
            return None
        pos += 1
        _, pos = _ber_read_length(data, pos)
        # OID (skip)
        pos = _ber_skip(data, pos)
        # Value; must be OCTET STRING (0x04) for sysDescr
        if data[pos] != 0x04:
            return None
        pos += 1
        val_len, pos = _ber_read_length(data, pos)
        return data[pos:pos + val_len].decode("utf-8", errors="replace")
    except Exception:
        return None

def snmp_get_sysdescr(ip: str, community: str = "public",
                       timeout: float = 2.0) -> Optional[str]:
    """
    Synchronous SNMPv2c GET sysDescr.0 against `ip`. Returns the
    sysDescr string on success, None on any failure (timeout, host
    unreachable, parse error, SNMP error).
    """
    try:
        pkt = _build_snmp_get_sysdescr(community, request_id=int(time.time()) % 1000)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(pkt, (ip, 161))
            resp, _ = sock.recvfrom(4096)
        finally:
            sock.close()
        return _parse_snmp_sysdescr_response(resp)
    except (socket.timeout, OSError, ValueError):
        return None

def classify_from_sysdescr(sysdescr: str) -> Optional[DeviceClass]:
    """Heuristic: infer device class from an SNMP sysDescr string."""
    if not sysdescr:
        return None
    s = sysdescr.lower()
    if any(k in s for k in ("cisco ios", "junos", "mikrotik", "routeros",
                             "arubaos", "fortigate", "pan-os", "openwrt",
                             "dd-wrt")):
        return DeviceClass.ROUTER
    if any(k in s for k in ("hp jetdirect", "hp laserjet", "hp inkjet",
                             "canon", "epson", "brother", "lexmark",
                             "ricoh", "xerox", "kyocera")):
        return DeviceClass.PRINTER
    if any(k in s for k in ("axis", "hikvision", "dahua", "hanwha",
                             "avigilon", "vivotek")):
        return DeviceClass.CAMERA
    if any(k in s for k in ("synology dsm", "qnap", "netapp",
                             "freenas", "truenas")):
        return DeviceClass.NAS
    if any(k in s for k in ("polycom", "yealink", "grandstream",
                             "snom")):
        return DeviceClass.VOIP
    if "linux" in s:
        return DeviceClass.SERVER
    if "windows" in s:
        return DeviceClass.LAPTOP
    return None

# ═══════════════════════════════════════════════════════════════
#  MAIN CLASSIFIER
# ═══════════════════════════════════════════════════════════════

class DeviceClassifier:
    """
    Per-process classifier. Observes flows, accumulates evidence,
    persists to alerts.db → device_classifications. Thread-safe.
    """

    def __init__(self, db_path: str = "alerts.db"):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._devices: Dict[str, DeviceEvidence] = {}
        self._dirty: Set[str] = set()
        self._init_db()
        self._load_from_db()
        log.info(f"  DeviceClassifier ready: {len(self._devices)} devices loaded")

    # ── Schema + persistence ────────────────────────────────────

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS device_classifications (
                    ip              TEXT PRIMARY KEY,
                    device_class    TEXT NOT NULL,
                    vendor          TEXT,
                    model_hint      TEXT,
                    os_hint         TEXT,
                    confidence      REAL NOT NULL,
                    sources         TEXT,
                    class_scores    TEXT,
                    flow_count      INTEGER,
                    observed_ports  TEXT,
                    first_seen      REAL,
                    last_updated    REAL,
                    snmp_probed_at  REAL,
                    snmp_sysdescr   TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def _load_from_db(self) -> None:
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            rows = conn.execute(
                "SELECT ip, vendor, model_hint, os_hint, class_scores, "
                "sources, flow_count, observed_ports, first_seen, "
                "last_updated, snmp_probed_at, snmp_sysdescr "
                "FROM device_classifications"
            ).fetchall()
        except Exception:
            rows = []
        finally:
            conn.close()

        for r in rows:
            (ip, vendor, model_hint, os_hint, class_scores_json,
             sources_json, flow_count, ports_json, first_seen,
             last_updated, snmp_at, snmp_sys) = r
            dev = DeviceEvidence(ip=ip)
            dev.vendor_hint = vendor
            dev.model_hint = model_hint
            dev.os_hint = os_hint
            try:
                scores = json.loads(class_scores_json or "{}")
                dev.class_scores = {
                    DeviceClass(k): v for k, v in scores.items()
                    if k in DeviceClass.__members__.values() or k in [c.value for c in DeviceClass]
                }
            except Exception:
                dev.class_scores = {}
            try:
                dev.sources = json.loads(sources_json or "[]")
            except Exception:
                dev.sources = []
            try:
                dev.observed_ports = {
                    int(k): v for k, v in json.loads(ports_json or "{}").items()
                }
            except Exception:
                dev.observed_ports = {}
            dev.flow_count = int(flow_count or 0)
            dev.first_seen = float(first_seen or 0)
            dev.last_updated = float(last_updated or 0)
            dev.snmp_probed_at = float(snmp_at) if snmp_at else None
            dev.snmp_sysdescr = snmp_sys
            self._devices[ip] = dev

    def persist_dirty(self) -> None:
        """Flush every dirty device to the DB. Called periodically."""
        with self._lock:
            dirty = list(self._dirty)
            self._dirty.clear()
        if not dirty:
            return
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            for ip in dirty:
                with self._lock:
                    dev = self._devices.get(ip)
                    if not dev:
                        continue
                    best, conf = dev.best_class()
                    conn.execute("""
                        INSERT OR REPLACE INTO device_classifications
                        (ip, device_class, vendor, model_hint, os_hint,
                         confidence, sources, class_scores, flow_count,
                         observed_ports, first_seen, last_updated,
                         snmp_probed_at, snmp_sysdescr)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        dev.ip, best.value, dev.vendor_hint, dev.model_hint,
                        dev.os_hint, round(conf, 4),
                        json.dumps(dev.sources),
                        json.dumps({k.value: round(v, 4)
                                    for k, v in dev.class_scores.items()}),
                        dev.flow_count,
                        json.dumps({str(k): v for k, v in dev.observed_ports.items()}),
                        dev.first_seen, dev.last_updated,
                        dev.snmp_probed_at, dev.snmp_sysdescr,
                    ))
            conn.commit()
        finally:
            conn.close()

    # ── Hot path: observe a flow ────────────────────────────────

    def observe(self, flow: dict) -> None:
        now = time.time()
        src_ip = flow.get("src_ip", "")
        dst_ip = flow.get("dst_ip", "")
        try:
            dst_port = int(flow.get("dst_port", 0) or 0)
        except (TypeError, ValueError):
            dst_port = 0
        try:
            src_port = int(flow.get("src_port", 0) or 0)
        except (TypeError, ValueError):
            src_port = 0

        # dst_ip is a server on dst_port; src_ip is a client using src_port
        self._observe_one(dst_ip, dst_port, is_server=True, flow=flow, now=now)
        self._observe_one(src_ip, src_port, is_server=False, flow=flow, now=now)

    def _observe_one(self, ip: str, port: int, is_server: bool,
                     flow: dict, now: float) -> None:
        if not ip or ip == "0.0.0.0" or ip.startswith("127.") \
           or ip.startswith("169.254") or ip == "255.255.255.255":
            return
        # Multicast (224.0.0.0/4) and IPv6 multicast; not real endpoints
        try:
            first_octet = int(ip.split(".", 1)[0])
            if 224 <= first_octet <= 239:
                return
        except (ValueError, IndexError):
            pass
        low = ip.lower()
        if ":" in ip and (low.startswith("ff") or ip.startswith("::") or low.startswith("fe80")):
            return
        # Subnet broadcast (.255 last octet is the common /24 broadcast)
        if ip.endswith(".255"):
            return
        # Only office-internal endpoints are real devices.
        if not get_classifier().is_internal(ip):
            return

        with self._lock:
            if ip not in self._devices:
                self._devices[ip] = DeviceEvidence(ip=ip, first_seen=now)
            dev = self._devices[ip]
            dev.last_updated = now
            dev.flow_count += 1

            # 1) Port evidence (server side only; a listener is a stronger
            #    fingerprint than a client port, which is just ephemeral)
            if is_server and port > 0 and port in PORT_EVIDENCE:
                dev_class, weight, desc = PORT_EVIDENCE[port]
                dev.add_signal(
                    dev_class, weight,
                    signal_key=f"port:{port}",
                    source_label=f"port {port} ({desc})",
                )
                dev.observed_ports[port] = dev.observed_ports.get(port, 0) + 1

            # 2) MAC OUI (only present on live-capture flow dicts)
            mac_key = "src_mac" if not is_server else "dst_mac"
            mac = flow.get(mac_key, "") or flow.get("mac", "")
            if mac:
                clean = mac.replace(":", "").replace("-", "").replace(".", "").upper()
                if len(clean) >= 6:
                    oui = clean[:6]
                    vendor = OUI_DB.get(oui)
                    if vendor:
                        dev.vendor_hint = vendor
                        cls_hint = VENDOR_CLASS_HINT.get(vendor)
                        if cls_hint:
                            dev.add_signal(
                                cls_hint, 0.55,
                                signal_key=f"oui:{oui}",
                                source_label=f"OUI {vendor}",
                            )

            # 3) DHCP fingerprint (only present if the capture layer parses it)
            dhcp_fp = flow.get("dhcp_option_55", "") or flow.get("dhcp_fp", "")
            if dhcp_fp and dhcp_fp in DHCP_FINGERPRINTS:
                os_name, cls = DHCP_FINGERPRINTS[dhcp_fp]
                dev.os_hint = os_name
                dev.add_signal(
                    cls, 0.75,
                    signal_key=f"dhcp:{dhcp_fp}",
                    source_label=f"DHCP {os_name}",
                )

            # 4) JA3 fingerprint (when eta.py attached it)
            ja3 = flow.get("ja3", "")
            if ja3:
                # A known JA3 hash would ideally map to specific apps; without a
                # full database we just record that TLS was observed, which is
                # a weak signal that the device is a client endpoint.
                dev.add_signal(
                    DeviceClass.LAPTOP, 0.10,
                    signal_key=f"ja3:seen",
                    source_label="JA3 observed",
                )

            self._dirty.add(ip)

    # ── Active SNMP probe ───────────────────────────────────────

    def snmp_probe(self, ip: str, community: str = "public",
                   timeout: float = 2.0) -> dict:
        """
        Send a synchronous SNMPv2c GET sysDescr.0 to `ip`. If it
        responds, record the dominant classification (weight 3.0; any
        passive vote is outvoted). Always returns a classification dict
        whether the probe succeeded or not.
        """
        sysdescr = snmp_get_sysdescr(ip, community=community, timeout=timeout)
        with self._lock:
            if ip not in self._devices:
                self._devices[ip] = DeviceEvidence(ip=ip, first_seen=time.time())
            dev = self._devices[ip]
            dev.snmp_probed_at = time.time()
            if sysdescr:
                dev.snmp_sysdescr = sysdescr
                cls = classify_from_sysdescr(sysdescr)
                if cls:
                    dev.add_signal(
                        cls, 3.0,
                        signal_key=f"snmp:{sysdescr[:40]}",
                        source_label=f"SNMP sysDescr: {sysdescr[:40]}",
                    )
            self._dirty.add(ip)
        # Flush immediately so the dashboard sees the result without a
        # poll delay.
        try:
            self.persist_dirty()
        except Exception as e:
            log.warning(f"  persist after snmp probe failed: {e}")
        return self.get_classification(ip)

    # ── Read-side API ───────────────────────────────────────────

    def get_classification(self, ip: str) -> dict:
        with self._lock:
            dev = self._devices.get(ip)
            if not dev:
                return {
                    "ip": ip,
                    "device_class": DeviceClass.UNKNOWN.value,
                    "vendor": None,
                    "model_hint": None,
                    "os_hint": None,
                    "confidence": 0.0,
                    "class_scores": {},
                    "sources": [],
                    "flow_count": 0,
                    "observed_ports": {},
                    "snmp_probed_at": None,
                    "snmp_sysdescr": None,
                }
            best, conf = dev.best_class()
            return {
                "ip": dev.ip,
                "device_class": best.value,
                "vendor": dev.vendor_hint,
                "model_hint": dev.model_hint,
                "os_hint": dev.os_hint,
                "confidence": round(conf, 4),
                "class_scores": {
                    k.value: round(v, 4) for k, v in dev.class_scores.items()
                },
                "sources": list(dev.sources),
                "flow_count": dev.flow_count,
                "observed_ports": dict(dev.observed_ports),
                "snmp_probed_at": dev.snmp_probed_at,
                "snmp_sysdescr": dev.snmp_sysdescr,
            }

    def get_all(self) -> List[dict]:
        with self._lock:
            ips = list(self._devices.keys())
        return [self.get_classification(ip) for ip in ips]

    # ── Background save thread ──────────────────────────────────

    def start_save_thread(self, interval_seconds: float = 10.0) -> threading.Thread:
        def _loop():
            while True:
                time.sleep(interval_seconds)
                try:
                    self.persist_dirty()
                except Exception as e:
                    log.warning(f"  persist_dirty error: {e}")

        t = threading.Thread(
            target=_loop, daemon=True, name="device-classifier-save"
        )
        t.start()
        return t
