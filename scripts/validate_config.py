#!/usr/bin/env python3
"""
validate_config.py; Pre-flight config sanity check for Sentrix.

Runs before engine startup and catches the common misconfigurations
that would otherwise crash at 3 AM:

    * missing or unparseable config files
    * invalid / overlapping CIDRs
    * identity_registry IPs that fall outside declared subnets
    * alert channels enabled without credentials
    * SMB allowlist entries that aren't valid IPs
    * departments in subnet_to_department with no sensitivity entry

Exit codes:
    0; all green
    1; warnings only (engine will still start)
    2; errors (engine will likely fail; do not proceed)

Usage:
    python scripts/validate_config.py
    python scripts/validate_config.py --strict   # warnings → errors

Can be wired as a Docker entrypoint pre-hook or `make validate` target.
"""
from __future__ import annotations

import argparse
import io
import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Force UTF-8 on Windows consoles so the status markers render.
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer,
                                      encoding="utf-8", errors="replace")
    except Exception:
        pass

_SCRIPT = Path(__file__).resolve()
_PROJECT_ROOT = _SCRIPT.parent.parent
_CONFIG_DIR = _PROJECT_ROOT / "config"

# ── Result accumulator ─────────────────────────────────────────────

class Results:
    def __init__(self) -> None:
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.checks: List[Tuple[str, str, str]] = []  # (status, name, msg)

    def ok(self, name: str, msg: str = "") -> None:
        self.checks.append(("OK", name, msg))

    def warn(self, name: str, msg: str) -> None:
        self.checks.append(("WARN", name, msg))
        self.warnings.append(f"{name}: {msg}")

    def error(self, name: str, msg: str) -> None:
        self.checks.append(("ERROR", name, msg))
        self.errors.append(f"{name}: {msg}")

    def summary(self) -> str:
        lines = []
        for status, name, msg in self.checks:
            tag = {"OK": "✓", "WARN": "⚠", "ERROR": "✗"}[status]
            lines.append(f"  [{tag}] {name}"
                         + (f"; {msg}" if msg else ""))
        return "\n".join(lines)

# ── Individual checks ──────────────────────────────────────────────

def _read_json(path: Path) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def _read_yaml(path: Path) -> Dict[str, Any]:
    import yaml
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def check_vlan_config(r: Results) -> Dict[str, Any]:
    path = _CONFIG_DIR / "vlan_config.json"
    name = "vlan_config.json"
    if not path.exists():
        r.error(name, "file missing")
        return {}
    try:
        cfg = _read_json(path)
    except Exception as e:
        r.error(name, f"parse failed: {e}")
        return {}

    vlan_map = cfg.get("vlan_map", {})
    if not vlan_map:
        r.warn(name, "vlan_map is empty; devices will be 'unmapped'")
    elif "99" not in vlan_map:
        r.error(name, "'99' unmapped sentinel missing; dashboard will "
                       "KeyError on first IP lookup")
    else:
        r.ok(name, f"{len(vlan_map)} VLANs")

    # Validate every CIDR and check for overlaps
    nets = []
    for vid, info in vlan_map.items():
        if vid == "99":
            continue
        cidr = info.get("subnet", "")
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            nets.append((vid, net))
        except (ValueError, TypeError):
            r.error(name, f"VLAN {vid}: invalid CIDR {cidr!r}")
    for i, (v1, n1) in enumerate(nets):
        for v2, n2 in nets[i+1:]:
            if n1.overlaps(n2):
                r.error(name,
                         f"subnet overlap: VLAN {v1}({n1}) vs {v2}({n2})")
    return cfg

def check_identity_registry(r: Results,
                             vlan_cfg: Dict[str, Any]) -> Dict[str, Any]:
    path = _CONFIG_DIR / "identity_registry.json"
    name = "identity_registry.json"
    if not path.exists():
        r.warn(name, "file missing; no known devices, subnet-only mapping")
        return {}
    try:
        cfg = _read_json(path)
    except Exception as e:
        r.error(name, f"parse failed: {e}")
        return {}

    devices = cfg.get("devices", {})
    dept_sens = cfg.get("department_sensitivity", {})
    subnet_to_dept = cfg.get("subnet_to_department", {})

    # Every listed device IP should be a valid address
    bad_ips = [ip for ip in devices
               if not _valid_ip(ip)]
    if bad_ips:
        r.error(name,
                 f"{len(bad_ips)} invalid device IPs: "
                 f"{bad_ips[:3]}{'...' if len(bad_ips) > 3 else ''}")

    # Every device IP should fall inside a declared subnet
    subnet_nets = []
    for cidr in subnet_to_dept:
        try:
            subnet_nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            r.error(name, f"subnet_to_department: bad CIDR {cidr!r}")
    orphans = []
    for ip in devices:
        if not _valid_ip(ip):
            continue
        addr = ipaddress.ip_address(ip)
        if not any(addr in n for n in subnet_nets
                    if addr.version == n.version):
            orphans.append(ip)
    if orphans:
        r.warn(name,
                f"{len(orphans)} device(s) outside every declared subnet: "
                f"{orphans[:3]}{'...' if len(orphans) > 3 else ''}")

    # Every dept in subnet_to_department must have a sensitivity entry
    missing = [d for d in set(subnet_to_dept.values())
               if d not in dept_sens]
    if missing:
        r.warn(name,
                f"departments with no sensitivity entry: {missing}")

    if not r.errors or not any(e.startswith(name) for e in r.errors):
        r.ok(name,
              f"{len(devices)} devices, {len(dept_sens)} depts, "
              f"{len(subnet_to_dept)} subnets")
    return cfg

def check_smb_allowlist(r: Results) -> None:
    path = _CONFIG_DIR / "smb_allowlist.yaml"
    name = "smb_allowlist.yaml"
    if not path.exists():
        r.warn(name, "file missing; SMB lateral rule will flag every "
                      "backup job")
        return
    try:
        cfg = _read_yaml(path)
    except Exception as e:
        r.error(name, f"parse failed: {e}")
        return
    hosts = cfg.get("trusted_hosts") or []
    if not hosts:
        r.warn(name, "trusted_hosts is empty; see onboard_office.py")
        return
    bad = [h for h in hosts
           if not isinstance(h, dict) or not _valid_ip(h.get("ip", ""))]
    if bad:
        r.error(name, f"{len(bad)} invalid host entries")
    else:
        r.ok(name, f"{len(hosts)} trusted hosts")

def check_alert_routing(r: Results) -> None:
    path = _CONFIG_DIR / "alert_routing.json"
    name = "alert_routing.json"
    if not path.exists():
        r.error(name, "file missing; no alerts will be dispatched")
        return
    try:
        cfg = _read_json(path)
    except Exception as e:
        r.error(name, f"parse failed: {e}")
        return

    channels = cfg.get("channels", {})
    routing = cfg.get("routing", {})

    if not any(c.get("enabled") for c in channels.values()):
        r.warn(name, "no channels enabled; alerts will land in DB only")

    # If email enabled, require smtp_host + username + from + to
    email = channels.get("email", {})
    if email.get("enabled"):
        missing = [k for k in ("smtp_host", "username", "from", "to")
                   if not email.get(k)]
        if missing:
            r.error(name, f"email enabled but missing: {missing}")

    # If slack enabled, require webhook_url (env-var placeholders OK)
    slack = channels.get("slack", {})
    if slack.get("enabled"):
        wh = slack.get("webhook_url", "")
        if not wh or "YOUR" in wh.upper():
            r.error(name, "slack enabled but webhook_url is placeholder")

    # If CERT-In enabled, require contact fields
    certin = channels.get("certin", {})
    if certin.get("enabled"):
        miss = [k for k in ("org_name", "contact_email", "contact_phone")
                if not certin.get(k)]
        if miss:
            r.error(name, f"certin enabled but missing: {miss}")

    # Every severity in routing should reference known channels
    for sev, chs in routing.items():
        for ch in chs:
            if ch not in channels:
                r.error(name, f"routing[{sev}] references unknown "
                               f"channel {ch!r}")

    if not any(e.startswith(name) for e in r.errors):
        enabled = [n for n, c in channels.items() if c.get("enabled")]
        r.ok(name, f"enabled channels: {enabled or 'none'}")

def check_internal_networks(r: Results) -> None:
    path = _CONFIG_DIR / "internal_networks.yaml"
    name = "internal_networks.yaml"
    if not path.exists():
        r.warn(name, "file missing; using RFC1918 defaults only (OK for "
                      "most offices)")
        return
    try:
        cfg = _read_yaml(path)
    except Exception as e:
        r.error(name, f"parse failed: {e}")
        return
    extra = cfg.get("extra_internal") or []
    public = cfg.get("public_office_ips") or []
    for c in extra:
        try:
            ipaddress.ip_network(c, strict=False)
        except ValueError:
            r.error(name, f"bad CIDR in extra_internal: {c!r}")
    for ip in public:
        if not _valid_ip(ip):
            r.error(name, f"bad IP in public_office_ips: {ip!r}")
    if not any(e.startswith(name) for e in r.errors):
        r.ok(name, f"{len(extra)} extra CIDRs, {len(public)} public IPs")

def check_env_secrets(r: Results, alert_cfg: Dict[str, Any]) -> None:
    """If alert_routing references ${VAR} placeholders, verify the env
    actually has those variables set (either in .env or os.environ)."""
    path = _PROJECT_ROOT / ".env"
    env: Dict[str, str] = dict(os.environ)
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env.setdefault(k.strip(), v.strip().strip("'\""))

    placeholder_re = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")
    missing: List[str] = []
    name = ".env secrets"
    channels = alert_cfg.get("channels", {}) if alert_cfg else {}

    def scan(obj: Any) -> None:
        if isinstance(obj, dict):
            for v in obj.values():
                scan(v)
        elif isinstance(obj, list):
            for v in obj:
                scan(v)
        elif isinstance(obj, str):
            for m in placeholder_re.finditer(obj):
                var = m.group(1)
                if var not in env:
                    missing.append(var)

    scan(channels)
    missing = sorted(set(missing))
    if missing:
        r.error(name, f"referenced but not defined: {missing}")
    else:
        r.ok(name, "all ${VAR} placeholders resolved")

# ── Utility ────────────────────────────────────────────────────────

def _valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except (ValueError, TypeError):
        return False

# ── Main ───────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true",
                    help="Treat warnings as errors.")
    args = ap.parse_args()

    print("Sentrix pre-flight config validation")
    print(f"  project root: {_PROJECT_ROOT}")
    print()

    r = Results()
    vlan_cfg = check_vlan_config(r)
    check_identity_registry(r, vlan_cfg)
    check_smb_allowlist(r)
    alert_cfg_path = _CONFIG_DIR / "alert_routing.json"
    try:
        alert_cfg = _read_json(alert_cfg_path) if alert_cfg_path.exists() else {}
    except Exception:
        alert_cfg = {}
    check_alert_routing(r)
    check_internal_networks(r)
    check_env_secrets(r, alert_cfg)

    print(r.summary())
    print()
    print(f"  errors   : {len(r.errors)}")
    print(f"  warnings : {len(r.warnings)}")

    if r.errors:
        return 2
    if r.warnings and args.strict:
        return 2
    if r.warnings:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
