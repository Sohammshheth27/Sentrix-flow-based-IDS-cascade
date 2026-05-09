#!/usr/bin/env python3
"""
seed_devices.py; ARP-scan the local subnet and seed device_classifications.

The live DeviceClassifier only sees IPs that appear in Zeek flows. On a
switched LAN the VM never sees unicast traffic between other hosts, so
silent neighbours (router, sleeping phones, printers) are invisible to
the engine and the dashboard shows an empty inventory.

This script closes that gap without changing live-path logic:
  1. Runs arp-scan --localnet; every host on the /24 that responds to
     ARP replies within the timeout. This includes phones, which MUST
     answer ARP to keep their Wi-Fi lease.
  2. For each (ip, mac) pair, INSERT OR IGNORE into
     alerts.db:device_classifications. Existing rows (written by the
     engine from real observations) are preserved untouched.
  3. Prints a short summary (added / already-known).

Designed to be:
  - Idempotent; safe to run repeatedly.
  - Non-destructive; never overwrites engine-observed state.
  - Filtered; respects ip_classifier.is_internal() so a misconfigured
    broadcast on a public subnet can't pollute the registry.

Usage:  sudo python3 scripts/seed_devices.py [--loop SECONDS]
"""
from __future__ import annotations

import argparse
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
ALERTS_DB = PROJECT / "alerts.db"

sys.path.insert(0, str(PROJECT / "src"))
try:
    from ip_classifier import get_classifier  # type: ignore
except Exception:
    get_classifier = None  # fallback: accept every RFC1918

ARP_LINE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f:]{17})\s*(.*)$",
    re.IGNORECASE,
)

def run_arp_scan() -> list[tuple[str, str, str]]:
    try:
        out = subprocess.run(
            ["sudo", "-n", "arp-scan", "--localnet",
             "--retry=3", "--timeout=500", "--ignoredups"],
            capture_output=True, text=True, timeout=20,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[seed_devices] arp-scan failed: {e}", file=sys.stderr)
        return []

    hosts: list[tuple[str, str, str]] = []
    for line in out.stdout.splitlines():
        m = ARP_LINE.match(line.strip())
        if m:
            ip, mac, vendor = m.group(1), m.group(2).lower(), m.group(3).strip()
            hosts.append((ip, mac, vendor))
    return hosts

def seed(conn: sqlite3.Connection, hosts: list[tuple[str, str, str]]) -> tuple[int, int, int]:
    classifier = get_classifier() if get_classifier else None
    now = time.time()
    added = skipped_existing = skipped_external = 0

    for ip, mac, vendor in hosts:
        if classifier and not classifier.is_internal(ip):
            skipped_external += 1
            continue
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO device_classifications
                (ip, device_class, vendor, model_hint, os_hint,
                 confidence, sources, class_scores, flow_count,
                 observed_ports, first_seen, last_updated)
            VALUES (?, 'unknown', ?, '', '', 0.0, 'arp-scan', '{}', 0,
                    '{}', ?, ?)
            """,
            (ip, vendor or "", now, now),
        )
        if cur.rowcount:
            added += 1
        else:
            skipped_existing += 1

    conn.commit()
    return added, skipped_existing, skipped_external

def one_pass() -> None:
    hosts = run_arp_scan()
    if not hosts:
        print("[seed_devices] no hosts found")
        return
    conn = sqlite3.connect(str(ALERTS_DB), timeout=5)
    try:
        added, existing, external = seed(conn, hosts)
    finally:
        conn.close()
    print(
        f"[seed_devices] discovered={len(hosts)} "
        f"added={added} already_present={existing} "
        f"skipped_external={external}"
    )

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", type=int, default=0,
                    help="run every N seconds (0 = single pass)")
    args = ap.parse_args()

    if args.loop <= 0:
        one_pass()
        return 0

    while True:
        try:
            one_pass()
        except Exception as e:
            print(f"[seed_devices] error: {e}", file=sys.stderr)
        time.sleep(args.loop)

if __name__ == "__main__":
    sys.exit(main())
