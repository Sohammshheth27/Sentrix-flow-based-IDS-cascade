"""Digital Personal Data Protection Act (2023) controls."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("dpdpa")

DEFAULT_PSEUDONYMIZE_AFTER_DAYS = 90
DEFAULT_PURGE_AFTER_DAYS = 365
DEFAULT_FLOW_RETENTION_DAYS = 30

class DPDPACompliance:

    def __init__(self, db_path: str = "alerts.db",
                 pseudonymize_after_days: int = DEFAULT_PSEUDONYMIZE_AFTER_DAYS,
                 purge_after_days: int = DEFAULT_PURGE_AFTER_DAYS):
        self.db_path = db_path
        self.pseudonymize_after = pseudonymize_after_days
        self.purge_after = purge_after_days

        salt_path = Path(db_path).parent / ".dpdpa_salt"
        if salt_path.exists():
            self._salt = salt_path.read_bytes()
        else:
            self._salt = os.urandom(32)
            salt_path.write_bytes(self._salt)
            log.info("DPDPA: generated new per-instance salt")

        self._ensure_columns()

    def _ensure_columns(self) -> None:
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.execute("PRAGMA table_info(alerts)")
            cols = {row[1] for row in cur.fetchall()}
            if "src_ip_pseudo" not in cols:
                conn.execute("ALTER TABLE alerts ADD COLUMN src_ip_pseudo TEXT DEFAULT ''")
            if "dst_ip_pseudo" not in cols:
                conn.execute("ALTER TABLE alerts ADD COLUMN dst_ip_pseudo TEXT DEFAULT ''")
            if "ip_pseudonymized" not in cols:
                conn.execute("ALTER TABLE alerts ADD COLUMN ip_pseudonymized INTEGER DEFAULT 0")
            conn.commit()
            conn.close()
        except Exception as e:
            log.warning(f"DPDPA: column setup failed: {e}")

    def _hash_ip(self, ip: str) -> str:
        return hashlib.sha256(self._salt + ip.encode("utf-8")).hexdigest()[:16]

    def pseudonymize_old_alerts(self) -> int:
        cutoff = (datetime.utcnow() - timedelta(days=self.pseudonymize_after)).isoformat()
        try:
            conn = sqlite3.connect(self.db_path)
            rows = conn.execute(
                "SELECT id, src_ip, dst_ip FROM alerts "
                "WHERE ip_pseudonymized = 0 AND timestamp < ?", (cutoff,)
            ).fetchall()
            count = 0
            for row_id, src_ip, dst_ip in rows:
                src_pseudo = self._hash_ip(src_ip or "")
                dst_pseudo = self._hash_ip(dst_ip or "")
                conn.execute(
                    "UPDATE alerts SET src_ip = ?, dst_ip = ?, "
                    "src_ip_pseudo = ?, dst_ip_pseudo = ?, "
                    "ip_pseudonymized = 1 WHERE id = ?",
                    (src_pseudo, dst_pseudo, src_pseudo, dst_pseudo, row_id))
                count += 1
            conn.commit()
            conn.close()
            if count:
                log.info(f"DPDPA: pseudonymized {count} alerts older than "
                         f"{self.pseudonymize_after} days")
            return count
        except Exception as e:
            log.error(f"DPDPA pseudonymization failed: {e}")
            return 0

    def purge_old_alerts(self) -> int:
        cutoff = (datetime.utcnow() - timedelta(days=self.purge_after)).isoformat()
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
            count = cur.rowcount
            conn.commit()
            conn.close()
            if count:
                log.info(f"DPDPA: purged {count} alerts older than {self.purge_after} days")
            return count
        except Exception as e:
            log.error(f"DPDPA purge failed: {e}")
            return 0

    def run_maintenance(self) -> Dict[str, int]:
        pseudo = self.pseudonymize_old_alerts()
        purged = self.purge_old_alerts()
        return {"pseudonymized": pseudo, "purged": purged}

    def export_data_subject(self, ip: str) -> List[Dict]:
        ip_hash = self._hash_ip(ip)
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM alerts WHERE src_ip = ? OR dst_ip = ? "
                "OR src_ip_pseudo = ? OR dst_ip_pseudo = ?",
                (ip, ip, ip_hash, ip_hash)
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            log.error(f"DPDPA export failed: {e}")
            return []

    def delete_data_subject(self, ip: str) -> int:
        ip_hash = self._hash_ip(ip)
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.execute(
                "DELETE FROM alerts WHERE src_ip = ? OR dst_ip = ? "
                "OR src_ip_pseudo = ? OR dst_ip_pseudo = ?",
                (ip, ip, ip_hash, ip_hash))
            count = cur.rowcount
            conn.commit()
            conn.close()
            log.info(f"DPDPA: deleted {count} alerts for data subject {ip}")
            return count
        except Exception as e:
            log.error(f"DPDPA delete failed: {e}")
            return 0
