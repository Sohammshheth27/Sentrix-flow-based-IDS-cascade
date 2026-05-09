"""shared runtime state between dashboard and engine"""
from __future__ import annotations

import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

def _iso(epoch_seconds: float) -> str:
    return datetime.fromtimestamp(
        epoch_seconds, tz=timezone.utc
    ).isoformat(timespec="seconds")

DEFAULT_DB = "alerts.db"

# UEBA dormancy default; 14 days from first deployment.
# Rationale: in a real office rollout you want ML-only detection
# running for a couple of weeks before adding the behavioural layer,
# so you're not chasing false positives from an unstable UEBA baseline
# that hasn't observed enough traffic yet. At the 14-day mark UEBA
# starts building its own baselines from scratch, so there's a short
# warm-up after activation before it fires its first alerts.
DEFAULT_UEBA_DORMANT_DAYS = 14

class RuntimeStateStore:
    """
    Shared runtime state. Both sides (dashboard + engine) instantiate
    their own RuntimeStateStore pointing at the same alerts.db file.
    """

    def __init__(self, db_path: str = DEFAULT_DB, poll_seconds: float = 2.0):
        self.db_path = str(db_path)
        self.poll_seconds = poll_seconds

        # Local in-memory cache refreshed by the engine's poller.
        # Dashboard reads the DB directly; engine uses this cache in
        # the hot path to avoid a SQLite hit per flow.
        self._cache_lock = threading.RLock()
        self._whitelist: set = set()
        self._scanner_allowlist: set = set()   # authorised scan sources
        self._suppressions: Dict[tuple, float] = {}  # (ip, type) → expiry_ts
        self._config: Dict[str, str] = {}
        self._last_refresh = 0.0

        self._init_schema()

    # ── Schema init ─────────────────────────────────────────────────

    def _init_schema(self) -> None:
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS runtime_whitelist (
                    ip          TEXT PRIMARY KEY,
                    reason      TEXT,
                    added_by    TEXT,
                    added_at    TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS runtime_suppressions (
                    src_ip       TEXT NOT NULL,
                    attack_type  TEXT NOT NULL,
                    expires_at   REAL NOT NULL,
                    reason       TEXT,
                    added_by     TEXT,
                    added_at     TEXT DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (src_ip, attack_type)
                );
                CREATE TABLE IF NOT EXISTS runtime_config (
                    key         TEXT PRIMARY KEY,
                    value       TEXT NOT NULL,
                    updated_by  TEXT,
                    updated_at  TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS alert_acknowledgements (
                    alert_id     INTEGER PRIMARY KEY,
                    acked_by     TEXT,
                    acked_at     TEXT DEFAULT CURRENT_TIMESTAMP,
                    note         TEXT
                );
                CREATE TABLE IF NOT EXISTS runtime_scanner_allowlist (
                    ip          TEXT PRIMARY KEY,
                    reason      TEXT,
                    added_by    TEXT,
                    added_at    TEXT DEFAULT CURRENT_TIMESTAMP
                );
            """)
            # Seed defaults if missing.
            conn.execute(
                "INSERT OR IGNORE INTO runtime_config (key, value, updated_by) "
                "VALUES ('paused', 'false', 'init')"
            )
            conn.execute(
                "INSERT OR IGNORE INTO runtime_config (key, value, updated_by) "
                "VALUES ('ml_threshold', '0.50', 'init')"
            )
            conn.execute(
                "INSERT OR IGNORE INTO runtime_config (key, value, updated_by) "
                "VALUES ('severity_floor', 'LOW', 'init')"
            )
            # UEBA observation clock; accumulated engine uptime in
            # seconds. Starts at 0 on first run; advances via
            # tick_ueba_clock() from the engine's background tick.
            # The 14-day activation threshold is target_seconds, also
            # stored here so it can be tuned live for testing.
            conn.execute(
                "INSERT OR IGNORE INTO runtime_config "
                "(key, value, updated_by) VALUES (?, ?, 'init')",
                ("ueba_observed_seconds", "0.0"),
            )
            conn.execute(
                "INSERT OR IGNORE INTO runtime_config "
                "(key, value, updated_by) VALUES (?, ?, 'init')",
                ("ueba_target_seconds",
                  str(DEFAULT_UEBA_DORMANT_DAYS * 86400)),
            )
            conn.execute(
                "INSERT OR IGNORE INTO runtime_config "
                "(key, value, updated_by) VALUES (?, ?, 'init')",
                ("ueba_paused", "false"),
            )
            conn.execute(
                "INSERT OR IGNORE INTO runtime_config "
                "(key, value, updated_by) VALUES (?, ?, 'init')",
                ("ueba_spike_zscore", "3.0"),
            )
            conn.commit()
        finally:
            conn.close()

    # ── Engine-side cache refresh ───────────────────────────────────

    def refresh(self) -> None:
        """
        Reload all runtime tables into the in-memory cache.
        Called by the engine's poll loop.
        """
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            # Whitelist
            wl = {row[0] for row in conn.execute(
                "SELECT ip FROM runtime_whitelist"
            ).fetchall()}

            # Scanner allowlist (vuln scanners, monitoring tools, etc.)
            # Skips Rule 9 (port sweep) and Rule 10 (horizontal scan)
            # for these source IPs. Does NOT exempt them from other
            # detections; ML, UEBA, Rule 1/2/3/6 etc. still apply.
            try:
                sc = {row[0] for row in conn.execute(
                    "SELECT ip FROM runtime_scanner_allowlist"
                ).fetchall()}
            except sqlite3.OperationalError:
                sc = set()  # table may not exist on older DBs

            # Suppressions; drop expired
            now = time.time()
            sup_rows = conn.execute(
                "SELECT src_ip, attack_type, expires_at FROM runtime_suppressions"
            ).fetchall()
            sup = {(r[0], r[1]): float(r[2]) for r in sup_rows
                    if float(r[2]) > now}
            # Best-effort cleanup of expired rows (not in hot path)
            expired = [(r[0], r[1]) for r in sup_rows if float(r[2]) <= now]
            if expired:
                conn.executemany(
                    "DELETE FROM runtime_suppressions "
                    "WHERE src_ip=? AND attack_type=?",
                    expired,
                )
                conn.commit()

            # Config
            cfg = {row[0]: row[1] for row in conn.execute(
                "SELECT key, value FROM runtime_config"
            ).fetchall()}
        finally:
            conn.close()

        with self._cache_lock:
            self._whitelist = wl
            self._scanner_allowlist = sc
            self._suppressions = sup
            self._config = cfg
            self._last_refresh = time.time()

    # ── Engine-side hot-path queries (cache only) ───────────────────

    def is_whitelisted(self, ip: str) -> bool:
        if not ip:
            return False
        with self._cache_lock:
            return ip in self._whitelist

    def is_scanner(self, ip: str) -> bool:
        """Hot-path check: is this IP an authorised scanner (exempt
        from Rule 9 / Rule 10)? Does NOT short-circuit other rules."""
        if not ip:
            return False
        with self._cache_lock:
            return ip in self._scanner_allowlist

    def is_suppressed(self, src_ip: str, attack_type: str) -> bool:
        with self._cache_lock:
            exp = self._suppressions.get((src_ip, attack_type))
            if exp is None:
                return False
            return exp > time.time()

    def is_paused(self) -> bool:
        with self._cache_lock:
            return self._config.get("paused", "false").lower() == "true"

    def is_ueba_paused(self) -> bool:
        """Cache-backed pause check (hot-path safe)."""
        with self._cache_lock:
            return self._config.get("ueba_paused", "false").lower() == "true"

    def is_ueba_active(self) -> bool:
        """
        Hot-path check: has UEBA accumulated enough observed
        engine-uptime to exit the learning phase?
        Cache-backed; safe to call per flow without hitting SQLite.
        """
        with self._cache_lock:
            observed_raw = self._config.get("ueba_observed_seconds", "0")
            target_raw = self._config.get("ueba_target_seconds",
                                            str(DEFAULT_UEBA_DORMANT_DAYS * 86400))
        try:
            return float(observed_raw) >= float(target_raw)
        except (TypeError, ValueError):
            return False

    def get_ueba_status(self) -> Dict:
        """
        Full UEBA status for dashboard consumption.

        Returns:
            observed_seconds ; cumulative observed engine uptime
            target_seconds   ; activation threshold (14 days by default)
            active           ; observed >= target
            paused           ; clock is frozen at the dashboard's request
            progress_pct     ; 100 * observed / target, clamped
            seconds_remaining; max(0, target - observed)
        """
        with self._cache_lock:
            observed_raw = self._config.get("ueba_observed_seconds", "0")
            target_raw = self._config.get("ueba_target_seconds",
                                            str(DEFAULT_UEBA_DORMANT_DAYS * 86400))
            paused_raw = self._config.get("ueba_paused", "false")
        try:
            observed = float(observed_raw)
        except (TypeError, ValueError):
            observed = 0.0
        try:
            target = float(target_raw)
        except (TypeError, ValueError):
            target = DEFAULT_UEBA_DORMANT_DAYS * 86400
        paused = paused_raw.lower() == "true"
        progress = 0.0 if target <= 0 else min(100.0, 100.0 * observed / target)
        remaining = max(0.0, target - observed)
        return {
            "observed_seconds": observed,
            "target_seconds":   target,
            "active":           observed >= target,
            "paused":           paused,
            "progress_pct":     round(progress, 2),
            "seconds_remaining": remaining,
        }

    def get_config(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._cache_lock:
            return self._config.get(key, default)

    def get_float(self, key: str, default: float) -> float:
        v = self.get_config(key)
        try:
            return float(v) if v is not None else default
        except (ValueError, TypeError):
            return default

    # ── Dashboard-side mutations (direct DB writes) ─────────────────

    def add_whitelist(self, ip: str, reason: str = "", added_by: str = "dashboard") -> None:
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO runtime_whitelist (ip, reason, added_by) "
                "VALUES (?, ?, ?)",
                (ip, reason, added_by),
            )
            conn.commit()
        finally:
            conn.close()

    def remove_whitelist(self, ip: str) -> None:
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            conn.execute("DELETE FROM runtime_whitelist WHERE ip = ?", (ip,))
            conn.commit()
        finally:
            conn.close()

    def list_whitelist(self) -> List[Dict]:
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            rows = conn.execute(
                "SELECT ip, reason, added_by, added_at "
                "FROM runtime_whitelist ORDER BY added_at DESC"
            ).fetchall()
        finally:
            conn.close()
        return [
            {"ip": r[0], "reason": r[1], "added_by": r[2], "added_at": r[3]}
            for r in rows
        ]

    # ── Scanner allowlist mutations ─────────────────────────────────

    def add_scanner(self, ip: str, reason: str = "",
                    added_by: str = "dashboard") -> None:
        """Register an IP as an authorised scanner (exempt from Rule 9/10)."""
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO runtime_scanner_allowlist "
                "(ip, reason, added_by) VALUES (?, ?, ?)",
                (ip, reason, added_by),
            )
            conn.commit()
        finally:
            conn.close()

    def remove_scanner(self, ip: str) -> None:
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            conn.execute(
                "DELETE FROM runtime_scanner_allowlist WHERE ip = ?",
                (ip,),
            )
            conn.commit()
        finally:
            conn.close()

    def list_scanners(self) -> List[Dict]:
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            rows = conn.execute(
                "SELECT ip, reason, added_by, added_at "
                "FROM runtime_scanner_allowlist ORDER BY added_at DESC"
            ).fetchall()
        finally:
            conn.close()
        return [
            {"ip": r[0], "reason": r[1], "added_by": r[2], "added_at": r[3]}
            for r in rows
        ]

    def add_suppression(self, src_ip: str, attack_type: str,
                         ttl_seconds: int, reason: str = "",
                         added_by: str = "dashboard") -> None:
        expires = time.time() + max(1, int(ttl_seconds))
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO runtime_suppressions "
                "(src_ip, attack_type, expires_at, reason, added_by) "
                "VALUES (?, ?, ?, ?, ?)",
                (src_ip, attack_type, expires, reason, added_by),
            )
            conn.commit()
        finally:
            conn.close()

    def set_config(self, key: str, value: str, updated_by: str = "dashboard") -> None:
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO runtime_config (key, value, updated_by) "
                "VALUES (?, ?, ?)",
                (key, str(value), updated_by),
            )
            conn.commit()
        finally:
            conn.close()

    def get_all_config(self) -> Dict[str, str]:
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            rows = conn.execute(
                "SELECT key, value FROM runtime_config"
            ).fetchall()
        finally:
            conn.close()
        return {r[0]: r[1] for r in rows}

    def tick_ueba_clock(self, delta_seconds: float) -> float:
        """
        Advance the UEBA observation clock by `delta_seconds`.
        Called from the engine's background tick thread. No-op when
        paused. Returns the new observed_seconds value.
        """
        if delta_seconds <= 0:
            return float(self._config.get("ueba_observed_seconds", 0) or 0)
        if self.is_ueba_paused():
            return float(self._config.get("ueba_observed_seconds", 0) or 0)

        # Read current, add delta, write back. Use DB read to avoid
        # racing with another tick reader (cache may be stale).
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            row = conn.execute(
                "SELECT value FROM runtime_config WHERE key = ?",
                ("ueba_observed_seconds",),
            ).fetchone()
            cur = float(row[0]) if row else 0.0
            new = cur + float(delta_seconds)
            conn.execute(
                "INSERT OR REPLACE INTO runtime_config "
                "(key, value, updated_by) VALUES (?, ?, 'engine-tick')",
                ("ueba_observed_seconds", f"{new:.3f}"),
            )
            conn.commit()
        finally:
            conn.close()

        # Update cache so is_ueba_active() reflects the new value.
        with self._cache_lock:
            self._config["ueba_observed_seconds"] = f"{new:.3f}"
        return new

    def pause_ueba(self, by: str = "dashboard") -> None:
        self.set_config("ueba_paused", "true", updated_by=by)
        self.refresh()

    def resume_ueba(self, by: str = "dashboard") -> None:
        self.set_config("ueba_paused", "false", updated_by=by)
        self.refresh()

    def reset_ueba_clock(
        self,
        by: str = "dashboard",
        ueba_instance=None,
    ) -> Dict:
        """
        Reset the UEBA observation clock back to zero AND wipe all
        learned baselines on the passed UEBA instance (if provided).
        This is the "start over" button.
        """
        self.set_config("ueba_observed_seconds", "0.0", updated_by=by)
        self.set_config("ueba_paused", "false", updated_by=by)
        self.refresh()
        if ueba_instance is not None:
            try:
                ueba_instance.reset_baselines()
            except Exception:
                pass
        return self.get_ueba_status()

    def activate_ueba_now(self, by: str = "dashboard") -> Dict:
        """
        Force UEBA active immediately by pushing observed_seconds
        past target_seconds. Used for SOC override and testing.
        Learning baselines are NOT wiped (contrast with reset).
        """
        status = self.get_ueba_status()
        self.set_config(
            "ueba_observed_seconds",
            f"{status['target_seconds']:.3f}",
            updated_by=by,
        )
        self.refresh()
        return self.get_ueba_status()

    def ack_alert(self, alert_id: int, note: str = "",
                   acked_by: str = "dashboard") -> None:
        conn = sqlite3.connect(self.db_path, timeout=5)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO alert_acknowledgements "
                "(alert_id, acked_by, note) VALUES (?, ?, ?)",
                (alert_id, acked_by, note),
            )
            conn.commit()
        finally:
            conn.close()

    # ── Background refresher ────────────────────────────────────────

    def start_refresher(self) -> threading.Thread:
        """
        Start a daemon thread that calls refresh() every poll_seconds.
        Engine should call this once at startup.
        """
        def _loop():
            while True:
                try:
                    self.refresh()
                except Exception as exc:
                    import logging
                    logging.getLogger("runtime_state").warning(
                        f"refresh failed: {exc}"
                    )
                time.sleep(self.poll_seconds)

        t = threading.Thread(target=_loop, daemon=True, name="runtime-state-refresh")
        t.start()
        return t
