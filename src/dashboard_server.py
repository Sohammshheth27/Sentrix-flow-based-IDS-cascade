"""dashboard_server.py"""
import os
import sys
import io
import json
import time
import sqlite3
import asyncio
import ipaddress
import threading

# Fix Windows console encoding for emoji/unicode characters
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
from datetime   import datetime, timedelta
from typing     import Dict, List, Optional, Set
from collections import defaultdict

from pathlib import Path

# Sentrix helpers (in same src/ directory)
try:
    from mitre_mapping import ATTACK_TYPE_TO_MITRE, TACTICS, tactics_for
except ImportError:
    ATTACK_TYPE_TO_MITRE, TACTICS, tactics_for = {}, [], lambda x: []

import uvicorn
from fastapi              import FastAPI, Request, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses    import FileResponse, HTMLResponse

# ── Project root (sentrix/) ────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ── Config ────────────────────────────────────────────────────

ALERTS_DB      = "alerts.db"
UEBA_DB        = "ueba_state.db"
KNOWN_DEVICES_DB = "known_devices.db"
# Resolve VLAN config path absolutely so the dashboard finds it regardless
# of which directory it was started from. Looks under config/ first (the
# layout used by the engine + ad_sync), then falls back to a sibling file.
_DASHBOARD_DIR  = os.path.dirname(os.path.abspath(__file__))
_DASHBOARD_PARENT = os.path.abspath(os.path.join(_DASHBOARD_DIR, ".."))
_VLAN_CANDIDATES = [
    os.path.join(_DASHBOARD_PARENT, "config", "vlan_config.json"),
    os.path.join(_DASHBOARD_PARENT, "vlan_config.json"),
    os.path.join(_DASHBOARD_DIR, "vlan_config.json"),
]
VLAN_CONFIG = next((p for p in _VLAN_CANDIDATES if os.path.exists(p)),
                   _VLAN_CANDIDATES[0])
POLL_INTERVAL  = 2.0    # seconds between DB polls (was 0.5; too fast for large DBs)
HOST           = "0.0.0.0"
PORT           = 8080

# ── Load VLAN config ──────────────────────────────────────────

def load_vlan_config() -> dict:
    try:
        with open(VLAN_CONFIG, encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        # No vlan_config.json - ship EMPTY. The office admin must
        # populate config/vlan_config.json with their real subnet ->
        # department mapping. Without it, devices appear with empty
        # department / "unmapped" priority. This is intentional: no
        # hardcoded subnet defaults that imply a network topology.
        print(f"[Dashboard] WARNING: {VLAN_CONFIG} not found - "
              f"VLAN map is EMPTY. Devices will have no department "
              f"assignment until the admin creates this file.")
        # Catch-all entry; used only when the admin-supplied vlan_config.json
        # isn't on disk yet. department="" is read by the front-end as "no
        # mapping yet"; the UI displays ":" rather than "?". Color is a
        # neutral grey that's distinguishable from any colour an admin
        # would actually assign.
        return {
            "vlan_map": {
                "99": {
                    "department": "",
                    "priority": "unmapped",
                    "color": "#6b7280",
                    "subnet": "0.0.0.0/0",
                    "icon": ""
                }
            },
            "priority_rank": {"critical":0,"high":1,"medium":2,"low":3,"unmapped":4}
        }

VLAN_CFG = load_vlan_config()

# ── IP → Department mapping ───────────────────────────────────

def get_department_for_ip(ip: str) -> dict:
    """Map an IP address to its department via subnet matching."""
    if not ip:
        return VLAN_CFG["vlan_map"]["99"]
    try:
        addr = ipaddress.ip_address(ip)
        # Match against configured subnets (skip the catch-all 0.0.0.0/0)
        for vlan_id, info in VLAN_CFG["vlan_map"].items():
            if vlan_id == "99":
                continue
            try:
                if addr in ipaddress.ip_network(info["subnet"], strict=False):
                    return {**info, "vlan": vlan_id}
            except:
                continue
    except:
        pass
    return {**VLAN_CFG["vlan_map"]["99"], "vlan": "99"}

# ── Known Device Registry ─────────────────────────────────────

class DeviceRegistry:
    """
    Tracks every IP address ever seen.
    When a new IP appears, fires a new_device notification.
    Persists to SQLite so it survives restarts.
    """

    def __init__(self, db_path: str = KNOWN_DEVICES_DB):
        self.db_path = db_path
        self._known  : Dict[str, dict] = {}
        self._lock   = threading.Lock()
        # IP classifier; skip registration for public IPs. Without this
        # the registry fills up with Google, Cloudflare, YouTube CDN
        # endpoints every time an office device talks to the internet.
        try:
            from ip_classifier import get_classifier
            self._ip_classifier = get_classifier()
        except Exception as e:
            print(f"[Registry] Failed to load ip_classifier: {e}")
            self._ip_classifier = None
        self._external_skipped = 0
        self._init_db()
        self._load_existing()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS known_devices (
                ip           TEXT PRIMARY KEY,
                first_seen   TEXT NOT NULL,
                last_seen    TEXT NOT NULL,
                department   TEXT,
                priority     TEXT,
                alert_count  INTEGER DEFAULT 0,
                risk_score   REAL DEFAULT 0.0,
                hostname     TEXT DEFAULT '',
                mac_address  TEXT DEFAULT ''
            )
        """)
        conn.commit()
        conn.close()

    def _load_existing(self):
        try:
            conn = sqlite3.connect(self.db_path)
            rows = conn.execute(
                "SELECT ip, first_seen, last_seen, department, "
                "priority, alert_count, risk_score FROM known_devices"
            ).fetchall()
            conn.close()
            loaded = 0
            purged = 0
            purge_ips: List[str] = []
            for row in rows:
                ip = row[0]
                # Defense-in-depth: filter public IPs on load too, so
                # a restored DB or migrated state doesn't re-pollute
                # the Known Devices panel with Google/Cloudflare/AWS.
                if self._ip_classifier is not None and \
                        self._ip_classifier.is_external(ip):
                    purge_ips.append(ip)
                    purged += 1
                    continue
                self._known[ip] = {
                    "ip":          ip,
                    "first_seen":  row[1],
                    "last_seen":   row[2],
                    "department":  row[3],
                    "priority":    row[4],
                    "alert_count": row[5],
                    "risk_score":  row[6],
                    "is_new":      False,
                }
                loaded += 1
            # If we found stale public IPs in the DB, purge them so
            # the cleanup is persistent (survives restarts without
            # needing a manual rm of known_devices.db).
            if purge_ips:
                try:
                    conn = sqlite3.connect(self.db_path, timeout=5)
                    conn.executemany(
                        "DELETE FROM known_devices WHERE ip = ?",
                        [(ip,) for ip in purge_ips]
                    )
                    conn.commit()
                    conn.close()
                except Exception as e:
                    print(f"[Registry] DB purge error: {e}")
            print(f"[Registry] Loaded {loaded} known devices "
                  f"(purged {purged} stale public IPs)")
        except Exception as e:
            print(f"[Registry] Load error: {e}")

    def check_and_register(self, ip: str,
                           alert_count_delta: int = 0,
                           risk_score: float = 0.0) -> Optional[dict]:
        """
        Check if IP is new. If new, register and return device dict.
        If existing, update stats and return None.
        Returns the new device dict if this is a first-time sighting.

        External (public) IPs are silently skipped; they are not
        office devices and must not appear in the Known Devices panel
        or known_devices.db.
        """
        if not ip:
            return None

        # Public-IP filter: Cloudflare, Google, YouTube CDNs, etc.
        if self._ip_classifier is not None and \
                self._ip_classifier.is_external(ip):
            self._external_skipped += 1
            return None

        dept_info = get_department_for_ip(ip)
        now_str   = datetime.now().isoformat()

        with self._lock:
            if ip not in self._known:
                # NEW DEVICE
                device = {
                    "ip"         : ip,
                    "first_seen" : now_str,
                    "last_seen"  : now_str,
                    "department" : dept_info["department"],
                    "priority"   : dept_info["priority"],
                    "alert_count": alert_count_delta,
                    "risk_score" : risk_score,
                    "is_new"     : True,
                    "color"      : dept_info.get("color", "#6b7280"),
                    "icon"       : dept_info.get("icon", "🖥️"),
                }
                self._known[ip] = device

                # Persist
                try:
                    conn = sqlite3.connect(self.db_path, timeout=5)
                    conn.execute("""
                        INSERT OR REPLACE INTO known_devices
                        (ip, first_seen, last_seen, department,
                         priority, alert_count, risk_score)
                        VALUES (?,?,?,?,?,?,?)
                    """, (ip, now_str, now_str,
                          dept_info["department"],
                          dept_info["priority"],
                          alert_count_delta, risk_score))
                    conn.commit()
                    conn.close()
                except:
                    pass

                print(f"[Registry] 🆕 New device: {ip} "
                      f"({dept_info['department']})")
                return device

            else:
                # Existing device; update stats
                self._known[ip]["last_seen"]   = now_str
                self._known[ip]["alert_count"] += alert_count_delta
                if risk_score > self._known[ip]["risk_score"]:
                    self._known[ip]["risk_score"] = risk_score
                return None

    def get_all(self) -> List[dict]:
        with self._lock:
            return list(self._known.values())

    def get_device(self, ip: str) -> Optional[dict]:
        with self._lock:
            return self._known.get(ip)

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._known)

# ── WebSocket Manager ─────────────────────────────────────────

class ConnectionManager:
    """Manages all active WebSocket connections."""

    def __init__(self):
        self._connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._connections.append(ws)
        print(f"[WS] Client connected; "
              f"{len(self._connections)} total")

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            if ws in self._connections:
                self._connections.remove(ws)
        print(f"[WS] Client disconnected; "
              f"{len(self._connections)} remaining")

    async def broadcast(self, message: dict):
        """Send message to all connected clients."""
        if not self._connections:
            return
        data = json.dumps(message)
        dead = []
        async with self._lock:
            clients = list(self._connections)
        for ws in clients:
            try:
                await ws.send_text(data)
            except:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(ws)

    @property
    def count(self) -> int:
        return len(self._connections)

# ── Alert Watcher ─────────────────────────────────────────────

class AlertWatcher:
    """
    Polls alerts.db for new rows every POLL_INTERVAL seconds.
    When new alerts are found:
      1. Checks each src_ip against DeviceRegistry
      2. Broadcasts new_device if first-time IP
      3. Broadcasts new_alert for the alert itself
      4. Broadcasts department_update with new stats
    """

    def __init__(self, registry: DeviceRegistry,
                 manager: ConnectionManager):
        self.registry  = registry
        self.manager   = manager
        self._last_id  = self._get_max_id()
        self._dept_stats: Dict[str, dict] = {}
        print(f"[Watcher] Starting from alert ID {self._last_id}")

    def _get_max_id(self) -> int:
        try:
            conn = sqlite3.connect(ALERTS_DB, timeout=5)
            conn.execute("PRAGMA journal_mode=WAL")
            row  = conn.execute(
                "SELECT MAX(id) FROM alerts"
            ).fetchone()
            conn.close()
            return row[0] or 0
        except:
            return 0

    def _get_new_alerts(self) -> List[dict]:
        try:
            conn = sqlite3.connect(ALERTS_DB, timeout=5)
            conn.execute("PRAGMA journal_mode=WAL")
            rows = conn.execute("""
                SELECT id, timestamp, severity, final_score,
                       ml_score, ueba_score, rule_score,
                       attack_type, src_ip, dst_ip, dst_port,
                       ueba_reasons, rule_names, correlated,
                       actual_label
                FROM alerts
                WHERE id > ?
                ORDER BY id ASC
                LIMIT 100
            """, (self._last_id,)).fetchall()
            conn.close()
            alerts = []
            for row in rows:
                dept = get_department_for_ip(row[8] or "")
                alerts.append({
                    "id"          : row[0],
                    "timestamp"   : row[1],
                    "severity"    : row[2],
                    "final_score" : row[3],
                    "ml_score"    : row[4],
                    "ueba_score"  : row[5],
                    "rule_score"  : row[6],
                    "attack_type" : row[7],
                    "src_ip"      : row[8],
                    "dst_ip"      : row[9],
                    "dst_port"    : row[10],
                    "ueba_reasons": json.loads(row[11] or "[]"),
                    "rule_names"  : json.loads(row[12] or "[]"),
                    "correlated"  : bool(row[13]),
                    "actual_label": row[14],
                    "department"  : dept["department"],
                    "priority"    : dept["priority"],
                    "color"       : dept.get("color","#6b7280"),
                })
            return alerts
        except Exception as e:
            return []

    async def poll(self):
        """Main polling loop; call from asyncio task."""
        while True:
            try:
                await self._check_for_new()
            except Exception as e:
                pass
            await asyncio.sleep(POLL_INTERVAL)

    async def _check_for_new(self):
        new_alerts = self._get_new_alerts()
        if not new_alerts:
            return

        self._last_id = new_alerts[-1]["id"]
        dept_updates  = set()

        for alert in new_alerts:
            src_ip = alert.get("src_ip", "")

            # Check for new device
            new_device = self.registry.check_and_register(
                src_ip,
                alert_count_delta = 1,
                risk_score        = alert["final_score"] * 100
            )

            if new_device:
                await self.manager.broadcast({
                    "type"   : "new_device",
                    "device" : new_device,
                    "alert"  : alert,
                })

            # Broadcast the alert
            await self.manager.broadcast({
                "type" : "new_alert",
                "alert": alert,
            })

            dept_updates.add(alert["department"])

        # Broadcast department stat updates
        for dept_name in dept_updates:
            stats = self._compute_dept_stats(dept_name)
            await self.manager.broadcast({
                "type"       : "department_update",
                "department" : dept_name,
                "data"       : stats,
            })

    def _compute_dept_stats(self, dept_name: str) -> dict:
        """Compute current stats for one department; optimized."""
        try:
            conn = sqlite3.connect(ALERTS_DB, timeout=5)
            conn.execute("PRAGMA journal_mode=WAL")

            # Use id-based range for speed on large DBs
            max_id = conn.execute("SELECT MAX(id) FROM alerts").fetchone()[0] or 0
            cutoff_id = max(0, max_id - 5000)  # last ~5K alerts for dept stats
            rows  = conn.execute("""
                SELECT severity, COUNT(*), MAX(final_score)
                FROM alerts
                WHERE id > ?
                GROUP BY severity
            """, (cutoff_id,)).fetchall()
            conn.close()

            counts   = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
            max_score = 0.0
            for row in rows:
                counts[row[0]] = counts.get(row[0], 0) + row[1]
                if row[2] > max_score:
                    max_score = row[2]

            total = sum(counts.values())
            return {
                "alert_count"    : total,
                "critical_count" : counts["CRITICAL"],
                "high_count"     : counts["HIGH"],
                "risk_score"     : round(max_score * 100, 1),
            }
        except:
            return {"alert_count":0,"critical_count":0,
                    "high_count":0,"risk_score":0.0}

# ── FastAPI App ───────────────────────────────────────────────

from contextlib import asynccontextmanager

# ── Optimize alerts.db at startup ─────────────────────────────
def _optimize_alerts_db():
    """Set WAL mode and add missing indexes for large DBs."""
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA cache_size=-16000")  # 16MB cache
        # Index for the poll query (WHERE id > ?)
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_id_sev ON alerts(id, severity)")
        except:
            pass
        row = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
        print(f"[Dashboard] alerts.db: {row[0]:,} rows, WAL mode enabled")
        conn.close()
    except Exception as e:
        print(f"[Dashboard] DB optimize warning: {e}")

_optimize_alerts_db()

registry = DeviceRegistry()
manager  = ConnectionManager()
watcher  = None

@asynccontextmanager
async def lifespan(app):
    global watcher
    watcher = AlertWatcher(registry, manager)
    asyncio.create_task(watcher.poll())
    asyncio.create_task(heartbeat_loop())
    print(f"[Dashboard] Server started on http://{HOST}:{PORT}")
    print(f"[Dashboard] WebSocket on ws://{HOST}:{PORT}/ws")
    yield

app = FastAPI(title="Sentrix SOC Dashboard", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

async def heartbeat_loop():
    """Send heartbeat to all clients every 10 seconds."""
    while True:
        await asyncio.sleep(10)
        if manager.count > 0:
            await manager.broadcast({
                "type"      : "heartbeat",
                "timestamp" : datetime.now().isoformat(),
                "clients"   : manager.count,
                "devices"   : registry.count,
            })

# ── REST Endpoints ────────────────────────────────────────────

@app.get("/api/departments")
async def get_departments():
    """Return all live devices grouped by department, with hostname /
    vendor / OS / device_type joined from known_devices.db. Sources its
    device list from the same path the Devices tab uses
    (_fetch_device_classifications), so the two stay consistent. The
    in-memory registry was diverging from the live alerts.db device
    inventory and skipping recently-seen devices."""
    rank = VLAN_CFG.get("priority_rank",
                         {"critical":0,"high":1,"medium":2,"low":3,"unmapped":4})

    # Same query the Devices tab uses; already joined with hostname etc.
    devices = _fetch_device_classifications()

    # Group by department, deriving every per-dept attribute from VLAN_CFG
    # (no hardcoded names / colours / icons in the response shape).
    depts: Dict[str, dict] = {}
    for dev in devices:
        ip = dev.get("ip") or ""
        # IP-based VLAN lookup is authoritative; if it returns dept="",
        # the IP doesn't fit any configured subnet and we group as
        # "Unmapped" (label only, not a fake VLAN entry).
        dept_info  = get_department_for_ip(ip)
        dept_name  = dept_info.get("department", "") or dev.get("department") or ""
        # Stable bucket key; empty department maps to a pseudo-bucket so
        # the front-end can render an "Unmapped" card without it being a
        # configured VLAN.
        bucket_key = dept_name or "__unmapped__"
        if bucket_key not in depts:
            depts[bucket_key] = {
                "department"   : dept_name or "Unmapped",
                "priority"     : dept_info.get("priority", "unmapped"),
                "color"        : dept_info.get("color", "#6b7280"),
                "icon"         : dept_info.get("icon", ""),
                "subnet"       : dept_info.get("subnet", ""),
                "vlan"         : dept_info.get("vlan", ""),
                "devices"      : [],
                "alert_count"  : 0,
                "risk_score"   : 0.0,
                "device_count" : 0,
            }
        depts[bucket_key]["devices"].append(dev)
        depts[bucket_key]["alert_count"] += dev.get("alert_count", 0)
        risk = dev.get("risk_score", 0) or 0
        if risk > depts[bucket_key]["risk_score"]:
            depts[bucket_key]["risk_score"] = risk
        depts[bucket_key]["device_count"] += 1

    sorted_depts = sorted(
        depts.values(),
        key=lambda d: (rank.get(d["priority"], 99), -d["risk_score"])
    )
    return {"departments": sorted_depts}

@app.get("/api/alerts/recent")
async def get_recent_alerts(
    limit: int = 50,
    severity: str = "",
    from_: str = Query("", alias="from"),   # ISO lower bound
    to: str = "",                             # ISO upper bound
):
    """
    Return recent alerts, optionally filtered by severity AND/OR a
    time window.

    final_score is computed as max(ml_score, ueba_score, rule_score,
    eta_score) since the alert_dispatch schema does not carry a
    separate final_score column. Similarly, correlated is derived from
    the reasons field and rule_names is parsed from reasons.

    Query params:
      limit    - max rows returned (default 50)
      severity - optional severity filter (CRITICAL/HIGH/MEDIUM/LOW)
      from     - ISO timestamp lower bound (inclusive)
      to       - ISO timestamp upper bound (exclusive)
    """
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        base_cols = """
            id, timestamp, severity,
            ml_score, ueba_score, rule_score, eta_score,
            attack_type, src_ip, dst_ip, dst_port,
            tag, reasons, confidence
        """
        # Build dynamic WHERE clause based on which filters are set.
        where = []
        params: List = []
        if severity:
            where.append("severity = ?")
            params.append(severity.upper())
        if from_:
            where.append("timestamp >= ?")
            params.append(from_)
        if to:
            where.append("timestamp < ?")
            params.append(to)
        where_sql = (" WHERE " + " AND ".join(where)) if where else ""
        params.append(limit)
        rows = conn.execute(
            f"SELECT {base_cols} FROM alerts{where_sql} "
            f"ORDER BY id DESC LIMIT ?",
            tuple(params),
        ).fetchall()
        conn.close()

        alerts = []
        for row in rows:
            (rid, ts, sev, mlsc, uebasc, rulesc, etasc,
             atype, sip, dip, dport, tag, reasons_json, conf) = row
            ml_s = float(mlsc or 0); ue_s = float(uebasc or 0)
            ru_s = float(rulesc or 0); et_s = float(etasc or 0)
            final_score = max(ml_s, ue_s, ru_s, et_s)
            try:
                reasons_list = json.loads(reasons_json or "[]")
            except Exception:
                reasons_list = []
            rule_names = [r for r in reasons_list
                           if isinstance(r, str) and r.startswith("Rule:")]
            dept = get_department_for_ip(sip or "")
            alerts.append({
                "id"         : rid,
                "timestamp"  : ts,
                "severity"   : sev,
                "final_score": round(final_score, 4),
                "ml_score"   : round(ml_s, 4),
                "ueba_score" : round(ue_s, 4),
                "rule_score" : round(ru_s, 4),
                "eta_score"  : round(et_s, 4),
                "confidence" : round(float(conf or 0), 2),
                "attack_type"  : atype,
                "mitre_tactic" : _family_to_tactic(atype),
                "src_ip"       : sip,
                "dst_ip"       : dip,
                "dst_port"     : dport,
                "tag"          : tag,
                "reasons"      : reasons_list,
                "rule_names"   : rule_names,
                "correlated"   : bool(rule_names),
                "department"   : dept["department"],
                "color"        : dept.get("color", "#6b7280"),
            })
        return {"alerts": alerts, "count": len(alerts)}
    except Exception as e:
        return {"alerts": [], "count": 0, "error": str(e)}

@app.get("/api/rules/stats")
async def get_rule_stats(hours: int = 24):
    """
    Per-rule fire counts over a rolling window (default 24h).

    Mines the alerts.rule_names column (JSON array of rule labels per
    alert, e.g. '["Rule: DNS Tunneling Suspected"]') and aggregates per
    distinct rule_name. Earlier versions of this handler queried a
    separate rule_alerts table that this engine build doesn't create :
    so we now derive the same per-rule statistics from the canonical
    alerts table directly. rule_id is a stable ordinal assigned in
    rule-name sort order, so labels like 'R1' are deterministic across
    reloads as long as the rule set is unchanged.

    Query params:
      hours - look-back window in hours (default 24, max 720 = 30d)
    """
    hours = max(1, min(int(hours), 720))
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")

        per_rule: Dict[str, Dict[str, Any]] = {}
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "BENIGN": 0}
        rank_sev = {v: k for k, v in sev_rank.items()}

        rows = conn.execute(
            f"""
            SELECT rule_names, timestamp, severity, src_ip, dst_ip, correlated
            FROM alerts
            WHERE timestamp > datetime(COALESCE((SELECT MAX(timestamp) FROM alerts), datetime('now')), '-{hours} hours')
              AND rule_names IS NOT NULL
              AND rule_names != ''
              AND rule_names != '[]'
            """
        ).fetchall()
        conn.close()

        for rule_names_json, ts, sev, src_ip, dst_ip, correlated in rows:
            try:
                names = json.loads(rule_names_json) if rule_names_json else []
            except (TypeError, ValueError):
                continue
            if not isinstance(names, list):
                continue
            for raw in names:
                # Strip the "Rule: " prefix that the engine prepends.
                name = (raw or "").strip()
                if name.startswith("Rule:"):
                    name = name[5:].strip()
                if not name:
                    continue
                slot = per_rule.setdefault(name, {
                    "fires": 0, "last_fired": "", "src_ips": set(),
                    "dst_ips": set(), "correlated": 0, "max_sev_rank": 0,
                })
                slot["fires"] += 1
                if ts and ts > slot["last_fired"]:
                    slot["last_fired"] = ts
                if src_ip: slot["src_ips"].add(src_ip)
                if dst_ip: slot["dst_ips"].add(dst_ip)
                if correlated: slot["correlated"] += 1
                slot["max_sev_rank"] = max(slot["max_sev_rank"], sev_rank.get(sev or "", 0))

        # Stable ordinal: rule_id assigned in alphabetic rule-name order
        sorted_names = sorted(per_rule.keys())
        rules = []
        for i, name in enumerate(sorted_names, start=1):
            s = per_rule[name]
            rules.append({
                "rule_id":        i,
                "rule_name":      name,
                "fires":          s["fires"],
                "last_fired":     s["last_fired"],
                "suppressed":     0,                   # not tracked in alerts schema
                "correlated":     s["correlated"],
                "unique_src_ips": len(s["src_ips"]),
                "unique_dst_ips": len(s["dst_ips"]),
                "worst_severity": rank_sev.get(s["max_sev_rank"], "BENIGN"),
            })
        return {"window_hours": hours, "rules": rules, "count": len(rules)}
    except Exception as e:
        print(f"[Dashboard] /api/rules/stats failed: {e}")
        return {"window_hours": hours, "rules": [], "count": 0, "error": str(e)}

@app.get("/api/rules/stats_legacy_unused")
async def _rule_stats_legacy_unused(hours: int = 24):
    """Legacy rule_alerts-table-based handler kept as a stub. Not routed
    on the dashboard; preserved here so the rule_alerts table can later
    feed it without code reshuffling."""
    hours = max(1, min(int(hours), 720))
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            rows = conn.execute(
                f"""
                SELECT rule_id, rule_name, COUNT(*) AS fires,
                       MAX(timestamp) AS last_fired,
                       SUM(CASE WHEN suppressed=1 THEN 1 ELSE 0 END) AS suppressed,
                       SUM(CASE WHEN correlated=1 THEN 1 ELSE 0 END) AS correlated,
                       COUNT(DISTINCT src_ip) AS unique_src_ips,
                       COUNT(DISTINCT dst_ip) AS unique_dst_ips
                FROM rule_alerts
                WHERE timestamp > datetime(COALESCE((SELECT MAX(timestamp) FROM alerts), datetime('now')), '-{hours} hours')
                GROUP BY rule_id, rule_name
                ORDER BY rule_id
                """
            ).fetchall()
        except sqlite3.OperationalError:
            # rule_alerts table may not exist yet if engine hasn't written
            # any rule alerts since DB creation.
            rows = []
        conn.close()
        return {
            "window_hours": hours,
            "rules": [
                {
                    "rule_id":        r[0],
                    "rule_name":      r[1],
                    "fires":          r[2],
                    "last_fired":     r[3],
                    "suppressed":     r[4] or 0,
                    "correlated":     r[5] or 0,
                    "unique_src_ips": r[6] or 0,
                    "unique_dst_ips": r[7] or 0,
                }
                for r in rows
            ],
            "count": len(rows),
        }
    except Exception as e:
        return {"window_hours": hours, "rules": [], "count": 0, "error": str(e)}

@app.get("/api/devices/{ip:path}")
async def get_device(ip: str):
    """Full drill-down for one device."""
    device = registry.get_device(ip)
    if not device:
        return {"error": "Device not found"}

    # Get recent alerts for this device
    try:
        conn  = sqlite3.connect(ALERTS_DB, timeout=5)
        rows  = conn.execute("""
            SELECT id, timestamp, severity, final_score,
                   attack_type, rule_names, ueba_reasons
            FROM alerts
            WHERE src_ip = ?
            ORDER BY id DESC LIMIT 50
        """, (ip,)).fetchall()
        conn.close()
        alerts = [{
            "id"         : r[0],
            "timestamp"  : r[1],
            "severity"   : r[2],
            "final_score": r[3],
            "attack_type": r[4],
            "rule_names" : json.loads(r[5] or "[]"),
            "ueba_reasons":json.loads(r[6] or "[]"),
        } for r in rows]
    except:
        alerts = []

    return {
        "device" : device,
        "alerts" : alerts,
        "dept"   : get_department_for_ip(ip),
    }

def _fetch_device_classifications() -> List[dict]:
    """Read live device classifications, joined with known_devices.db
    enrichment (hostname, mac, vendor, os, device_type, department).

    Sources (joined per IP):
      - alerts.db:device_classifications  -> device_class, vendor (fingerprint),
                                             os_hint, confidence, flow_count
      - alerts.db:alerts                  -> alert_count, max_severity
      - known_devices.db:known_devices    -> hostname, mac, vendor (OUI),
                                             os (User-Agent), department,
                                             priority, device_type
    """
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        # ATTACH the second SQLite file so we can JOIN across DBs.
        kd_path = os.path.join(os.path.dirname(os.path.abspath(ALERTS_DB)),
                                KNOWN_DEVICES_DB)
        try:
            conn.execute(f"ATTACH DATABASE '{kd_path}' AS kd")
            kd_attached = True
        except Exception as ae:
            print(f"[Dashboard] could not ATTACH {kd_path}: {ae}")
            kd_attached = False

        if kd_attached:
            rows = conn.execute("""
                SELECT dc.ip, dc.device_class, dc.vendor AS dc_vendor,
                       dc.os_hint, dc.confidence,
                       dc.flow_count AS dc_flows, dc.first_seen, dc.last_updated,
                       COALESCE(ac.n_alerts, 0)     AS alert_count,
                       COALESCE(ac.max_sev_rank, 0) AS max_sev_rank,
                       COALESCE(kd.hostname,    '') AS hostname,
                       COALESCE(kd.mac_address, '') AS mac_address,
                       COALESCE(kd.vendor,      '') AS kd_vendor,
                       COALESCE(kd.os,          '') AS kd_os,
                       COALESCE(kd.department,  '') AS department,
                       COALESCE(kd.priority,    'medium') AS priority,
                       COALESCE(kd.device_type, '') AS kd_device_type
                FROM device_classifications dc
                LEFT JOIN (
                    SELECT src_ip AS ip, COUNT(*) AS n_alerts,
                           MAX(CASE severity
                                  WHEN 'CRITICAL' THEN 4
                                  WHEN 'HIGH'     THEN 3
                                  WHEN 'MEDIUM'   THEN 2
                                  WHEN 'LOW'      THEN 1
                                  ELSE 0 END) AS max_sev_rank
                    FROM alerts GROUP BY src_ip
                ) ac ON ac.ip = dc.ip
                LEFT JOIN kd.known_devices kd ON kd.ip = dc.ip
                ORDER BY alert_count DESC, dc.flow_count DESC
            """).fetchall()
        else:
            # Fallback; same as legacy behaviour, no enrichment
            rows = conn.execute("""
                SELECT dc.ip, dc.device_class, dc.vendor, '', dc.confidence,
                       dc.flow_count, dc.first_seen, dc.last_updated,
                       COALESCE(ac.n_alerts, 0), COALESCE(ac.max_sev_rank, 0),
                       '', '', '', '', '', 'medium', ''
                FROM device_classifications dc
                LEFT JOIN (
                    SELECT src_ip AS ip, COUNT(*) AS n_alerts,
                           MAX(CASE severity
                                  WHEN 'CRITICAL' THEN 4
                                  WHEN 'HIGH'     THEN 3
                                  WHEN 'MEDIUM'   THEN 2
                                  WHEN 'LOW'      THEN 1
                                  ELSE 0 END) AS max_sev_rank
                    FROM alerts GROUP BY src_ip
                ) ac ON ac.ip = dc.ip
                ORDER BY alert_count DESC, dc.flow_count DESC
            """).fetchall()
        conn.close()
    except Exception as e:
        print(f"[Dashboard] device_classifications read failed: {e}")
        return []

    sev_names = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "BENIGN"}
    out: List[dict] = []
    for row in rows:
        (ip, dcls, dc_vendor, os_hint, conf, flows, first_s, last_s,
         n_alerts, max_sev,
         hostname, mac, kd_vendor, kd_os, department, priority, kd_dtype) = row

        def _iso(ts):
            try:
                return datetime.fromtimestamp(float(ts)).isoformat() if ts else ""
            except Exception:
                return ""

        # Vendor priority: known_devices (OUI lookup) > device_classifier > empty
        vendor = kd_vendor or dc_vendor or ""
        # OS priority: known_devices (User-Agent parse) > device_classifier > empty
        os_label = kd_os or os_hint or ""
        # Device type: prefer known_devices.device_type, fall back to dc.device_class
        device_type = kd_dtype or (dcls if dcls and dcls != "unknown" else "")
        # Combined "vendor / os" string for the UI's single column
        vendor_os = " / ".join(x for x in (vendor, os_label) if x)

        out.append({
            "ip":           ip,
            "hostname":     hostname or "",
            "mac_address":  mac or "",
            "vendor":       vendor,
            "os":           os_label,
            "vendor_os":    vendor_os,
            "device_type":  device_type,
            "device_class": dcls or "unknown",  # legacy alias
            "department":   department or "",
            "priority":     priority or "medium",
            "confidence":   float(conf or 0.0),
            "flow_count":   int(flows or 0),
            "first_seen":   _iso(first_s),
            "last_seen":    _iso(last_s),
            "alert_count":  int(n_alerts),
            "max_severity": sev_names.get(int(max_sev), "BENIGN"),
            "risk_score":   round(int(n_alerts) * 10.0 + int(flows or 0) * 0.01, 4),
            "is_new":       False,
        })
    return out

@app.get("/api/known-devices")
async def get_known_devices():
    """All known devices, pulled live from alerts.db:device_classifications."""
    devices = sorted(
        _fetch_device_classifications(),
        key=lambda d: -d.get("risk_score", 0),
    )
    return {"devices": devices, "count": len(devices)}

@app.get("/api/summary")
async def get_summary():
    """Top-level dashboard statistics; optimized for large DBs."""
    try:
        conn  = sqlite3.connect(ALERTS_DB, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA cache_size=-8000")  # 8MB cache

        # Use id-based range instead of timestamp scan for speed.
        # Find approximate cutoff id: get max id, then estimate 24h worth.
        max_id = conn.execute("SELECT MAX(id) FROM alerts").fetchone()[0] or 0

        # Scan only last 50K rows max for summary (covers most 24h windows)
        cutoff_id = max(0, max_id - 50000)

        total = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE id > ?",
            (cutoff_id,)
        ).fetchone()[0]

        # Severity counts EXCLUDING benign-verdict rows. Engine attaches
        # MEDIUM/HIGH before the benign reclassifier runs, so they would
        # inflate severity buckets. Split them out so the doughnut shows
        # a real threat distribution.
        # ── Schema v2 (2026-04-27) ──
        # The canonical "benign" signal is `verdict LIKE 'benign-%'`. The
        # legacy `attack_type='BENIGN'` filter is kept as fallback for rows
        # written before the migration; will be retired once all writers
        # use the new `verdict` column.
        by_sev = conn.execute("""
            SELECT severity, COUNT(*)
            FROM alerts
            WHERE id > ?
              AND COALESCE(verdict,'')     NOT LIKE 'benign-%'
              AND COALESCE(attack_type,'') != 'BENIGN'
            GROUP BY severity
        """, (cutoff_id,)).fetchall()
        benign_total = conn.execute("""
            SELECT COUNT(*) FROM alerts
            WHERE id > ?
              AND ( COALESCE(verdict,'')     LIKE 'benign-%'
                 OR COALESCE(attack_type,'') = 'BENIGN' )
        """, (cutoff_id,)).fetchone()[0]

        recent = conn.execute("""
            SELECT attack_type, COUNT(*) as c
            FROM alerts WHERE id > ?
            GROUP BY attack_type
            ORDER BY c DESC LIMIT 5
        """, (cutoff_id,)).fetchall()

        # total_devices comes from device_classifications (engine's live
        # registry), not the legacy known_devices.db registry that was
        # never being populated in the live path.
        try:
            devices_count = conn.execute(
                "SELECT COUNT(*) FROM device_classifications"
            ).fetchone()[0]
        except Exception:
            devices_count = 0

        conn.close()

        counts = {r[0]:r[1] for r in by_sev}
        return {
            "total_alerts_24h"  : total,
            "critical_count"    : counts.get("CRITICAL", 0),
            "high_count"        : counts.get("HIGH", 0),
            "medium_count"      : counts.get("MEDIUM", 0),
            "low_count"         : counts.get("LOW", 0),
            "benign_count"      : benign_total,
            "total_devices"     : devices_count,
            "top_attack_types"  : [
                {"type": r[0], "count": r[1]} for r in recent
            ],
            "timestamp"         : datetime.now().isoformat(),
        }
    except Exception as e:
        return {"error": str(e)}

# ── WebSocket endpoint ────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)

    # Send full state on connect
    try:
        summary = await get_summary()
        depts   = await get_departments()
        devices = await get_known_devices()
        alerts  = await get_recent_alerts(limit=20)

        await ws.send_text(json.dumps({
            "type"        : "init",
            "summary"     : summary,
            "departments" : depts["departments"],
            "devices"     : devices["devices"][:50],
            "alerts"      : alerts["alerts"],
        }))
    except Exception as e:
        print(f"[WS] Init send error: {e}")

    try:
        while True:
            # Keep connection alive; wait for client ping
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text(json.dumps({"type":"pong"}))
    except WebSocketDisconnect:
        await manager.disconnect(ws)
    except Exception:
        await manager.disconnect(ws)

# ── Serve dashboard HTML ──────────────────────────────────────

@app.get("/")
async def serve_root():
    """Default route; serves the Sentrix SOC Console (the new dashboard).
    Old legacy dashboard remains accessible at /legacy."""
    candidates = [
        str(_PROJECT_ROOT / "dashboard" / "sentrix_console.html"),
        str(_PROJECT_ROOT / "sentrix_console.html"),
        "sentrix_console.html",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentrix_console.html"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return FileResponse(path)
    return HTMLResponse("<h1>sentrix_console.html not found</h1>"
                        "<p>Place sentrix_console.html in the dashboard/ folder.</p>")

@app.get("/legacy")
async def serve_legacy_dashboard():
    """Original dashboard.html; kept for archive access only."""
    candidates = [
        str(_PROJECT_ROOT / "dashboard" / "dashboard.html"),
        str(_PROJECT_ROOT / "dashboard.html"),
        "dashboard.html",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return FileResponse(path)
    return HTMLResponse("<h1>dashboard.html not found</h1>"
                        "<p>Place dashboard.html in the dashboard/ folder.</p>")

# ── Analytics endpoints (Kibana-style aggregates) ─────────────

@app.get("/api/analytics/threat-families")
async def analytics_threat_families(hours: int = 24, limit: int = 20):
    """attack_type histogram over the last N hours."""
    hours = max(1, min(int(hours), 720))
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        rows = conn.execute(
            f"""SELECT COALESCE(attack_type,'Unclassified') AS t,
                       COUNT(*) AS c
                FROM alerts
                WHERE timestamp > datetime(COALESCE((SELECT MAX(timestamp) FROM alerts), datetime('now')), '-{hours} hours')
                GROUP BY t ORDER BY c DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        conn.close()
        return {"window_hours": hours, "families": [
            {"attack_type": r[0], "count": r[1]} for r in rows
        ]}
    except Exception as e:
        return {"window_hours": hours, "families": [], "error": str(e)}

# ── MITRE ATT&CK tactic mapping (display layer) ───────────────
from typing import Any as _Any
_MITRE_MAP_PATH = os.path.join(_DASHBOARD_PARENT, "config", "mitre_mapping.json")
_MITRE_MAP_CACHE: Dict[str, _Any] = {"loaded_at": 0.0, "data": None}

def _load_mitre_mapping() -> dict:
    """Load and cache the family→tactic mapping. Refreshes from disk every
    60 s so admins can edit `config/mitre_mapping.json` and see updates
    without a dashboard restart."""
    now = time.time()
    if _MITRE_MAP_CACHE["data"] and (now - _MITRE_MAP_CACHE["loaded_at"]) < 60:
        return _MITRE_MAP_CACHE["data"]
    try:
        with open(_MITRE_MAP_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {"family_to_tactic": {}, "tactic_meta": {}}
    except Exception as e:
        print(f"[Dashboard] mitre_mapping.json load failed: {e}")
        data = {"family_to_tactic": {}, "tactic_meta": {}}
    _MITRE_MAP_CACHE.update({"loaded_at": now, "data": data})
    return data

def _family_to_tactic(family: str, mapping: dict = None) -> str:
    """Resolve a family name to its dominant MITRE tactic. Returns
    'Unclassified' for unknown families so the chart doesn't drop them."""
    if not family:
        return "Unclassified"
    mapping = mapping or _load_mitre_mapping()
    return mapping.get("family_to_tactic", {}).get(family, "Unclassified")

@app.get("/api/analytics/training-families")
async def analytics_training_families():
    """Per-family flow counts across the combined Stage 2 training corpus
    (CTU-13 + CTU-IoT-23 + CTU-SME-11 + Stratosphere-MCFP + UWF-ZeekData24
    + supporting benign sources). Counts are derived from the multiclass
    model's class_weights (inverse-frequency weights stored at train time):
        weight_i = train_size / (n_classes × count_i)
    →  count_i = train_size / (n_classes × weight_i)
    No need to re-scan parquet files. Each family is also tagged with its
    MITRE tactic (via mitre_mapping.json) so the chart can group/colour by
    tactic if desired."""
    meta_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                              "models", "sentrix_multiclass_metadata.json")
    try:
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
        classes     = meta.get("classes", []) or []
        weights     = meta.get("class_weights", {}) or {}
        train_size  = int(meta.get("train_size", 0))
        n_classes   = int(meta.get("n_classes", len(classes)))
        if not classes or not weights or train_size <= 0 or n_classes <= 0:
            return {"families": [], "error": "incomplete training metadata"}

        mapping = _load_mitre_mapping()
        tactic_meta = mapping.get("tactic_meta", {})

        out = []
        for i, cls in enumerate(classes):
            w = float(weights.get(str(i), weights.get(i, 0.0)))
            if w <= 0:
                continue
            count = int(round(train_size / (n_classes * w)))
            tac = _family_to_tactic(cls, mapping)
            out.append({
                "family":     cls,
                "count":      count,
                "tactic":     tac,
                "tactic_id":  tactic_meta.get(tac, {}).get("id", ""),
                "color":      tactic_meta.get(tac, {}).get("color", "#94a3b8"),
            })
        out.sort(key=lambda x: -x["count"])
        return {
            "train_size":   train_size,
            "n_classes":    n_classes,
            "val_macro_f1": meta.get("val_macro_f1"),
            "test_macro_f1":meta.get("test_macro_f1"),
            "families":     out,
        }
    except FileNotFoundError:
        return {"families": [], "error": f"metadata not found at {meta_path}"}
    except Exception as e:
        print(f"[Dashboard] /api/analytics/training-families failed: {e}")
        return {"families": [], "error": str(e)}

@app.get("/api/analytics/mitre-tactics")
async def analytics_mitre_tactics(hours: int = 24):
    """Threat distribution grouped by MITRE ATT&CK tactic. Each alert's
    attack_type is mapped to its dominant tactic via
    `config/mitre_mapping.json`. Counts include a `families` breakdown
    so the dashboard tooltip can show which families contribute to each
    tactic slice. Tactics with zero alerts are still returned (with
    count=0) so the operator can see the FULL ATT&CK coverage :
    including the 8 tactics our 18-class Stage 2 model cannot detect."""
    hours = max(1, min(int(hours), 720))
    mapping = _load_mitre_mapping()
    fam_to_tac = mapping.get("family_to_tactic", {})
    tactic_meta = mapping.get("tactic_meta", {})
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        # Per-alert pull so we can classify Other-class alerts individually.
        alerts_rows = conn.execute(
            f"""SELECT COALESCE(attack_type,'Unclassified') AS t,
                       dst_ip, dst_port
                FROM alerts
                WHERE timestamp > datetime(COALESCE((SELECT MAX(timestamp) FROM alerts), datetime('now')), '-{hours} hours')
                  AND COALESCE(verdict,'')     NOT LIKE 'benign-%'
                  AND COALESCE(attack_type,'') != 'BENIGN'""",
        ).fetchall()
        conn.close()

        # Classify each alert into a tactic. For Other-class alerts, use
        # destination-pattern heuristic so they don't lump into "Unclassified":
        #   port 445  (SMB internal-to-internal) -> Lateral Movement
        #   port 80   (HTTP outbound to public)  -> Exfiltration
        #   port 5228 (Google Push outbound)     -> Command and Control
        #   anything else (ephemeral high port)  -> Command and Control
        def _classify_other(dst_port):
            try:
                p = int(dst_port) if dst_port is not None else 0
            except Exception:
                p = 0
            if p == 445:
                return "Lateral Movement", "Other-LateralSMB"
            if p == 80:
                return "Exfiltration", "Other-CloudHTTP"
            if p == 5228:
                return "Command and Control", "Other-MobilePush"
            return "Command and Control", "Other-EphemeralPort"

        per_tactic: Dict[str, Dict[str, _Any]] = {}
        family_counts: Dict[str, int] = {}
        for family, dst_ip, dst_port in alerts_rows:
            if family == "Other":
                tac, sub_label = _classify_other(dst_port)
                family_label = sub_label
            else:
                tac = fam_to_tac.get(family, "Unclassified")
                family_label = family
            family_counts[family_label] = family_counts.get(family_label, 0) + 1
            slot = per_tactic.setdefault(tac, {"count": 0, "families_set": set()})
            slot["count"] += 1
            slot["families_set"].add(family_label)

        # Convert family_set to list-of-dicts for JSON, sorted by count desc
        for tac, slot in per_tactic.items():
            slot["families"] = sorted(
                [{"family": f, "count": family_counts[f]} for f in slot["families_set"]],
                key=lambda x: -x["count"],
            )
            slot.pop("families_set", None)

        # Ensure every defined tactic appears (even at 0) so the
        # operator sees the full coverage map; sort by tactic_meta order.
        for tac_name in tactic_meta.keys():
            if tac_name not in per_tactic:
                per_tactic[tac_name] = {"count": 0, "families": []}

        out = []
        for tac, slot in per_tactic.items():
            meta = tactic_meta.get(tac, {})
            out.append({
                "tactic":    tac,
                "tactic_id": meta.get("id", ""),
                "color":     meta.get("color", "#94a3b8"),
                "order":     meta.get("order", 99),
                "count":     slot["count"],
                "families":  sorted(slot["families"], key=lambda x: -x["count"]),
                "covered":   tac in mapping.get("_covered_by_model", []),
            })
        out.sort(key=lambda x: x["order"])
        return {
            "window_hours": hours,
            "tactics":      out,
            "covered_count":   sum(1 for x in out if x["covered"]),
            "uncovered_tactics": mapping.get("_uncovered_tactics", []),
        }
    except Exception as e:
        print(f"[Dashboard] /api/analytics/mitre-tactics failed: {e}")
        return {"window_hours": hours, "tactics": [], "error": str(e)}

@app.get("/api/analytics/top-offenders")
async def analytics_top_offenders(hours: int = 24, limit: int = 15):
    """Top src_ip by alert count (optionally scoped to internal src)."""
    hours = max(1, min(int(hours), 720))
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        rows = conn.execute(
            f"""SELECT src_ip,
                       COUNT(*) AS c,
                       MAX(severity)     AS worst_sev,
                       MAX(timestamp)    AS last_seen,
                       GROUP_CONCAT(DISTINCT attack_type) AS attacks
                FROM alerts
                WHERE timestamp > datetime(COALESCE((SELECT MAX(timestamp) FROM alerts), datetime('now')), '-{hours} hours')
                  AND src_ip IS NOT NULL AND src_ip != ''
                GROUP BY src_ip ORDER BY c DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        conn.close()
        return {"window_hours": hours, "offenders": [
            {"src_ip": r[0], "count": r[1], "worst_severity": r[2],
             "last_seen": r[3], "attacks": (r[4] or "").split(",")[:5]}
            for r in rows
        ]}
    except Exception as e:
        return {"window_hours": hours, "offenders": [], "error": str(e)}

@app.get("/api/analytics/ml-histogram")
async def analytics_ml_histogram(hours: int = 24, bins: int = 20):
    """Histogram of ml_score from alerts."""
    hours = max(1, min(int(hours), 720))
    bins = max(5, min(int(bins), 50))
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        rows = conn.execute(
            f"""SELECT ml_score FROM alerts
                WHERE timestamp > datetime(COALESCE((SELECT MAX(timestamp) FROM alerts), datetime('now')), '-{hours} hours')
                  AND ml_score IS NOT NULL""",
        ).fetchall()
        conn.close()
        hist = [0] * bins
        for (s,) in rows:
            try:
                v = float(s)
                if v < 0: v = 0.0
                if v > 1: v = 1.0
                idx = min(int(v * bins), bins - 1)
                hist[idx] += 1
            except (TypeError, ValueError):
                continue
        edges = [round(i / bins, 3) for i in range(bins + 1)]
        return {
            "window_hours": hours, "bins": bins,
            "counts": hist, "edges": edges,
            "n_samples": sum(hist),
        }
    except Exception as e:
        return {"window_hours": hours, "counts": [], "edges": [], "error": str(e)}

@app.get("/api/analytics/mitre")
async def analytics_mitre(hours: int = 24):
    """MITRE ATT&CK tactic coverage heatmap; counts per tactic from
    alerts in the window, using the static attack_type → tactic map."""
    hours = max(1, min(int(hours), 720))
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        rows = conn.execute(
            f"""SELECT COALESCE(attack_type,'Unclassified') AS t, COUNT(*) AS c
                FROM alerts
                WHERE timestamp > datetime(COALESCE((SELECT MAX(timestamp) FROM alerts), datetime('now')), '-{hours} hours')
                GROUP BY t""",
        ).fetchall()
        conn.close()
        tactic_counts: Dict[str, int] = {tid: 0 for tid, _ in TACTICS}
        attack_to_tactics: Dict[str, List[str]] = {}
        for atk, c in rows:
            tids = tactics_for(atk)
            attack_to_tactics[atk] = tids
            for tid in tids:
                tactic_counts[tid] = tactic_counts.get(tid, 0) + int(c)
        return {
            "window_hours": hours,
            "tactics": [
                {"tactic_id": tid, "tactic_name": name,
                 "count": tactic_counts.get(tid, 0)}
                for tid, name in TACTICS
            ],
            "attack_types": [
                {"attack_type": atk, "tactic_ids": tids}
                for atk, tids in attack_to_tactics.items()
            ],
        }
    except Exception as e:
        return {"window_hours": hours, "tactics": [], "error": str(e)}

@app.get("/api/analytics/training-composition")
async def analytics_training_composition():
    """Composition of training data sources used to build Sentrix.

    Merges two metadata files to get complete 4-source coverage:
      1. sentrix_metadata_seed42.json → training_sources + per_source_heldout
         (contains all 4 sources: MAWI + CTU-13 + CTU-IoT-23 + UGR-16)
      2. sentrix_scaler_metadata.json → per_source_train_counts
         (older file; only has 3 sources, pre-UGR16 iteration)

    Prefers per_source_heldout counts since they include UGR-16 and
    accurately reflect the 4-source composition of the production model.
    """
    # ── 1. Main metadata (training_sources + per_source_heldout) ──
    meta_candidates = [
        _PROJECT_ROOT / "models" / "sentrix_metadata.json",
        _PROJECT_ROOT / "models" / "sentrix_metadata_seed42.json",
        _PROJECT_ROOT / "models" / "phase4_metadata_seed42.json",
        _PROJECT_ROOT / "models" / "sentrix_metadata.json",
        _PROJECT_ROOT / "models" / "phase4_metadata.json",
    ]
    meta = None
    for p in meta_candidates:
        if p.exists():
            try:
                meta = json.loads(p.read_text())
                break
            except Exception:
                continue
    if not meta:
        return {"sources": [], "error": "no metadata found"}

    ts = meta.get("training_sources", [])
    heldout = meta.get("metrics", {}).get("per_source_heldout", {})

    # ── 2. Scaler metadata (older, 3-source, may miss UGR-16) ─────
    scaler_paths = [
        _PROJECT_ROOT / "models" / "sentrix_scaler_metadata.json",
        _PROJECT_ROOT / "models" / "phase4_scaler_metadata.json",
    ]
    scaler_counts: Dict[str, int] = {}
    for sp in scaler_paths:
        if sp.exists():
            try:
                sm = json.loads(sp.read_text())
                per_src = sm.get("per_source_train_counts", {})
                for label_cls, src_map in per_src.items():
                    for src, c in (src_map or {}).items():
                        scaler_counts[src] = scaler_counts.get(src, 0) + int(c)
                break
            except Exception:
                continue

    # ── 3. Merge: build one row per source, with whatever counts we have ──
    # Aliases for inconsistent naming between metadata files; the
    # training-counts side uses "CTU-IoT-23" while the heldout side
    # uses "CTU-IoT"; same dataset, both get folded together.
    _ALIASES = {
        "CTU-IoT":      "CTU-IoT-23",
        "CTU_IoT":      "CTU-IoT-23",
        "ctu-iot":      "CTU-IoT-23",
        "MAWI-heldout": "MAWI",
        "UGR16":        "UGR-16",
    }
    def _normalise(name: str) -> str:
        n = str(name).replace("-heldout", "")
        return _ALIASES.get(n, n)
    sources: Dict[str, Dict] = {}
    for k, v in scaler_counts.items():
        sources.setdefault(_normalise(k), {})["train_count"] = int(v)
    for k, v in (heldout or {}).items():
        try:
            n = int((v or {}).get("n", 0))
        except (TypeError, ValueError):
            n = 0
        if n > 0:
            sources.setdefault(_normalise(k), {})["heldout_count"] = n

    # Build list with fallback: if no train_count but have heldout_count,
    # use heldout_count as display value (this is how UGR-16 appears).
    counts_by_source: Dict[str, int] = {}
    for src_name, d in sources.items():
        counts_by_source[src_name] = int(
            d.get("train_count") or d.get("heldout_count") or 0
        )

    return {
        "training_sources_desc": ts,
        "counts_by_source": counts_by_source,
        "detail_by_source": [
            {
                "name": n,
                "train_count": d.get("train_count"),
                "heldout_count": d.get("heldout_count"),
            }
            for n, d in sources.items()
        ],
        "version": meta.get("version", ""),
        "seed": meta.get("seed"),
        "note": (
            "Counts prefer per_source_train_counts; sources missing there "
            "(notably UGR-16 in pre-4.3 metadata) fall back to their "
            "per_source_heldout n."
        ),
    }

@app.get("/api/health")
async def sentrix_health():
    """Engine throughput, latency, queue depth, uptime; reads latest
    engine_stats row written by realtime_engine's background writer."""
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        # engine_stats table may not exist until the engine writes once
        try:
            row = conn.execute(
                """SELECT timestamp, flows_processed, flows_per_sec,
                          layer1_immediate, layer1_boosted,
                          layer2_attacks, layer25_policy_violations,
                          layer3_peer_deviation, total_alerts,
                          latency_p50_ms, latency_p95_ms,
                          queue_depth, uptime_seconds
                   FROM engine_stats ORDER BY timestamp DESC LIMIT 1""",
            ).fetchone()
        except sqlite3.OperationalError:
            row = None
        # Alert rate (client-computed over last minute)
        try:
            last_minute = conn.execute(
                "SELECT COUNT(*) FROM alerts "
                "WHERE timestamp > datetime('now', '-1 minutes')"
            ).fetchone()[0]
        except sqlite3.OperationalError:
            last_minute = 0
        conn.close()
        # Live total alert count + per-layer breakdown from alerts.db
        # so the Health tab stays in sync with Overview / Live-Alerts.
        try:
            live_total = sqlite3.connect(ALERTS_DB, timeout=5).execute(
                "SELECT COUNT(*) FROM alerts WHERE COALESCE(attack_type,'') != 'BENIGN'"
            ).fetchone()[0]
        except sqlite3.OperationalError:
            live_total = 0
        try:
            live_l1_imm = sqlite3.connect(ALERTS_DB, timeout=5).execute(
                "SELECT COUNT(*) FROM alerts WHERE severity='HIGH' AND COALESCE(attack_type,'') != 'BENIGN'"
            ).fetchone()[0]
            live_l2_att = sqlite3.connect(ALERTS_DB, timeout=5).execute(
                "SELECT COUNT(*) FROM alerts WHERE source LIKE 'sentrix%' AND COALESCE(attack_type,'') != 'BENIGN'"
            ).fetchone()[0]
            live_l25_pol = sqlite3.connect(ALERTS_DB, timeout=5).execute(
                "SELECT COUNT(*) FROM alerts WHERE source = 'suricata'"
            ).fetchone()[0]
        except Exception:
            live_l1_imm = live_l2_att = live_l25_pol = 0
        if not row:
            return {
                "engine_stats_available": True,  # we have alerts.db data even without engine_stats
                "alerts_last_minute": last_minute,
                "total_alerts": live_total,
                "layer1_immediate": live_l1_imm,
                "layer1_boosted": 0,
                "layer2_attacks": live_l2_att,
                "layer25_policy_violations": live_l25_pol,
                "layer3_peer_deviation": 0,
                "flows_processed": 0,
                "flows_per_sec": 0,
                "latency_p50_ms": 0,
                "latency_p95_ms": 0,
                "queue_depth": 0,
                "uptime_seconds": 0,
                "timestamp": datetime.now().isoformat(),
                "note": "Engine offline; counts pulled live from alerts.db",
            }
        keys = ["timestamp", "flows_processed", "flows_per_sec",
                "layer1_immediate", "layer1_boosted", "layer2_attacks",
                "layer25_policy_violations", "layer3_peer_deviation",
                "total_alerts", "latency_p50_ms", "latency_p95_ms",
                "queue_depth", "uptime_seconds"]
        out = {k: v for k, v in zip(keys, row)}
        # Override stale fields with live counts from alerts.db
        out["total_alerts"] = live_total
        out["layer1_immediate"] = live_l1_imm
        out["layer2_attacks"] = live_l2_att
        out["layer25_policy_violations"] = live_l25_pol
        return {
            "engine_stats_available": True,
            "alerts_last_minute": last_minute,
            **out,
        }
    except Exception as e:
        return {"engine_stats_available": False, "error": str(e)}

@app.get("/static/{filename:path}")
async def serve_static(filename: str):
    """Serve Chart.js, Alpine.js, and other frontend libs locally so
    the console works even behind corporate firewalls that block CDNs.
    Files live in dashboard/static/."""
    # Restrict to known extensions and no path traversal
    if ".." in filename or filename.startswith("/"):
        return HTMLResponse("forbidden", status_code=403)
    candidates = [
        _PROJECT_ROOT / "dashboard" / "static" / filename,
        Path(__file__).resolve().parent.parent / "dashboard" / "static" / filename,
    ]
    for p in candidates:
        if p.exists() and p.is_file():
            # Set headers so browsers cache the libs but don't cache
            # the console HTML aggressively.
            return FileResponse(str(p))
    return HTMLResponse("not found", status_code=404)

@app.get("/console")
async def serve_sentrix_console():
    """Kibana-style Sentrix SOC Console (sentrix_console.html).
    Lives alongside the original dashboard.html; pick whichever you prefer."""
    candidates = [
        str(_PROJECT_ROOT / "dashboard" / "sentrix_console.html"),
        str(_PROJECT_ROOT / "sentrix_console.html"),
        "sentrix_console.html",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentrix_console.html"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return FileResponse(path)
    return HTMLResponse("<h1>sentrix_console.html not found</h1>"
                        "<p>Place sentrix_console.html in the dashboard/ folder.</p>")

# ── Entry point ───────────────────────────────────────────────

# ═══════════════════════════════════════════════════════════════
#  RUNTIME-STATE ENDPOINTS  (Kill-Tactic bidirectional channel)
# ═══════════════════════════════════════════════════════════════
#
# The dashboard writes here, the realtime engine polls the
# corresponding tables in alerts.db every 2 seconds and honours
# changes in its per-flow loop. No IPC, no restart required.
#
# See src/runtime_state.py for table schemas and semantics.

sys.path.insert(0, str(_PROJECT_ROOT / "src"))
from runtime_state import RuntimeStateStore as _RuntimeStateStore

_runtime_state = _RuntimeStateStore(db_path=ALERTS_DB, poll_seconds=2.0)

@app.get("/api/runtime/whitelist")
async def runtime_list_whitelist():
    return {"whitelist": _runtime_state.list_whitelist()}

@app.post("/api/runtime/whitelist")
async def runtime_add_whitelist(body: dict):
    ip = (body or {}).get("ip", "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="ip required")
    reason = (body or {}).get("reason", "dashboard override")
    added_by = (body or {}).get("added_by", "dashboard")
    _runtime_state.add_whitelist(ip, reason=reason, added_by=added_by)
    await manager.broadcast({
        "type": "runtime_whitelist_added",
        "ip": ip, "reason": reason, "added_by": added_by,
    })
    return {"status": "ok", "ip": ip}

@app.delete("/api/runtime/whitelist/{ip:path}")
async def runtime_remove_whitelist(ip: str):
    _runtime_state.remove_whitelist(ip)
    await manager.broadcast({"type": "runtime_whitelist_removed", "ip": ip})
    return {"status": "ok", "ip": ip}

# ── Scanner allowlist (Rule 9 / Rule 10 exemption) ──────────────
@app.get("/api/runtime/scanners")
async def runtime_list_scanners():
    """List IPs authorised as scanners (exempt from port sweep +
    horizontal scan rules). Typical entries: Nessus/Qualys/Tenable
    appliances, Nagios/PRTG monitoring servers, Ansible/SaltStack
    orchestrators."""
    return {"scanners": _runtime_state.list_scanners()}

@app.post("/api/runtime/scanners")
async def runtime_add_scanner(body: dict):
    ip = (body or {}).get("ip", "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="ip required")
    reason = (body or {}).get("reason", "authorised scanner")
    added_by = (body or {}).get("added_by", "dashboard")
    _runtime_state.add_scanner(ip, reason=reason, added_by=added_by)
    await manager.broadcast({
        "type": "runtime_scanner_added",
        "ip": ip, "reason": reason, "added_by": added_by,
    })
    return {"status": "ok", "ip": ip}

@app.delete("/api/runtime/scanners/{ip:path}")
async def runtime_remove_scanner(ip: str):
    _runtime_state.remove_scanner(ip)
    await manager.broadcast({"type": "runtime_scanner_removed", "ip": ip})
    return {"status": "ok", "ip": ip}

@app.post("/api/runtime/suppress")
async def runtime_suppress(body: dict):
    src_ip = (body or {}).get("src_ip", "").strip()
    attack_type = (body or {}).get("attack_type", "").strip()
    ttl = int((body or {}).get("ttl_seconds", 300))
    if not src_ip or not attack_type:
        raise HTTPException(
            status_code=400,
            detail="src_ip and attack_type required",
        )
    reason = (body or {}).get("reason", "")
    _runtime_state.add_suppression(src_ip, attack_type,
                                     ttl_seconds=ttl, reason=reason)
    await manager.broadcast({
        "type": "runtime_suppression_added",
        "src_ip": src_ip, "attack_type": attack_type, "ttl": ttl,
    })
    return {"status": "ok", "src_ip": src_ip,
            "attack_type": attack_type, "ttl": ttl}

@app.get("/api/runtime/config")
async def runtime_get_config():
    return _runtime_state.get_all_config()

@app.post("/api/runtime/config/{key}")
async def runtime_set_config(key: str, body: dict):
    value = (body or {}).get("value")
    if value is None:
        raise HTTPException(status_code=400, detail="value required")
    _runtime_state.set_config(key, str(value))
    await manager.broadcast({
        "type": "runtime_config_changed",
        "key": key, "value": str(value),
    })
    return {"status": "ok", "key": key, "value": str(value)}

@app.post("/api/runtime/pause")
async def runtime_pause():
    _runtime_state.set_config("paused", "true")
    await manager.broadcast({
        "type": "runtime_config_changed",
        "key": "paused", "value": "true",
    })
    return {"status": "ok", "paused": True}

@app.post("/api/runtime/resume")
async def runtime_resume():
    _runtime_state.set_config("paused", "false")
    await manager.broadcast({
        "type": "runtime_config_changed",
        "key": "paused", "value": "false",
    })
    return {"status": "ok", "paused": False}

# ── UEBA Long; 14-day observed-uptime learning clock ────────────
#
# GET  /api/runtime/ueba/status      ; progress / pause / active
# POST /api/runtime/ueba/pause       ; freeze clock + baselines
# POST /api/runtime/ueba/resume      ; unfreeze
# POST /api/runtime/ueba/reset       ; zero clock + wipe baselines
# POST /api/runtime/ueba/activate-now; force past target (SOC override)

@app.get("/api/runtime/ueba/status")
async def runtime_ueba_status():
    """
    Current UEBA learning-clock state.
      observed_seconds, target_seconds, active, paused,
      progress_pct, seconds_remaining
    """
    _runtime_state.refresh()
    return _runtime_state.get_ueba_status()

@app.post("/api/runtime/ueba/pause")
async def runtime_ueba_pause():
    """Freeze the learning clock AND baseline updates."""
    _runtime_state.pause_ueba(by="dashboard")
    await manager.broadcast({
        "type": "runtime_config_changed",
        "key": "ueba_paused", "value": "true",
    })
    return {"status": "ok", "ueba": _runtime_state.get_ueba_status()}

@app.post("/api/runtime/ueba/resume")
async def runtime_ueba_resume():
    """Unfreeze; clock and baselines start advancing again."""
    _runtime_state.resume_ueba(by="dashboard")
    await manager.broadcast({
        "type": "runtime_config_changed",
        "key": "ueba_paused", "value": "false",
    })
    return {"status": "ok", "ueba": _runtime_state.get_ueba_status()}

@app.post("/api/runtime/ueba/reset")
async def runtime_ueba_reset():
    """
    Hard reset: observation counter zeroed, paused flag cleared, all
    learned per-device and per-department baselines WIPED. The
    engine will start a fresh 14-day learning window.
    """
    # We cannot reach the engine's UEBALong instance from the
    # dashboard process directly, so the engine polls the clock
    # via runtime_state.refresh() and notices the observed_seconds
    # reset. UEBALong watches for resets via its own periodic
    # inspection; but the cleanest way is to write a reset signal
    # flag that the engine consumes and acts on. For now we do the
    # clock reset here; baseline wipe happens on the next engine
    # restart by deleting the state file. See the reset_signal
    # key below; the engine reads it every tick.
    status = _runtime_state.reset_ueba_clock(by="dashboard")
    _runtime_state.set_config("ueba_reset_signal",
                                str(time.time()),
                                updated_by="dashboard")
    await manager.broadcast({
        "type": "runtime_config_changed",
        "key": "ueba_observed_seconds", "value": "0.0",
        "ueba": status,
    })
    return {"status": "ok", "ueba": status}

@app.post("/api/runtime/ueba/activate-now")
async def runtime_ueba_activate_now():
    """Skip past the 14-day clock; for SOC testing."""
    status = _runtime_state.activate_ueba_now(by="dashboard")
    await manager.broadcast({
        "type": "runtime_config_changed",
        "key": "ueba_observed_seconds",
        "value": f"{status['observed_seconds']:.3f}",
        "ueba": status,
    })
    return {"status": "ok", "ueba": status}

# ── Device classification endpoints ──────────────────────────
#
# The engine's DeviceClassifier writes into device_classifications
# every 10 seconds. Dashboard reads from there directly. The SNMP
# probe endpoint instantiates its OWN DeviceClassifier inside the
# dashboard process, runs a synchronous probe, and writes the
# result into the same table; engine picks up the change on its
# next observation of that IP.

import sys as _sys
_sys.path.insert(0, str(_PROJECT_ROOT / "src"))
from device_classifier import DeviceClassifier as _DeviceClassifier

# Single shared classifier instance for the dashboard process.
# Lazily initialized on first use so dashboard_server import time
# doesn't touch the DB before alerts.db has been created.
_classifier: _DeviceClassifier | None = None

def _get_classifier() -> _DeviceClassifier:
    global _classifier
    if _classifier is None:
        _classifier = _DeviceClassifier(db_path=ALERTS_DB)
    return _classifier

@app.get("/api/classification/{ip:path}")
async def get_device_classification(ip: str):
    """
    Read the current classification verdict for a device.
    Source of truth is the device_classifications table in
    alerts.db, written by the engine's classifier every 10s.
    """
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        row = conn.execute(
            "SELECT ip, device_class, vendor, model_hint, os_hint, "
            "confidence, sources, class_scores, flow_count, "
            "observed_ports, first_seen, last_updated, "
            "snmp_probed_at, snmp_sysdescr "
            "FROM device_classifications WHERE ip = ?",
            (ip,),
        ).fetchone()
        conn.close()
    except Exception as e:
        return {"error": str(e), "ip": ip}

    if not row:
        return {
            "ip": ip,
            "device_class": "unknown",
            "confidence": 0.0,
            "vendor": None,
            "model_hint": None,
            "os_hint": None,
            "class_scores": {},
            "sources": [],
            "flow_count": 0,
            "observed_ports": {},
            "snmp_probed_at": None,
            "snmp_sysdescr": None,
        }
    try:
        class_scores = json.loads(row[7] or "{}")
    except Exception:
        class_scores = {}
    try:
        sources = json.loads(row[6] or "[]")
    except Exception:
        sources = []
    try:
        observed_ports = json.loads(row[9] or "{}")
    except Exception:
        observed_ports = {}
    return {
        "ip":            row[0],
        "device_class":  row[1],
        "vendor":        row[2],
        "model_hint":    row[3],
        "os_hint":       row[4],
        "confidence":    row[5] or 0.0,
        "sources":       sources,
        "class_scores":  class_scores,
        "flow_count":    row[8] or 0,
        "observed_ports": observed_ports,
        "first_seen":    row[10],
        "last_updated":  row[11],
        "snmp_probed_at": row[12],
        "snmp_sysdescr": row[13],
    }

@app.post("/api/classification/{ip:path}/probe-snmp")
async def probe_device_snmp(ip: str, body: dict = None):
    """
    Active SNMPv2c GET sysDescr.0 probe against `ip`. Synchronous,
    2-second timeout by default. Writes the result directly into
    device_classifications. Returns the updated classification.

    Body: {community: str = "public", timeout: float = 2.0}
    """
    body = body or {}
    community = str(body.get("community", "public"))
    try:
        timeout = float(body.get("timeout", 2.0))
    except (TypeError, ValueError):
        timeout = 2.0

    classifier = _get_classifier()
    result = classifier.snmp_probe(ip, community=community, timeout=timeout)

    # Broadcast so any open dashboard instantly updates
    await manager.broadcast({
        "type": "device_classification_updated",
        "ip": ip,
        "device_class": result.get("device_class"),
        "snmp_sysdescr": result.get("snmp_sysdescr"),
    })

    return {
        "status": "ok" if result.get("snmp_sysdescr") else "no_response",
        "classification": result,
    }

# Note: the uvicorn.run block was moved to the end of file so that
# ALL routes defined below (admin CRUD, UEBA, etc.) are registered
# before the server starts listening. Previously uvicorn.run() sat
# mid-file and blocked before those routes registered, leaving them
# dead. See the `if __name__ == "__main__":` block at EOF.

# ═══════════════════════════════════════════════════════════════
#  ADMIN CRUD ENDPOINTS
# ═══════════════════════════════════════════════════════════════

import re
from fastapi import HTTPException
from pydantic import BaseModel
from typing import Optional

# ── Models ────────────────────────────────────────────────────

class DepartmentModel(BaseModel):
    name      : str
    priority  : str = "medium"
    color     : str = "#60a5fa"
    subnet    : str = "0.0.0.0/0"
    icon      : str = "🏢"

class DeviceUpdateModel(BaseModel):
    hostname   : Optional[str] = ""
    notes      : Optional[str] = ""
    department : Optional[str] = ""
    priority   : Optional[str] = ""

class BlockModel(BaseModel):
    ip     : str
    reason : Optional[str] = ""

class IncidentModel(BaseModel):
    title      : str
    description: Optional[str] = ""
    severity   : Optional[str] = "HIGH"
    alert_ids  : Optional[list] = []
    src_ips    : Optional[list] = []

class IncidentUpdateModel(BaseModel):
    status     : Optional[str] = ""
    notes      : Optional[str] = ""
    title      : Optional[str] = ""
    assigned_to: Optional[str] = ""

# ── Blocklist helpers ─────────────────────────────────────────

BLOCKLIST_FILE = "blocklist.json"

def load_blocklist() -> dict:
    try:
        with open(BLOCKLIST_FILE, encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}

def save_blocklist(bl: dict):
    with open(BLOCKLIST_FILE, 'w', encoding='utf-8') as f:
        json.dump(bl, f, indent=2)

# ── Incidents DB ──────────────────────────────────────────────

INCIDENTS_DB = "incidents.db"

def init_incidents_db():
    conn = sqlite3.connect(INCIDENTS_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            description TEXT,
            severity    TEXT DEFAULT 'HIGH',
            status      TEXT DEFAULT 'open',
            alert_ids   TEXT DEFAULT '[]',
            src_ips     TEXT DEFAULT '[]',
            notes       TEXT DEFAULT '[]',
            assigned_to TEXT DEFAULT '',
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at  TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_incidents_db()

# ── Alert management columns ──────────────────────────────────

def ensure_alert_columns():
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        # Add ack/status columns if not exist
        try: conn.execute("ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'new'")
        except: pass
        try: conn.execute("ALTER TABLE alerts ADD COLUMN acknowledged_at TEXT")
        except: pass
        try: conn.execute("ALTER TABLE alerts ADD COLUMN acknowledged_by TEXT DEFAULT ''")
        except: pass
        conn.commit()
        conn.close()
    except: pass

ensure_alert_columns()

# ── DEPARTMENT CRUD ───────────────────────────────────────────

@app.post("/api/departments")
async def add_department(dept: DepartmentModel):
    """Add a new department to vlan_config.json."""
    try:
        with open(VLAN_CONFIG, encoding='utf-8') as f:
            cfg = json.load(f)

        # Find next available VLAN ID
        existing_ids = [int(k) for k in cfg["vlan_map"].keys()
                        if k.isdigit()]
        new_id = str(max(existing_ids) + 10 if existing_ids else 100)

        cfg["vlan_map"][new_id] = {
            "department": dept.name,
            "priority"  : dept.priority,
            "color"     : dept.color,
            "subnet"    : dept.subnet,
            "icon"      : dept.icon,
        }

        with open(VLAN_CONFIG, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)

        # Reload global config
        global VLAN_CFG
        VLAN_CFG = cfg

        # Broadcast update to dashboard clients
        await manager.broadcast({
            "type"   : "config_updated",
            "action" : "department_added",
            "name"   : dept.name,
        })

        return {"status": "ok", "vlan_id": new_id, "department": dept.name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/departments/{vlan_id}")
async def update_department(vlan_id: str, dept: DepartmentModel):
    """Edit an existing department."""
    try:
        with open(VLAN_CONFIG, encoding='utf-8') as f:
            cfg = json.load(f)

        if vlan_id not in cfg["vlan_map"]:
            raise HTTPException(status_code=404, detail="VLAN not found")

        cfg["vlan_map"][vlan_id].update({
            "department": dept.name,
            "priority"  : dept.priority,
            "color"     : dept.color,
            "subnet"    : dept.subnet,
            "icon"      : dept.icon,
        })

        with open(VLAN_CONFIG, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)

        global VLAN_CFG
        VLAN_CFG = cfg

        await manager.broadcast({
            "type"   : "config_updated",
            "action" : "department_updated",
            "name"   : dept.name,
        })

        return {"status": "ok"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/departments/{vlan_id}")
async def delete_department(vlan_id: str):
    """Delete a department (devices move to Unknown)."""
    try:
        with open(VLAN_CONFIG, encoding='utf-8') as f:
            cfg = json.load(f)

        if vlan_id not in cfg["vlan_map"]:
            raise HTTPException(status_code=404, detail="VLAN not found")

        name = cfg["vlan_map"][vlan_id]["department"]
        del cfg["vlan_map"][vlan_id]

        with open(VLAN_CONFIG, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)

        global VLAN_CFG
        VLAN_CFG = cfg

        await manager.broadcast({
            "type"   : "config_updated",
            "action" : "department_deleted",
            "name"   : name,
        })

        return {"status": "ok", "deleted": name}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/departments/config")
async def get_departments_config():
    """Get full VLAN config for admin editing."""
    try:
        with open(VLAN_CONFIG, encoding='utf-8') as f:
            cfg = json.load(f)
        return cfg
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── DEVICE MANAGEMENT ─────────────────────────────────────────

@app.put("/api/devices/{ip:path}")
async def update_device(ip: str, update: DeviceUpdateModel):
    """Update device hostname, notes, or manual department assignment."""
    try:
        conn = sqlite3.connect(KNOWN_DEVICES_DB, timeout=5)

        # Add columns if not exist
        try: conn.execute("ALTER TABLE known_devices ADD COLUMN hostname TEXT DEFAULT ''")
        except: pass
        try: conn.execute("ALTER TABLE known_devices ADD COLUMN notes TEXT DEFAULT ''")
        except: pass
        try: conn.execute("ALTER TABLE known_devices ADD COLUMN dept_override TEXT DEFAULT ''")
        except: pass

        # Check device exists
        row = conn.execute(
            "SELECT ip FROM known_devices WHERE ip=?", (ip,)
        ).fetchone()

        if not row:
            # Auto-register
            dept = get_department_for_ip(ip)
            now  = datetime.now().isoformat()
            conn.execute("""
                INSERT INTO known_devices
                (ip, first_seen, last_seen, department, priority, hostname, notes, dept_override)
                VALUES (?,?,?,?,?,?,?,?)
            """, (ip, now, now, dept["department"], dept["priority"],
                  update.hostname or "", update.notes or "",
                  update.department or ""))
        else:
            updates = []
            vals    = []
            if update.hostname  is not None: updates.append("hostname=?");     vals.append(update.hostname)
            if update.notes     is not None: updates.append("notes=?");        vals.append(update.notes)
            if update.department is not None: updates.append("dept_override=?"); vals.append(update.department)
            if update.priority  is not None: updates.append("priority=?");     vals.append(update.priority)
            if updates:
                vals.append(ip)
                conn.execute(
                    f"UPDATE known_devices SET {','.join(updates)} WHERE ip=?",
                    vals
                )

        conn.commit()
        conn.close()

        # Update in-memory registry
        dev = registry.get_device(ip)
        if dev:
            if update.hostname:   dev["hostname"]  = update.hostname
            if update.notes:      dev["notes"]     = update.notes
            if update.department: dev["department"] = update.department

        await manager.broadcast({
            "type"   : "device_updated",
            "ip"     : ip,
            "update" : update.dict(),
        })

        return {"status": "ok", "ip": ip}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── ALERT MANAGEMENT ─────────────────────────────────────────

@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int, body: dict = {}):
    """Mark an alert as acknowledged."""
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        now  = datetime.now().isoformat()
        by   = body.get("by", "admin")
        conn.execute("""
            UPDATE alerts
            SET status='acknowledged', acknowledged_at=?, acknowledged_by=?
            WHERE id=?
        """, (now, by, alert_id))
        conn.commit()
        conn.close()

        await manager.broadcast({
            "type"    : "alert_acknowledged",
            "alert_id": alert_id,
            "by"      : by,
            "at"      : now,
        })

        return {"status": "ok", "alert_id": alert_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/alerts/{alert_id}/false-positive")
async def false_positive(alert_id: int):
    """Mark an alert as a false positive."""
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        conn.execute(
            "UPDATE alerts SET status='false_positive' WHERE id=?",
            (alert_id,)
        )
        conn.commit()
        conn.close()

        await manager.broadcast({
            "type"    : "alert_false_positive",
            "alert_id": alert_id,
        })

        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── BLOCKLIST ─────────────────────────────────────────────────

@app.get("/api/blocklist")
async def get_blocklist():
    bl = load_blocklist()
    items = [{"ip":k,**v} for k,v in bl.items()]
    return {"blocklist": items, "count": len(items)}

@app.post("/api/blocklist")
async def block_ip(body: BlockModel):
    bl = load_blocklist()
    bl[body.ip] = {
        "reason"    : body.reason,
        "blocked_at": datetime.now().isoformat(),
    }
    save_blocklist(bl)

    await manager.broadcast({
        "type"  : "ip_blocked",
        "ip"    : body.ip,
        "reason": body.reason,
    })

    return {"status": "ok", "blocked": body.ip}

@app.delete("/api/blocklist/{ip:path}")
async def unblock_ip(ip: str):
    bl = load_blocklist()
    if ip not in bl:
        raise HTTPException(status_code=404, detail="IP not in blocklist")
    del bl[ip]
    save_blocklist(bl)

    await manager.broadcast({"type": "ip_unblocked", "ip": ip})

    return {"status": "ok", "unblocked": ip}

# ── INCIDENTS ─────────────────────────────────────────────────

@app.post("/api/incidents")
async def create_incident(inc: IncidentModel):
    try:
        conn = sqlite3.connect(INCIDENTS_DB, timeout=5)
        now  = datetime.now().isoformat()
        cur  = conn.execute("""
            INSERT INTO incidents
            (title, description, severity, status, alert_ids, src_ips, notes, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            inc.title, inc.description, inc.severity,
            "open",
            json.dumps(inc.alert_ids),
            json.dumps(inc.src_ips),
            json.dumps([{"text": "Incident created", "at": now}]),
            now, now
        ))
        new_id = cur.lastrowid
        conn.commit()
        conn.close()

        await manager.broadcast({
            "type"    : "incident_created",
            "id"      : new_id,
            "title"   : inc.title,
            "severity": inc.severity,
        })

        return {"status": "ok", "id": new_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/incidents")
async def list_incidents(status: str = ""):
    try:
        conn = sqlite3.connect(INCIDENTS_DB, timeout=5)
        if status:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE status=? ORDER BY id DESC",
                (status,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY id DESC"
            ).fetchall()
        conn.close()

        cols = ["id","title","description","severity","status",
                "alert_ids","src_ips","notes","assigned_to",
                "created_at","updated_at"]
        result = []
        for row in rows:
            d = dict(zip(cols, row))
            d["alert_ids"] = json.loads(d["alert_ids"] or "[]")
            d["src_ips"]   = json.loads(d["src_ips"]   or "[]")
            d["notes"]     = json.loads(d["notes"]      or "[]")
            result.append(d)
        return {"incidents": result, "count": len(result)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/incidents/{inc_id}")
async def update_incident(inc_id: int, upd: IncidentUpdateModel):
    try:
        conn = sqlite3.connect(INCIDENTS_DB, timeout=5)
        now  = datetime.now().isoformat()

        if upd.notes:
            row = conn.execute(
                "SELECT notes FROM incidents WHERE id=?", (inc_id,)
            ).fetchone()
            existing = json.loads(row[0] or "[]") if row else []
            existing.append({"text": upd.notes, "at": now})
            conn.execute(
                "UPDATE incidents SET notes=?, updated_at=? WHERE id=?",
                (json.dumps(existing), now, inc_id)
            )

        if upd.status:
            conn.execute(
                "UPDATE incidents SET status=?, updated_at=? WHERE id=?",
                (upd.status, now, inc_id)
            )

        if upd.title:
            conn.execute(
                "UPDATE incidents SET title=?, updated_at=? WHERE id=?",
                (upd.title, now, inc_id)
            )

        if upd.assigned_to:
            conn.execute(
                "UPDATE incidents SET assigned_to=?, updated_at=? WHERE id=?",
                (upd.assigned_to, now, inc_id)
            )

        conn.commit()
        conn.close()

        await manager.broadcast({
            "type": "incident_updated",
            "id"  : inc_id,
        })

        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── SEARCH ────────────────────────────────────────────────────

@app.get("/api/search")
async def search(q: str = "", limit: int = 20):
    """Search across devices, alerts, and incidents."""
    if not q or len(q) < 2:
        return {"results": []}

    results = []
    q_lower = q.lower()

    # Search devices
    for dev in registry.get_all():
        if (q_lower in dev["ip"].lower() or
            q_lower in (dev.get("hostname") or "").lower() or
            q_lower in (dev.get("department") or "").lower()):
            results.append({"type":"device", **dev})

    # Search alerts
    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        # Limit search scope to recent alerts for speed on large DBs
        max_id_row = conn.execute("SELECT MAX(id) FROM alerts").fetchone()
        max_id = (max_id_row[0] or 0)
        cutoff_id = max(0, max_id - 20000)
        rows = conn.execute("""
            SELECT id, timestamp, severity, attack_type, src_ip
            FROM alerts
            WHERE id > ? AND (src_ip LIKE ? OR attack_type LIKE ?)
            ORDER BY id DESC LIMIT ?
        """, (cutoff_id, f"%{q}%", f"%{q}%", limit)).fetchall()
        conn.close()
        for row in rows:
            dept = get_department_for_ip(row[4] or "")
            results.append({
                "type"       : "alert",
                "id"         : row[0],
                "timestamp"  : row[1],
                "severity"   : row[2],
                "attack_type": row[3],
                "src_ip"     : row[4],
                "department" : dept["department"],
            })
    except:
        pass

    return {"results": results[:limit], "count": len(results)}

# ── TRAFFIC STATS (for real-time sparklines) ──────────────────

@app.get("/api/stats/hourly")
async def hourly_stats():
    """Alert counts by hour for the last 24 hours; optimized."""
    try:
        conn  = sqlite3.connect(ALERTS_DB, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")
        # Use id-based range for speed on large DBs
        max_id = conn.execute("SELECT MAX(id) FROM alerts").fetchone()[0] or 0
        cutoff_id = max(0, max_id - 50000)
        rows  = conn.execute("""
            SELECT strftime('%H', timestamp) as hour,
                   severity, COUNT(*) as cnt
            FROM alerts
            WHERE id > ?
            GROUP BY hour, severity
            ORDER BY hour
        """, (cutoff_id,)).fetchall()
        conn.close()

        hours = {str(h).zfill(2): {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
                 for h in range(24)}
        for row in rows:
            if row[0] in hours and row[1] in hours[row[0]]:
                hours[row[0]][row[1]] = row[2]

        return {"hourly": hours}
    except Exception as e:
        return {"hourly": {}, "error": str(e)}

# ── Range-bounded analytics ───────────────────────────────────
#
# A single endpoint that the dashboard hits once per date-range
# change. Returns everything needed to paint every chart on the
# analytics page; timeseries, top N attack types, top src IPs,
# top dst ports, severity totals, unique device count. One round
# trip. The bucket param picks hour-level or day-level resolution.

@app.get("/api/stats/range")
async def stats_range(
    from_: str = Query("", alias="from"),
    to:    str = "",
    bucket: str = "hour",   # "hour" or "day"
):
    """
    Aggregate analytics for an arbitrary time window.

    Default range: last 24 hours if no from/to given.
    bucket = hour  →  strftime('%Y-%m-%dT%H:00')
    bucket = day   →  strftime('%Y-%m-%d')
    """
    from datetime import timedelta
    now = datetime.now()
    try:
        t_to = (datetime.fromisoformat(to.replace("Z", "+00:00"))
                 if to else now)
    except Exception:
        t_to = now
    try:
        t_from = (datetime.fromisoformat(from_.replace("Z", "+00:00"))
                   if from_ else t_to - timedelta(hours=24))
    except Exception:
        t_from = t_to - timedelta(hours=24)

    from_iso = t_from.isoformat()
    to_iso   = t_to.isoformat()

    bucket_fmt = "%Y-%m-%d" if bucket == "day" else "%Y-%m-%dT%H:00"

    try:
        conn = sqlite3.connect(ALERTS_DB, timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")

        # ── Timeseries (bucket → per-severity counts) ──
        rows = conn.execute(f"""
            SELECT strftime('{bucket_fmt}', timestamp) AS bkt,
                   severity, COUNT(*) AS cnt
            FROM alerts
            WHERE timestamp >= ? AND timestamp < ?
            GROUP BY bkt, severity
            ORDER BY bkt
        """, (from_iso, to_iso)).fetchall()

        ts_map: Dict[str, Dict[str, int]] = {}
        for bkt, sev, cnt in rows:
            ts_map.setdefault(bkt, {
                "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
            })
            if sev in ts_map[bkt]:
                ts_map[bkt][sev] = cnt
        timeseries = [
            {"bucket": b, **ts_map[b]} for b in sorted(ts_map.keys())
        ]

        # ── Top attack types ──
        top_attack = conn.execute("""
            SELECT attack_type, COUNT(*) AS c
            FROM alerts
            WHERE timestamp >= ? AND timestamp < ?
              AND attack_type != ''
            GROUP BY attack_type
            ORDER BY c DESC LIMIT 10
        """, (from_iso, to_iso)).fetchall()

        # ── Top src IPs ──
        top_src = conn.execute("""
            SELECT src_ip, COUNT(*) AS c
            FROM alerts
            WHERE timestamp >= ? AND timestamp < ?
              AND src_ip != ''
            GROUP BY src_ip
            ORDER BY c DESC LIMIT 10
        """, (from_iso, to_iso)).fetchall()

        # ── Top dst ports ──
        top_dst_port = conn.execute("""
            SELECT dst_port, COUNT(*) AS c
            FROM alerts
            WHERE timestamp >= ? AND timestamp < ?
              AND dst_port > 0
            GROUP BY dst_port
            ORDER BY c DESC LIMIT 10
        """, (from_iso, to_iso)).fetchall()

        # ── Top tags (which layer fired) ──
        top_tag = conn.execute("""
            SELECT tag, COUNT(*) AS c
            FROM alerts
            WHERE timestamp >= ? AND timestamp < ?
              AND tag != ''
            GROUP BY tag
            ORDER BY c DESC LIMIT 10
        """, (from_iso, to_iso)).fetchall()

        # ── Summary totals ──
        by_sev = conn.execute("""
            SELECT severity, COUNT(*) AS c
            FROM alerts
            WHERE timestamp >= ? AND timestamp < ?
            GROUP BY severity
        """, (from_iso, to_iso)).fetchall()
        sev_counts = {r[0]: r[1] for r in by_sev}

        total = sum(sev_counts.values())
        unique_src = conn.execute("""
            SELECT COUNT(DISTINCT src_ip) FROM alerts
            WHERE timestamp >= ? AND timestamp < ? AND src_ip != ''
        """, (from_iso, to_iso)).fetchone()[0] or 0

        conn.close()

        return {
            "from": from_iso,
            "to":   to_iso,
            "bucket": bucket,
            "summary": {
                "total": total,
                "CRITICAL": sev_counts.get("CRITICAL", 0),
                "HIGH":     sev_counts.get("HIGH", 0),
                "MEDIUM":   sev_counts.get("MEDIUM", 0),
                "LOW":      sev_counts.get("LOW", 0),
                "unique_src_ips": unique_src,
            },
            "timeseries":       timeseries,
            "top_attack_types": [{"name": r[0], "count": r[1]} for r in top_attack],
            "top_src_ips":      [{"ip":   r[0], "count": r[1]} for r in top_src],
            "top_dst_ports":    [{"port": r[0], "count": r[1]} for r in top_dst_port],
            "top_tags":         [{"tag":  r[0], "count": r[1]} for r in top_tag],
        }
    except Exception as e:
        return {"error": str(e)}

# ═══════════════════════════════════════════════════════════════
#  UEBA v2 API ENDPOINTS
# ═══════════════════════════════════════════════════════════════

UEBA_V2_DB = str(_PROJECT_ROOT / "ueba_v2.db")

def _ueba_conn():
    import sqlite3
    conn = sqlite3.connect(UEBA_V2_DB, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

@app.get("/api/ueba/entities")
async def get_ueba_entities(
    min_score: float = 0,
    limit: int = 100,
    dept: str = ""
):
    """Top entities by UEBA risk score."""
    try:
        conn  = _ueba_conn()
        query = """
            SELECT ip, department, priority, first_seen, last_seen,
                   total_flows, total_alerts, risk_score, baseline_ready,
                   peer_group_id, hostname, is_iot
            FROM entities
            WHERE risk_score >= ?
            {}
            ORDER BY risk_score DESC
            LIMIT ?
        """.format("AND department=?" if dept else "")
        params = [min_score, dept, limit] if dept else [min_score, limit]
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return {"entities": [dict(r) for r in rows], "count": len(rows)}
    except Exception as e:
        return {"entities": [], "error": str(e)}

@app.get("/api/ueba/entity/{ip:path}")
async def get_ueba_entity(ip: str):
    """Full entity profile + risk history."""
    try:
        conn   = _ueba_conn()
        entity = conn.execute(
            "SELECT * FROM entities WHERE ip=?", (ip,)
        ).fetchone()

        if not entity:
            return {"error": "Entity not found"}

        events = conn.execute("""
            SELECT ts, delta_score, reason
            FROM risk_events
            WHERE ip=? ORDER BY ts DESC LIMIT 20
        """, (ip,)).fetchall()

        features = conn.execute("""
            SELECT ts, features, anomaly_score
            FROM entity_features
            WHERE ip=? ORDER BY ts DESC LIMIT 50
        """, (ip,)).fetchall()

        conn.close()

        return {
            "entity"        : dict(entity),
            "risk_events"   : [dict(e) for e in events],
            "feature_history": [dict(f) for f in features],
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/ueba/stats")
async def get_ueba_stats():
    """UEBA v2 engine statistics."""
    try:
        conn = _ueba_conn()
        totals = conn.execute("""
            SELECT
              COUNT(*) as total_entities,
              COUNT(CASE WHEN baseline_ready=1 THEN 1 END) as entities_ready,
              COUNT(CASE WHEN risk_score >= 65 THEN 1 END) as high_risk,
              COUNT(CASE WHEN risk_score >= 80 THEN 1 END) as critical_risk,
              AVG(risk_score) as avg_risk_score,
              MAX(risk_score) as max_risk_score,
              SUM(total_flows) as total_flows_processed
            FROM entities
        """).fetchone()

        recent_events = conn.execute("""
            SELECT COUNT(*) as cnt FROM risk_events
            WHERE ts > ?
        """, (time.time() - 3600,)).fetchone()

        depts = conn.execute("""
            SELECT department,
                   COUNT(*) as entities,
                   AVG(risk_score) as avg_risk,
                   MAX(risk_score) as max_risk
            FROM entities
            GROUP BY department
            ORDER BY avg_risk DESC
        """).fetchall()

        conn.close()

        return {
            "totals"        : dict(totals) if totals else {},
            "risk_events_1h": recent_events[0] if recent_events else 0,
            "by_department" : [dict(d) for d in depts],
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/ueba/risk-scores")
async def get_risk_scores_timeline(ip: str = "", hours: int = 24):
    """Risk score history for sparklines/timeline."""
    try:
        conn = _ueba_conn()
        since = time.time() - hours * 3600

        if ip:
            rows = conn.execute("""
                SELECT ts, delta_score, reason
                FROM risk_events
                WHERE ip=? AND ts > ?
                ORDER BY ts ASC
                LIMIT 200
            """, (ip, since)).fetchall()
        else:
            rows = conn.execute("""
                SELECT ip, ts, delta_score, reason
                FROM risk_events
                WHERE ts > ?
                ORDER BY ts DESC
                LIMIT 500
            """, (since,)).fetchall()

        conn.close()
        return {"events": [dict(r) for r in rows]}
    except Exception as e:
        return {"events": [], "error": str(e)}

@app.get("/api/ueba/device-baselines")
async def get_ueba_device_baselines():
    """In-progress per-device behavioural baselines from ueba_long_state.json.
    Joined with known_devices.db for hostname/vendor enrichment.
    Coverage is rescaled to the dataset's natural span (max-min observed),
    so a device seen end-to-end across the capture shows 100%; useful for
    forensic-replay screenshots where the 14-day target is meaningless.
    """
    import json as _json
    state_path = "/home/sohamm/sentrix/ueba_long_state.json"
    known_path = "/home/sohamm/sentrix/known_devices.db"
    try:
        with open(state_path, "r") as f:
            d = _json.load(f)
        devices = d.get("devices", {})

        # Build hostname/vendor lookup from known_devices.db
        host_map = {}
        try:
            kconn = sqlite3.connect(known_path, timeout=5)
            for ip, hostname, vendor, os_ in kconn.execute(
                "SELECT ip, hostname, vendor, os FROM known_devices"
            ).fetchall():
                host_map[ip] = {
                    "hostname": (hostname or "").strip(),
                    "vendor":   (vendor or "").strip(),
                    "os":       (os_ or "").strip(),
                }
            kconn.close()
        except Exception:
            pass

        # Compute dataset span: union of [first_seen, last_seen] across devices.
        # Coverage = device_observed_seconds / dataset_span_seconds
        all_first = []
        all_last  = []
        for dev in devices.values():
            fs = float(dev.get("first_seen", 0))
            ls = float(dev.get("last_seen", 0))
            if fs > 0: all_first.append(fs)
            if ls > 0: all_last.append(ls)
        ds_start = min(all_first) if all_first else 0
        ds_end   = max(all_last)  if all_last  else 0
        ds_span  = max(1.0, ds_end - ds_start)  # avoid div-by-zero

        out = []
        for ip, dev in devices.items():
            n_flows = int(dev.get("total_flows", 0))
            first_seen = float(dev.get("first_seen", 0))
            last_seen  = float(dev.get("last_seen", 0))
            observed = max(0.0, last_seen - first_seen)
            coverage_pct = min(100.0, 100.0 * observed / (14 * 86400))  # 14-day baseline target
            stats = dev.get("stats", {})
            features = {}
            for fname, fstat in stats.items():
                n = int(fstat.get("n", 0))
                mean = float(fstat.get("mean", 0))
                m2 = float(fstat.get("M2", 0))
                stdev = (m2 / n) ** 0.5 if n > 1 else 0.0
                features[fname] = {"mean": round(mean, 4), "stdev": round(stdev, 4)}
            host_info = host_map.get(ip, {})
            out.append({
                "ip": ip,
                "hostname": host_info.get("hostname", ""),
                "vendor":   host_info.get("vendor", ""),
                "os":       host_info.get("os", ""),
                "total_flows": n_flows,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "observed_seconds": observed,
                "coverage_pct": round(coverage_pct, 1),
                "features": features,
            })
        out.sort(key=lambda x: -x["total_flows"])
        return {
            "devices": out,
            "count": len(out),
            "dataset_span_seconds": ds_span,
            "dataset_start": ds_start,
            "dataset_end": ds_end,
        }
    except Exception as e:
        return {"devices": [], "count": 0, "error": str(e)}

@app.get("/api/ueba/peer-groups")
async def get_peer_groups():
    """Summary of peer group distribution."""
    try:
        conn = _ueba_conn()
        groups = conn.execute("""
            SELECT peer_group_id,
                   department,
                   COUNT(*) as member_count,
                   AVG(risk_score) as avg_risk,
                   MAX(risk_score) as max_risk
            FROM entities
            WHERE peer_group_id >= 0
            GROUP BY peer_group_id, department
            ORDER BY avg_risk DESC
        """).fetchall()
        conn.close()
        return {"groups": [dict(g) for g in groups]}
    except Exception as e:
        return {"groups": [], "error": str(e)}

# ═══════════════════════════════════════════════════════════════
#  CUSTOM CLUSTER API ENDPOINTS
# ═══════════════════════════════════════════════════════════════

def _get_cluster_mgr():
    """Cluster manager removed; ueba_core.py no longer exists."""
    return None

@app.get("/api/ueba/clusters")
async def get_clusters(include_dissolved: bool = False):
    """List all active custom clusters."""
    mgr = _get_cluster_mgr()
    if not mgr:
        return {"clusters": [], "error": "Cluster manager unavailable"}
    clusters = mgr.get_all_clusters()
    result   = {"clusters": clusters, "count": len(clusters)}
    if include_dissolved:
        result["dissolved"] = mgr.get_dissolved_clusters()
    return result

@app.post("/api/ueba/clusters")
async def create_cluster(request: Request):
    """Create a new custom cluster."""
    body = await request.json()
    name = body.get("name", "").strip()
    if not name:
        return {"error": "Cluster name is required"}
    mgr = _get_cluster_mgr()
    if not mgr:
        return {"error": "Cluster manager unavailable"}
    cid = mgr.create_cluster(
        name        = name,
        department  = body.get("department", ""),
        project     = body.get("project", ""),
        description = body.get("description", ""),
        created_by  = body.get("created_by", "admin"),
    )
    # Add initial devices if provided
    for ip in body.get("devices", []):
        mgr.add_device(cid, ip)
    return {"cluster_id": cid, "name": name, "success": True}

@app.put("/api/ueba/clusters/{cluster_id}/devices")
async def manage_cluster_devices(cluster_id: int, request: Request):
    """Add or remove devices from a cluster."""
    body   = await request.json()
    action = body.get("action", "add")   # "add" or "remove"
    ips    = body.get("ips", [])
    mgr    = _get_cluster_mgr()
    if not mgr:
        return {"error": "Cluster manager unavailable"}
    results = []
    for ip in ips:
        if action == "add":
            ok = mgr.add_device(cluster_id, ip, body.get("by", "admin"))
        else:
            ok = mgr.remove_device(cluster_id, ip)
        results.append({"ip": ip, "success": ok})
    return {"results": results, "action": action}

@app.delete("/api/ueba/clusters/{cluster_id}")
async def dissolve_cluster(cluster_id: int):
    """Dissolve a cluster. Devices return to automatic peer groups."""
    mgr = _get_cluster_mgr()
    if not mgr:
        return {"error": "Cluster manager unavailable"}
    cluster = mgr.get_cluster(cluster_id)
    if not cluster:
        return {"error": "Cluster not found or already dissolved"}
    name    = cluster.get("name", "")
    members = len(cluster.get("members", []))
    ok      = mgr.dissolve_cluster(cluster_id)
    return {
        "success"     : ok,
        "dissolved"   : name,
        "members_freed": members,
        "message"     : f"'{name}' dissolved; {members} devices returned to automatic groups",
    }

@app.get("/api/ueba/clusters/{cluster_id}/alerts")
async def get_cluster_alerts(cluster_id: int, limit: int = 50):
    """Get anomaly alerts fired within a specific cluster."""
    mgr = _get_cluster_mgr()
    if not mgr:
        return {"alerts": []}
    return {"alerts": mgr.get_cluster_alerts(cluster_id, limit)}

@app.get("/api/ueba/device/{ip}/clusters")
async def get_device_clusters(ip: str):
    """Get all clusters a device belongs to."""
    mgr = _get_cluster_mgr()
    if not mgr:
        return {"clusters": []}
    return {"clusters": mgr.get_device_clusters(ip)}

# ═══════════════════════════════════════════════════════════════
#  DPDPA COMPLIANCE ENDPOINTS
# ═══════════════════════════════════════════════════════════════

try:
    from dpdpa_compliance import DPDPACompliance
    _dpdpa = DPDPACompliance(db_path=ALERTS_DB)
except Exception as _e:
    print(f"[Dashboard] DPDPA init failed: {type(_e).__name__}: {_e}")
    _dpdpa = None

@app.post("/api/dpdpa/maintenance")
async def dpdpa_maintenance():
    if not _dpdpa:
        return {"error": "DPDPA module not available"}
    result = _dpdpa.run_maintenance()
    return {"status": "ok", **result}

@app.get("/api/dpdpa/export/{ip:path}")
async def dpdpa_export(ip: str):
    if not _dpdpa:
        return {"error": "DPDPA module not available"}
    records = _dpdpa.export_data_subject(ip)
    return {"ip": ip, "record_count": len(records), "records": records}

@app.delete("/api/dpdpa/delete/{ip:path}")
async def dpdpa_delete(ip: str):
    if not _dpdpa:
        return {"error": "DPDPA module not available"}
    count = _dpdpa.delete_data_subject(ip)
    return {"ip": ip, "deleted": count}

# ═══════════════════════════════════════════════════════════════
#  ENTRY POINT  (must come after all @app.* route definitions)
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  SOC DASHBOARD SERVER")
    print("="*60)
    print(f"  Dashboard : http://localhost:{PORT}")
    print(f"  API       : http://localhost:{PORT}/api/summary")
    print(f"  WebSocket : ws://localhost:{PORT}/ws")
    print("="*60 + "\n")

    uvicorn.run(
        app,
        host      = HOST,
        port      = PORT,
        log_level = "warning",
    )
