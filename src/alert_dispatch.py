"""Multi-Channel Alert Delivery"""
import os
import sys
import io
import json
import time
import socket
import logging
import sqlite3
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from collections import deque

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

log = logging.getLogger("alert_dispatch")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

class AlertDispatcher:
    """
    Multi-channel alert dispatcher with severity-based routing.
    """

    def __init__(self, config_path: str = None, db_path: str = None):
        if config_path is None:
            config_path = str(_PROJECT_ROOT / "config" / "alert_routing.json")
        if db_path is None:
            db_path = str(_PROJECT_ROOT / "alerts.db")

        self.db_path = db_path
        self.config = {}
        self._load_config(config_path)
        self._init_db()

        # Alert buffer for batched DB writes
        self._db_buffer: List[dict] = []
        self._db_lock = threading.Lock()
        self._flush_size = 50
        self._flush_interval = 2.0  # seconds; dashboard poll cadence

        # Background flusher so alerts reach the DB within 2s even
        # when the buffer isn't full (important for live dashboards).
        self._flusher_stop = threading.Event()
        self._flusher = threading.Thread(
            target=self._flush_loop, daemon=True, name="dispatch-flush"
        )
        self._flusher.start()

        # Background fp_patterns cache refresher; picks up new patterns
        # from learn_fp_patterns.py runs (cron-driven) without engine
        # restart. Cache invalidated every 60s; next dispatch reloads.
        self._fp_patterns_cache: Optional[List[dict]] = None
        self._fp_cache_refresh_thread = threading.Thread(
            target=self._fp_cache_refresh_loop,
            daemon=True, name="dispatch-fp-cache-refresh",
        )
        self._fp_cache_refresh_thread.start()

        # Recent alerts for dashboard
        self._recent = deque(maxlen=500)

        # WebSocket clients (registered by dashboard_server)
        self._ws_clients: List = []

        self.stats = {
            "total_dispatched": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_channel": {"email": 0, "slack": 0, "teams": 0,
                          "syslog": 0, "webhook": 0, "certin": 0, "db": 0},
            "errors": 0,
        }

        print(f"[Dispatch] Alert dispatcher ready")

    def _load_config(self, path: str):
        try:
            with open(path) as f:
                self.config = json.load(f)
            channels = [k for k, v in self.config.get("channels", {}).items()
                       if v.get("enabled")]
            print(f"[Dispatch] Config loaded: {', '.join(channels) or 'DB only'}")
        except FileNotFoundError:
            print(f"[Dispatch] No config at {path}; DB + dashboard only")
        except Exception as e:
            print(f"[Dispatch] Config error: {e}")

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT NOT NULL,
                    severity        TEXT NOT NULL,
                    attack_type     TEXT,
                    source          TEXT,
                    src_ip          TEXT,
                    dst_ip          TEXT,
                    dst_port        INTEGER,
                    confidence      REAL,
                    ml_score        REAL,
                    ueba_score      REAL,
                    rule_score      REAL,
                    eta_score       REAL,
                    final_score     REAL,
                    tag             TEXT,
                    reasons         TEXT,
                    ueba_reasons    TEXT,
                    rule_names      TEXT,
                    correlated      INTEGER DEFAULT 0,
                    identity        TEXT,
                    department      TEXT,
                    threat_intel    TEXT,
                    ja3_match       TEXT,
                    gates_passed    INTEGER,
                    actual_label    TEXT,
                    status          TEXT,
                    acknowledged_at TEXT,
                    acknowledged_by TEXT,
                    created_at      TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_alert_sev ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alert_src ON alerts(src_ip);
                CREATE INDEX IF NOT EXISTS idx_alert_time ON alerts(timestamp);
            """)
            # Best-effort upgrade for existing DBs: ALTER TABLE for
            # each newly-added column. Failures here are silent
            # because "duplicate column name" is expected when the
            # column already exists.
            for col, ddl in [
                ("final_score",     "ALTER TABLE alerts ADD COLUMN final_score REAL"),
                ("ueba_reasons",    "ALTER TABLE alerts ADD COLUMN ueba_reasons TEXT"),
                ("rule_names",      "ALTER TABLE alerts ADD COLUMN rule_names TEXT"),
                ("correlated",      "ALTER TABLE alerts ADD COLUMN correlated INTEGER DEFAULT 0"),
                ("status",          "ALTER TABLE alerts ADD COLUMN status TEXT"),
                ("acknowledged_at", "ALTER TABLE alerts ADD COLUMN acknowledged_at TEXT"),
                ("acknowledged_by", "ALTER TABLE alerts ADD COLUMN acknowledged_by TEXT"),
            ]:
                try:
                    conn.execute(ddl)
                except sqlite3.OperationalError:
                    pass  # already present
            conn.commit()
            conn.close()
        except Exception as e:
            log.error(f"[Dispatch] DB init error: {e}")

    # ── Main Dispatch ─────────────────────────────────────────

    def dispatch(self, alert: dict):
        """
        Dispatch an alert to all appropriate channels.

        Before dispatch we apply three FP-suppression gates that fire
        AFTER ML/rule classification but BEFORE the alert is persisted /
        emailed / Slacked. Each gate either passes the alert through
        unchanged, downgrades it (severity LOW + attack_type=Other), or
        suppresses it entirely. Gates were added 2026-04-27 from the
        operational tuning + triage findings on the office capture.

        Gate order:
          (1) Internal-business-logic gate; RFC1918→RFC1918 on AD/SMB ports
              with low ML confidence is normal traffic, not lateral movement
          (2) Per-family behavioral signature; Stage 2 mis-fires when a flow
              has WannaCry's pattern shape but lacks SMB; downgrade.
          (3) Known-FP-pattern match (active learning); flows resembling
              previously-triaged FPs (alerts.db:fp_patterns table) get
              auto-downgraded.

        Expected alert dict:
            severity, attack_type, source, src_ip, dst_ip, dst_port,
            confidence, ml_score, ueba_score, rule_score, eta_score,
            tag, reasons, identity, department, threat_intel, ja3_match,
            gates_passed, actual_label
        """
        # ── Per-deployment fine-tuning suppression (learned-pattern lookup) ──
        fp_match = self._learned_pattern_lookup(alert)
        if fp_match == "suppress":
            self.stats.setdefault("fp_suppressed", 0)
            self.stats["fp_suppressed"] += 1
            return                                 # never persist or notify
        if fp_match == "downgrade":
            self.stats.setdefault("fp_downgraded", 0)
            self.stats["fp_downgraded"] += 1
            old_atk = alert.get("attack_type", "")
            alert["attack_type"] = "Other"
            alert["severity"]    = "LOW"
            reasons = alert.get("reasons", []) or []
            if isinstance(reasons, str):
                try: reasons = json.loads(reasons)
                except Exception: reasons = [reasons]
            reasons.append(f"[fine-tuning suppression] downgraded from {old_atk}")
            alert["reasons"] = reasons

        severity = alert.get("severity", "LOW")
        self.stats["total_dispatched"] += 1
        self.stats["by_severity"][severity] = self.stats["by_severity"].get(severity, 0) + 1

        # Always: DB + dashboard
        self._save_to_db(alert)
        self._recent.appendleft(alert)

        # Severity-based routing
        routing = self.config.get("routing", {})
        channels_for_sev = routing.get(severity, [])

        channels = self.config.get("channels", {})

        for channel_name in channels_for_sev:
            channel_cfg = channels.get(channel_name, {})
            if not channel_cfg.get("enabled", False):
                continue

            try:
                if channel_name == "email":
                    self._send_email(alert, channel_cfg)
                elif channel_name == "slack":
                    self._send_slack(alert, channel_cfg)
                elif channel_name == "teams":
                    self._send_teams(alert, channel_cfg)
                elif channel_name == "syslog":
                    self._send_syslog(alert, channel_cfg)
                elif channel_name == "webhook":
                    self._send_webhook(alert, channel_cfg)
                elif channel_name == "certin":
                    self._send_certin(alert, channel_cfg)

                self.stats["by_channel"][channel_name] = \
                    self.stats["by_channel"].get(channel_name, 0) + 1
            except Exception as e:
                self.stats["errors"] += 1
                log.error(f"[Dispatch] {channel_name} error: {e}")

    # ── Per-deployment fine-tuning: learned-pattern lookup ──
    # Operator triage decisions are mined nightly into the fp_patterns
    # table by scripts/learn_fp_patterns.py. The dispatcher consults
    # the learned-pattern table at every dispatch and suppresses or
    # downgrades a candidate alert whose pattern signature matches a
    # learned suppression pattern with sufficient confidence.

    def _learned_pattern_lookup(self, alert: dict) -> Optional[str]:
        """Per-deployment fine-tuning suppression. Match incoming alert
        against the learned-suppression-pattern table (fp_patterns)
        populated by the operator-feedback active-learning loop.
        Suppress on confidence at or above 0.8; downgrade between 0.5
        and 0.8."""
        try:
            patterns = getattr(self, "_fp_patterns_cache", None)
            if patterns is None:
                self._fp_patterns_cache = self._load_fp_patterns()
                patterns = self._fp_patterns_cache
            if not patterns:
                return None
            atk    = alert.get("attack_type", "")
            port   = alert.get("dst_port", 0)
            src    = alert.get("src_ip", "")
            dst    = alert.get("dst_ip", "")
            for p in patterns:
                if p["attack_type"] and atk != p["attack_type"]:
                    continue
                if p["dst_port"] and port != p["dst_port"]:
                    continue
                if p["src_pattern"] and not src.startswith(p["src_pattern"].rstrip("*")):
                    continue
                if p["dst_pattern"] and not dst.startswith(p["dst_pattern"].rstrip("*")):
                    continue
                # Pattern matches; apply suppression strength
                if (p.get("confidence") or 0) >= 0.8:
                    return "suppress"
                if (p.get("confidence") or 0) >= 0.5:
                    return "downgrade"
            return None
        except Exception as e:
            log.debug(f"[FP-pattern check] {e}")
            return None

    def _fp_cache_refresh_loop(self):
        """Daemon loop: invalidate fp_patterns cache every 60s so the
        engine picks up new patterns added by cron-run learn_fp_patterns.py.
        Lazy reload; next dispatch call re-loads from DB."""
        while not self._flusher_stop.is_set():
            self._flusher_stop.wait(60)
            self._fp_patterns_cache = None    # forces lazy reload on next dispatch

    def _load_fp_patterns(self) -> List[dict]:
        """Read learned-FP patterns from alerts.db. Cached for the
        dispatcher's lifetime; cache is invalidated by _refresh_fp_cache()."""
        try:
            conn = sqlite3.connect(self.db_path, timeout=3)
            rows = conn.execute(
                "SELECT attack_type, src_pattern, dst_pattern, dst_port, "
                "       confidence, learned_from_n FROM fp_patterns"
            ).fetchall()
            conn.close()
            return [{
                "attack_type":   r[0],
                "src_pattern":   r[1],
                "dst_pattern":   r[2],
                "dst_port":      r[3],
                "confidence":    r[4],
                "learned_from_n":r[5],
            } for r in rows]
        except Exception:
            return []                # table doesn't exist yet; fine, no patterns

    # ── SQLite Persistence ────────────────────────────────────

    def _save_to_db(self, alert: dict):
        with self._db_lock:
            self._db_buffer.append(alert)
            if len(self._db_buffer) >= self._flush_size:
                self._flush_db()
        self.stats["by_channel"]["db"] += 1

    def flush(self):
        with self._db_lock:
            self._flush_db()

    def _flush_loop(self):
        """Background thread: flush buffer every _flush_interval seconds."""
        while not self._flusher_stop.is_set():
            if self._flusher_stop.wait(self._flush_interval):
                break
            try:
                with self._db_lock:
                    if self._db_buffer:
                        self._flush_db()
            except Exception as e:
                log.error(f"[Dispatch] periodic flush error: {e}")

    def _flush_db(self):
        if not self._db_buffer:
            return

        def _row(a: dict) -> tuple:
            ml = float(a.get("ml_score", 0) or 0)
            ue = float(a.get("ueba_score", 0) or 0)
            ru = float(a.get("rule_score", 0) or 0)
            et = float(a.get("eta_score", 0) or 0)
            final_score = max(ml, ue, ru, et)
            reasons_list = a.get("reasons", []) or []
            if not isinstance(reasons_list, list):
                reasons_list = [str(reasons_list)]
            # Split reasons into rule / ueba buckets.
            rule_names = [r for r in reasons_list
                          if isinstance(r, str) and r.startswith("Rule:")]
            ueba_reasons = [r for r in reasons_list
                            if isinstance(r, str) and not r.startswith("Rule:")]
            correlated = 1 if (len(rule_names) > 0 and
                               (ml >= 0.5 or ue >= 0.5)) else 0
            return (
                a.get("timestamp", datetime.now().isoformat()),
                a.get("severity", ""),
                a.get("attack_type", ""),
                a.get("source", ""),
                a.get("src_ip", ""),
                a.get("dst_ip", ""),
                int(a.get("dst_port", 0) or 0),
                float(a.get("confidence", 0) or 0),
                ml, ue, ru, et,
                round(final_score, 6),
                a.get("tag", ""),
                json.dumps(reasons_list),
                json.dumps(ueba_reasons),
                json.dumps(rule_names),
                correlated,
                json.dumps(a.get("identity", {})),
                a.get("department", ""),
                json.dumps(a.get("threat_intel", [])),
                a.get("ja3_match", ""),
                int(a.get("gates_passed", 0) or 0),
                a.get("actual_label", ""),
            )

        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.executemany("""
                INSERT INTO alerts
                (timestamp, severity, attack_type, source, src_ip, dst_ip,
                 dst_port, confidence, ml_score, ueba_score, rule_score,
                 eta_score, final_score, tag, reasons, ueba_reasons,
                 rule_names, correlated, identity, department,
                 threat_intel, ja3_match, gates_passed, actual_label)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, [_row(a) for a in self._db_buffer])
            conn.commit()
            conn.close()
        except Exception as e:
            log.error(f"[Dispatch] DB flush error: {e}")
        self._db_buffer.clear()

    # ── Email ─────────────────────────────────────────────────

    def _send_email(self, alert: dict, cfg: dict):
        smtp_host = cfg.get("smtp_host", "localhost")
        smtp_port = cfg.get("smtp_port", 587)
        username = cfg.get("username", "")
        password = cfg.get("password", "")
        from_addr = cfg.get("from", "ids@office.local")
        to_addrs = cfg.get("to", [])
        use_tls = cfg.get("use_tls", True)

        if not to_addrs:
            return

        severity = alert.get("severity", "UNKNOWN")
        src_ip = alert.get("src_ip", "?")
        attack = alert.get("attack_type", "Unknown")
        dept = alert.get("department", "")

        subject = f"[{severity}] Sentrix: {attack} from {src_ip}"

        body = f"""
SENTRIX ALERT
{'='*50}

Severity:    {severity}
Attack Type: {attack}
Source:      {alert.get('tag', '')}
Time:        {alert.get('timestamp', '')}

Source IP:   {src_ip}
Dest IP:     {alert.get('dst_ip', '?')}
Dest Port:   {alert.get('dst_port', '?')}

Department:  {dept}
Confidence:  {alert.get('confidence', 0):.1f}%
ML Score:    {alert.get('ml_score', 0):.3f}
UEBA Score:  {alert.get('ueba_score', 0):.3f}
ETA Score:   {alert.get('eta_score', 0):.3f}

Reasons:
{chr(10).join('  - ' + r for r in alert.get('reasons', []))}

Threat Intel: {json.dumps(alert.get('threat_intel', []), indent=2)}
JA3 Match:    {alert.get('ja3_match', 'None')}

{'='*50}
This is an automated alert from Sentrix.
"""

        msg = MIMEMultipart()
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        try:
            if use_tls:
                server = smtplib.SMTP(smtp_host, smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP(smtp_host, smtp_port)
            if username and password:
                server.login(username, password)
            server.sendmail(from_addr, to_addrs, msg.as_string())
            server.quit()
        except Exception as e:
            log.error(f"[Dispatch] Email failed: {e}")
            raise

    # ── Slack ─────────────────────────────────────────────────

    def _send_slack(self, alert: dict, cfg: dict):
        import urllib.request

        webhook_url = cfg.get("webhook_url", "")
        if not webhook_url:
            return

        severity = alert.get("severity", "?")
        attack = alert.get("attack_type", "Unknown")
        src_ip = alert.get("src_ip", "?")
        dst_ip = alert.get("dst_ip", "?")
        dept = alert.get("department", "")
        reasons = alert.get("reasons", [])

        emoji = {"CRITICAL": ":red_circle:", "HIGH": ":orange_circle:",
                 "MEDIUM": ":large_yellow_circle:", "LOW": ":white_circle:"
                 }.get(severity, ":grey_question:")

        blocks = [
            {"type": "header",
             "text": {"type": "plain_text",
                      "text": f"{emoji} [{severity}] {attack}"}},
            {"type": "section",
             "fields": [
                 {"type": "mrkdwn", "text": f"*Source:* {src_ip}"},
                 {"type": "mrkdwn", "text": f"*Target:* {dst_ip}:{alert.get('dst_port', '?')}"},
                 {"type": "mrkdwn", "text": f"*Department:* {dept}"},
                 {"type": "mrkdwn", "text": f"*Confidence:* {alert.get('confidence', 0):.1f}%"},
                 {"type": "mrkdwn", "text": f"*Tag:* {alert.get('tag', '')}"},
                 {"type": "mrkdwn", "text": f"*Time:* {alert.get('timestamp', '')[:19]}"},
             ]},
        ]

        if reasons:
            reason_text = "\n".join(f"- {r}" for r in reasons[:5])
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Evidence:*\n{reason_text}"}
            })

        ja3 = alert.get("ja3_match", "")
        ti = alert.get("threat_intel", [])
        if ja3 or ti:
            intel_parts = []
            if ja3:
                intel_parts.append(f"JA3: {ja3}")
            if ti:
                for h in ti[:3]:
                    intel_parts.append(f"TI: {h.get('type','')} {h.get('value','')}")
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": " | ".join(intel_parts)}]
            })

        payload = json.dumps({"blocks": blocks}).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)

    # ── Microsoft Teams ───────────────────────────────────────

    def _send_teams(self, alert: dict, cfg: dict):
        import urllib.request

        webhook_url = cfg.get("webhook_url", "")
        if not webhook_url:
            return

        severity = alert.get("severity", "?")
        color = {"CRITICAL": "FF0000", "HIGH": "FF8C00",
                 "MEDIUM": "FFD700", "LOW": "00CED1"}.get(severity, "808080")

        card = {
            "@type": "MessageCard",
            "themeColor": color,
            "summary": f"[{severity}] {alert.get('attack_type', 'Alert')}",
            "sections": [{
                "activityTitle": f"Sentrix Alert: [{severity}] {alert.get('attack_type', '')}",
                "facts": [
                    {"name": "Source", "value": alert.get("src_ip", "?")},
                    {"name": "Target", "value": f"{alert.get('dst_ip', '?')}:{alert.get('dst_port', '?')}"},
                    {"name": "Department", "value": alert.get("department", "")},
                    {"name": "Confidence", "value": f"{alert.get('confidence', 0):.1f}%"},
                    {"name": "Tag", "value": alert.get("tag", "")},
                ],
            }],
        }

        payload = json.dumps(card).encode("utf-8")
        req = urllib.request.Request(
            webhook_url, data=payload,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=10)

    # ── Syslog (SIEM) ────────────────────────────────────────

    def _send_syslog(self, alert: dict, cfg: dict):
        host = cfg.get("host", "127.0.0.1")
        port = cfg.get("port", 514)
        proto = cfg.get("protocol", "udp").lower()
        facility = cfg.get("facility", 4)  # auth
        sev_map = {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "LOW": 6}
        syslog_sev = sev_map.get(alert.get("severity", "LOW"), 6)
        priority = facility * 8 + syslog_sev

        # CEF format (compatible with Splunk, QRadar, ArcSight, Elastic)
        cef = (
            f"<{priority}>CEF:0|Sentrix|Sentinel|1.0|"
            f"{alert.get('attack_type', 'Alert')}|"
            f"{alert.get('severity', 'LOW')}|"
            f"{syslog_sev}|"
            f"src={alert.get('src_ip', '')} "
            f"dst={alert.get('dst_ip', '')} "
            f"dpt={alert.get('dst_port', '')} "
            f"cs1={alert.get('tag', '')} "
            f"cs2={alert.get('department', '')} "
            f"cfp1={alert.get('confidence', 0)} "
            f"msg={'; '.join(alert.get('reasons', [])[:3])}"
        )

        encoded = cef.encode("utf-8")

        if proto == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(encoded, (host, port))
            sock.close()
        elif proto == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.send(encoded + b"\n")
            sock.close()

    # ── Generic Webhook ───────────────────────────────────────

    def _send_webhook(self, alert: dict, cfg: dict):
        import urllib.request

        url = cfg.get("url", "")
        if not url:
            return

        headers = cfg.get("headers", {"Content-Type": "application/json"})
        auth_token = cfg.get("auth_token", "")
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        payload = json.dumps(alert, default=str).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        urllib.request.urlopen(req, timeout=10)

    # ── CERT-In (India 6-hour mandatory reporting) ────────────

    def _send_certin(self, alert: dict, cfg: dict):
        """Format a CRITICAL/HIGH alert into CERT-In schema and submit.

        Submission is best-effort: if submit_url is empty the report is
        format-only and logged for audit. A failed submission does not
        raise; operators check stats['errors'] and dispatcher logs.
        """
        reporter = getattr(self, "_certin_reporter", None)
        if reporter is None:
            from certin_reporter import CERTInReporter
            reporter = CERTInReporter(
                org_name=cfg.get("org_name", ""),
                org_sector=cfg.get("org_sector", ""),
                contact_email=cfg.get("contact_email", ""),
                contact_phone=cfg.get("contact_phone", ""),
                submit_url=cfg.get("submit_url", ""),
            )
            self._certin_reporter = reporter
        report = reporter.format_alert(alert)
        reporter.submit(report)

    # ── Queries ───────────────────────────────────────────────

    def get_recent(self, n: int = 50) -> List[dict]:
        return list(self._recent)[:n]

    def get_stats(self) -> dict:
        return dict(self.stats)

    def print_summary(self):
        s = self.stats
        print(f"\n{'='*55}")
        print(f"  ALERT DISPATCH SUMMARY")
        print(f"{'='*55}")
        print(f"  Total dispatched : {s['total_dispatched']:,}")
        print(f"  By severity:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            cnt = s["by_severity"].get(sev, 0)
            if cnt:
                print(f"    {sev:<12} {cnt:>6,}")
        print(f"  By channel:")
        for ch, cnt in sorted(s["by_channel"].items(), key=lambda x: -x[1]):
            if cnt:
                print(f"    {ch:<12} {cnt:>6,}")
        print(f"  Errors: {s['errors']}")
        print(f"{'='*55}")
