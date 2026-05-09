"""Global Threat Intelligence Engine"""
import os
import sys
import io
import re
import json
import time
import sqlite3
import hashlib
import logging
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

log = logging.getLogger("threat_intel")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

class ThreatIntelEngine:
    """
    Global threat intelligence with multi-source feed ingestion.

    Provides O(1) lookup for IP, domain, and JA3 reputation.
    Feeds are cached in SQLite and refreshed periodically.
    """

    def __init__(self, config_path: str = None, db_path: str = None):
        if config_path is None:
            config_path = str(_PROJECT_ROOT / "config" / "threat_feeds.json")
        if db_path is None:
            db_path = str(_PROJECT_ROOT / "threat_intel.db")

        self.db_path = db_path
        self.config = {}
        self._feeds = {}
        self._settings = {}

        # In-memory lookup tables (rebuilt from DB on start)
        self._bad_ips: Dict[str, dict] = {}        # ip → {category, severity, feed, added}
        self._bad_domains: Dict[str, dict] = {}     # domain → {category, severity, feed}
        self._bad_ja3: Dict[str, dict] = {}         # ja3_hash → {name, category, severity}
        self._bad_urls: Set[str] = set()
        self._whitelist_ips: Set[str] = set()
        self._whitelist_domains: Set[str] = set()

        # ── Layered allowlist defenses against TI feed false positives ──
        # L1: globally-popular-domain allowlist (Tranco/Umbrella top-100K).
        #     Catches "famous domain mis-listed by single feed"; the dominant
        #     FP source observed in the office capture (15 / 22 HIGH alerts
        #     came from drive.google.com mis-listing).
        self._tranco_top: Set[str] = set()
        # L4: admin-curated immediate-override exclusion list. Survives feed
        #     re-syncs because we check this BEFORE bad_domains lookup.
        self._ti_exclusions: Set[str] = set()
        # L3: per-deployment self-learned allowlist. Domains the office's own
        #     hosts query consistently for ≥promotion_days get auto-trusted.
        #     Loaded from threat_intel.db:learned_allowlist (see _init_db).
        self._learned_allowlist: Set[str] = set()

        self._lock = threading.Lock()
        self._last_update: Dict[str, float] = {}

        # Stats
        self.stats = {
            "lookups": 0,
            "hits": 0,
            "ip_hits": 0,
            "ja3_hits": 0,
            "domain_hits": 0,
            "feeds_loaded": 0,
            "total_iocs": 0,
        }

        self._load_config(config_path)
        self._init_db()
        self._load_from_db()

        # Load the three layered allowlists
        self._load_tranco_top()
        self._load_ti_exclusions()
        self._load_learned_allowlist()

        # ── Background L3 flush + L1 reload thread ────────────────
        # Every flush_interval_sec: persist domain_observations to disk
        # and reload learned_allowlist (in case promote_observed_domains.py
        # ran via cron and added new entries). Daemon thread = no cleanup
        # burden on engine shutdown.
        self._flush_interval_sec = 300        # 5 min
        self._stop_bg = False
        self._bg_thread = threading.Thread(
            target=self._background_maintenance,
            daemon=True,
            name="ThreatIntel-bg-flush",
        )
        self._bg_thread.start()

        total = len(self._bad_ips) + len(self._bad_domains) + len(self._bad_ja3)
        self.stats["total_iocs"] = total
        print(f"[ThreatIntel] Loaded: {len(self._bad_ips)} IPs, "
              f"{len(self._bad_domains)} domains, {len(self._bad_ja3)} JA3, "
              f"{len(self._bad_urls)} URLs")
        print(f"[ThreatIntel] Whitelisted: {len(self._whitelist_ips)} IPs, "
              f"{len(self._whitelist_domains)} domains")
        print(f"[ThreatIntel] Allowlist layers: "
              f"L1 Tranco={len(self._tranco_top):,} · "
              f"L4 exclusions={len(self._ti_exclusions)} · "
              f"L3 learned={len(self._learned_allowlist)}")

    # ── Layered allowlist loaders ─────────────────────────────

    def _load_tranco_top(self):
        """L1: Load top-N most-popular domains as a global allowlist.
        Falls back to empty set if file missing; system still functions."""
        path = _PROJECT_ROOT / "data" / "tranco_top100k.csv"
        if not path.exists():
            print(f"[ThreatIntel] L1 Tranco list not found at {path} (allowlist disabled)")
            return
        try:
            with path.open(encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.strip().split(",", 1)
                    if len(parts) == 2:
                        self._tranco_top.add(parts[1].lower())
        except Exception as e:
            print(f"[ThreatIntel] L1 Tranco load failed: {e}")

    def _load_ti_exclusions(self):
        """L4: Operator-curated immediate-override list. Domains in this file
        are NEVER flagged by TI, regardless of feed. Survives feed re-syncs."""
        path = _PROJECT_ROOT / "config" / "ti_exclusions.json"
        if not path.exists():
            return
        try:
            with path.open(encoding="utf-8") as f:
                data = json.load(f)
            for d in data.get("known_legitimate_domains", []):
                self._ti_exclusions.add(d.lower())
        except Exception as e:
            print(f"[ThreatIntel] L4 exclusions load failed: {e}")

    def _load_learned_allowlist(self):
        """L3: Per-deployment self-learned allowlist. Domains promoted by the
        UEBA-style observer when used by ≥K hosts for ≥Y days. Stored in
        threat_intel.db:learned_allowlist (created by _init_db)."""
        try:
            conn = sqlite3.connect(self.db_path, timeout=5)
            for row in conn.execute("SELECT domain FROM learned_allowlist"):
                self._learned_allowlist.add(row[0])
            conn.close()
        except Exception as e:
            # Table may not exist on first run; that's ok
            pass

    def _load_config(self, path: str):
        try:
            with open(path) as f:
                self.config = json.load(f)
            self._feeds = self.config.get("feeds", {})
            self._settings = self.config.get("settings", {})

            overrides = self.config.get("local_overrides", {})
            self._whitelist_ips = set(overrides.get("whitelisted_ips", []))
            self._whitelist_domains = set(overrides.get("whitelisted_domains", []))

            enabled = sum(1 for f in self._feeds.values() if f.get("enabled"))
            print(f"[ThreatIntel] Config loaded: {enabled} feeds enabled")
        except FileNotFoundError:
            print(f"[ThreatIntel] No config at {path}; empty threat intel")
        except Exception as e:
            print(f"[ThreatIntel] Config error: {e}")

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS bad_ips (
                    ip TEXT PRIMARY KEY,
                    category TEXT,
                    severity TEXT,
                    feed TEXT,
                    added_at TEXT
                );
                CREATE TABLE IF NOT EXISTS bad_domains (
                    domain TEXT PRIMARY KEY,
                    category TEXT,
                    severity TEXT,
                    feed TEXT,
                    added_at TEXT
                );
                CREATE TABLE IF NOT EXISTS bad_ja3 (
                    ja3_hash TEXT PRIMARY KEY,
                    name TEXT,
                    category TEXT,
                    severity TEXT,
                    feed TEXT,
                    added_at TEXT
                );
                CREATE TABLE IF NOT EXISTS bad_urls (
                    url TEXT PRIMARY KEY,
                    category TEXT,
                    severity TEXT,
                    feed TEXT,
                    added_at TEXT
                );
                CREATE TABLE IF NOT EXISTS feed_state (
                    feed_name TEXT PRIMARY KEY,
                    last_updated TEXT,
                    entry_count INTEGER,
                    status TEXT
                );
                -- L3: per-deployment domain observations for self-learning
                CREATE TABLE IF NOT EXISTS domain_observations (
                    domain TEXT PRIMARY KEY,
                    distinct_hosts INTEGER DEFAULT 0,
                    total_queries  INTEGER DEFAULT 0,
                    first_seen     TEXT,
                    last_seen      TEXT,
                    days_seen      INTEGER DEFAULT 0,
                    hosts_csv      TEXT     -- compact set of host IPs
                );
                CREATE INDEX IF NOT EXISTS idx_dom_obs_lastseen ON domain_observations(last_seen);
                -- L3: domains promoted to learned allowlist by promote_observed_domains.py
                CREATE TABLE IF NOT EXISTS learned_allowlist (
                    domain TEXT PRIMARY KEY,
                    promoted_at  TEXT DEFAULT CURRENT_TIMESTAMP,
                    n_hosts      INTEGER,
                    days_seen    INTEGER,
                    note         TEXT
                );
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[ThreatIntel] DB init error: {e}")

    def _load_from_db(self):
        """Load cached IOCs from SQLite into memory for O(1) lookup."""
        try:
            conn = sqlite3.connect(self.db_path, timeout=5)

            for row in conn.execute("SELECT ip, category, severity, feed FROM bad_ips"):
                self._bad_ips[row[0]] = {
                    "category": row[1], "severity": row[2], "feed": row[3]}

            for row in conn.execute("SELECT domain, category, severity, feed FROM bad_domains"):
                self._bad_domains[row[0]] = {
                    "category": row[1], "severity": row[2], "feed": row[3]}

            for row in conn.execute("SELECT ja3_hash, name, category, severity FROM bad_ja3"):
                self._bad_ja3[row[0]] = {
                    "name": row[1], "category": row[2], "severity": row[3]}

            for row in conn.execute("SELECT url FROM bad_urls"):
                self._bad_urls.add(row[0])

            for row in conn.execute("SELECT feed_name, last_updated FROM feed_state"):
                try:
                    self._last_update[row[0]] = datetime.fromisoformat(row[1]).timestamp()
                except Exception:
                    pass

            conn.close()
        except Exception as e:
            print(f"[ThreatIntel] DB load error: {e}")

    # ── Public API ────────────────────────────────────────────

    def lookup_ip(self, ip: str) -> Optional[dict]:
        """Check if IP is in any threat feed. O(1) hash lookup."""
        self.stats["lookups"] += 1
        if not ip or ip in self._whitelist_ips:
            return None
        result = self._bad_ips.get(ip)
        if result:
            self.stats["hits"] += 1
            self.stats["ip_hits"] += 1
            return {"type": "ip", "value": ip, **result}
        return None

    def _is_allowlisted(self, domain_check: str) -> Optional[str]:
        """Check the three layered allowlists. Returns the layer name
        ('L1-tranco', 'L4-exclusion', 'L3-learned', or 'override') if the
        domain is allowlisted, else None."""
        if domain_check in self._whitelist_domains:
            return "override"           # legacy in-config whitelist
        if domain_check in self._ti_exclusions:
            return "L4-exclusion"
        if domain_check in self._learned_allowlist:
            return "L3-learned"
        if domain_check in self._tranco_top:
            return "L1-tranco"
        return None

    def lookup_domain(self, domain: str, src_ip: str = "") -> Optional[dict]:
        """Check if domain is in any threat feed. Layered allowlist defenses
        suppress false positives from feed mis-listings before the bad_domains
        lookup. Allowlisted domains return None and are recorded for stats."""
        self.stats["lookups"] += 1
        if not domain:
            return None

        # Record this observation for L3 self-learning (cheap; in-memory)
        if src_ip:
            self.observe_domain(domain, src_ip)

        # Check exact match and parent domains. At each level, layered
        # allowlists override TI flag (L1 Tranco / L4 exclusions / L3
        # learned / legacy override). Bad-domain match only fires if NO
        # layer allowlists the domain or any of its parents.
        parts = domain.lower().split(".")
        for i in range(len(parts)):
            check = ".".join(parts[i:])
            allowlist_layer = self._is_allowlisted(check)
            if allowlist_layer:
                # Allowlisted at this level; count for stats so operators
                # can see which layer is doing the work
                self.stats.setdefault("allowlist_suppressions", 0)
                self.stats["allowlist_suppressions"] += 1
                self.stats.setdefault(f"allowlist_{allowlist_layer}", 0)
                self.stats[f"allowlist_{allowlist_layer}"] += 1
                return None
            result = self._bad_domains.get(check)
            if result:
                self.stats["hits"] += 1
                self.stats["domain_hits"] += 1
                return {"type": "domain", "value": check, **result}
        return None

    def observe_domain(self, domain: str, src_ip: str):
        """L3: Record that src_ip queried this domain. Used by the periodic
        promoter to identify domains used by ≥K hosts for ≥Y days, which get
        auto-promoted to learned_allowlist. In-memory cache flushed to DB by
        flush_observations() called periodically by the engine."""
        if not hasattr(self, "_obs_buffer"):
            self._obs_buffer: Dict[str, Set[str]] = {}
        d = domain.lower()
        # Track the SLD (last 2 labels) to keep the buffer bounded :
        # subdomains of cdn.example.com all roll up to example.com.
        parts = d.split(".")
        if len(parts) >= 2:
            sld = ".".join(parts[-2:])
            self._obs_buffer.setdefault(sld, set()).add(src_ip)

    def _background_maintenance(self):
        """Daemon loop: flush L3 observations, reload L3 learned allowlist
        (catches updates from cron-run promote_observed_domains.py),
        reload L4 ti_exclusions (catches admin edits; survives engine
        runtime). Errors are caught; never crash the engine."""
        import time as _t
        while not self._stop_bg:
            _t.sleep(self._flush_interval_sec)
            try:
                self.flush_observations()
                # Reload L3 + L4 from disk so engine picks up changes
                # made by external scripts / admin edits without restart.
                old_l3 = len(self._learned_allowlist)
                old_l4 = len(self._ti_exclusions)
                self._learned_allowlist.clear()
                self._ti_exclusions.clear()
                self._load_learned_allowlist()
                self._load_ti_exclusions()
                if (len(self._learned_allowlist) != old_l3
                    or len(self._ti_exclusions)   != old_l4):
                    print(f"[ThreatIntel] background reload: "
                          f"L3 {old_l3}→{len(self._learned_allowlist)}, "
                          f"L4 {old_l4}→{len(self._ti_exclusions)}")
            except Exception as e:
                print(f"[ThreatIntel] background maintenance error: {e}")

    def flush_observations(self):
        """Flush the in-memory observation buffer to threat_intel.db.
        Called by the background thread every flush_interval_sec, OR
        explicitly by the engine on shutdown."""
        if not getattr(self, "_obs_buffer", None):
            return
        try:
            from datetime import datetime as _dt
            now_iso = _dt.now().isoformat()
            today    = now_iso[:10]
            conn = sqlite3.connect(self.db_path, timeout=5)
            for sld, hosts in self._obs_buffer.items():
                row = conn.execute(
                    "SELECT distinct_hosts, total_queries, first_seen, "
                    "       hosts_csv, days_seen, last_seen "
                    "FROM domain_observations WHERE domain = ?", (sld,)
                ).fetchone()
                if row:
                    existing_hosts = set((row[3] or "").split(",")) - {""}
                    new_hosts = existing_hosts | hosts
                    last_seen_date = (row[5] or "")[:10]
                    days_seen = row[4] + (1 if last_seen_date != today else 0)
                    conn.execute(
                        "UPDATE domain_observations SET "
                        "  distinct_hosts = ?, total_queries = ?, "
                        "  hosts_csv = ?, last_seen = ?, days_seen = ? "
                        "WHERE domain = ?",
                        (len(new_hosts), row[1] + len(hosts),
                         ",".join(sorted(new_hosts))[:1024],
                         now_iso, days_seen, sld)
                    )
                else:
                    conn.execute(
                        "INSERT INTO domain_observations "
                        "(domain, distinct_hosts, total_queries, first_seen, "
                        " last_seen, days_seen, hosts_csv) "
                        "VALUES (?, ?, ?, ?, ?, 1, ?)",
                        (sld, len(hosts), len(hosts), now_iso, now_iso,
                         ",".join(sorted(hosts))[:1024])
                    )
            conn.commit()
            conn.close()
            self._obs_buffer.clear()
        except Exception as e:
            print(f"[ThreatIntel] flush_observations failed: {e}")

    def lookup_ja3(self, ja3_hash: str) -> Optional[dict]:
        """Check if JA3 fingerprint matches known malware."""
        self.stats["lookups"] += 1
        if not ja3_hash:
            return None
        result = self._bad_ja3.get(ja3_hash)
        if result:
            self.stats["hits"] += 1
            self.stats["ja3_hits"] += 1
            return {"type": "ja3", "value": ja3_hash, **result}
        return None

    def lookup_flow(self, flow: dict) -> List[dict]:
        """
        Check all IOC types for a single flow.
        Returns list of all threat intel matches (can be multiple).
        """
        hits = []

        # Check destination IP
        dst_ip = flow.get("dst_ip", "")
        hit = self.lookup_ip(dst_ip)
        if hit:
            hits.append(hit)

        # Check source IP (could be known-bad; compromised internal)
        src_ip = flow.get("src_ip", "")
        hit = self.lookup_ip(src_ip)
        if hit:
            hit["direction"] = "src"
            hits.append(hit)

        # Check JA3 if available
        ja3 = flow.get("ja3", flow.get("ja3_hash", ""))
        hit = self.lookup_ja3(ja3)
        if hit:
            hits.append(hit)

        # Check domain if available (from DNS query or SNI)
        domain = flow.get("domain", flow.get("dns_query", flow.get("sni", "")))
        hit = self.lookup_domain(domain)
        if hit:
            hits.append(hit)

        return hits

    # ── Feed Update ───────────────────────────────────────────

    def update_feeds(self, force: bool = False) -> dict:
        """
        Fetch latest IOCs from all enabled feeds.
        Respects update_hours interval unless force=True.
        """
        import urllib.request

        results = {}
        now = time.time()

        for name, feed_cfg in self._feeds.items():
            if not feed_cfg.get("enabled", False):
                continue

            update_interval = feed_cfg.get("update_hours", 6) * 3600
            last = self._last_update.get(name, 0)

            if not force and (now - last) < update_interval:
                results[name] = "skipped (not due)"
                continue

            url = feed_cfg.get("url", "")
            feed_type = feed_cfg.get("type", "ip_list")
            category = feed_cfg.get("category", "unknown")
            severity = feed_cfg.get("severity", "MEDIUM")
            comment = feed_cfg.get("comment_prefix", "#")
            timeout = self._settings.get("fetch_timeout_sec", 30)

            try:
                print(f"[ThreatIntel] Fetching {name}...")
                req = urllib.request.Request(url, headers={
                    "User-Agent": "Sentrix-ThreatIntel/1.0"
                })
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = resp.read().decode("utf-8", errors="replace")

                count = 0
                if feed_type == "ip_list":
                    count = self._parse_ip_list(data, name, category,
                                                severity, comment)
                elif feed_type == "ja3_list":
                    count = self._parse_ja3_csv(data, name, category, severity)
                elif feed_type == "url_list":
                    count = self._parse_url_list(data, name, category,
                                                 severity, comment)

                self._last_update[name] = now
                self._save_feed_state(name, count)
                results[name] = f"ok ({count} entries)"
                self.stats["feeds_loaded"] += 1
                print(f"[ThreatIntel] {name}: {count} entries loaded")

            except Exception as e:
                results[name] = f"error: {e}"
                print(f"[ThreatIntel] {name} fetch failed: {e}")

        self.stats["total_iocs"] = (len(self._bad_ips) + len(self._bad_domains)
                                    + len(self._bad_ja3))
        return results

    def _parse_ip_list(self, data: str, feed: str, category: str,
                       severity: str, comment: str) -> int:
        count = 0
        now_iso = datetime.utcnow().isoformat()
        conn = sqlite3.connect(self.db_path, timeout=10)

        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith(comment):
                continue
            # Extract IP (first token on the line)
            ip = line.split()[0].split(",")[0].strip()
            if not _IP_RE.match(ip) or ip in self._whitelist_ips:
                continue

            with self._lock:
                self._bad_ips[ip] = {
                    "category": category, "severity": severity, "feed": feed}

            conn.execute(
                "INSERT OR REPLACE INTO bad_ips VALUES (?,?,?,?,?)",
                (ip, category, severity, feed, now_iso))
            count += 1

        conn.commit()
        conn.close()
        return count

    def _parse_ja3_csv(self, data: str, feed: str, category: str,
                       severity: str) -> int:
        count = 0
        now_iso = datetime.utcnow().isoformat()
        conn = sqlite3.connect(self.db_path, timeout=10)

        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("ja3_md5"):
                continue
            parts = line.split(",")
            if len(parts) < 2:
                continue
            ja3_hash = parts[0].strip()
            # SSLBL CSV: ja3_md5,Firstseen,Lastseen,Listingreason
            # Take the last column (malware family), not the date.
            name = parts[-1].strip() if len(parts) >= 4 else (
                parts[1].strip() if len(parts) > 1 else "Unknown")

            if len(ja3_hash) != 32:
                continue

            with self._lock:
                self._bad_ja3[ja3_hash] = {
                    "name": name, "category": category, "severity": severity}

            conn.execute(
                "INSERT OR REPLACE INTO bad_ja3 VALUES (?,?,?,?,?,?)",
                (ja3_hash, name, category, severity, feed, now_iso))
            count += 1

        conn.commit()
        conn.close()
        return count

    def _parse_url_list(self, data: str, feed: str, category: str,
                        severity: str, comment: str) -> int:
        count = 0
        now_iso = datetime.utcnow().isoformat()
        conn = sqlite3.connect(self.db_path, timeout=10)

        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith(comment):
                continue

            url = line.strip()
            with self._lock:
                self._bad_urls.add(url)

            # Also extract domain for domain-level blocking
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.hostname
                if domain and domain not in self._whitelist_domains:
                    self._bad_domains[domain] = {
                        "category": category, "severity": severity, "feed": feed}
                    conn.execute(
                        "INSERT OR REPLACE INTO bad_domains VALUES (?,?,?,?,?)",
                        (domain, category, severity, feed, now_iso))
            except Exception:
                pass

            conn.execute(
                "INSERT OR REPLACE INTO bad_urls VALUES (?,?,?,?,?)",
                (url, category, severity, feed, now_iso))
            count += 1

        conn.commit()
        conn.close()
        return count

    def _save_feed_state(self, name: str, count: int):
        try:
            conn = sqlite3.connect(self.db_path, timeout=5)
            conn.execute(
                "INSERT OR REPLACE INTO feed_state VALUES (?,?,?,?)",
                (name, datetime.utcnow().isoformat(), count, "ok"))
            conn.commit()
            conn.close()
        except Exception:
            pass

    # ── Utilities ─────────────────────────────────────────────

    def needs_update(self) -> List[str]:
        """Return list of feeds that are due for refresh."""
        now = time.time()
        due = []
        for name, cfg in self._feeds.items():
            if not cfg.get("enabled"):
                continue
            interval = cfg.get("update_hours", 6) * 3600
            last = self._last_update.get(name, 0)
            if (now - last) >= interval:
                due.append(name)
        return due

    def get_stats(self) -> dict:
        return {
            **self.stats,
            "bad_ips": len(self._bad_ips),
            "bad_domains": len(self._bad_domains),
            "bad_ja3": len(self._bad_ja3),
            "bad_urls": len(self._bad_urls),
            "feeds_configured": len(self._feeds),
            "feeds_due": len(self.needs_update()),
        }

    def print_summary(self):
        s = self.get_stats()
        print(f"\n{'='*55}")
        print(f"  THREAT INTELLIGENCE SUMMARY")
        print(f"{'='*55}")
        print(f"  IOC Database:")
        print(f"    Bad IPs      : {s['bad_ips']:,}")
        print(f"    Bad Domains  : {s['bad_domains']:,}")
        print(f"    Bad JA3      : {s['bad_ja3']:,}")
        print(f"    Bad URLs     : {s['bad_urls']:,}")
        print(f"  Lookups:")
        print(f"    Total        : {s['lookups']:,}")
        print(f"    Hits         : {s['hits']:,}")
        print(f"    Hit rate     : {s['hits']/max(s['lookups'],1)*100:.2f}%")
        print(f"    IP hits      : {s['ip_hits']:,}")
        print(f"    JA3 hits     : {s['ja3_hits']:,}")
        print(f"    Domain hits  : {s['domain_hits']:,}")
        print(f"  Feeds due      : {s['feeds_due']}")
        print(f"{'='*55}")
