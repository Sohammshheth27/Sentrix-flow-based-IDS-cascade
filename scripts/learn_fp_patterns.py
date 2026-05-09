"""Active learning from operator triage_verdicts."""
from __future__ import annotations
import sqlite3
from collections import defaultdict
from datetime import datetime
from pathlib import Path

DB_PATH = Path("/home/sohamm/sentrix/alerts.db")

def _classify_subnet(ip: str) -> str:
    """Reduce an IP to a coarse subnet pattern for grouping."""
    if not ip or "." not in ip:
        return ""
    parts = ip.split(".")
    if len(parts) != 4:
        return ""
    o0, o1 = parts[0], parts[1]
    # RFC1918 internal; group by /24 since office subnets are usually /24
    if o0 == "10" or (o0 == "192" and o1 == "168"):
        return f"{o0}.{o1}.{parts[2]}.*"
    if o0 == "172" and 16 <= int(o1) <= 31:
        return f"{o0}.{o1}.{parts[2]}.*"
    # External: group by /16 to avoid overfit on a single Google IP
    return f"{o0}.{o1}.*"

def main():
    if not DB_PATH.exists():
        print(f"[learn_fp] {DB_PATH} not found"); return
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")

    # Create the fp_patterns table if needed
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS fp_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type    TEXT,
            src_pattern    TEXT,    -- e.g. "192.168.19.*"
            dst_pattern    TEXT,    -- e.g. "142.250.*"
            dst_port       INTEGER,
            confidence     REAL,    -- TP/(TP+FP) for this pattern; 0 = always-FP
            learned_from_n INTEGER, -- how many triage records contributed
            learned_at     TEXT,
            last_matched   TEXT,
            suppression_count INTEGER DEFAULT 0,
            UNIQUE(attack_type, src_pattern, dst_pattern, dst_port)
        );
        CREATE INDEX IF NOT EXISTS idx_fp_patterns_lookup
            ON fp_patterns(attack_type, dst_port);
    """)
    conn.commit()

    # Pull every triaged alert. JOIN alerts.id with triage_verdicts.alert_id.
    rows = conn.execute("""
        SELECT a.attack_type, a.src_ip, a.dst_ip, a.dst_port, t.verdict
        FROM alerts a
        JOIN triage_verdicts t ON t.alert_id = a.id
        WHERE t.verdict IN ('TP', 'FP')
    """).fetchall()
    if not rows:
        print("[learn_fp] no TP/FP triage verdicts to learn from")
        conn.close()
        return

    # Group by pattern key. For each pattern, count how many were FP vs TP.
    bucket: dict = defaultdict(lambda: {"tp": 0, "fp": 0})
    for atk, sip, dip, dport, verdict in rows:
        key = (
            atk or "",
            _classify_subnet(sip or ""),
            _classify_subnet(dip or ""),
            int(dport or 0),
        )
        if verdict == "FP":
            bucket[key]["fp"] += 1
        elif verdict == "TP":
            bucket[key]["tp"] += 1

    # For each pattern, compute confidence = FP / (FP+TP)
    # Higher confidence = more confidently a FP. Insert/update fp_patterns.
    now_iso = datetime.now().isoformat(timespec="seconds")
    learned = 0
    for (atk, src_p, dst_p, port), counts in bucket.items():
        n = counts["tp"] + counts["fp"]
        if n < 1:
            continue
        # Skip patterns that have ANY TPs; these are not FP-only patterns
        if counts["tp"] > 0:
            continue
        # Skip patterns with zero distinguishing attributes (could over-suppress)
        if not any([atk, src_p, dst_p, port]):
            continue
        confidence = counts["fp"] / n
        try:
            conn.execute(
                "INSERT OR REPLACE INTO fp_patterns "
                "(attack_type, src_pattern, dst_pattern, dst_port, "
                " confidence, learned_from_n, learned_at, last_matched, "
                " suppression_count) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, '', 0)",
                (atk, src_p, dst_p, port, confidence, counts["fp"], now_iso),
            )
            learned += 1
        except Exception as e:
            print(f"[learn_fp] insert failed for {atk}/{src_p}/{dst_p}/{port}: {e}")

    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM fp_patterns").fetchone()[0]
    print(f"[learn_fp] processed {len(rows)} triage records → "
          f"learned {learned} new/updated patterns "
          f"({total} total in fp_patterns)")
    print()
    print("== top 10 learned patterns ==")
    for r in conn.execute(
        "SELECT attack_type, src_pattern, dst_pattern, dst_port, "
        "       confidence, learned_from_n "
        "FROM fp_patterns "
        "ORDER BY learned_from_n DESC, confidence DESC LIMIT 10"
    ):
        print(f"  {r[0]:<22s} src={r[1]:<18s} dst={r[2]:<18s} "
              f"port={r[3]:<5d} conf={r[4]:.2f} n={r[5]}")
    conn.close()

if __name__ == "__main__":
    main()
