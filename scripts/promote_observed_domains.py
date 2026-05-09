"""L3 self-learning allowlist promoter."""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from datetime import datetime

PROJECT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT / "threat_intel.db"
CFG_PATH = PROJECT / "config" / "ti_exclusions.json"

def load_thresholds() -> dict:
    """Read promotion thresholds from ti_exclusions.json. Falls back to
    sensible defaults if file/keys missing."""
    defaults = {"min_distinct_hosts": 3, "min_days_seen": 3, "min_total_queries": 10}
    try:
        cfg = json.loads(CFG_PATH.read_text(encoding="utf-8"))
        return {**defaults, **cfg.get("_promotion_thresholds_for_L3", {})}
    except Exception:
        return defaults

def main():
    thresholds = load_thresholds()
    print(f"[promote] thresholds: {thresholds}")
    if not DB_PATH.exists():
        print(f"[promote] threat_intel.db not found at {DB_PATH}")
        return
    conn = sqlite3.connect(str(DB_PATH), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")

    # Find candidates
    rows = conn.execute(
        """SELECT domain, distinct_hosts, total_queries, days_seen
           FROM domain_observations
           WHERE distinct_hosts >= ?
             AND days_seen      >= ?
             AND total_queries  >= ?""",
        (thresholds["min_distinct_hosts"],
         thresholds["min_days_seen"],
         thresholds["min_total_queries"]),
    ).fetchall()

    promoted_now = 0
    skipped_already_in = 0
    for domain, n_hosts, n_qs, days_seen in rows:
        # Skip if already promoted
        existing = conn.execute(
            "SELECT 1 FROM learned_allowlist WHERE domain = ?", (domain,)
        ).fetchone()
        if existing:
            skipped_already_in += 1
            continue
        conn.execute(
            "INSERT INTO learned_allowlist "
            "(domain, n_hosts, days_seen, note) VALUES (?, ?, ?, ?)",
            (domain, n_hosts, days_seen,
             f"auto-promoted {datetime.now().isoformat()[:19]}; {n_hosts} hosts × {days_seen}d × {n_qs}q"),
        )
        promoted_now += 1

    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM learned_allowlist").fetchone()[0]
    print(f"[promote] candidates: {len(rows)} · "
          f"newly-promoted: {promoted_now} · "
          f"already-in-list: {skipped_already_in} · "
          f"total in learned_allowlist: {total}")
    conn.close()

if __name__ == "__main__":
    main()
