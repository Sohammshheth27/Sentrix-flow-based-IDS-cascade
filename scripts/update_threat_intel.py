"""Standalone threat feed refresher."""
import sys
import time
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from threat_intel import ThreatIntelEngine

LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "threat_intel_refresh.log"

def main() -> int:
    started = time.time()
    ts = datetime.utcnow().isoformat(timespec="seconds")

    try:
        ti = ThreatIntelEngine()
        results = ti.update_feeds(force=False)
    except Exception as e:
        line = f"{ts}Z  FATAL  engine_init_or_update_failed: {e}\n"
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line)
        print(line, end="")
        return 2

    ok = sum(1 for v in results.values() if v.startswith("ok"))
    skipped = sum(1 for v in results.values() if v.startswith("skipped"))
    failed = sum(1 for v in results.values() if v.startswith("error"))
    stats = ti.get_stats()
    elapsed = time.time() - started

    summary = (
        f"{ts}Z  ok={ok} skipped={skipped} failed={failed}  "
        f"ips={stats['bad_ips']} domains={stats['bad_domains']} "
        f"ja3={stats['bad_ja3']} urls={stats['bad_urls']}  "
        f"elapsed={elapsed:.1f}s"
    )
    detail = " ".join(f"{k}={v}" for k, v in results.items())

    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(summary + "\n")
        f.write(f"  detail: {detail}\n")
    print(summary)
    print(f"  detail: {detail}")

    if ok == 0 and failed > 0:
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
