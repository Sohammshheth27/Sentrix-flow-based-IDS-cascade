"""Register the hourly threat-intel refresh with"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "schedule.json"
REFRESH_SCRIPT = PROJECT_ROOT / "scripts" / "update_threat_intel.py"

TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")

def load_config() -> dict:
    with CONFIG_PATH.open(encoding="utf-8") as f:
        cfg = json.load(f)

    start = cfg.get("office_hours", {}).get("start", "")
    if not TIME_RE.match(start):
        sys.exit(
            f"ERROR: office_hours.start='{start}' is not valid HH:MM "
            f"(00:00-23:59). Edit {CONFIG_PATH} and re-run."
        )

    ti_cfg = cfg.get("threat_intel_refresh", {})
    if not ti_cfg.get("enabled", True):
        sys.exit("threat_intel_refresh.enabled is false; nothing to register.")

    return {
        "start_time": start,
        "task_name": ti_cfg.get("task_name", "Sentrix\\ThreatIntelRefresh"),
        "interval_hours": int(ti_cfg.get("interval_hours", 1)),
    }

def build_command(cfg: dict) -> list:
    if not REFRESH_SCRIPT.exists():
        sys.exit(f"ERROR: refresh script not found at {REFRESH_SCRIPT}")

    python_exe = sys.executable
    tr = f'"{python_exe}" "{REFRESH_SCRIPT}"'

    return [
        "schtasks", "/Create",
        "/SC", "HOURLY",
        "/MO", str(cfg["interval_hours"]),
        "/TN", cfg["task_name"],
        "/TR", tr,
        "/ST", cfg["start_time"],
        "/F",
    ]

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="Print command without executing")
    args = ap.parse_args()

    cfg = load_config()
    cmd = build_command(cfg)

    print("Config:")
    print(f"  office start time : {cfg['start_time']}")
    print(f"  task name         : {cfg['task_name']}")
    print(f"  interval          : every {cfg['interval_hours']}h (24/7)")
    print()
    print("Command:")
    print("  " + " ".join(
        f'"{a}"' if " " in a or "\\" in a else a for a in cmd))
    print()

    if args.dry_run:
        print("(dry run; not executed)")
        return 0

    result = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode != 0:
        print(f"\nschtasks failed with exit code {result.returncode}")
        return result.returncode

    print("\nRegistered. Verify with:")
    print(f'  schtasks /Query /TN "{cfg["task_name"]}" /V /FO LIST')
    return 0

if __name__ == "__main__":
    sys.exit(main())
