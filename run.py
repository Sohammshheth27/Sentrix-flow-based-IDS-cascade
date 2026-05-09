"""one-command launcher for Sentrix live pipeline"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
DEFAULT_CSV = "D:/Tuesday_19_Dec_2023.csv"
DASHBOARD_URL = "http://localhost:8080"
DASHBOARD_HEALTH = f"{DASHBOARD_URL}/api/summary"
STARTUP_TIMEOUT = 30.0   # seconds to wait for dashboard to respond
ENGINE_READY_MARKER = "Engine ready"

# ── ANSI colours (degrade gracefully on plain Windows consoles) ──

def _supports_ansi() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if sys.platform == "win32":
        # Modern Windows Terminal + PowerShell handle ANSI.
        return True
    return sys.stdout.isatty()

if _supports_ansi():
    C = "\033[96m"; G = "\033[92m"; Y = "\033[93m"
    R = "\033[91m"; D = "\033[90m"; X = "\033[0m"; B = "\033[1m"
else:
    C = G = Y = R = D = X = B = ""

def banner(msg: str) -> None:
    bar = "=" * 70
    print(f"\n{C}{bar}\n  {B}{msg}{X}{C}\n{bar}{X}")

def info(msg: str) -> None:
    print(f"{D}[run.py]{X} {msg}")

def warn(msg: str) -> None:
    print(f"{Y}[run.py] WARN:{X} {msg}")

def fail(msg: str) -> None:
    print(f"{R}[run.py] FAIL:{X} {msg}")

# ── Subprocess management ───────────────────────────────────────

class Managed:
    """Wraps a Popen object with a labelled stdout pump thread."""

    def __init__(self, name: str, color: str, proc: subprocess.Popen):
        self.name = name
        self.color = color
        self.proc = proc
        self._ready = threading.Event()
        self._lines: list[str] = []
        self._pump = threading.Thread(
            target=self._pump_stdout, daemon=True,
            name=f"pump-{name}"
        )
        self._pump.start()

    def _pump_stdout(self) -> None:
        assert self.proc.stdout is not None
        # Windows default stdout is cp1252 and blows up on any
        # non-latin-1 character (≥, ✓, box-drawing, etc.). Encode
        # safely instead of crashing the pump thread.
        enc = (sys.stdout.encoding or "utf-8")
        for raw in self.proc.stdout:
            line = raw.rstrip("\r\n")
            self._lines.append(line)
            if ENGINE_READY_MARKER in line or "Uvicorn running" in line:
                self._ready.set()
            try:
                print(f"{self.color}[{self.name}]{X} {line}")
            except UnicodeEncodeError:
                safe = line.encode(enc, errors="replace").decode(enc)
                print(f"{self.color}[{self.name}]{X} {safe}")

    def wait_ready(self, timeout: float) -> bool:
        return self._ready.wait(timeout)

    def is_alive(self) -> bool:
        return self.proc.poll() is None

    def terminate(self) -> None:
        if not self.is_alive():
            return
        try:
            if sys.platform == "win32":
                self.proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                self.proc.terminate()
        except Exception:
            pass

    def kill(self) -> None:
        if not self.is_alive():
            return
        try:
            self.proc.kill()
        except Exception:
            pass

def spawn(name: str, color: str, cmd: list[str], cwd: Path) -> Managed:
    info(f"launching {name}: {' '.join(cmd)}")
    creationflags = 0
    if sys.platform == "win32":
        # CREATE_NEW_PROCESS_GROUP so we can send CTRL_BREAK to this
        # subprocess specifically without killing the parent.
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        creationflags=creationflags,
    )
    return Managed(name, color, proc)

# ── Health check ────────────────────────────────────────────────

def wait_for_dashboard(url: str, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                if resp.status == 200:
                    return True
        except urllib.error.URLError:
            pass
        except Exception:
            pass
        time.sleep(0.5)
    return False

# ── Main orchestration ─────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Sentrix launcher")
    parser.add_argument("--file", default=DEFAULT_CSV,
                         help=f"CSV file to replay (default {DEFAULT_CSV})")
    parser.add_argument("--rows", type=int, default=None,
                         help="limit replay to N rows")
    parser.add_argument("--no-browser", action="store_true",
                         help="don't open a browser window")
    parser.add_argument("--mode", default="csv",
                         choices=["csv", "zeek"],
                         help="capture mode (default csv); "
                              "'zeek' requires running Zeek + logs")
    parser.add_argument("--zeek-dir", default=None,
                         help="Zeek log directory (zeek mode only)")
    args = parser.parse_args()

    if not SRC.exists():
        fail(f"src/ directory not found at {SRC}")
        return 1

    if args.mode == "csv":
        csv_path = Path(args.file)
        if not csv_path.exists():
            fail(f"CSV file not found: {csv_path}")
            return 1

    banner("SENTRIX LIVE LAUNCH")
    info(f"project root: {ROOT}")
    info(f"capture mode: {args.mode}")
    if args.mode == "csv":
        info(f"csv file:     {args.file}")
        if args.rows:
            info(f"row cap:      {args.rows}")

    python = sys.executable

    # ── 1. Dashboard ────────────────────────────────────────────
    dash_cmd = [python, "-u", str(SRC / "dashboard_server.py")]
    dashboard = spawn("dashboard", C, dash_cmd, cwd=ROOT)

    info("waiting for dashboard to become healthy ...")
    if not wait_for_dashboard(DASHBOARD_HEALTH, STARTUP_TIMEOUT):
        fail(f"dashboard did not respond at {DASHBOARD_HEALTH} "
             f"within {STARTUP_TIMEOUT:.0f}s")
        dashboard.terminate()
        return 2
    info(f"dashboard healthy at {DASHBOARD_URL}")

    # ── 2. Engine ──────────────────────────────────────────────
    engine_cmd = [python, "-u", str(SRC / "realtime_engine.py"),
                    "--mode", args.mode]
    if args.mode == "csv":
        engine_cmd.extend(["--file", str(args.file)])
        if args.rows:
            engine_cmd.extend(["--rows", str(args.rows)])
    if args.mode == "zeek" and args.zeek_dir:
        engine_cmd.extend(["--zeek-dir", args.zeek_dir])

    engine = spawn("engine", G, engine_cmd, cwd=ROOT)

    info("waiting for engine to finish initialisation ...")
    engine_ready = engine.wait_ready(timeout=60.0)
    if not engine_ready and not engine.is_alive():
        fail("engine exited before becoming ready")
        dashboard.terminate()
        return 3
    if not engine_ready:
        warn("engine did not report 'Engine ready' within 60s; "
             "continuing anyway")
    else:
        info("engine ready")

    # ── 3. Browser ─────────────────────────────────────────────
    if not args.no_browser:
        info(f"opening browser at {DASHBOARD_URL}")
        try:
            webbrowser.open(DASHBOARD_URL)
        except Exception as exc:
            warn(f"could not open browser: {exc}")

    banner("RUNNING ;  Ctrl+C to stop")

    # ── 4. Wait loop with signal forwarding ────────────────────
    def shutdown(*_):
        info("shutdown signal received; stopping subprocesses ...")
        for m in (engine, dashboard):
            m.terminate()
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if not engine.is_alive() and not dashboard.is_alive():
                break
            time.sleep(0.1)
        for m in (engine, dashboard):
            if m.is_alive():
                warn(f"force killing {m.name}")
                m.kill()
        info("all subprocesses stopped")
        sys.exit(0)

    if sys.platform == "win32":
        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGBREAK, shutdown)
    else:
        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)

    # Keep main thread alive; pump threads handle stdout.
    try:
        while True:
            if not dashboard.is_alive():
                fail("dashboard crashed; shutting down")
                shutdown()
            if not engine.is_alive():
                fail("engine crashed; shutting down")
                shutdown()
            time.sleep(1.0)
    except KeyboardInterrupt:
        shutdown()

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
