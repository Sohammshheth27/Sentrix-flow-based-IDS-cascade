"""Long-term-only UEBA with two-layer baselines"""
from __future__ import annotations

import json
import logging
import math
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger("ueba_long")

# ── Tunables ────────────────────────────────────────────────────────

DEFAULT_TARGET_SECONDS = 14 * 86400      # 14 days of observed uptime
DEFAULT_SPIKE_ZSCORE = 3.0                # alert when |z| exceeds this
DEFAULT_MIN_SAMPLES_FOR_Z = 30             # need at least N points before scoring
DEFAULT_STATE_SAVE_INTERVAL = 300.0        # 5 minutes

# The six metrics we track per flow. Each is a scalar feature
# extractable directly from a flow dict. These were chosen because:
#   (a) they're log-compressed so outliers don't blow up the variance
#   (b) they cover volume (bytes/pkts), shape (bytes/pkt), timing
#       (duration, rates), which is what "long-term behaviour" means
METRIC_NAMES = (
    "log1p_bytes",
    "log1p_packets",
    "log1p_duration",
    "bytes_per_packet",
    "log1p_bytes_per_sec",
    "log1p_packets_per_sec",
)

def _log1p_safe(x: float) -> float:
    try:
        return math.log1p(max(0.0, float(x)))
    except (TypeError, ValueError):
        return 0.0

def _flow_metrics(flow: Dict[str, Any]) -> Dict[str, float]:
    """Extract the six tracked metrics from a raw flow dict."""
    def g(*keys: str) -> float:
        for k in keys:
            v = flow.get(k)
            if v is None or v == "":
                continue
            try:
                fv = float(v)
                if math.isnan(fv) or math.isinf(fv):
                    continue
                return fv
            except (TypeError, ValueError):
                continue
        return 0.0

    total_bytes = g("total_bytes", "total_payload_bytes", "bytes")
    total_pkts = g("total_packets", "packets_count", "packets",
                    "packets_numbers")
    if total_bytes <= 0:
        total_bytes = g("fwd_bytes", "fwd_total_payload_bytes") + \
                       g("bwd_bytes", "bwd_total_payload_bytes")
    if total_pkts <= 0:
        total_pkts = g("fwd_packets", "fwd_packets_count") + \
                       g("bwd_packets", "bwd_packets_count")

    duration = g("duration", "flow_duration")
    bpp = total_bytes / max(total_pkts, 1.0)
    bps = total_bytes / max(duration, 0.001)
    pps = total_pkts / max(duration, 0.001)

    return {
        "log1p_bytes":           _log1p_safe(total_bytes),
        "log1p_packets":         _log1p_safe(total_pkts),
        "log1p_duration":        _log1p_safe(duration),
        "bytes_per_packet":      float(max(0.0, bpp)),
        "log1p_bytes_per_sec":   _log1p_safe(bps),
        "log1p_packets_per_sec": _log1p_safe(pps),
    }

# ── Welford's online stats ──────────────────────────────────────────

class WelfordStat:
    """Numerically stable running mean and variance. O(1) memory."""
    __slots__ = ("n", "mean", "M2")

    def __init__(self, n: int = 0, mean: float = 0.0, M2: float = 0.0):
        self.n = n
        self.mean = mean
        self.M2 = M2

    def update(self, value: float) -> None:
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        delta2 = value - self.mean
        self.M2 += delta * delta2

    @property
    def variance(self) -> float:
        if self.n < 2:
            return 0.0
        return self.M2 / (self.n - 1)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    def zscore(self, value: float) -> float:
        """Z of `value` vs the tracked distribution. 0.0 if std==0."""
        s = self.std
        if s <= 0:
            return 0.0
        return (value - self.mean) / s

    def to_dict(self) -> Dict[str, float]:
        return {"n": self.n, "mean": self.mean, "M2": self.M2}

    @classmethod
    def from_dict(cls, d: Dict[str, float]) -> "WelfordStat":
        return cls(n=int(d.get("n", 0)),
                    mean=float(d.get("mean", 0.0)),
                    M2=float(d.get("M2", 0.0)))

    def copy(self) -> "WelfordStat":
        return WelfordStat(n=self.n, mean=self.mean, M2=self.M2)

# ── Device and Department baselines ─────────────────────────────────

class Baseline:
    """A bundle of WelfordStat objects, one per tracked metric."""

    def __init__(self) -> None:
        self.stats: Dict[str, WelfordStat] = {
            name: WelfordStat() for name in METRIC_NAMES
        }
        self.total_flows = 0
        self.first_seen: Optional[float] = None
        self.last_seen: Optional[float] = None
        self.inherited_from: Optional[str] = None  # dept name if inherited

    def update(self, metrics: Dict[str, float], now: float) -> None:
        for name in METRIC_NAMES:
            if name in metrics:
                self.stats[name].update(metrics[name])
        self.total_flows += 1
        if self.first_seen is None:
            self.first_seen = now
        self.last_seen = now

    def max_zscore(self, metrics: Dict[str, float]) -> tuple[float, str]:
        """Return (max |z-score|, metric_name_that_produced_it)."""
        best_abs = 0.0
        best_name = ""
        best_signed = 0.0
        for name in METRIC_NAMES:
            if name not in metrics:
                continue
            st = self.stats[name]
            if st.n < DEFAULT_MIN_SAMPLES_FOR_Z:
                continue
            z = st.zscore(metrics[name])
            if abs(z) > best_abs:
                best_abs = abs(z)
                best_name = name
                best_signed = z
        return best_signed, best_name

    def mature(self) -> bool:
        """True once every metric has at least MIN_SAMPLES_FOR_Z points."""
        return all(
            self.stats[name].n >= DEFAULT_MIN_SAMPLES_FOR_Z
            for name in METRIC_NAMES
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_flows": self.total_flows,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "inherited_from": self.inherited_from,
            "stats": {n: s.to_dict() for n, s in self.stats.items()},
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Baseline":
        b = cls()
        b.total_flows = int(d.get("total_flows", 0))
        b.first_seen = d.get("first_seen")
        b.last_seen = d.get("last_seen")
        b.inherited_from = d.get("inherited_from")
        for name in METRIC_NAMES:
            sd = d.get("stats", {}).get(name)
            if sd is not None:
                b.stats[name] = WelfordStat.from_dict(sd)
        return b

    def seed_from(self, other: "Baseline", source_name: str) -> None:
        """
        Copy another baseline's state (used when a new device inherits
        its department's baseline post-activation).
        """
        for name in METRIC_NAMES:
            self.stats[name] = other.stats[name].copy()
        self.inherited_from = source_name

# ── UEBALong main orchestrator ──────────────────────────────────────

class UEBALong:
    """
    Long-term-only UEBA with per-device and per-department baselines,
    14-day learning window, and automatic department-baseline inheritance
    for devices first seen after activation.
    """

    def __init__(
        self,
        state_path: Optional[Path] = None,
        runtime_state=None,
        entity_context=None,
        target_seconds: int = DEFAULT_TARGET_SECONDS,
        spike_zscore: float = DEFAULT_SPIKE_ZSCORE,
        timezone: str = "Asia/Kolkata",
    ):
        self.state_path = Path(state_path) if state_path else None
        self.runtime_state = runtime_state
        self.entity_context = entity_context
        self.target_seconds = target_seconds
        self.spike_zscore = spike_zscore
        self.timezone = timezone

        # Holiday calendar; suppress UEBA scoring on the first workday
        # morning after a holiday to avoid post-holiday FP storms.
        self._holidays: Set[str] = set()
        self._holiday_suppress_hours = 4
        _hcfg = Path(__file__).resolve().parent.parent / "config" / "holidays.yaml"
        if _hcfg.exists():
            try:
                import yaml
                with open(_hcfg, "r", encoding="utf-8") as _fh:
                    _hdata = yaml.safe_load(_fh) or {}
                self._holidays = set(_hdata.get("holidays") or [])
                self._holiday_suppress_hours = int(
                    _hdata.get("suppression_hours_after_holiday", 4))
                log.info(f"  UEBALong: loaded {len(self._holidays)} holidays "
                         f"(suppress {self._holiday_suppress_hours}h after)")
            except Exception as e:
                log.warning(f"  UEBALong: holiday calendar load failed: {e}")

        self._lock = threading.RLock()
        self._devices: Dict[str, Baseline] = {}
        self._departments: Dict[str, Baseline] = {}

        # Stats
        self.stats = {
            "flows_processed":   0,
            "devices_tracked":   0,
            "departments":       0,
            "alerts_fired":      0,
            "alerts_suppressed_learning": 0,
            "inheritances":      0,
            "last_save_at":      0.0,
        }

        self._save_thread: Optional[threading.Thread] = None
        self._save_stop = threading.Event()

        if self.state_path and self.state_path.exists():
            self.load_state()
        else:
            log.info("  UEBALong: no prior state; starting fresh")

        self._start_save_thread()
        log.info(
            f"  UEBALong ready: {len(self._devices)} devices, "
            f"{len(self._departments)} departments loaded"
        )

    def _in_post_holiday_window(self, now: float) -> bool:
        """True if 'now' falls within the suppression window after a holiday.

        Date boundaries are evaluated in self.timezone (default Asia/Kolkata)
        so that a 00:30 IST flow on the day after Diwali lands on the correct
        calendar date; a naive fromtimestamp() on a UTC-clocked server would
        resolve that moment to the previous UTC day and miss the post-holiday
        window by 5.5 hours.
        """
        if not self._holidays:
            return False
        try:
            from zoneinfo import ZoneInfo
            tz = ZoneInfo(self.timezone)
        except Exception:
            tz = None
        dt = datetime.fromtimestamp(now, tz=tz) if tz else datetime.fromtimestamp(now)
        yesterday = (dt - timedelta(days=1)).strftime("%Y-%m-%d")
        if yesterday in self._holidays and dt.hour < self._holiday_suppress_hours:
            return True
        today = dt.strftime("%Y-%m-%d")
        if today in self._holidays:
            return True
        return False

    # ── Core processing ─────────────────────────────────────────────

    def process_flow(
        self,
        flow: Dict[str, Any],
        raw_features: Optional[Dict[str, Any]] = None,
        specialist_results: Optional[List[Dict[str, Any]]] = None,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Main per-flow entry point. Always called from realtime_engine.
        During learning: updates baselines, returns should_alert=False.
        After activation: updates + scores, returns should_alert when
        any metric exceeds spike_zscore.
        """
        if now is None:
            now = time.time()

        src_ip = flow.get("src_ip", "")
        if not src_ip:
            return self._empty_result("no src_ip")

        # External IPs (Google, Cloudflare, YouTube CDNs, etc.) are
        # not office devices; skip baseline and scoring entirely so
        # we don't pollute ueba_long_state.json with per-public-IP
        # state. Uses the entity_context classifier singleton.
        if (self.entity_context is not None
                and getattr(self.entity_context, "_ip_classifier", None)
                and self.entity_context._ip_classifier.is_external(src_ip)):
            self.stats["external_skipped"] = \
                self.stats.get("external_skipped", 0) + 1
            return self._empty_result("external_ip")

        self.stats["flows_processed"] += 1

        # Pause check; if the dashboard has paused the UEBA clock,
        # neither observe nor score. Baselines freeze.
        if self.runtime_state and self.runtime_state.is_ueba_paused():
            return self._empty_result("ueba_paused")

        # Resolve department
        dept = self._resolve_department(src_ip)

        metrics = _flow_metrics(flow)

        with self._lock:
            # Department baseline; updated every flow regardless of
            # learning/active phase.
            dept_bl = self._departments.get(dept)
            if dept_bl is None:
                dept_bl = Baseline()
                self._departments[dept] = dept_bl
                self.stats["departments"] = len(self._departments)

            # Device baseline; lazily created.
            dev_bl = self._devices.get(src_ip)
            is_new_device = dev_bl is None
            if is_new_device:
                dev_bl = Baseline()
                self._devices[src_ip] = dev_bl
                self.stats["devices_tracked"] = len(self._devices)

            ueba_active = self._is_active()

            # Cold-start inheritance; brand-new device gets seeded
            # from its department baseline as soon as that baseline
            # is mature, regardless of whether UEBA is still in its
            # 14-day learning window. Previously this was gated on
            # ueba_active, which meant a device joining on day 5
            # had to build its own baseline from scratch and was
            # effectively unscoreable until week 5+. Alert *scoring*
            # is still gated by ueba_active on the outer loop below,
            # so inheriting during learning is safe: we warm the
            # device baseline now, start scoring it when the clock
            # activates on day 14.
            if is_new_device and dept_bl.mature():
                dev_bl.seed_from(dept_bl, source_name=dept)
                self.stats["inheritances"] += 1
                log.info(
                    f"  UEBALong: new device {src_ip} inheriting "
                    f"baseline from department '{dept}' "
                    f"({dept_bl.total_flows} flows, "
                    f"phase={'active' if ueba_active else 'learning'})"
                )

            # Always update dept baseline (aggregate observation).
            dept_bl.update(metrics, now)

            # Update the device baseline unless it's a mature
            # post-activation device; then we want the device to
            # eventually drift from the inherited baseline, so we
            # still update but that's fine; the inheritance mark
            # remains in place for audit purposes only.
            dev_bl.update(metrics, now)

            # ── Scoring (only after activation) ─────────────────
            if not ueba_active:
                self.stats["alerts_suppressed_learning"] += 1
                return self._learning_result(dev_bl, dept_bl, dept)

            # Pick the best baseline to score against. A brand-new
            # device that just inherited uses its seeded (= dept)
            # baseline; mature devices use their own.
            score_bl = dev_bl if dev_bl.mature() else dept_bl
            if not score_bl.mature():
                # Department itself isn't mature yet; can't score.
                return self._learning_result(dev_bl, dept_bl, dept)

            signed_z, metric_name = score_bl.max_zscore(metrics)

        # Below this point we're outside the lock to minimise
        # contention on the per-flow hot path.

        abs_z = abs(signed_z)
        spike_thr = self._current_spike_threshold()

        if abs_z >= spike_thr:
            self.stats["alerts_fired"] += 1
            severity = self._zscore_to_severity(abs_z)
            return {
                "risk_score": round(min(abs_z * 10, 100.0), 2),
                "anomaly_score": round(min(abs_z / 10.0, 1.0), 4),
                "specialist_verdict": "Behavioral_Anomaly",
                "specialist_confidence": round(min(abs_z / 5.0, 1.0), 4),
                "specialist_consensus": 0,
                "reasons": [
                    f"UEBA spike: {metric_name} z={signed_z:+.2f} "
                    f"(threshold {spike_thr:.1f})",
                    f"scored against {'device' if dev_bl.mature() else 'department'} "
                    f"baseline"
                    + (f" (inherited from {dev_bl.inherited_from})"
                       if dev_bl.inherited_from else ""),
                ],
                "should_alert": not self._in_post_holiday_window(now),
                "alert_severity": severity,
                "alert_tag": "UEBA_LONG",
                "baseline_ready": True,
                "device_role": "",
                "gates_passed": 1,
                "gate_blocked_by": "",
            }

        # Below threshold; benign.
        return {
            "risk_score": round(min(abs_z * 2, 100.0), 2),
            "anomaly_score": round(min(abs_z / 10.0, 1.0), 4),
            "specialist_verdict": "BENIGN",
            "specialist_confidence": 0.0,
            "specialist_consensus": 0,
            "reasons": [],
            "should_alert": False,
            "alert_severity": "BENIGN",
            "alert_tag": "",
            "baseline_ready": True,
            "device_role": "",
            "gates_passed": 1,
            "gate_blocked_by": "",
        }

    # ── Helpers ─────────────────────────────────────────────────────

    def _resolve_department(self, src_ip: str) -> str:
        if self.entity_context is None:
            return "Unknown"
        try:
            ident = self.entity_context.get_identity(src_ip)
            if ident is not None and getattr(ident, "department", None):
                return ident.department
        except Exception:
            pass
        return "Unknown"

    def _is_active(self) -> bool:
        if self.runtime_state is None:
            return False
        return self.runtime_state.is_ueba_active()

    def _current_spike_threshold(self) -> float:
        if self.runtime_state is None:
            return self.spike_zscore
        try:
            return self.runtime_state.get_float(
                "ueba_spike_zscore", self.spike_zscore
            )
        except Exception:
            return self.spike_zscore

    @staticmethod
    def _zscore_to_severity(abs_z: float) -> str:
        if abs_z >= 6.0: return "CRITICAL"
        if abs_z >= 4.5: return "HIGH"
        if abs_z >= 3.5: return "MEDIUM"
        return "LOW"

    def _empty_result(self, reason: str) -> Dict[str, Any]:
        return {
            "risk_score": 0.0,
            "anomaly_score": 0.0,
            "specialist_verdict": "BENIGN",
            "specialist_confidence": 0.0,
            "specialist_consensus": 0,
            "reasons": [reason] if reason else [],
            "should_alert": False,
            "alert_severity": "BENIGN",
            "alert_tag": "",
            "baseline_ready": False,
            "device_role": "",
            "gates_passed": 0,
            "gate_blocked_by": reason,
        }

    def _learning_result(self, dev_bl: Baseline, dept_bl: Baseline,
                          dept: str) -> Dict[str, Any]:
        progress_pct = self._learning_progress_pct()
        return {
            "risk_score": 0.0,
            "anomaly_score": 0.0,
            "specialist_verdict": "BENIGN",
            "specialist_confidence": 0.0,
            "specialist_consensus": 0,
            "reasons": [
                f"UEBA learning: {progress_pct:.1f}% "
                f"(dev flows {dev_bl.total_flows}, "
                f"dept '{dept}' flows {dept_bl.total_flows})"
            ],
            "should_alert": False,
            "alert_severity": "BENIGN",
            "alert_tag": "",
            "baseline_ready": False,
            "device_role": "",
            "gates_passed": 0,
            "gate_blocked_by": "learning",
        }

    def _learning_progress_pct(self) -> float:
        if self.runtime_state is None:
            return 0.0
        try:
            status = self.runtime_state.get_ueba_status()
            observed = float(status.get("observed_seconds", 0.0) or 0)
            target = float(status.get("target_seconds", self.target_seconds))
            if target <= 0:
                return 100.0
            return min(100.0, 100.0 * observed / target)
        except Exception:
            return 0.0

    # ── Reset / admin ───────────────────────────────────────────────

    def reset_baselines(self) -> None:
        """Wipe ALL learned state. Called by runtime_state.reset_clock."""
        with self._lock:
            self._devices.clear()
            self._departments.clear()
            self.stats["devices_tracked"] = 0
            self.stats["departments"] = 0
            self.stats["inheritances"] = 0
        log.info("  UEBALong: baselines reset")
        if self.state_path:
            try:
                if self.state_path.exists():
                    self.state_path.unlink()
            except Exception:
                pass

    # ── Persistence ─────────────────────────────────────────────────

    def save_state(self) -> None:
        if not self.state_path:
            return
        try:
            with self._lock:
                payload = {
                    "version": 1,
                    "saved_at": time.time(),
                    "devices": {
                        ip: bl.to_dict() for ip, bl in self._devices.items()
                    },
                    "departments": {
                        d: bl.to_dict() for d, bl in self._departments.items()
                    },
                    "stats": dict(self.stats),
                }
            tmp = self.state_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(self.state_path)
            self.stats["last_save_at"] = time.time()
        except Exception as e:
            log.warning(f"  UEBALong: save_state failed: {e}")

    def load_state(self) -> None:
        if not self.state_path or not self.state_path.exists():
            return
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
            with self._lock:
                self._devices = {
                    ip: Baseline.from_dict(d)
                    for ip, d in (payload.get("devices") or {}).items()
                }
                self._departments = {
                    d: Baseline.from_dict(b)
                    for d, b in (payload.get("departments") or {}).items()
                }
                self.stats["devices_tracked"] = len(self._devices)
                self.stats["departments"] = len(self._departments)
            log.info(
                f"  UEBALong: loaded state from {self.state_path.name} "
                f"({len(self._devices)} devices, "
                f"{len(self._departments)} depts)"
            )
        except Exception as e:
            log.warning(f"  UEBALong: load_state failed: {e}")

    def _start_save_thread(self) -> None:
        def _loop():
            while not self._save_stop.is_set():
                if self._save_stop.wait(DEFAULT_STATE_SAVE_INTERVAL):
                    break
                try:
                    self.save_state()
                except Exception as e:
                    log.warning(f"  UEBALong: periodic save error: {e}")

        self._save_thread = threading.Thread(
            target=_loop, daemon=True, name="ueba-long-save"
        )
        self._save_thread.start()

    def shutdown(self) -> None:
        """Flush state on clean shutdown."""
        self._save_stop.set()
        self.save_state()

    # ── Inspection (for dashboards/debug) ──────────────────────────

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "devices_tracked":   len(self._devices),
                "departments":       len(self._departments),
                "total_flows":       self.stats["flows_processed"],
                "alerts_fired":      self.stats["alerts_fired"],
                "alerts_suppressed_learning":
                                     self.stats["alerts_suppressed_learning"],
                "inheritances":      self.stats["inheritances"],
                "last_save_at":      self.stats["last_save_at"],
            }

    def get_department_baselines(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {
                name: {
                    "total_flows": bl.total_flows,
                    "mature": bl.mature(),
                    "metrics": {
                        m: {"n": bl.stats[m].n,
                             "mean": round(bl.stats[m].mean, 4),
                             "std":  round(bl.stats[m].std, 4)}
                        for m in METRIC_NAMES
                    },
                }
                for name, bl in self._departments.items()
            }
