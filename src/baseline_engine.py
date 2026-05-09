"""3-Timescale Behavioral Baseline"""
import sys
import io
import time
import math
import json
import sqlite3
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════

# Per-role: minimum flows before baseline is active
ROLE_MATURITY = {
    "IoT":            30,
    "Printer":        40,
    "Workstation":    80,
    "Server":         200,
    "Infrastructure": 300,
    "Unknown":        80,
}

# 2-week window = 14 days
MEDIUM_WINDOW_DAYS = 14

# Recency weights within the 2-week window
# More recent data gets higher weight
RECENCY_WEIGHTS = {
    "recent":  0.50,   # last 3 days
    "mid":     0.30,   # days 4-7
    "old":     0.20,   # days 8-14
}
RECENT_CUTOFF_DAYS = 3
MID_CUTOFF_DAYS = 7

# Minimum samples per slot before Z-score is meaningful
MIN_SLOT_SAMPLES = 2

# Anchor maturity: need 14 days AND 80% of slots populated
ANCHOR_MIN_DAYS = 14
ANCHOR_MIN_SLOT_COVERAGE = 0.80  # 134/168 slots

# Graduated freeze thresholds
FREEZE_NORMAL    = 0.15   # full learning
FREEZE_ELEVATED  = 0.40   # 50% learning
FREEZE_ANOMALOUS = 0.70   # 10% learning
# >= 0.70 → 0% learning (fully frozen)

DOW_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

# ═══════════════════════════════════════════════════════════════
#  TIME SLOT DATA STRUCTURE
# ═══════════════════════════════════════════════════════════════

class SlotSnapshot:
    """One hourly observation from one day."""
    __slots__ = ['date', 'fpm', 'unique_dst', 'bytes_pf', 'send_ratio',
                 'proto_dist', 'ports', 'timestamp']

    def __init__(self, date: str, fpm: float, unique_dst: float,
                 bytes_pf: float, send_ratio: float,
                 proto_dist: Dict[int, float] = None,
                 ports: set = None, timestamp: float = 0.0):
        self.date = date           # "2026-04-09"
        self.fpm = fpm
        self.unique_dst = unique_dst
        self.bytes_pf = bytes_pf
        self.send_ratio = send_ratio
        self.proto_dist = proto_dist or {}
        self.ports = ports or set()
        self.timestamp = timestamp

class TimeSlot:
    """
    One slot in the 168-slot grid (e.g., Monday 10:00-11:00).
    Stores up to 14 daily snapshots (one per day in the 2-week window).
    Computes weighted mean + std for Z-score detection.
    """

    def __init__(self, dow: int, hour: int):
        self.dow = dow
        self.hour = hour
        self.snapshots: List[SlotSnapshot] = []  # max 14
        self._cached_mean_fpm = 0.0
        self._cached_std_fpm = 1.0
        self._cached_mean_dst = 0.0
        self._cached_std_dst = 1.0
        self._cached_mean_bpf = 0.0
        self._cached_std_bpf = 1.0
        self._cached_mean_sr = 0.5
        self._cached_std_sr = 0.1
        self._dirty = True

    def add_snapshot(self, snap: SlotSnapshot):
        """Add a daily snapshot. Keep max 14 (2-week window)."""
        # Remove existing snapshot for same date (update)
        self.snapshots = [s for s in self.snapshots if s.date != snap.date]
        self.snapshots.append(snap)
        # Prune to 14
        if len(self.snapshots) > 14:
            self.snapshots = self.snapshots[-14:]
        self._dirty = True

    def prune_old(self, cutoff_timestamp: float):
        """Remove snapshots older than the 2-week window."""
        before = len(self.snapshots)
        self.snapshots = [s for s in self.snapshots if s.timestamp >= cutoff_timestamp]
        if len(self.snapshots) != before:
            self._dirty = True

    def _recompute(self, now: float = None):
        """Compute recency-weighted mean and std."""
        if not self._dirty:
            return
        self._dirty = False

        n = len(self.snapshots)
        if n == 0:
            return

        if now is None:
            now = time.time()

        # Assign recency weights
        weights = []
        values_fpm = []
        values_dst = []
        values_bpf = []
        values_sr = []

        for snap in self.snapshots:
            age_days = (now - snap.timestamp) / 86400
            if age_days <= RECENT_CUTOFF_DAYS:
                w = RECENCY_WEIGHTS["recent"]
            elif age_days <= MID_CUTOFF_DAYS:
                w = RECENCY_WEIGHTS["mid"]
            else:
                w = RECENCY_WEIGHTS["old"]

            weights.append(w)
            values_fpm.append(snap.fpm)
            values_dst.append(snap.unique_dst)
            values_bpf.append(snap.bytes_pf)
            values_sr.append(snap.send_ratio)

        # Normalize weights
        total_w = sum(weights)
        if total_w <= 0:
            return
        weights = [w / total_w for w in weights]

        # Weighted mean
        self._cached_mean_fpm = sum(w * v for w, v in zip(weights, values_fpm))
        self._cached_mean_dst = sum(w * v for w, v in zip(weights, values_dst))
        self._cached_mean_bpf = sum(w * v for w, v in zip(weights, values_bpf))
        self._cached_mean_sr = sum(w * v for w, v in zip(weights, values_sr))

        # Weighted std (with Bessel correction for small samples)
        self._cached_std_fpm = self._weighted_std(weights, values_fpm, self._cached_mean_fpm)
        self._cached_std_dst = self._weighted_std(weights, values_dst, self._cached_mean_dst)
        self._cached_std_bpf = self._weighted_std(weights, values_bpf, self._cached_mean_bpf)
        self._cached_std_sr = self._weighted_std(weights, values_sr, self._cached_mean_sr)

    @staticmethod
    def _weighted_std(weights, values, mean) -> float:
        if len(values) < 2:
            return max(mean * 0.20, 1.0)  # default 20% of mean when only 1 sample
        variance = sum(w * (v - mean) ** 2 for w, v in zip(weights, values))
        return max(math.sqrt(variance), 0.01)

    @property
    def n_samples(self) -> int:
        return len(self.snapshots)

    def get_stats(self, now: float = None) -> dict:
        """Return current mean+std for all metrics."""
        self._recompute(now)
        return {
            "mean_fpm": self._cached_mean_fpm,
            "std_fpm": self._cached_std_fpm,
            "mean_unique_dst": self._cached_mean_dst,
            "std_unique_dst": self._cached_std_dst,
            "mean_bytes_pf": self._cached_mean_bpf,
            "std_bytes_pf": self._cached_std_bpf,
            "mean_send_ratio": self._cached_mean_sr,
            "std_send_ratio": self._cached_std_sr,
            "n_samples": self.n_samples,
        }

# ═══════════════════════════════════════════════════════════════
#  ANCHOR (Frozen Long-Term Fingerprint)
# ═══════════════════════════════════════════════════════════════

class BehavioralAnchor:
    """
    Frozen behavioral fingerprint captured after 2 full weeks.
    NEVER auto-updated. Only reset by explicit analyst action.
    """

    def __init__(self):
        self.is_set = False
        self.fpm = 0.0
        self.unique_dst = 0.0
        self.bytes_per_flow = 0.0
        self.send_ratio = 0.5
        self.proto_dist: Dict[int, float] = {}
        self.common_ports: set = set()
        self.created_at = 0.0
        self.created_date = ""

    def capture(self, fpm: float, unique_dst: float, bytes_pf: float,
                send_ratio: float, proto_dist: dict = None,
                ports: set = None, now: float = None):
        """Capture the current state as the anchor. Called once."""
        if now is None:
            now = time.time()
        self.fpm = fpm
        self.unique_dst = unique_dst
        self.bytes_per_flow = bytes_pf
        self.send_ratio = send_ratio
        self.proto_dist = dict(proto_dist) if proto_dist else {}
        self.common_ports = set(ports) if ports else set()
        self.created_at = now
        self.created_date = datetime.fromtimestamp(now).strftime("%Y-%m-%d")
        self.is_set = True

    def drift_ratio(self, current_fpm: float, current_dst: float,
                    current_bpf: float) -> Tuple[float, List[str]]:
        """
        Compare current metrics against anchor.
        Returns (max_drift_ratio, drift_reasons).
        """
        if not self.is_set:
            return 0.0, []

        reasons = []
        max_drift = 0.0

        if self.fpm > 0.1:
            drift = current_fpm / self.fpm
            if drift > max_drift:
                max_drift = drift
            if drift >= 3.0:
                reasons.append(f"Anchor drift: fpm {current_fpm:.0f} vs "
                             f"anchor {self.fpm:.0f} ({drift:.1f}x, "
                             f"set {self.created_date})")

        if self.unique_dst > 0.1:
            drift = current_dst / self.unique_dst
            if drift > max_drift:
                max_drift = drift
            if drift >= 5.0:
                reasons.append(f"Anchor drift: dst {current_dst:.0f} vs "
                             f"anchor {self.unique_dst:.0f} ({drift:.1f}x)")

        if self.bytes_per_flow > 1.0:
            drift = current_bpf / self.bytes_per_flow
            if drift > max_drift:
                max_drift = drift
            if drift >= 10.0:
                reasons.append(f"Anchor drift: bytes {current_bpf:.0f} vs "
                             f"anchor {self.bytes_per_flow:.0f} ({drift:.1f}x)")

        return max_drift, reasons

    def to_dict(self) -> dict:
        return {
            "is_set": self.is_set,
            "fpm": round(self.fpm, 2),
            "unique_dst": round(self.unique_dst, 2),
            "bytes_per_flow": round(self.bytes_per_flow, 2),
            "send_ratio": round(self.send_ratio, 4),
            "created_date": self.created_date,
            "age_days": round((time.time() - self.created_at) / 86400, 1) if self.is_set else 0,
        }

# ═══════════════════════════════════════════════════════════════
#  MAIN: 3-TIMESCALE BASELINE
# ═══════════════════════════════════════════════════════════════

class TimeSlottedBaseline:
    """
    3-timescale behavioral baseline for a single entity.

    SHORT:  Sliding window deques (handled externally by EntityProfileV4)
    MEDIUM: 168 time slots (this class)
    ANCHOR: Frozen fingerprint (this class)
    """

    def __init__(self, role: str = "Unknown"):
        self.role = role
        self.maturity_threshold = ROLE_MATURITY.get(role, 80)

        # Medium-term: 7 days x 24 hours = 168 slots
        self._slots: List[List[TimeSlot]] = [
            [TimeSlot(dow, hour) for hour in range(24)]
            for dow in range(7)
        ]

        # Anchor
        self.anchor = BehavioralAnchor()

        # Global fallback (when specific slot has < MIN_SLOT_SAMPLES)
        # Computed from ALL slots combined
        self._global_mean_fpm = 0.0
        self._global_std_fpm = 1.0
        self._global_mean_dst = 0.0
        self._global_std_dst = 1.0
        self._global_mean_bpf = 0.0
        self._global_std_bpf = 1.0
        self._global_mean_sr = 0.5
        self._global_std_sr = 0.1
        self._global_samples = 0

        # Day-of-week fallback (when specific hour slot is thin)
        self._dow_means: Dict[int, dict] = {}

        # Tracking
        self.total_recordings = 0
        self.first_recording = 0.0
        self.last_recording = 0.0
        self._slots_populated = 0

        # Graduated freeze
        self._learning_rate = 1.0   # 0.0 to 1.0
        self._freeze_level = "NORMAL"

        # Hourly aggregation buffer
        # Accumulates per-flow metrics within the current hour
        # Flushed to slot snapshot when the hour changes
        self._current_hour_key = ""  # "Mon-10"
        self._hour_fpm_samples: List[float] = []
        self._hour_dst_samples: List[float] = []
        self._hour_bpf_samples: List[float] = []
        self._hour_sr_samples: List[float] = []
        self._hour_protos: Dict[int, int] = defaultdict(int)
        self._hour_ports: set = set()
        self._hour_count = 0

    # ── Recording ─────────────────────────────────────────────

    def record(self, fpm: float, unique_dst: float, bytes_pf: float,
               send_ratio: float, proto: int = 0, dst_port: int = 0,
               anomaly_score: float = 0.0, now: float = None):
        """
        Record one observation. Called on every flow (or periodically).

        Accumulates into hourly buffer, then flushes to time slot
        when the hour changes.
        """
        if now is None:
            now = time.time()

        if self.first_recording == 0.0:
            self.first_recording = now
        self.last_recording = now
        self.total_recordings += 1

        # Update graduated freeze from anomaly score
        self._update_freeze(anomaly_score)

        # Apply learning rate
        if self._learning_rate <= 0.0:
            return  # Fully frozen; don't record

        dt = datetime.fromtimestamp(now)
        dow = dt.weekday()
        hour = dt.hour
        date_str = dt.strftime("%Y-%m-%d")
        hour_key = f"{dow}-{hour}"

        # Check if hour changed → flush previous hour to slot
        if self._current_hour_key and self._current_hour_key != hour_key:
            self._flush_hour(now)

        self._current_hour_key = hour_key

        # Accumulate into hourly buffer (with learning rate scaling)
        if self._learning_rate >= 0.50 or self.total_recordings % 2 == 0:
            self._hour_fpm_samples.append(fpm)
            self._hour_dst_samples.append(unique_dst)
            self._hour_bpf_samples.append(bytes_pf)
            self._hour_sr_samples.append(send_ratio)
            if proto:
                self._hour_protos[proto] += 1
            if dst_port:
                self._hour_ports.add(dst_port)
            self._hour_count += 1

    def _flush_hour(self, now: float):
        """Flush hourly buffer into the appropriate time slot."""
        if self._hour_count == 0:
            return

        # Parse the hour key
        parts = self._current_hour_key.split("-")
        if len(parts) != 2:
            self._clear_hour_buffer()
            return

        dow = int(parts[0])
        hour = int(parts[1])

        # Compute hourly aggregates
        n = len(self._hour_fpm_samples)
        if n == 0:
            self._clear_hour_buffer()
            return

        avg_fpm = sum(self._hour_fpm_samples) / n
        avg_dst = sum(self._hour_dst_samples) / n
        avg_bpf = sum(self._hour_bpf_samples) / n
        avg_sr = sum(self._hour_sr_samples) / n

        # Proto distribution for this hour
        total_protos = sum(self._hour_protos.values())
        proto_dist = {p: c / max(total_protos, 1)
                      for p, c in self._hour_protos.items()}

        # Determine date from now (approximate; the flush is for previous hour)
        dt = datetime.fromtimestamp(now - 1800)  # midpoint of previous hour
        date_str = dt.strftime("%Y-%m-%d")

        snap = SlotSnapshot(
            date=date_str,
            fpm=avg_fpm,
            unique_dst=avg_dst,
            bytes_pf=avg_bpf,
            send_ratio=avg_sr,
            proto_dist=proto_dist,
            ports=set(self._hour_ports),
            timestamp=now,
        )

        self._slots[dow][hour].add_snapshot(snap)
        self._clear_hour_buffer()

        # Prune old snapshots across all slots
        cutoff = now - (MEDIUM_WINDOW_DAYS * 86400)
        self._slots[dow][hour].prune_old(cutoff)

        # Update global fallback
        self._recompute_global(now)

        # Check if anchor should be captured
        self._maybe_capture_anchor(now)

    def _clear_hour_buffer(self):
        self._hour_fpm_samples.clear()
        self._hour_dst_samples.clear()
        self._hour_bpf_samples.clear()
        self._hour_sr_samples.clear()
        self._hour_protos.clear()
        self._hour_ports.clear()
        self._hour_count = 0

    def force_flush(self, now: float = None):
        """Force flush current hour buffer (call at shutdown or on demand)."""
        if now is None:
            now = time.time()
        if self._hour_count > 0:
            self._flush_hour(now)

    # ── Graduated Freeze ──────────────────────────────────────

    def _update_freeze(self, anomaly_score: float):
        """Update learning rate based on current anomaly score."""
        if anomaly_score >= FREEZE_ANOMALOUS:
            self._learning_rate = 0.0
            self._freeze_level = "FROZEN"
        elif anomaly_score >= FREEZE_ELEVATED:
            self._learning_rate = 0.10
            self._freeze_level = "ANOMALOUS"
        elif anomaly_score >= FREEZE_NORMAL:
            self._learning_rate = 0.50
            self._freeze_level = "ELEVATED"
        else:
            self._learning_rate = 1.0
            self._freeze_level = "NORMAL"

    # ── Query: Expected Values ────────────────────────────────

    def get_expected(self, now: float = None) -> dict:
        """
        Get expected metric values for the current time slot.
        Falls back to day-of-week average, then global average.

        Returns dict with mean_fpm, std_fpm, mean_dst, std_dst, etc.
        """
        if now is None:
            now = time.time()

        dt = datetime.fromtimestamp(now)
        dow = dt.weekday()
        hour = dt.hour

        slot = self._slots[dow][hour]

        if slot.n_samples >= MIN_SLOT_SAMPLES:
            # Best case: enough data for this exact time slot
            stats = slot.get_stats(now)
            stats["source"] = f"{DOW_NAMES[dow]} {hour:02d}:00 slot"
            stats["fallback"] = False
            return stats

        # Fallback 1: day-of-week average (all hours for this day)
        dow_stats = self._get_dow_average(dow, now)
        if dow_stats and dow_stats["n_samples"] >= MIN_SLOT_SAMPLES:
            dow_stats["source"] = f"{DOW_NAMES[dow]} daily average"
            dow_stats["fallback"] = True
            return dow_stats

        # Fallback 2: global average (all slots)
        if self._global_samples >= 1:
            return {
                "mean_fpm": self._global_mean_fpm,
                "std_fpm": self._global_std_fpm,
                "mean_unique_dst": self._global_mean_dst,
                "std_unique_dst": self._global_std_dst,
                "mean_bytes_pf": self._global_mean_bpf,
                "std_bytes_pf": self._global_std_bpf,
                "mean_send_ratio": self._global_mean_sr,
                "std_send_ratio": self._global_std_sr,
                "n_samples": self._global_samples,
                "source": "global average",
                "fallback": True,
            }

        # Fallback 3: current hour buffer (not yet flushed; early baseline)
        return self._get_hour_buffer_stats()

    def _get_dow_average(self, dow: int, now: float) -> Optional[dict]:
        """Average across all hours for a given day of week."""
        all_fpm = []
        all_dst = []
        all_bpf = []
        all_sr = []

        for hour in range(24):
            slot = self._slots[dow][hour]
            if slot.n_samples > 0:
                stats = slot.get_stats(now)
                all_fpm.append(stats["mean_fpm"])
                all_dst.append(stats["mean_unique_dst"])
                all_bpf.append(stats["mean_bytes_pf"])
                all_sr.append(stats["mean_send_ratio"])

        n = len(all_fpm)
        if n == 0:
            return None

        mean_fpm = sum(all_fpm) / n
        mean_dst = sum(all_dst) / n
        mean_bpf = sum(all_bpf) / n
        mean_sr = sum(all_sr) / n

        return {
            "mean_fpm": mean_fpm,
            "std_fpm": max((sum((v - mean_fpm)**2 for v in all_fpm) / max(n, 1))**0.5, 0.01),
            "mean_unique_dst": mean_dst,
            "std_unique_dst": max((sum((v - mean_dst)**2 for v in all_dst) / max(n, 1))**0.5, 0.01),
            "mean_bytes_pf": mean_bpf,
            "std_bytes_pf": max((sum((v - mean_bpf)**2 for v in all_bpf) / max(n, 1))**0.5, 0.01),
            "mean_send_ratio": mean_sr,
            "std_send_ratio": max((sum((v - mean_sr)**2 for v in all_sr) / max(n, 1))**0.5, 0.01),
            "n_samples": n,
        }

    def _get_hour_buffer_stats(self) -> dict:
        """Compute stats from current unflushed hourly buffer. Early-baseline fallback."""
        n = len(self._hour_fpm_samples)
        if n == 0:
            return {
                "mean_fpm": 1.0, "std_fpm": 1.0,
                "mean_unique_dst": 1.0, "std_unique_dst": 1.0,
                "mean_bytes_pf": 1.0, "std_bytes_pf": 1.0,
                "mean_send_ratio": 0.5, "std_send_ratio": 0.1,
                "n_samples": 0, "source": "no data", "fallback": True,
            }

        mean_fpm = sum(self._hour_fpm_samples) / n
        mean_dst = sum(self._hour_dst_samples) / n
        mean_bpf = sum(self._hour_bpf_samples) / n
        mean_sr = sum(self._hour_sr_samples) / n

        def _std(vals, mean):
            if len(vals) < 2:
                return max(mean * 0.20, 1.0)
            return max((sum((v - mean)**2 for v in vals) / len(vals))**0.5, 0.01)

        return {
            "mean_fpm": mean_fpm,
            "std_fpm": _std(self._hour_fpm_samples, mean_fpm),
            "mean_unique_dst": mean_dst,
            "std_unique_dst": _std(self._hour_dst_samples, mean_dst),
            "mean_bytes_pf": mean_bpf,
            "std_bytes_pf": _std(self._hour_bpf_samples, mean_bpf),
            "mean_send_ratio": mean_sr,
            "std_send_ratio": _std(self._hour_sr_samples, mean_sr),
            "n_samples": n,
            "source": "current hour buffer",
            "fallback": True,
        }

    def _recompute_global(self, now: float):
        """Recompute global fallback from all populated slots."""
        all_fpm = []
        all_dst = []
        all_bpf = []
        all_sr = []
        populated = 0

        for dow in range(7):
            for hour in range(24):
                slot = self._slots[dow][hour]
                if slot.n_samples > 0:
                    populated += 1
                    stats = slot.get_stats(now)
                    all_fpm.append(stats["mean_fpm"])
                    all_dst.append(stats["mean_unique_dst"])
                    all_bpf.append(stats["mean_bytes_pf"])
                    all_sr.append(stats["mean_send_ratio"])

        self._slots_populated = populated
        n = len(all_fpm)
        if n == 0:
            return

        self._global_samples = n
        self._global_mean_fpm = sum(all_fpm) / n
        self._global_std_fpm = max((sum((v - self._global_mean_fpm)**2 for v in all_fpm) / n)**0.5, 0.01)
        self._global_mean_dst = sum(all_dst) / n
        self._global_std_dst = max((sum((v - self._global_mean_dst)**2 for v in all_dst) / n)**0.5, 0.01)
        self._global_mean_bpf = sum(all_bpf) / n
        self._global_std_bpf = max((sum((v - self._global_mean_bpf)**2 for v in all_bpf) / n)**0.5, 0.01)
        self._global_mean_sr = sum(all_sr) / n
        self._global_std_sr = max((sum((v - self._global_mean_sr)**2 for v in all_sr) / n)**0.5, 0.01)

    # ── Z-Score Queries ───────────────────────────────────────

    def z_score_fpm(self, current_fpm: float, now: float = None) -> float:
        """Z-score of current fpm against the appropriate time slot."""
        expected = self.get_expected(now)
        std = max(expected["std_fpm"], 0.01)
        return abs(current_fpm - expected["mean_fpm"]) / std

    def z_score_unique_dst(self, current_dst: float, now: float = None) -> float:
        expected = self.get_expected(now)
        std = max(expected["std_unique_dst"], 0.01)
        return abs(current_dst - expected["mean_unique_dst"]) / std

    def z_score_bytes_pf(self, current_bpf: float, now: float = None) -> float:
        expected = self.get_expected(now)
        std = max(expected["std_bytes_pf"], 0.01)
        return abs(current_bpf - expected["mean_bytes_pf"]) / std

    def z_score_send_ratio(self, current_sr: float, now: float = None) -> float:
        expected = self.get_expected(now)
        std = max(expected["std_send_ratio"], 0.001)
        return abs(current_sr - expected["mean_send_ratio"]) / std

    # ── Anchor Management ─────────────────────────────────────

    def _maybe_capture_anchor(self, now: float):
        """Capture anchor after 2 full weeks with good slot coverage."""
        if self.anchor.is_set:
            return

        age_days = (now - self.first_recording) / 86400
        if age_days < ANCHOR_MIN_DAYS:
            return

        coverage = self._slots_populated / 168
        if coverage < ANCHOR_MIN_SLOT_COVERAGE:
            return

        # Capture anchor from global averages
        self.anchor.capture(
            fpm=self._global_mean_fpm,
            unique_dst=self._global_mean_dst,
            bytes_pf=self._global_mean_bpf,
            send_ratio=self._global_mean_sr,
            now=now,
        )

    def check_anchor_drift(self, current_fpm: float, current_dst: float,
                           current_bpf: float) -> Tuple[float, List[str]]:
        """Compare current metrics against frozen anchor."""
        return self.anchor.drift_ratio(current_fpm, current_dst, current_bpf)

    # ── Maturity ──────────────────────────────────────────────

    @property
    def is_mature(self) -> bool:
        """Baseline has enough data for detection."""
        if self.total_recordings < self.maturity_threshold:
            return False
        # Mature if we have flushed slot data OR current hour buffer has data
        return self._global_samples >= 1 or self._hour_count >= 10

    @property
    def is_fully_mature(self) -> bool:
        """2 full weeks of data, anchor set."""
        return self.anchor.is_set and self._slots_populated >= 100

    @property
    def maturity_pct(self) -> float:
        """0-100% maturity indicator."""
        if self.total_recordings == 0:
            return 0.0
        flow_pct = min(self.total_recordings / self.maturity_threshold, 1.0) * 50
        slot_pct = min(self._slots_populated / 168, 1.0) * 50
        return min(flow_pct + slot_pct, 100.0)

    # ── Compatibility: EMA-style queries for gradual migration ─

    @property
    def baseline_fpm(self) -> Optional[float]:
        """EMA-compatible: return global mean fpm."""
        if self._global_samples == 0:
            return None
        return self._global_mean_fpm

    @property
    def baseline_unique_dst(self) -> Optional[float]:
        if self._global_samples == 0:
            return None
        return self._global_mean_dst

    @property
    def baseline_bytes_per_flow(self) -> Optional[float]:
        if self._global_samples == 0:
            return None
        return self._global_mean_bpf

    @property
    def baseline_send_ratio(self) -> Optional[float]:
        if self._global_samples == 0:
            return None
        return self._global_mean_sr

    # ── Status ────────────────────────────────────────────────

    def get_status(self) -> dict:
        return {
            "role": self.role,
            "maturity_threshold": self.maturity_threshold,
            "total_recordings": self.total_recordings,
            "is_mature": self.is_mature,
            "is_fully_mature": self.is_fully_mature,
            "maturity_pct": round(self.maturity_pct, 1),
            "slots_populated": self._slots_populated,
            "slots_total": 168,
            "slot_coverage": f"{self._slots_populated}/168 ({self._slots_populated/168*100:.0f}%)",
            "freeze_level": self._freeze_level,
            "learning_rate": self._learning_rate,
            "anchor": self.anchor.to_dict(),
            "global_mean_fpm": round(self._global_mean_fpm, 2),
            "global_std_fpm": round(self._global_std_fpm, 2),
            "age_days": round((time.time() - self.first_recording) / 86400, 1) if self.first_recording else 0,
        }

    def print_heatmap(self):
        """Print a visual heatmap of slot population."""
        print(f"\n  Baseline Heatmap ({self._slots_populated}/168 slots)")
        print(f"  Hour:  00 01 02 03 04 05 06 07 08 09 10 11 "
              f"12 13 14 15 16 17 18 19 20 21 22 23")
        for dow in range(7):
            row = f"  {DOW_NAMES[dow]}: "
            for hour in range(24):
                n = self._slots[dow][hour].n_samples
                if n == 0:
                    row += " . "
                elif n == 1:
                    row += " o "
                elif n < 5:
                    row += " O "
                else:
                    row += " # "
            print(row)
        print(f"  Legend: .=empty  o=1 sample  O=2-4  #=5+")
