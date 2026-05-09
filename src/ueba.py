"""Specialist-Fused UEBA Engine (Zero False Positive Target)"""
import os
import sys
import io
import json
import time
import math
import sqlite3
import threading
import numpy as np
import joblib
import onnxruntime as ort
from pathlib import Path

# Fix Windows console encoding
if sys.stdout and sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass
if sys.stderr and sys.stderr.encoding != 'utf-8':
    try:
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Set

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

from baseline_engine import TimeSlottedBaseline, ROLE_MATURITY

# ═══════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════

WINDOW_SEC             = 60
REPUTATION_DECAY       = 0.998     # FP reputation decays slowly

# Per-specialist confidence gates (calibrated from validation)
SPEC_GATE = {
    "spec1_cic":    0.75,   # 7-class multi-attack; needs higher bar
    "spec2_botnet": 0.80,   # binary; high precision expected
    "spec3_iot":    0.75,   # 7-class IoT; moderate bar
}

# Severity thresholds (from confidence)
CONF_CRITICAL = 0.95
CONF_HIGH     = 0.85
CONF_MEDIUM   = 0.70
CONF_LOW      = 0.55
CONF_GATE     = 0.55

# Risk thresholds per device role
ROLE_THRESHOLDS = {
    "Workstation":    60,
    "Server":         75,
    "IoT":            50,
    "Infrastructure": 85,
    "Printer":        45,
    "Unknown":        60,
}

ROLE_DECAY = {
    "Workstation":    0.997,
    "Server":         0.999,
    "IoT":            0.995,
    "Infrastructure": 0.9995,
    "Printer":        0.994,
    "Unknown":        0.997,
}

ROLE_SEVERITY_MULT = {
    "Workstation":    1.0,
    "Server":         0.7,
    "IoT":            1.3,
    "Infrastructure": 0.5,
    "Printer":        1.5,
    "Unknown":        1.0,
}

# Threat ports (MITRE ATT&CK + SANS + Shodan honeypot data)
THREAT_PORTS = {
    4444: "Metasploit", 4445: "Metasploit-alt", 5555: "Android-ADB",
    23: "Telnet/Mirai", 2323: "Telnet-alt/Mirai",
    6667: "IRC-C2", 6668: "IRC-C2", 6669: "IRC-C2",
    31337: "Backdoor-Elite", 1234: "Backdoor",
    9999: "IoT-C2", 48101: "Mirai-C2",
    3389: "RDP", 5900: "VNC", 5985: "WinRM",
    445: "SMB", 135: "RPC", 139: "NetBIOS",
    8545: "Ethereum-RPC", 3333: "Cryptominer",
}

# Device classification ports
SERVER_PORTS   = {80, 443, 8080, 8443, 22, 3306, 5432, 25, 110, 143, 993, 995}
IOT_PORTS      = {1883, 8883, 5683, 1884, 554, 8554, 502, 102}
INFRA_PORTS    = {53, 67, 68, 88, 389, 636, 123, 514, 161}
PRINTER_PORTS  = {9100, 515, 631}

# Consensus: minimum agreeing sources to fire at each severity
CONSENSUS_REQUIRED = {
    "CRITICAL": 2,   # at least 2 sources must agree for CRITICAL
    "HIGH":     2,
    "MEDIUM":   1,   # single strong signal OK for MEDIUM
    "LOW":      1,
}

# Temporal aggregation
TEMPORAL_WINDOW_SEC  = 60
TEMPORAL_ALERT_RATIO = 0.15   # 15% of flows in window must be attack

# Alert dedup
DEDUP_COOLDOWN_SEC = 300      # 5 min per alert type per entity

# ═══════════════════════════════════════════════════════════════════
#  SPECIALIST ONNX INFERENCE
# ═══════════════════════════════════════════════════════════════════

class SpecialistModel:
    """Single specialist ONNX model with scaler and metadata."""

    def __init__(self, name: str, models_dir: Path):
        self.name = name
        self.loaded = False
        self.session = None
        self.scaler = None
        self.meta = {}
        self.features = []
        self.classes = []
        self.n_features = 0
        self.benign_idx = 0
        self.input_name = ""
        self._lock = threading.Lock()

        self._load(models_dir)

    def _load(self, md: Path):
        prefix_map = {
            # spec1/spec2 now point at universal-32 variants (better F1,
            # fixes Argus/Zeek mismatch on spec2). spec3 stays native-41 :
            # its IoT protocol features can't be reconstructed from the
            # universal schema (uni variant loses ~22pts F1).
            "spec1_cic":    ("spec1_cic_uni",    "spec1_cic_uni_meta.json",    "spec1_cic_uni_scaler.pkl"),
            "spec2_botnet": ("spec2_botnet_uni", "spec2_botnet_uni_meta.json", "spec2_botnet_uni_scaler.pkl"),
            "spec3_iot":    ("spec3_iot",        "spec3_meta.json",            "spec3_scaler.pkl"),
        }

        if self.name not in prefix_map:
            print(f"[Specialist:{self.name}] Unknown model name")
            return

        model_base, meta_file, scaler_file = prefix_map[self.name]
        onnx_path = md / f"{model_base}.onnx"
        meta_path = md / meta_file
        scaler_path = md / scaler_file

        if not onnx_path.exists():
            print(f"[Specialist:{self.name}] ONNX not found: {onnx_path}")
            return

        try:
            with open(meta_path) as f:
                self.meta = json.load(f)

            self.features = self.meta["features"]
            self.n_features = self.meta["n_features"]
            self.classes = self.meta["classes"]
            self.benign_idx = self.meta.get("benign_idx", 0)

            self.scaler = joblib.load(scaler_path)

            # ONNX session with optimisations
            opts = ort.SessionOptions()
            opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            opts.intra_op_num_threads = 2
            opts.inter_op_num_threads = 1
            self.session = ort.InferenceSession(str(onnx_path), opts)
            self.input_name = self.session.get_inputs()[0].name

            self.loaded = True
            size_mb = onnx_path.stat().st_size / (1024 * 1024)
            print(f"[Specialist:{self.name}] Loaded: {self.n_features} features, "
                  f"{len(self.classes)} classes, {size_mb:.1f}MB ONNX")

        except Exception as e:
            print(f"[Specialist:{self.name}] Load failed: {e}")

    def predict(self, X: np.ndarray) -> List[dict]:
        """
        Predict on batch of raw feature vectors (unscaled).
        Returns list of {label, confidence, is_attack, probabilities}.
        """
        if not self.loaded:
            return [self._benign_result()] * len(X)

        with self._lock:
            X_scaled = self.scaler.transform(X).astype(np.float32)
            onnx_out = self.session.run(None, {self.input_name: X_scaled})

            labels_raw = np.array(onnx_out[0])
            proba_maps = onnx_out[1]  # list of dicts {class_idx: prob}

            results = []
            for i in range(len(X)):
                label = int(labels_raw[i])
                proba_dict = proba_maps[i]

                # Build probability array in class order
                probs = np.array([proba_dict.get(c, 0.0)
                                  for c in range(len(self.classes))],
                                 dtype=np.float32)

                pred_idx = int(np.argmax(probs))
                pred_label = self.classes[pred_idx] if pred_idx < len(self.classes) else "Unknown"
                confidence = float(probs[pred_idx])
                benign_prob = float(probs[self.benign_idx]) if self.benign_idx < len(probs) else 0.0
                is_attack = pred_label != "Benign" and pred_label != "BenignTraffic"

                results.append({
                    "label": pred_label,
                    "confidence": confidence,
                    "is_attack": is_attack,
                    "benign_prob": benign_prob,
                    "attack_prob": 1.0 - benign_prob,
                    "probabilities": probs.tolist(),
                    "source": self.name,
                })

            return results

    def _benign_result(self) -> dict:
        return {
            "label": "Benign", "confidence": 1.0, "is_attack": False,
            "benign_prob": 1.0, "attack_prob": 0.0, "probabilities": [],
            "source": self.name,
        }

class SpecialistRouter:
    """
    Routes flows to the correct specialist(s) based on available features.

    Feature mapping:
      - CIC features present → spec1_cic
      - Netflow features present → spec2_botnet
      - IoT protocol features present → spec3_iot

    A single flow can be routed to multiple specialists for consensus.
    """

    # Core CIC features that must be present for spec1_cic routing
    CIC_REQUIRED = {"Dst Port", "Flow Duration", "Tot Fwd Pkts", "Flow Byts/s",
                    "SYN Flag Cnt", "Pkt Len Mean"}

    # Netflow features for spec2_botnet
    BOTNET_REQUIRED = {"Dur", "TotPkts", "TotBytes", "SrcBytes"}

    # IoT protocol features for spec3_iot
    IOT_REQUIRED = {"tcp.flags", "tcp.dstport", "tcp.len", "udp.port"}

    def __init__(self, specialists: Dict[str, SpecialistModel]):
        self.specialists = specialists

    def route(self, flow: dict, available_features: Set[str] = None
              ) -> List[str]:
        """
        Determine which specialists can classify this flow.
        Returns list of specialist names.
        """
        if available_features is None:
            available_features = set(flow.keys())

        routes = []

        # spec1_cic: CIC flow features
        if self.CIC_REQUIRED & available_features:
            routes.append("spec1_cic")

        # spec2_botnet: netflow features
        if self.BOTNET_REQUIRED & available_features:
            routes.append("spec2_botnet")

        # spec3_iot: IoT protocol features
        if self.IOT_REQUIRED & available_features:
            routes.append("spec3_iot")

        # Fallback: if no direct match, try all loaded specialists
        # by building features from what we have
        if not routes:
            for name, model in self.specialists.items():
                if model.loaded:
                    routes.append(name)

        return routes

    def extract_specialist_features(self, flow: dict, specialist_name: str,
                                     model: SpecialistModel) -> Optional[np.ndarray]:
        """
        Extract the features this specialist needs from the flow dict.
        Returns None if not enough features are available.
        """
        features = []
        missing = 0
        for feat_name in model.features:
            val = flow.get(feat_name, None)
            if val is None:
                # Try common aliases
                val = self._alias_lookup(feat_name, flow)
            if val is None:
                features.append(0.0)
                missing += 1
            else:
                try:
                    features.append(float(val))
                except (ValueError, TypeError):
                    features.append(0.0)
                    missing += 1

        # If >50% of features are missing, skip this specialist
        if missing > model.n_features * 0.5:
            return None

        return np.array(features, dtype=np.float32).reshape(1, -1)

    def _alias_lookup(self, feat_name: str, flow: dict) -> Optional[float]:
        """Map common feature aliases between datasets."""
        aliases = {
            # CIC aliases
            "Dst Port": ["dst_port", "Dport", "tcp.dstport"],
            "Protocol": ["protocol", "Proto_num"],
            "Flow Duration": ["duration", "Dur"],
            "Tot Fwd Pkts": ["TotPkts", "total_pkts", "fwd_pkts"],
            "Tot Bwd Pkts": ["bwd_pkts"],
            "TotLen Fwd Pkts": ["fwd_bytes", "SrcBytes", "total_bytes"],
            "TotLen Bwd Pkts": ["bwd_bytes"],
            "Flow Byts/s": ["bytes_per_sec", "BytesPerSec"],
            "Flow Pkts/s": ["pkts_per_sec"],
            "SYN Flag Cnt": ["syn_flag", "tcp.connection.syn"],
            "FIN Flag Cnt": ["fin_flag", "tcp.connection.fin"],
            "RST Flag Cnt": ["rst_flag", "tcp.connection.rst"],
            "ACK Flag Cnt": ["ack_flag", "tcp.flags.ack"],
            "PSH Flag Cnt": ["psh_flag"],
            "Pkt Len Mean": ["pkt_size_avg", "BytesPerPkt"],
            "Pkt Size Avg": ["pkt_size_avg", "BytesPerPkt"],
            # Botnet aliases
            "Dur": ["duration", "Flow Duration"],
            "Proto_num": ["protocol", "Protocol"],
            "Dport": ["dst_port", "Dst Port", "tcp.dstport"],
            "TotPkts": ["Tot Fwd Pkts", "total_pkts"],
            "TotBytes": ["total_bytes", "TotLen Fwd Pkts"],
            "SrcBytes": ["fwd_bytes", "TotLen Fwd Pkts"],
            "BytesPerPkt": ["pkt_size_avg", "Pkt Len Mean"],
            "BytesPerSec": ["bytes_per_sec", "Flow Byts/s"],
            # IoT aliases
            "tcp.dstport": ["dst_port", "Dst Port", "Dport"],
            "tcp.flags": ["flags"],
            "tcp.flags.ack": ["ack_flag", "ACK Flag Cnt"],
            "tcp.len": ["pkt_size_avg"],
            "udp.port": ["dst_port"],
        }
        if feat_name in aliases:
            for alias in aliases[feat_name]:
                if alias in flow:
                    return flow[alias]
        return None

# ═══════════════════════════════════════════════════════════════════
#  ENTITY PROFILE (Enhanced with specialist history)
# ═══════════════════════════════════════════════════════════════════

class EntityProfileV4:
    """
    Per-IP behavioral profile with:
    - Sliding windows (short-term, 60s) for 10 behavioral checks
    - 3-Timescale baseline (medium-term 2-week slots + frozen anchor)
    - Per-specialist confidence history (tracks FP rate)
    - Entity reputation score (0-100, starts at 50)
    """

    __slots__ = [
        'ip', 'role', 'risk_score', 'total_flows', 'first_seen', 'last_seen',
        # Short-term sliding windows
        '_flow_times', '_dst_ips', '_dst_ports_window', '_dst_ports_all',
        '_protocols', '_bytes_fwd', '_bytes_bwd', '_rst_count', '_syn_count',
        '_total_conns', '_intervals',
        # 3-Timescale baseline (replaces old EMA)
        'baseline',               # TimeSlottedBaseline; single source of truth
        '_proto_dist',            # protocol distribution (kept for Check 9)
        # Hourly profile (kept for Check 7 backward compat)
        '_hourly_profile', '_hourly_total',
        # Alert dedup
        '_last_alert_type', '_last_alert_time',
        # V4 additions
        '_specialist_history',
        '_reputation', '_fp_count', '_tp_count',
        '_alert_window', '_adaptive_threshold',
    ]

    def __init__(self, ip: str):
        self.ip = ip
        self.role = "Unknown"
        self.risk_score = 0.0
        self.total_flows = 0
        self.first_seen = time.time()
        self.last_seen = time.time()

        # Short-term sliding windows (exact recent data)
        self._flow_times = deque(maxlen=2000)
        self._dst_ips = deque(maxlen=2000)
        self._dst_ports_window = deque(maxlen=2000)
        self._dst_ports_all = set()
        self._protocols = deque(maxlen=2000)
        self._bytes_fwd = deque(maxlen=2000)
        self._bytes_bwd = deque(maxlen=2000)
        self._rst_count = deque(maxlen=2000)
        self._syn_count = deque(maxlen=2000)
        self._total_conns = deque(maxlen=2000)
        self._intervals = deque(maxlen=500)

        # 3-Timescale baseline; SINGLE source of truth
        # Replaces old EMA (_baseline_fpm, _baseline_unique_dst, etc.)
        # Handles: time slots, graduated freeze, anchor, maturity
        self.baseline = TimeSlottedBaseline(role="Unknown")
        self._proto_dist = defaultdict(float)

        # Hourly profile (kept for hour_deviation check)
        self._hourly_profile = [0.0] * 24
        self._hourly_total = 0

        # Alert dedup
        self._last_alert_type = ""
        self._last_alert_time = 0.0

        # V4: Specialist tracking + reputation
        self._specialist_history = defaultdict(lambda: deque(maxlen=200))
        self._reputation = 50.0
        self._fp_count = 0
        self._tp_count = 0
        self._alert_window = deque(maxlen=500)
        self._adaptive_threshold = None

    def _prune(self, now: float):
        cutoff = now - WINDOW_SEC
        for q in [self._flow_times, self._dst_ips, self._dst_ports_window,
                  self._protocols, self._bytes_fwd, self._bytes_bwd,
                  self._rst_count, self._syn_count, self._total_conns]:
            while q:
                first = q[0]
                ts = first[0] if isinstance(first, tuple) else first
                if ts < cutoff:
                    q.popleft()
                else:
                    break

    def update(self, flow: dict, now: float):
        self.last_seen = now
        self.total_flows += 1

        dst_ip = flow.get("dst_ip", "")
        dst_port = int(flow.get("dst_port", 0) or 0)
        proto_raw = flow.get("protocol", flow.get("Protocol Type", 0))
        try:
            proto = int(proto_raw)
        except (ValueError, TypeError):
            proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
            proto = proto_map.get(str(proto_raw).lower(), 0)

        fwd_bytes = float(flow.get("fwd_bytes", flow.get("Tot sum", 0)) or 0)
        bwd_bytes = float(flow.get("bwd_bytes", flow.get("bytes", 0)) or 0)
        if fwd_bytes == 0 and bwd_bytes == 0:
            total_b = float(flow.get("bytes", flow.get("Tot size", 0)) or 0)
            fwd_bytes = total_b * 0.6
            bwd_bytes = total_b * 0.4

        syn_flag = int(flow.get("syn_flag", flow.get("SYN Flag Cnt", 0)) or 0)
        rst_flag = int(flow.get("rst_flag", flow.get("RST Flag Cnt", 0)) or 0)
        ack_flag = int(flow.get("ack_flag", flow.get("ACK Flag Cnt", 0)) or 0)
        fin_flag = int(flow.get("fin_flag", flow.get("FIN Flag Cnt", 0)) or 0)

        self._prune(now)

        self._flow_times.append(now)
        if dst_ip:
            self._dst_ips.append((now, dst_ip))
        if dst_port:
            self._dst_ports_window.append((now, dst_port))
            self._dst_ports_all.add(dst_port)
        self._protocols.append((now, proto))
        self._bytes_fwd.append((now, fwd_bytes))
        self._bytes_bwd.append((now, bwd_bytes))
        self._total_conns.append((now, 1))

        is_rst = rst_flag > 0
        self._rst_count.append((now, is_rst))
        is_syn_only = syn_flag > 0 and ack_flag == 0 and fin_flag == 0
        self._syn_count.append((now, is_syn_only))

        if len(self._flow_times) >= 2:
            interval = self._flow_times[-1] - self._flow_times[-2]
            if 0 < interval < 3600:
                self._intervals.append(interval)

        hour = datetime.fromtimestamp(now).hour
        self._hourly_profile[hour] += 1
        self._hourly_total += 1

        if self.total_flows in (50, 200):
            self._classify_role()
            # Update baseline role when entity role is classified
            self.baseline.role = self.role
            self.baseline.maturity_threshold = ROLE_MATURITY.get(self.role, 80)

        # Update protocol distribution (used by Check 9)
        total_proto = sum(self._proto_dist.values()) + 1
        for p in self._proto_dist:
            self._proto_dist[p] = self._proto_dist[p] / total_proto * (total_proto - 1)
        self._proto_dist[proto] = self._proto_dist.get(proto, 0) + 1
        total_proto = sum(self._proto_dist.values())
        for p in self._proto_dist:
            self._proto_dist[p] /= max(total_proto, 1)

        # Feed into 3-timescale baseline (handles its own graduated freeze)
        if self.total_flows >= 20:
            current_fpm = self.current_fpm(now)
            current_dst = float(self.current_unique_dsts(now))
            total_b = fwd_bytes + bwd_bytes
            sr = fwd_bytes / max(total_b, 1.0)
            self.baseline.record(
                fpm=current_fpm, unique_dst=current_dst,
                bytes_pf=total_b, send_ratio=sr,
                proto=proto, dst_port=int(flow.get("dst_port", 0) or 0),
                anomaly_score=0.0,  # updated later in process_flow
                now=now,
            )

    def _classify_role(self):
        ports = self._dst_ports_all
        if ports & INFRA_PORTS:
            self.role = "Infrastructure"
        elif ports & PRINTER_PORTS:
            self.role = "Printer"
        elif ports & IOT_PORTS:
            self.role = "IoT"
        elif ports & SERVER_PORTS and len(ports) > 5:
            self.role = "Server"
        elif ports:
            self.role = "Workstation"

    # _update_baselines REMOVED; replaced by self.baseline.record()
    # in update() method above. TimeSlottedBaseline handles everything:
    # time slots, graduated freeze, anchor, maturity checks.

    @property
    def has_baseline(self) -> bool:
        return self.baseline.is_mature

    def current_fpm(self, now: float) -> float:
        cutoff = now - 60
        return sum(1 for t in self._flow_times if t > cutoff)

    def current_unique_dsts(self, now: float) -> int:
        cutoff = now - 60
        return len(set(ip for t, ip in self._dst_ips if t > cutoff))

    def current_failed_ratio(self, now: float) -> float:
        cutoff = now - 60
        total = sum(1 for t, _ in self._total_conns if t > cutoff)
        if total < 3:
            return 0.0
        rst = sum(1 for t, r in self._rst_count if t > cutoff and r)
        syn_only = sum(1 for t, s in self._syn_count if t > cutoff and s)
        return (rst + syn_only) / max(total, 1)

    def current_send_ratio(self, now: float) -> float:
        cutoff = now - 60
        fwd = sum(b for t, b in self._bytes_fwd if t > cutoff)
        bwd = sum(b for t, b in self._bytes_bwd if t > cutoff)
        total = fwd + bwd
        return fwd / total if total > 100 else 0.5

    def current_total_bytes(self, now: float) -> float:
        cutoff = now - 60
        fwd = sum(b for t, b in self._bytes_fwd if t > cutoff)
        bwd = sum(b for t, b in self._bytes_bwd if t > cutoff)
        return fwd + bwd

    def periodicity_cv(self) -> Tuple[float, float]:
        if len(self._intervals) < 10:
            return 1.0, 0.0
        arr = list(self._intervals)[-50:]
        mean = sum(arr) / len(arr)
        if mean < 0.1:
            return 1.0, mean
        std = (sum((x - mean) ** 2 for x in arr) / len(arr)) ** 0.5
        return std / mean, mean

    def hour_deviation(self, now: float) -> float:
        if self._hourly_total < 200:
            return 0.0
        hour = datetime.fromtimestamp(now).hour
        hour_fraction = self._hourly_profile[hour] / max(self._hourly_total, 1)
        if hour_fraction < 0.01:
            return 1.0
        if hour_fraction < 0.03:
            return 0.5
        return 0.0

    # V4: Reputation management
    def record_verdict(self, was_true_positive: bool, now: float):
        """Record whether an alert was TP or FP for reputation tracking."""
        if was_true_positive:
            self._tp_count += 1
            self._reputation = min(100.0, self._reputation + 2.0)
        else:
            self._fp_count += 1
            self._reputation = max(0.0, self._reputation - 5.0)

    def record_alert_flow(self, is_attack: bool, confidence: float,
                          severity: str, now: float):
        """Record flow classification for temporal aggregation."""
        self._alert_window.append((now, is_attack, confidence, severity))

    def get_window_attack_ratio(self, now: float) -> Tuple[float, int, int]:
        """Get attack ratio in temporal window."""
        cutoff = now - TEMPORAL_WINDOW_SEC
        total = 0
        attacks = 0
        for t, is_atk, _, _ in self._alert_window:
            if t >= cutoff:
                total += 1
                if is_atk:
                    attacks += 1
        ratio = attacks / max(total, 1)
        return ratio, attacks, total

    @property
    def effective_threshold(self) -> float:
        """Adaptive risk threshold based on role + reputation."""
        base = ROLE_THRESHOLDS.get(self.role, 60)
        if self._adaptive_threshold is not None:
            return self._adaptive_threshold

        # High reputation (many TPs) → lower threshold (easier to alert)
        # Low reputation (many FPs) → higher threshold (harder to alert)
        rep_adj = (self._reputation - 50.0) * 0.2  # ±10 from reputation
        return max(30.0, min(95.0, base - rep_adj))

# ═══════════════════════════════════════════════════════════════════
#  ANOMALY SCORER (10 behavioural checks)
# ═══════════════════════════════════════════════════════════════════

class AnomalyScorer:
    """10 independent behavioral checks with specialist ML fusion."""

    @staticmethod
    def score(entity: EntityProfileV4, flow: dict, now: float,
              specialist_results: List[dict] = None
              ) -> Tuple[float, List[str]]:
        """
        Run all 10 checks. Returns (total_score, reasons).
        """
        score = 0.0
        reasons = []

        if not entity.has_baseline:
            return 0.0, []

        bl = entity.baseline
        expected = bl.get_expected(now)

        # ── Check 1: Flow rate deviation (Z-score) ───────────
        current_fpm = entity.current_fpm(now)
        if current_fpm > 0:
            z_fpm = bl.z_score_fpm(current_fpm, now)
            if z_fpm >= 8.0:
                score += 0.50
                reasons.append(f"Rate spike: {current_fpm:.0f}/min "
                             f"(z={z_fpm:.1f}, expected {expected['mean_fpm']:.0f}"
                             f"+/-{expected['std_fpm']:.0f} [{expected.get('source','')}])")
            elif z_fpm >= 5.0:
                score += 0.35
                reasons.append(f"Rate spike: z={z_fpm:.1f} "
                             f"({current_fpm:.0f} vs {expected['mean_fpm']:.0f})")
            elif z_fpm >= 3.0:
                score += 0.20
                reasons.append(f"Rate elevated: z={z_fpm:.1f}")

        # ── Check 2: Destination diversity spike (Z-score) ───
        current_unique = entity.current_unique_dsts(now)
        if current_unique > 0:
            z_dst = bl.z_score_unique_dst(float(current_unique), now)
            if z_dst >= 8.0 and current_unique >= 20:
                score += 0.40
                reasons.append(f"Dst diversity: {current_unique} unique IPs "
                             f"(z={z_dst:.1f})")
            elif z_dst >= 4.0 and current_unique >= 10:
                score += 0.20
                reasons.append(f"Dst diversity: {current_unique} unique IPs "
                             f"(z={z_dst:.1f})")

        # ── Check 3: New port usage ──────────────────────────
        dst_port = int(flow.get("dst_port", 0) or 0)
        if dst_port and entity.total_flows > 100:
            if dst_port not in entity._dst_ports_all and len(entity._dst_ports_all) >= 3:
                if dst_port in THREAT_PORTS:
                    score += 0.40
                    reasons.append(f"Threat port: {dst_port} ({THREAT_PORTS[dst_port]})")
                else:
                    score += 0.10
                    reasons.append(f"New port: {dst_port}")

        # ── Check 4: Failed connection ratio ─────────────────
        failed_ratio = entity.current_failed_ratio(now)
        total_conns = sum(1 for t, _ in entity._total_conns if t > now - WINDOW_SEC)
        if total_conns >= 5:
            if failed_ratio > 0.80:
                score += 0.45
                reasons.append(f"Failed connections: {failed_ratio*100:.0f}% ({total_conns} total)")
            elif failed_ratio > 0.50:
                score += 0.25
                reasons.append(f"High failure rate: {failed_ratio*100:.0f}%")
            elif failed_ratio > 0.20:
                score += 0.10
                reasons.append(f"Elevated failures: {failed_ratio*100:.0f}%")

        # ── Check 5: Bi-directional asymmetry ────────────────
        send_ratio = entity.current_send_ratio(now)
        total_bytes_window = entity.current_total_bytes(now)
        if total_bytes_window > 500_000:
            if send_ratio > 0.95:
                score += 0.50
                reasons.append(f"Exfiltration: {send_ratio*100:.0f}% outbound "
                             f"({total_bytes_window/1e6:.1f}MB)")
            elif send_ratio > 0.85:
                score += 0.30
                reasons.append(f"Upload-heavy: {send_ratio*100:.0f}% outbound")
        elif total_bytes_window > 50_000 and send_ratio > 0.90:
            score += 0.15
            reasons.append(f"Asymmetric: {send_ratio*100:.0f}% outbound")

        # ── Check 6: Periodicity detection (C2 beaconing) ────
        cv, mean_interval = entity.periodicity_cv()
        if len(entity._intervals) >= 15:
            if cv < 0.05 and mean_interval > 10:
                score += 0.40
                reasons.append(f"Periodic beaconing: every {mean_interval:.1f}s (CV={cv:.3f})")
            elif cv < 0.15 and mean_interval > 30:
                score += 0.20
                reasons.append(f"Semi-periodic: ~{mean_interval:.0f}s intervals")

        # ── Check 7: Time-of-day deviation ───────────────────
        # Now Z-score aware: compares against time-slot expected rate
        hour_dev = entity.hour_deviation(now)
        exp_fpm = max(expected["mean_fpm"], 0.1)
        if hour_dev >= 1.0 and current_fpm > exp_fpm * 2:
            score += 0.25
            hour = datetime.fromtimestamp(now).hour
            reasons.append(f"Off-hours: {hour:02d}:00 (rare for this device)")
        elif hour_dev >= 0.5 and current_fpm > exp_fpm * 3:
            score += 0.12
            reasons.append("Unusual hour activity")

        # ── Check 8: Byte volume deviation (Z-score) ─────────
        flow_bytes = float(flow.get("bytes", flow.get("Tot sum",
                          flow.get("Tot size", 0))) or 0)
        if flow_bytes > 0:
            z_bytes = bl.z_score_bytes_pf(flow_bytes, now)
            if z_bytes >= 8.0:
                score += 0.35
                reasons.append(f"Volume spike: {flow_bytes/1e6:.1f}MB "
                             f"(z={z_bytes:.1f})")
            elif z_bytes >= 5.0:
                score += 0.25
                reasons.append(f"Large flow: z={z_bytes:.1f}")

        # ── Check 9: Protocol distribution shift ─────────────
        proto_raw = flow.get("protocol", flow.get("Protocol Type", 0))
        try:
            proto = int(proto_raw)
        except (ValueError, TypeError):
            proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
            proto = proto_map.get(str(proto_raw).lower(), 0)

        if entity.total_flows > 50 and entity._proto_dist:
            proto_frac = entity._proto_dist.get(proto, 0)
            if proto_frac < 0.02 and sum(1 for t, p in entity._protocols
                                          if t > now - WINDOW_SEC and p == proto) >= 3:
                score += 0.20
                proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
                reasons.append(f"Protocol shift: {proto_name} "
                             f"({proto_frac*100:.1f}% historical)")

        # ── Check 10: Specialist ML consensus signal ─────────
        if specialist_results:
            attacking_specialists = [
                r for r in specialist_results
                if r["is_attack"] and r["confidence"] >= SPEC_GATE.get(r["source"], 0.70)
            ]
            n_attacking = len(attacking_specialists)

            if n_attacking >= 2:
                # Multi-specialist consensus; strong signal
                best_conf = max(r["confidence"] for r in attacking_specialists)
                score += 0.30
                names = ", ".join(r["source"].replace("spec", "S") for r in attacking_specialists)
                reasons.append(f"Specialist consensus ({n_attacking}): "
                             f"{names} @ {best_conf*100:.0f}%")
            elif n_attacking == 1:
                r = attacking_specialists[0]
                if r["confidence"] >= 0.90:
                    score += 0.15
                    reasons.append(f"ML specialist: {r['source']} → {r['label']} "
                                 f"@ {r['confidence']*100:.0f}%")
                elif r["confidence"] >= 0.75:
                    score += 0.05

            # ML says benign with high confidence → dampen UEBA
            all_benign = all(not r["is_attack"] for r in specialist_results)
            if all_benign and specialist_results:
                avg_benign_conf = sum(r["benign_prob"] for r in specialist_results) / len(specialist_results)
                if avg_benign_conf > 0.90 and score < 0.60 and len(reasons) < 3:
                    score = max(0, score - 0.15)

        return min(score, 1.0), reasons

# ═══════════════════════════════════════════════════════════════════
#  RISK ACCUMULATOR
# ═══════════════════════════════════════════════════════════════════

class RiskAccumulator:
    @staticmethod
    def update(entity: EntityProfileV4, anomaly_score: float,
               is_anomalous: bool) -> float:
        role = entity.role
        if is_anomalous:
            mult = ROLE_SEVERITY_MULT.get(role, 1.0)
            delta = anomaly_score * 15.0 * mult
            entity.risk_score = min(100.0, entity.risk_score + delta)
        else:
            decay = ROLE_DECAY.get(role, 0.997)
            entity.risk_score = max(0.0, entity.risk_score * decay)
        return entity.risk_score

# ═══════════════════════════════════════════════════════════════════
#  WHITELIST
# ═══════════════════════════════════════════════════════════════════

class Whitelist:
    def __init__(self, config_path: str = None):
        if config_path is None:
            config_path = str(_PROJECT_ROOT / "config" / "whitelist.json")
        self._pairs = set()
        self._ports = set()
        self._trusted_src = set()
        self._load(config_path)

    def _load(self, path: str):
        try:
            with open(path) as f:
                cfg = json.load(f)
            for entry in cfg.get("ip_port_pairs", []):
                self._pairs.add((entry["dst_ip"], int(entry["dst_port"])))
            self._ports = set(cfg.get("dst_ports_always_benign", []))
            self._trusted_src = set(cfg.get("src_ips_trusted", []))
        except FileNotFoundError:
            pass

    def is_whitelisted(self, flow: dict) -> bool:
        dst_ip = flow.get("dst_ip", "")
        dst_port = int(flow.get("dst_port", 0) or 0)
        src_ip = flow.get("src_ip", "")
        if (dst_ip, dst_port) in self._pairs:
            return True
        if dst_port in self._ports:
            return True
        if src_ip in self._trusted_src:
            return True
        return False

# ═══════════════════════════════════════════════════════════════════
#  7-GATE ALERT PIPELINE
# ═══════════════════════════════════════════════════════════════════

class SevenGatePipeline:
    """
    7-gate false-positive elimination pipeline.

    Every flow must pass ALL gates to produce an alert.
    Each gate can independently block and provides a reason.
    """

    def evaluate(self, entity: EntityProfileV4, risk_score: float,
                 anomaly_score: float, reasons: List[str],
                 specialist_results: List[dict],
                 now: float) -> dict:
        """
        Returns:
            {
                "should_alert": bool,
                "severity": str,
                "tag": str,       # CONFIRMED | SPECIALIST | UEBA_OVERRIDE | BEHAVIORAL
                "gates_passed": int,
                "gate_blocked_by": str,
                "consensus_count": int,
            }
        """
        gates_passed = 0

        # ── Gate 1: Whitelist (handled externally before this call) ─
        # Already filtered; if we're here, not whitelisted
        gates_passed += 1

        # ── Gate 2: Baseline maturity ────────────────────────
        if not entity.has_baseline:
            return self._blocked(gates_passed, "G2:baseline_immature")
        gates_passed += 1

        # ── Gate 3: Specialist confidence gate ───────────────
        # At least one specialist must exceed its calibrated threshold
        specialist_attacking = []
        if specialist_results:
            for r in specialist_results:
                gate_thresh = SPEC_GATE.get(r["source"], 0.70)
                if r["is_attack"] and r["confidence"] >= gate_thresh:
                    specialist_attacking.append(r)

        has_specialist_signal = len(specialist_attacking) > 0
        has_behavioral_signal = anomaly_score >= 0.40 and len(reasons) >= 2

        if not has_specialist_signal and not has_behavioral_signal:
            return self._blocked(gates_passed, "G3:low_confidence")
        gates_passed += 1

        # ── Gate 4: Multi-source consensus ───────────────────
        # Count independent signal sources
        signal_sources = 0
        if has_specialist_signal:
            signal_sources += 1
        if has_behavioral_signal:
            signal_sources += 1
        if anomaly_score >= 0.60:
            signal_sources += 1  # strong behavioral = extra source

        # Determine preliminary severity
        if has_specialist_signal:
            best_spec = max(specialist_attacking, key=lambda r: r["confidence"])
            spec_conf = best_spec["confidence"]
        else:
            spec_conf = 0.0

        combined_conf = max(spec_conf, anomaly_score)
        severity = self._conf_to_severity(combined_conf)

        required = CONSENSUS_REQUIRED.get(severity, 1)
        if signal_sources < required:
            # Not enough independent sources agree
            # Exception: CRITICAL specialist with very high confidence bypasses
            if spec_conf >= 0.97:
                pass  # let through; overwhelming evidence
            else:
                return self._blocked(gates_passed, f"G4:consensus({signal_sources}/{required})")
        gates_passed += 1

        # ── Gate 5: Temporal aggregation ─────────────────────
        atk_ratio, n_attacks, n_total = entity.get_window_attack_ratio(now)

        # For CRITICAL with high specialist confidence, skip temporal gate
        if severity == "CRITICAL" and spec_conf >= CONF_CRITICAL:
            pass  # immediate alert
        elif n_total >= 5 and atk_ratio < TEMPORAL_ALERT_RATIO:
            # Too few attack flows in window; likely isolated FP
            return self._blocked(gates_passed,
                                 f"G5:temporal({atk_ratio:.2f}<{TEMPORAL_ALERT_RATIO})")
        gates_passed += 1

        # ── Gate 6: Entity reputation ────────────────────────
        # High-FP entities get a harder bar
        if entity._reputation < 25.0 and severity not in ("CRITICAL",):
            # Entity has bad reputation (lots of past FPs)
            # Require stronger evidence
            if combined_conf < 0.85:
                return self._blocked(gates_passed,
                                     f"G6:reputation({entity._reputation:.0f})")
        gates_passed += 1

        # ── Gate 7: Deduplication + cooldown ─────────────────
        alert_type = reasons[0][:30] if reasons else "unknown"
        if has_specialist_signal:
            alert_type = best_spec["label"]

        if (entity._last_alert_type == alert_type and
                now - entity._last_alert_time < DEDUP_COOLDOWN_SEC):
            # Same alert recently; check if severity escalated
            return self._blocked(gates_passed, "G7:dedup_cooldown")
        gates_passed += 1

        # ── All 7 gates passed ───────────────────────────────
        # Determine tag
        if has_specialist_signal and has_behavioral_signal:
            tag = "CONFIRMED"          # ML + Behavioral agree
        elif has_specialist_signal and len(specialist_attacking) >= 2:
            tag = "SPECIALIST"         # Multiple specialists agree
        elif has_behavioral_signal and not has_specialist_signal:
            tag = "UEBA_OVERRIDE"      # Behavioral only; novel attack
        elif has_specialist_signal:
            tag = "SPECIALIST"
        else:
            tag = "BEHAVIORAL"

        # Recalculate severity with consensus boost
        if signal_sources >= 3:
            combined_conf = min(combined_conf * 1.15, 1.0)
            severity = self._conf_to_severity(combined_conf)
        elif signal_sources >= 2:
            combined_conf = min(combined_conf * 1.10, 1.0)
            severity = self._conf_to_severity(combined_conf)

        # Also factor in risk score
        if risk_score >= 80 and severity not in ("CRITICAL",):
            severity = "CRITICAL" if combined_conf >= 0.80 else "HIGH"
        elif risk_score >= 60 and severity == "MEDIUM":
            severity = "HIGH"

        # Record dedup
        entity._last_alert_type = alert_type
        entity._last_alert_time = now

        return {
            "should_alert": True,
            "severity": severity,
            "tag": tag,
            "gates_passed": gates_passed,
            "gate_blocked_by": "",
            "consensus_count": signal_sources,
        }

    def _blocked(self, gates_passed: int, reason: str) -> dict:
        return {
            "should_alert": False,
            "severity": "BENIGN",
            "tag": "",
            "gates_passed": gates_passed,
            "gate_blocked_by": reason,
            "consensus_count": 0,
        }

    def _conf_to_severity(self, conf: float) -> str:
        if conf >= CONF_CRITICAL: return "CRITICAL"
        if conf >= CONF_HIGH:     return "HIGH"
        if conf >= CONF_MEDIUM:   return "MEDIUM"
        if conf >= CONF_LOW:      return "LOW"
        return "BENIGN"

# ═══════════════════════════════════════════════════════════════════
#  MAIN ENGINE; UEBAv4
# ═══════════════════════════════════════════════════════════════════

class UEBAv4:
    """
    Production UEBA v4; Specialist-Fused Zero-FP Engine.

    Integrates 3 specialist ONNX models with 10 behavioural checks
    through a 7-gate false-positive elimination pipeline.
    """

    def __init__(self, models_dir: str = None, db_path: str = None):
        if models_dir is None:
            models_dir = str(_PROJECT_ROOT / "models")
        if db_path is None:
            db_path = str(_PROJECT_ROOT / "ueba.db")

        self.models_dir = Path(models_dir)
        self.db_path = db_path

        # Entity profiles
        self._entities: Dict[str, EntityProfileV4] = {}
        self._lock = threading.Lock()

        # Components
        self._scorer = AnomalyScorer()
        self._risk = RiskAccumulator()
        self._gate = SevenGatePipeline()
        self._whitelist = Whitelist()

        # Load specialists
        print("[UEBAv4] Loading specialist ONNX models...")
        self._specialists: Dict[str, SpecialistModel] = {}
        for name in ["spec1_cic", "spec2_botnet", "spec3_iot"]:
            model = SpecialistModel(name, self.models_dir)
            self._specialists[name] = model

        self._router = SpecialistRouter(self._specialists)

        loaded = sum(1 for m in self._specialists.values() if m.loaded)
        print(f"[UEBAv4] Specialists loaded: {loaded}/3")

        # Stats
        self.stats = {
            "flows_processed": 0,
            "entities_tracked": 0,
            "specialist_queries": 0,
            "specialist_attacks_detected": 0,
            "anomalies_detected": 0,
            "alerts_fired": 0,
            "alerts_confirmed": 0,
            "alerts_specialist": 0,
            "alerts_ueba_override": 0,
            "alerts_behavioral": 0,
            "whitelisted": 0,
            "gate_blocked": defaultdict(int),
            "by_specialist": defaultdict(int),
            "by_severity": defaultdict(int),
            "by_attack_type": defaultdict(int),
        }

        self._init_db()

        print(f"[UEBAv4] Engine ready")
        print(f"[UEBAv4] 3 Specialists | 10 Behavioral Checks | 7-Gate FP Elimination")
        print(f"[UEBAv4] Confidence gates: CIC≥{SPEC_GATE['spec1_cic']} "
              f"Botnet≥{SPEC_GATE['spec2_botnet']} IoT≥{SPEC_GATE['spec3_iot']}")

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS v4_alerts (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT NOT NULL,
                    ip              TEXT NOT NULL,
                    device_role     TEXT,
                    risk_score      REAL,
                    anomaly_score   REAL,
                    severity        TEXT,
                    tag             TEXT,
                    attack_type     TEXT,
                    specialist_src  TEXT,
                    specialist_conf REAL,
                    consensus_count INTEGER,
                    gates_passed    INTEGER,
                    reasons         TEXT,
                    dst_ip          TEXT,
                    dst_port        INTEGER
                );
                CREATE TABLE IF NOT EXISTS v4_entity_profiles (
                    ip              TEXT PRIMARY KEY,
                    device_role     TEXT,
                    risk_score      REAL,
                    reputation      REAL,
                    total_flows     INTEGER,
                    baseline_fpm    REAL,
                    tp_count        INTEGER,
                    fp_count        INTEGER,
                    first_seen      TEXT,
                    last_seen       TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_v4_ip ON v4_alerts(ip);
                CREATE INDEX IF NOT EXISTS idx_v4_sev ON v4_alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_v4_tag ON v4_alerts(tag);
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[UEBAv4] DB init error: {e}")

    # ── Main entry point ─────────────────────────────────────────

    def process_flow(self, flow: dict,
                     raw_features: dict = None,
                     specialist_results: List[dict] = None,
                     now: float = None) -> dict:
        """
        Process one network flow through the full v4 pipeline.

        Args:
            flow: dict with src_ip, dst_ip, dst_port, bytes, protocol, flags, etc.
            raw_features: Optional dict of all available features for specialist routing.
                         If None, uses flow dict directly.
            specialist_results: Optional list of specialist verdicts from ML cascade.
                         If provided, UEBA skips its own specialist inference (no redundancy).
                         If None, UEBA runs specialists internally.
            now: Optional timestamp override (for testing/replay). Defaults to time.time().

        Returns: Full result dict (see module docstring).
        """
        src_ip = flow.get("src_ip", "")
        if not src_ip:
            return self._empty_result()

        if now is None:
            now = time.time()
        self.stats["flows_processed"] += 1

        # ── Gate 1: Whitelist ─────────────────────────────────
        if self._whitelist.is_whitelisted(flow):
            self.stats["whitelisted"] += 1
            return self._whitelisted_result()

        # Get or create entity
        with self._lock:
            if src_ip not in self._entities:
                self._entities[src_ip] = EntityProfileV4(src_ip)
                self.stats["entities_tracked"] = len(self._entities)
            entity = self._entities[src_ip]

        # Update entity profile
        entity.update(flow, now)

        # ── Specialist inference ──────────────────────────────
        # If specialist_results provided from pipeline's ML cascade, use them
        # Otherwise run specialists internally (standalone mode)
        if specialist_results is None:
            feature_source = raw_features if raw_features else flow
            specialist_results = self._run_specialists(feature_source)

        # Find best specialist verdict
        best_spec = None
        spec_attacking = [r for r in specialist_results
                         if r["is_attack"] and r["confidence"] >= SPEC_GATE.get(r["source"], 0.70)]
        if spec_attacking:
            best_spec = max(spec_attacking, key=lambda r: r["confidence"])

        # Find best specialist verdict
        is_spec_attack = best_spec is not None
        spec_conf = best_spec["confidence"] if best_spec else 0.0
        spec_sev = self._conf_to_severity(spec_conf) if is_spec_attack else "BENIGN"

        # ── Check baseline ────────────────────────────────────
        if not entity.has_baseline:
            return {
                "risk_score": entity.risk_score,
                "anomaly_score": 0.0,
                "specialist_verdict": best_spec["label"] if best_spec else "BENIGN",
                "specialist_confidence": spec_conf,
                "specialist_consensus": len(spec_attacking),
                "reasons": [f"Learning: {entity.total_flows}/{entity.baseline.maturity_threshold} flows "
                           f"({entity.baseline.maturity_pct:.0f}% mature)"],
                "should_alert": False,
                "alert_severity": "BENIGN",
                "alert_tag": "",
                "baseline_ready": False,
                "device_role": entity.role,
                "gates_passed": 2,
                "gate_blocked_by": "G2:baseline_immature",
            }

        # ── Behavioral scoring (10 checks) ────────────────────
        anomaly_score, reasons = self._scorer.score(
            entity, flow, now, specialist_results
        )

        is_anomalous = anomaly_score > 0.15

        # Feed anomaly score back to baseline for graduated freeze
        # TimeSlottedBaseline handles freeze internally:
        #   NORMAL (<0.15): 100% learning
        #   ELEVATED (0.15-0.40): 50% learning
        #   ANOMALOUS (0.40-0.70): 10% learning
        #   FROZEN (>=0.70): 0% learning
        entity.baseline._update_freeze(anomaly_score)

        # Record in temporal window (after behavioral scoring)
        # Use the STRONGER signal: specialist attack OR behavioral anomaly
        is_attack_signal = is_spec_attack or (anomaly_score >= 0.40 and len(reasons) >= 2)
        signal_conf = max(spec_conf, anomaly_score)
        signal_sev = self._conf_to_severity(signal_conf) if is_attack_signal else "BENIGN"
        entity.record_alert_flow(is_attack_signal, signal_conf, signal_sev, now)

        # ── Risk accumulation ─────────────────────────────────
        risk = self._risk.update(entity, anomaly_score, is_anomalous)

        if is_anomalous:
            self.stats["anomalies_detected"] += 1

        # ── 7-Gate pipeline ───────────────────────────────────
        gate_result = self._gate.evaluate(
            entity, risk, anomaly_score, reasons,
            specialist_results, now
        )

        should_alert = gate_result["should_alert"]
        severity = gate_result["severity"]
        tag = gate_result["tag"]

        if should_alert:
            self.stats["alerts_fired"] += 1
            self.stats["by_severity"][severity] += 1

            if tag == "CONFIRMED":
                self.stats["alerts_confirmed"] += 1
            elif tag == "SPECIALIST":
                self.stats["alerts_specialist"] += 1
            elif tag == "UEBA_OVERRIDE":
                self.stats["alerts_ueba_override"] += 1
            else:
                self.stats["alerts_behavioral"] += 1

            attack_type = best_spec["label"] if best_spec else (
                reasons[0][:30] if reasons else "Behavioral_Anomaly")
            self.stats["by_attack_type"][attack_type] += 1

            self._save_alert(entity, risk, anomaly_score, severity, tag,
                           attack_type, best_spec, gate_result, reasons,
                           flow, now)
        else:
            attack_type = "BENIGN"
            if gate_result["gate_blocked_by"]:
                gate_name = gate_result["gate_blocked_by"].split(":")[0]
                self.stats["gate_blocked"][gate_name] += 1

        return {
            "risk_score": round(risk, 2),
            "anomaly_score": round(anomaly_score, 4),
            "specialist_verdict": best_spec["label"] if best_spec else "BENIGN",
            "specialist_confidence": round(spec_conf, 4),
            "specialist_consensus": len(spec_attacking),
            "reasons": reasons,
            "should_alert": should_alert,
            "alert_severity": severity,
            "alert_tag": tag,
            "baseline_ready": True,
            "device_role": entity.role,
            "gates_passed": gate_result["gates_passed"],
            "gate_blocked_by": gate_result["gate_blocked_by"],
        }

    def _run_specialists(self, features: dict) -> List[dict]:
        """Run all applicable specialists on this flow."""
        results = []
        routes = self._router.route(features)

        for spec_name in routes:
            model = self._specialists.get(spec_name)
            if not model or not model.loaded:
                continue

            X = self._router.extract_specialist_features(features, spec_name, model)
            if X is None:
                continue

            self.stats["specialist_queries"] += 1
            preds = model.predict(X)
            if preds:
                result = preds[0]
                results.append(result)
                if result["is_attack"]:
                    self.stats["specialist_attacks_detected"] += 1
                    self.stats["by_specialist"][spec_name] += 1

        return results

    def _conf_to_severity(self, conf: float) -> str:
        if conf >= CONF_CRITICAL: return "CRITICAL"
        if conf >= CONF_HIGH:     return "HIGH"
        if conf >= CONF_MEDIUM:   return "MEDIUM"
        if conf >= CONF_LOW:      return "LOW"
        return "BENIGN"

    def _empty_result(self) -> dict:
        return {
            "risk_score": 0.0, "anomaly_score": 0.0,
            "specialist_verdict": "BENIGN", "specialist_confidence": 0.0,
            "specialist_consensus": 0, "reasons": [],
            "should_alert": False, "alert_severity": "BENIGN",
            "alert_tag": "", "baseline_ready": False,
            "device_role": "Unknown", "gates_passed": 0,
            "gate_blocked_by": "no_src_ip",
        }

    def _whitelisted_result(self) -> dict:
        return {
            "risk_score": 0.0, "anomaly_score": 0.0,
            "specialist_verdict": "BENIGN", "specialist_confidence": 1.0,
            "specialist_consensus": 0, "reasons": [],
            "should_alert": False, "alert_severity": "BENIGN",
            "alert_tag": "", "baseline_ready": True,
            "device_role": "Unknown", "gates_passed": 1,
            "gate_blocked_by": "G1:whitelisted",
        }

    def _save_alert(self, entity, risk, anomaly, severity, tag,
                    attack_type, best_spec, gate_result, reasons,
                    flow, now):
        try:
            conn = sqlite3.connect(self.db_path, timeout=5)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                INSERT INTO v4_alerts
                (timestamp, ip, device_role, risk_score, anomaly_score,
                 severity, tag, attack_type, specialist_src, specialist_conf,
                 consensus_count, gates_passed, reasons, dst_ip, dst_port)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.fromtimestamp(now).isoformat(),
                entity.ip, entity.role, round(risk, 2),
                round(anomaly, 4), severity, tag, attack_type,
                best_spec["source"] if best_spec else "",
                round(best_spec["confidence"], 4) if best_spec else 0.0,
                gate_result["consensus_count"],
                gate_result["gates_passed"],
                json.dumps(reasons),
                flow.get("dst_ip", ""),
                int(flow.get("dst_port", 0) or 0),
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass

    # ── Feedback loop: record TP/FP for reputation ────────────

    def record_feedback(self, ip: str, was_true_positive: bool):
        """
        Call this when an analyst confirms or dismisses an alert.
        Adjusts entity reputation and specialist trust.
        """
        with self._lock:
            entity = self._entities.get(ip)
            if entity:
                entity.record_verdict(was_true_positive, time.time())

    # ── Public queries ────────────────────────────────────────

    def get_entity(self, ip: str) -> Optional[dict]:
        with self._lock:
            e = self._entities.get(ip)
            if not e:
                return None
            return {
                "ip": e.ip, "role": e.role,
                "risk_score": round(e.risk_score, 2),
                "reputation": round(e._reputation, 1),
                "total_flows": e.total_flows,
                "baseline_fpm": round(e._baseline_fpm or 0, 2),
                "baseline_ready": e.has_baseline,
                "ports_seen": len(e._dst_ports_all),
                "tp_count": e._tp_count,
                "fp_count": e._fp_count,
                "first_seen": datetime.fromtimestamp(e.first_seen).isoformat(),
                "last_seen": datetime.fromtimestamp(e.last_seen).isoformat(),
            }

    def get_high_risk(self, min_risk: float = 30.0) -> List[dict]:
        with self._lock:
            results = []
            for e in self._entities.values():
                if e.risk_score >= min_risk:
                    results.append({
                        "ip": e.ip, "role": e.role,
                        "risk_score": round(e.risk_score, 2),
                        "reputation": round(e._reputation, 1),
                        "total_flows": e.total_flows,
                    })
            return sorted(results, key=lambda x: -x["risk_score"])

    def get_stats(self) -> dict:
        return {
            **{k: v for k, v in self.stats.items()
               if not isinstance(v, defaultdict)},
            "gate_blocked": dict(self.stats["gate_blocked"]),
            "by_specialist": dict(self.stats["by_specialist"]),
            "by_severity": dict(self.stats["by_severity"]),
            "by_attack_type": dict(self.stats["by_attack_type"]),
        }

    def save_state(self):
        with self._lock:
            profiles = list(self._entities.values())
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.execute("PRAGMA journal_mode=WAL")
            for e in profiles:
                conn.execute("""
                    INSERT OR REPLACE INTO v4_entity_profiles
                    (ip, device_role, risk_score, reputation, total_flows,
                     baseline_fpm, tp_count, fp_count, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    e.ip, e.role, round(e.risk_score, 2),
                    round(e._reputation, 1), e.total_flows,
                    round(e._baseline_fpm or 0, 2),
                    e._tp_count, e._fp_count,
                    datetime.fromtimestamp(e.first_seen).isoformat(),
                    datetime.fromtimestamp(e.last_seen).isoformat(),
                ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[UEBAv4] State save error: {e}")

    def print_summary(self):
        s = self.stats
        print(f"\n{'='*65}")
        print("  UEBA v4; SPECIALIST-FUSED ENGINE SUMMARY")
        print(f"{'='*65}")
        print(f"  Flows processed      : {s['flows_processed']:,}")
        print(f"  Entities tracked     : {s['entities_tracked']:,}")
        print(f"  Whitelisted          : {s['whitelisted']:,}")
        print(f"  Specialist queries   : {s['specialist_queries']:,}")
        print(f"  Specialist attacks   : {s['specialist_attacks_detected']:,}")
        print(f"  Anomalies detected   : {s['anomalies_detected']:,}")
        print(f"  Alerts fired         : {s['alerts_fired']:,}")
        print(f"    CONFIRMED (ML+UEBA)  : {s['alerts_confirmed']:,}")
        print(f"    SPECIALIST           : {s['alerts_specialist']:,}")
        print(f"    UEBA_OVERRIDE        : {s['alerts_ueba_override']:,}")
        print(f"    BEHAVIORAL           : {s['alerts_behavioral']:,}")

        if s["gate_blocked"]:
            print(f"\n  Gate blocking stats:")
            for gate, cnt in sorted(dict(s["gate_blocked"]).items()):
                print(f"    {gate:<25} {cnt:>8,}")

        if s["by_specialist"]:
            print(f"\n  Attack detections by specialist:")
            for spec, cnt in sorted(dict(s["by_specialist"]).items(), key=lambda x: -x[1]):
                print(f"    {spec:<25} {cnt:>8,}")

        if s["by_attack_type"]:
            print(f"\n  Top attack types:")
            for atype, cnt in sorted(dict(s["by_attack_type"]).items(),
                                     key=lambda x: -x[1])[:10]:
                print(f"    {atype:<25} {cnt:>8,}")

        if s["by_severity"]:
            print(f"\n  Alert severity distribution:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                cnt = dict(s["by_severity"]).get(sev, 0)
                if cnt:
                    print(f"    {sev:<12} {cnt:>8,}")

        # FP reduction rate
        total = s["flows_processed"]
        if total > 0:
            reduced = s["whitelisted"] + sum(dict(s["gate_blocked"]).values())
            print(f"\n  FP reduction: {reduced:,}/{total:,} flows blocked "
                  f"({reduced/total*100:.1f}%)")

        high_risk = self.get_high_risk(30.0)
        if high_risk:
            print(f"\n  High risk entities ({len(high_risk)}):")
            for e in high_risk[:10]:
                bar = "#" * int(e['risk_score'] / 5)
                print(f"    {e['ip']:<18} {e['role']:<15} "
                      f"risk={e['risk_score']:>5.1f} rep={e['reputation']:>4.0f}  {bar}")

        print(f"{'='*65}")
