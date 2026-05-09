"""Sentrix binary ensemble + attack-family typer"""
from __future__ import annotations

import logging
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# ── Canonical 45-feature schema (mirrors base_ipfix_normalizer.CANONICAL_FEATURES)
CANONICAL_FEATURES: Tuple[str, ...] = (
    "src_port", "dst_port", "protocol", "duration",
    "fwd_packets", "bwd_packets", "total_packets",
    "fwd_bytes", "bwd_bytes", "total_bytes",
    "pkt_size_min", "pkt_size_max",
    "syn_flag", "fin_flag", "rst_flag", "ack_flag", "psh_flag",
    "bytes_per_sec", "packets_per_sec",
    "fwd_packets_per_sec", "bwd_packets_per_sec",
    "pkt_size_mean", "fwd_byte_ratio",
    "bytes_per_packet", "fwd_bwd_pkt_ratio", "fwd_bwd_byte_ratio",
    "duration_per_packet",
    "is_well_known_port", "is_http", "is_https",
    "is_dns", "is_ssh", "is_threat_port",
    "syn_ratio", "rst_ratio", "fin_ratio",
    "syn_without_ack", "rst_without_established",
    "flag_entropy", "traffic_asymmetry", "protocol_port_mismatch",
    "short_session_flag", "long_session_flag",
    "small_packet_flag", "large_packet_flag",
)
assert len(CANONICAL_FEATURES) == 45

EPS = 1e-6
_HTTP_PORTS = frozenset({80, 8080, 8000, 8008})
_HTTPS_PORTS = frozenset({443, 8443})
_DNS_PORT = 53
_SSH_PORT = 22
_THREAT_PORTS = frozenset({1337, 4444, 4445, 5555, 6667, 6697, 9999, 31337, 48101})
_COMMON_TCP_PORTS = frozenset({
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587,
    993, 995, 3306, 3389, 5432, 5900, 8080, 8443,
})

_SEV_THRESHOLDS = {"CRITICAL": 0.95, "HIGH": 0.80, "MEDIUM": 0.50, "LOW": 0.20}

def _f(v, default: float = 0.0) -> float:
    try:
        x = float(v)
        if x != x or abs(x) == float("inf"):
            return default
        return x
    except (TypeError, ValueError):
        return default

def _i(v, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return default

def _prob_to_severity(p: float) -> str:
    if p >= _SEV_THRESHOLDS["CRITICAL"]: return "CRITICAL"
    if p >= _SEV_THRESHOLDS["HIGH"]:     return "HIGH"
    if p >= _SEV_THRESHOLDS["MEDIUM"]:   return "MEDIUM"
    if p >= _SEV_THRESHOLDS["LOW"]:      return "LOW"
    return "BENIGN"

def _flow_to_canonical(flow: Dict[str, Any]) -> Dict[str, Any]:
    """Derive the 45 canonical features + {timestamp, src_ip, dst_ip} from a
    realtime_engine flow dict. Math matches BaseIPFIXNormalizer exactly."""
    # Raw primitives
    src_port = _i(flow.get("src_port", 0))
    dst_port = _i(flow.get("dst_port", 0))
    proto = flow.get("protocol", 6)
    if isinstance(proto, str):
        proto = {"tcp": 6, "udp": 17, "icmp": 1,
                 "TCP": 6, "UDP": 17, "ICMP": 1}.get(proto, 0)
    protocol = _i(proto)
    duration = max(_f(flow.get("duration", 0.0)), 0.0)

    fwd_p = max(_f(flow.get("fwd_packets", 0)), 0.0)
    bwd_p = max(_f(flow.get("bwd_packets", 0)), 0.0)
    total_p = _f(flow.get("total_packets", 0))
    if total_p <= 0:
        total_p = fwd_p + bwd_p

    fwd_b = max(_f(flow.get("fwd_bytes", 0)), 0.0)
    bwd_b = max(_f(flow.get("bwd_bytes", 0)), 0.0)
    total_b = _f(flow.get("total_bytes", 0))
    if total_b <= 0:
        total_b = fwd_b + bwd_b

    pkt_min = _f(flow.get("pkt_size_min", 0))
    pkt_max = _f(flow.get("pkt_size_max", 0))

    syn = _i(flow.get("syn_flag", 0))
    fin = _i(flow.get("fin_flag", 0))
    rst = _i(flow.get("rst_flag", 0))
    ack = _i(flow.get("ack_flag", 0))
    psh = _i(flow.get("psh_flag", 0))

    dur_safe = max(duration, EPS)
    tp_safe = max(total_p, 1.0)
    tb_safe = max(total_b, 0.0)

    bytes_per_sec = tb_safe / dur_safe
    packets_per_sec = total_p / dur_safe
    fwd_packets_per_sec = fwd_p / dur_safe
    bwd_packets_per_sec = bwd_p / dur_safe
    pkt_size_mean = tb_safe / tp_safe
    fwd_byte_ratio = fwd_b / max(tb_safe, 1.0)
    bytes_per_packet = tb_safe / tp_safe
    fwd_bwd_pkt_ratio = fwd_p / max(bwd_p, 1.0)
    fwd_bwd_byte_ratio = fwd_b / max(bwd_b, 1.0)
    duration_per_packet = duration / tp_safe

    is_well_known_port = 1 if 0 < dst_port < 1024 else 0
    is_http = 1 if dst_port in _HTTP_PORTS else 0
    is_https = 1 if dst_port in _HTTPS_PORTS else 0
    is_dns = 1 if (dst_port == _DNS_PORT or src_port == _DNS_PORT) else 0
    is_ssh = 1 if dst_port == _SSH_PORT else 0
    is_threat_port = 1 if dst_port in _THREAT_PORTS else 0

    # Binary mode flag ratios; same as the three canonical datasets.
    syn_ratio = float(syn)
    rst_ratio = float(rst)
    fin_ratio = float(fin)

    syn_without_ack = 1 if (syn == 1 and ack == 0) else 0
    rst_without_established = 1 if (rst == 1 and (syn + ack) == 0) else 0

    # Shannon entropy of flag presence
    flags = [syn, fin, rst, ack, psh]
    fsum = sum(flags)
    if fsum > 0:
        flag_entropy = 0.0
        for x in flags:
            if x > 0:
                p = x / fsum
                flag_entropy -= p * math.log(p)
    else:
        flag_entropy = 0.0

    asym_denom = max(total_b, EPS)
    traffic_asymmetry = abs(fwd_b - bwd_b) / asym_denom

    protocol_port_mismatch = (
        1 if (protocol == 6 and dst_port not in _COMMON_TCP_PORTS) else 0
    )
    short_session_flag = 1 if duration < 1.0 else 0
    long_session_flag = 1 if duration > 600.0 else 0
    small_packet_flag = 1 if pkt_size_mean < 64 else 0
    large_packet_flag = 1 if pkt_size_mean > 1400 else 0

    return {
        "src_port": src_port, "dst_port": dst_port,
        "protocol": protocol, "duration": duration,
        "fwd_packets": fwd_p, "bwd_packets": bwd_p, "total_packets": total_p,
        "fwd_bytes": fwd_b, "bwd_bytes": bwd_b, "total_bytes": total_b,
        "pkt_size_min": pkt_min, "pkt_size_max": pkt_max,
        "syn_flag": syn, "fin_flag": fin, "rst_flag": rst,
        "ack_flag": ack, "psh_flag": psh,
        "bytes_per_sec": bytes_per_sec, "packets_per_sec": packets_per_sec,
        "fwd_packets_per_sec": fwd_packets_per_sec,
        "bwd_packets_per_sec": bwd_packets_per_sec,
        "pkt_size_mean": pkt_size_mean, "fwd_byte_ratio": fwd_byte_ratio,
        "bytes_per_packet": bytes_per_packet,
        "fwd_bwd_pkt_ratio": fwd_bwd_pkt_ratio,
        "fwd_bwd_byte_ratio": fwd_bwd_byte_ratio,
        "duration_per_packet": duration_per_packet,
        "is_well_known_port": is_well_known_port,
        "is_http": is_http, "is_https": is_https,
        "is_dns": is_dns, "is_ssh": is_ssh,
        "is_threat_port": is_threat_port,
        "syn_ratio": syn_ratio, "rst_ratio": rst_ratio, "fin_ratio": fin_ratio,
        "syn_without_ack": syn_without_ack,
        "rst_without_established": rst_without_established,
        "flag_entropy": flag_entropy,
        "traffic_asymmetry": traffic_asymmetry,
        "protocol_port_mismatch": protocol_port_mismatch,
        "short_session_flag": short_session_flag,
        "long_session_flag": long_session_flag,
        "small_packet_flag": small_packet_flag,
        "large_packet_flag": large_packet_flag,
        # Metadata for StreamingHostAggregator (not features)
        "timestamp": _f(flow.get("capture_time", flow.get("timestamp", 0.0))),
        "src_ip": str(flow.get("src_ip", "") or ""),
        "dst_ip": str(flow.get("dst_ip", "") or ""),
    }

class SentrixCascade:
    """Drop-in ML cascade. Wraps SentrixLiveEngine from sentrix_realtime.py."""

    def __init__(self, models_dir: Path):
        self.models_dir = Path(models_dir)
        # Feed the SpecialistCascade interface expectations
        self.feature_names: List[str] = []
        self.n_features = 53  # informational only; derived internally

        self.ready = False
        self.engine = None
        self.stage2_classes: List[str] = []

        log.info("Loading SentrixCascade ...")
        self._load()

    def _load(self) -> None:
        # SentrixLiveEngine lives at project root (sibling of src/)
        project_root = self.models_dir.parent
        if str(project_root) not in sys.path:
            sys.path.insert(0, str(project_root))
        try:
            from sentrix_realtime import SentrixLiveEngine
        except ImportError as e:
            log.error(f"  SentrixLiveEngine import failed: {e}")
            return

        try:
            self.engine = SentrixLiveEngine(
                models_dir=self.models_dir, use_onnx_for_stage2=True,
            )
            self.stage2_classes = list(self.engine.stage2_classes or [])
            self.ready = True
            log.info(
                f"  SentrixCascade ready: "
                f"weights LGB={self.engine.W_LGB:.2f} "
                f"XGB={self.engine.W_XGB:.2f} RF={self.engine.W_RF:.2f}  "
                f"T={self.engine.T:.3f}  "
                f"TAU_LOW={self.engine.TAU_LOW:.3f} TAU_HIGH={self.engine.TAU_HIGH:.3f}  "
                f"stage2={self.engine.stage2_kind} ({len(self.stage2_classes)} classes: "
                f"{', '.join(self.stage2_classes)})"
            )
        except Exception as e:
            log.error(f"  SentrixCascade load error: {e}")
            self.ready = False

    def _benign_result(self) -> Dict[str, Any]:
        return {
            "is_attack": False, "severity": "BENIGN",
            "attack_type": "BENIGN", "probability": 0.0,
            "specialist_source": "sentrix_binary",
            "specialist_details": [],
        }

    def predict(
        self,
        features_batch: List[List[float]],
        raw_features_batch: Optional[List[Dict]] = None,
    ) -> Tuple[List[Dict], List[List[Dict]]]:
        """
        features_batch is ignored; the cascade re-derives features from raw flows to
        guarantee train/infer parity with the 45-feature canonical schema.
        Returns (ml_results, specialist_results_per_flow).
        """
        n = len(features_batch) if features_batch else len(raw_features_batch or [])
        if n == 0:
            return [], []
        if not raw_features_batch or not self.ready:
            return [self._benign_result() for _ in range(n)], [[] for _ in range(n)]

        ml_results: List[Dict] = []
        spec_results: List[List[Dict]] = []
        for flow in raw_features_batch:
            try:
                canon = _flow_to_canonical(flow)
                alert = self.engine.process_row(canon)
            except Exception as e:
                log.warning(f"sentrix process_row failed: {e}")
                ml_results.append(self._benign_result())
                spec_results.append([])
                continue

            p = float(alert.get("p_attack", 0.0))
            is_attack = (alert.get("label") == "attack")
            family = alert.get("attack_family")
            family_conf = alert.get("family_confidence")

            if is_attack and family:
                attack_type = family
                severity = _prob_to_severity(p)
                spec_source = "sentrix_stage2"
                details = [{
                    "name": family,
                    "confidence": round(float(family_conf or 0.0), 6),
                    "kind": "attack_family",
                }]
            elif is_attack:
                attack_type = "Unclassified"
                severity = _prob_to_severity(p)
                spec_source = "sentrix_binary"
                details = []
            else:
                attack_type = "BENIGN"
                severity = "BENIGN"
                spec_source = "sentrix_binary"
                details = []

            ml_results.append({
                "is_attack": is_attack,
                "severity": severity,
                "attack_type": attack_type,
                "probability": round(p, 6),
                "specialist_source": spec_source,
                "specialist_details": details,
            })
            spec_results.append(details)

        return ml_results, spec_results
