"""Production Real-Time Orchestrator"""
import os
import sys
import io
import json
import time
import signal
import ipaddress
import logging
import argparse
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass
if sys.stderr.encoding != 'utf-8':
    try:
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

# Add project paths
_SRC = Path(__file__).resolve().parent
_PROJECT = _SRC.parent
sys.path.insert(0, str(_SRC))
sys.path.insert(0, str(_PROJECT))

import numpy as np

# Our modules
from capture import CaptureService
from intelligence_gate import IntelligenceGate
from sentrix_cascade import SentrixCascade
from ueba_long import UEBALong
# Hand-curated rules engine retired 2026-05-01. Behavioural patterns
# previously covered by the rules engine are now handled by Stage 1
# ML, UEBA, and the per-deployment fine-tuning loop. Signature-based
# detection has migrated to the Suricata integration at Layer 0.
from threat_intel import ThreatIntelEngine
from eta import EncryptedTrafficAnalyzer
from entity_context import EntityContextEngine
from ip_classifier import get_classifier
# NOTE: flow_logger is NOT imported here by design. The detection
# engine never writes to flows.tsv; that's the capture script's
# job (scripts/capture_flows.py). This decoupling prevents the
# engine's (potentially biased) labels from poisoning the training
# corpus. See SESSION_NOTES_2026-04-14.md for rationale.
from alert_dispatch import AlertDispatcher
from policy_engine import PolicyEngine
from runtime_state import RuntimeStateStore
from device_classifier import DeviceClassifier
from feature_normalizer import FeatureNormalizer, NUMERIC_FEATURES
from drift_monitor import DriftMonitor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
log = logging.getLogger("engine")

# ── Console Colors ────────────────────────────────────────────
R = '\033[91m'; O = '\033[33m'; Y = '\033[93m'
G = '\033[92m'; C = '\033[96m'; D = '\033[90m'
B = '\033[1m'; X = '\033[0m'
def col(s, c): return f"{c}{s}{X}"

MODELS_DIR = str(_PROJECT / "models")
BATCH_SIZE = 256

SEV_COLORS = {"CRITICAL": R, "HIGH": O, "MEDIUM": Y, "LOW": C, "BENIGN": D}

def _is_non_unicast(ip: str) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    if a.is_multicast or a.is_link_local or a.is_loopback or a.is_unspecified:
        return True
    if isinstance(a, ipaddress.IPv4Address) and str(a).endswith(".255"):
        return True
    return False

class AsymmetricFlowTracker:
    """Detect dual-ISP asymmetric capture on a per-source-IP basis.

    Tracks the fraction of flows where bwd_bytes == 0 over a rolling
    1-hour window. When >80% of an IP's flows are one-directional,
    the directional ratio features (fwd_bwd_pkt_ratio, fwd_bwd_byte_ratio)
    become unreliable and should be zeroed before ML scoring.
    """

    def __init__(self, window_seconds: float = 3600.0, threshold: float = 0.80):
        self._window = window_seconds
        self._threshold = threshold
        self._data: Dict[str, List] = {}
        self._lock = threading.Lock()

    def record(self, src_ip: str, bwd_bytes: float, now: float) -> None:
        with self._lock:
            if src_ip not in self._data:
                self._data[src_ip] = []
            self._data[src_ip].append((now, bwd_bytes == 0))

    def is_asymmetric(self, src_ip: str, now: float) -> bool:
        with self._lock:
            entries = self._data.get(src_ip)
            if not entries or len(entries) < 20:
                return False
            cutoff = now - self._window
            entries[:] = [(t, v) for t, v in entries if t > cutoff]
            if len(entries) < 20:
                return False
            zero_frac = sum(1 for _, v in entries if v) / len(entries)
            return zero_frac > self._threshold

    def suppress_directional(self, flow: dict, now: float) -> None:
        src_ip = flow.get("src_ip", "")
        if src_ip and self.is_asymmetric(src_ip, now):
            flow["fwd_bwd_pkt_ratio"] = 0.0
            flow["fwd_bwd_byte_ratio"] = 0.0
            flow["fwd_byte_ratio"] = 0.0

class PerEntityMetrics:
    """Per-src_ip rolling-window metrics for peer-group scoring.

    Maintains a 60s window of flows per source IP and derives the
    four metrics PeerGroupBaseline compares against:
        fpm             (flows per minute)
        unique_dst      (distinct destinations in window)
        bytes_per_flow  (mean total_bytes in window)
        send_ratio      (fwd_bytes / total_bytes in window)
    plus the port and protocol sets seen.

    Peer-group *pushes* are throttled per src_ip (one sample per
    PUSH_EVERY_N flows) so a chatty device doesn't swamp the group
    baseline with one-sample-per-flow noise.
    """

    PUSH_EVERY_N = 100
    MIN_FLOWS    = 5

    def __init__(self, window_seconds: float = 60.0):
        self._window = window_seconds
        self._data: Dict[str, List] = {}
        self._push_counter: Dict[str, int] = {}
        self._lock = threading.Lock()

    def record(self, src_ip: str, flow: dict, now: float) -> None:
        if not src_ip:
            return
        with self._lock:
            entries = self._data.setdefault(src_ip, [])
            entries.append((
                now,
                flow.get("dst_ip", ""),
                float(flow.get("total_bytes", 0) or 0),
                float(flow.get("fwd_bytes", 0) or 0),
                int(flow.get("dst_port", 0) or 0),
                int(flow.get("protocol", 0) or 0),
            ))
            cutoff = now - self._window
            # Prune in place; O(n) but n is small.
            self._data[src_ip] = [e for e in entries if e[0] > cutoff]
            self._push_counter[src_ip] = self._push_counter.get(src_ip, 0) + 1

    def compute(self, src_ip: str) -> Optional[dict]:
        with self._lock:
            entries = self._data.get(src_ip)
            if not entries or len(entries) < self.MIN_FLOWS:
                return None
            n = len(entries)
            fpm = (n / max(self._window, 1.0)) * 60.0
            unique_dst = len({e[1] for e in entries if e[1]})
            tb = sum(e[2] for e in entries)
            fb = sum(e[3] for e in entries)
            bytes_per_flow = tb / n
            send_ratio = (fb / tb) if tb > 0 else 0.5
            ports = {e[4] for e in entries if e[4]}
            protos = {e[5] for e in entries if e[5]}
            return {
                "fpm": fpm,
                "unique_dst": float(unique_dst),
                "bytes_per_flow": bytes_per_flow,
                "send_ratio": send_ratio,
                "ports": ports,
                "protocols": protos,
                "n_flows": n,
            }

    def should_push(self, src_ip: str) -> bool:
        """True if this src_ip has accumulated enough flows to
        contribute a new sample to its peer group."""
        with self._lock:
            c = self._push_counter.get(src_ip, 0)
            if c >= self.PUSH_EVERY_N:
                self._push_counter[src_ip] = 0
                return True
            return False

# (UEBA dormant result is no longer needed; UEBALong handles
#  learning-vs-scoring gating internally and always returns a
#  well-formed result dict.)

class RealTimeEngine:
    """
    Production real-time detection engine.
    Correct layer ordering: JA3/TLS → ThreatIntel → ML → UEBA → Alert
    """

    def __init__(self, capture_mode: str = "csv", **kwargs):
        print(col(f"\n{'='*65}", C))
        print(col("  SENTRIX  -  Real-Time Detection Engine", C))
        print(col("  JA3/TLS First  |  Sentrix ML + Attack-Family Typer  |  UEBA v4", C))
        print(col(f"{'='*65}", C))

        self._start_time = time.time()
        self._running = False

        # Per-flow latency ring buffer for /api/health (bounded, lock-free)
        from collections import deque as _deque
        self._latency_ms = _deque(maxlen=2000)
        self._last_flows_processed = 0
        self._last_stats_write_ts = time.time()

        # ── Initialize all components ─────────────────────────
        print(col("\n  Initializing components...", D))

        # Threat Intelligence (7 feeds)
        print(col("  [1/10] Threat Intelligence...", D))
        self.threat_intel = ThreatIntelEngine()

        # Encrypted Traffic Analytics (JA3/TLS/SPLT)
        print(col("  [2/10] Encrypted Traffic Analytics...", D))
        self.eta = EncryptedTrafficAnalyzer(threat_intel=self.threat_intel)

        # Entity Context (Peer Groups + Identity)
        print(col("  [3/10] Entity Context + Identity...", D))
        self.entity_ctx = EntityContextEngine()

        # Intelligence Gate (Layer 1; JA3 ABOVE models)
        print(col("  [4/10] Intelligence Gate (Layer 1)...", D))
        from ueba import Whitelist
        self.intel_gate = IntelligenceGate(
            threat_intel=self.threat_intel,
            eta_engine=self.eta,
            entity_context=self.entity_ctx,
            whitelist=Whitelist(),
        )

        # ML Cascade (Layer 2; Sentrix binary ensemble + attack-family typer)
        print(col("  [5/10] ML Cascade (Layer 2, Sentrix)...", D))
        self.ml_cascade = SentrixCascade(Path(MODELS_DIR))
        self.normalizer = FeatureNormalizer()
        self.asymmetric_tracker = AsymmetricFlowTracker()
        self.peer_metrics = PerEntityMetrics(window_seconds=60.0)
        self.ip_classifier = get_classifier()
        # Detection engine does NOT write to logs/flows.tsv.
        # Training corpus capture is a separate process :
        # scripts/capture_flows.py. See design note at import.
        self.drift_monitor = DriftMonitor(
            scaler_path=Path(MODELS_DIR) / "sentrix_scaler.pkl",
            feature_names=NUMERIC_FEATURES,
        )

        # Runtime state; bidirectional channel with the dashboard.
        # Dashboard writes whitelist/suppressions/config via its API;
        # engine polls every 2s and honours changes in the per-flow loop.
        print(col("  [5b] Runtime state store...", D))
        _alerts_db = str(_PROJECT / "alerts.db")
        self.runtime_state = RuntimeStateStore(db_path=_alerts_db,
                                                 poll_seconds=2.0)
        self.runtime_state.refresh()
        self.runtime_state.start_refresher()

        # Device classifier; zero-cost observer. Every flow feeds
        # evidence; results persist to alerts.db every 10s.
        print(col("  [5c] Device classifier...", D))
        self.device_classifier = DeviceClassifier(db_path=_alerts_db)
        self.device_classifier.start_save_thread(interval_seconds=10.0)

        # UEBA Long (Layer 3; long-term baseline only, 14-day learn)
        print(col("  [6/10] UEBA Long (Layer 3)...", D))
        self.ueba = UEBALong(
            state_path=_PROJECT / "ueba_long_state.json",
            runtime_state=self.runtime_state,
            entity_context=self.entity_ctx,
        )

        # Policy Engine (Layer 2.5; anonymizer/device/dept restrictions)
        print(col("  [7/10] Policy Engine (Layer 2.5)...", D))
        self.policy = PolicyEngine(threat_intel=self.threat_intel)

        # Rules Engine; SMB allowlist loaded from config/smb_allowlist.yaml
        # if present; no hardcoded IPs (the old 192.168.1.{1,2,3} never
        # matched in real deployments).
        # Rules engine retired 2026-05-01; rule_score is forced to 0.0
        # at every flow and the rules slot in the fused score
        # contributes nothing. Detection coverage previously provided
        # by the rules engine now resides in Stage 1 ML, UEBA, and
        # the per-deployment fine-tuning loop in the alert dispatcher.
        self.rules = None

        # Alert Dispatcher
        print(col("  [9/10] Alert Dispatcher...", D))
        self.dispatcher = AlertDispatcher()

        # Capture Service
        self.capture = CaptureService(mode=capture_mode, **kwargs)

        # Stats
        self.stats = {
            "flows_processed": 0,
            "layer1_immediate": 0,
            "layer1_whitelisted": 0,
            "layer1_boosted": 0,
            "layer2_attacks": 0,
            "layer25_policy_violations": 0,
            "layer3_alerts": 0,
            "total_alerts": 0,
        }

        print(col(f"\n  Engine ready. Mode: {capture_mode}", G))
        print(col(f"  Architecture: Layer0(Capture) -> Layer1(JA3/TI) "
                  f"-> Layer2(ML) -> Layer3(UEBA) -> Layer4(Alert)", G))

        # UEBA learning banner; shows accumulated observation time
        # and whether the clock is paused.
        _us = self.runtime_state.get_ueba_status()
        obs_s = _us.get("observed_seconds", 0.0)
        tgt_s = _us.get("target_seconds", 14 * 86400)
        obs_d = obs_s / 86400
        tgt_d = tgt_s / 86400
        if _us["active"] and not _us["paused"]:
            print(col(
                f"  UEBA Layer 3: ACTIVE; scoring on mature baselines "
                f"({obs_d:.1f}d observed)", G))
        elif _us["paused"]:
            print(col(
                f"  UEBA Layer 3: PAUSED; learning frozen at "
                f"{obs_d:.1f}d / {tgt_d:.0f}d "
                f"({_us['progress_pct']:.1f}%)", Y))
            print(col(
                "  Neither the clock nor baselines are updating. "
                "Resume from the dashboard.", D))
        else:
            print(col(
                f"  UEBA Layer 3: LEARNING; "
                f"{obs_d:.2f}d / {tgt_d:.0f}d observed "
                f"({_us['progress_pct']:.1f}%)", Y))
            print(col(
                "  UEBA observes and updates baselines but suppresses "
                "alerts. ML + Policy + Rules handle detection.", D))

        print(col(f"{'='*65}\n", C))

    # ── Main Processing Loop ──────────────────────────────────

    def start(self):
        """Start the real-time engine."""
        self._running = True
        self.capture.start()

        # Background tasks
        self._start_background_tasks()

        print(col("  LIVE DETECTION FEED", C))
        print(col(f"  {'TIME':<10} {'SEV':<10} {'TYPE':<20} "
                  f"{'SOURCE':<18} {'TAG':<12} DETAILS", D))
        print(col("  " + "-" * 75, D))

        try:
            while self._running:
                batch = self.capture.get_batch(
                    batch_size=BATCH_SIZE, timeout=1.0)
                if not batch:
                    continue
                self._process_batch(batch)

        except KeyboardInterrupt:
            print(col("\n\n  Stopped by user", Y))
        finally:
            self._shutdown()

    def stop(self):
        self._running = False

    def _process_batch(self, flows: List[dict]):
        """Process a batch through all 4 layers."""

        # Global pause check; drop entire batch if the dashboard
        # has paused the engine. Polling the state once per batch
        # (not per flow) keeps the hot path cheap.
        if self.runtime_state.is_paused():
            return

        for flow in flows:
            _t_flow_start = time.perf_counter()
            self.stats["flows_processed"] += 1
            now = flow.get("capture_time", time.time())

            # Device classifier; observe every flow, even the ones
            # that'll be filtered out below. Cheap hot-path call,
            # updates in-memory evidence only; persistence is batched.
            try:
                self.device_classifier.observe(flow)
            except Exception:
                pass

            # Non-unicast pre-filter; drop multicast/broadcast/link-local
            # before any detection layer. These are never valid attack endpoints.
            src_ip_early = flow.get("src_ip", "")
            dst_ip_early = flow.get("dst_ip", "")
            if _is_non_unicast(src_ip_early) or _is_non_unicast(dst_ip_early):
                self.stats["layer1_whitelisted"] += 1
                continue

            # Runtime whitelist; short-circuit before any layer runs.
            if (self.runtime_state.is_whitelisted(src_ip_early) or
                self.runtime_state.is_whitelisted(dst_ip_early)):
                self.stats["layer1_whitelisted"] += 1
                continue

            # ══════════════════════════════════════════════════
            #  LAYER 1: Intelligence Gate (JA3 FIRST)
            # ══════════════════════════════════════════════════
            verdict = self.intel_gate.evaluate(flow)

            if verdict["action"] == "SKIP_BENIGN":
                self.stats["layer1_whitelisted"] += 1
                continue

            if verdict["action"] == "ALERT_IMMEDIATE":
                # Runtime suppression can silence even Layer-1 hits
                # if the SOC has marked this (ip, attack_type) noisy.
                _atype = (verdict.get("alert_details", {}).get("attack_type")
                           or "Known_Threat")
                if self.runtime_state.is_suppressed(
                    flow.get("src_ip", ""), _atype
                ):
                    continue
                # Known malware JA3 or known C2 IP; skip ML entirely
                self.stats["layer1_immediate"] += 1
                self.stats["total_alerts"] += 1
                self._dispatch_immediate_alert(flow, verdict, now)
                continue

            # Decomposed intel boosts from the gate. intel_boost is the
            # sum applied to ML; the components (ti/ja3/dns/eta_pure)
            # are consumed separately below for first-class fusion
            # signals so provenance isn't collapsed into one field.
            intel_boost   = verdict.get("intel_boost",
                                        verdict.get("eta_boost", 0.0))
            ti_boost      = verdict.get("ti_boost",   0.0)
            ti_severity   = verdict.get("ti_severity", "")
            eta_pure      = verdict.get("eta_pure",   0.0)
            eta_anom_n    = verdict.get("eta_anomaly_count", 0)
            if intel_boost > 0:
                self.stats["layer1_boosted"] += 1

            # ══════════════════════════════════════════════════
            #  LAYER 2: ML Cascade (threshold adjusted by intel_boost)
            # ══════════════════════════════════════════════════
            # Asymmetric capture detection; suppress unreliable
            # directional features for IPs on one-sided ISP paths.
            bwd = float(flow.get("bwd_bytes", 0) or 0)
            self.asymmetric_tracker.record(src_ip_early, bwd, now)
            self.asymmetric_tracker.suppress_directional(flow, now)

            features = self._extract_features(flow)
            self.drift_monitor.record(features)
            ml_results, spec_results = self.ml_cascade.predict(
                [features], [flow])
            ml_result = ml_results[0]
            spec_detail = spec_results[0]

            # Apply intel_boost: if TLS/JA3/DNS/TI evidence is suspicious,
            # lower the bar. Only flips ML-benign → MEDIUM attack; the
            # first-class signals below handle ML-already-attack cases.
            if intel_boost > 0 and not ml_result["is_attack"]:
                adjusted_prob = ml_result["probability"] + intel_boost
                if adjusted_prob > 0.50:
                    ml_result["is_attack"] = True
                    ml_result["severity"] = "MEDIUM"
                    ml_result["attack_type"] = "TLS_Suspicious"
                    ml_result["specialist_source"] = "intel_boost"

            if ml_result["is_attack"]:
                self.stats["layer2_attacks"] += 1

            # ══════════════════════════════════════════════════
            #  LAYER 2.5: Policy Engine (anonymizer/device/dept)
            # ══════════════════════════════════════════════════
            identity = verdict.get("identity", {})
            policy_result = self.policy.evaluate(flow, identity=identity, now=now)

            if policy_result["violation"]:
                self.stats["layer25_policy_violations"] += 1

            # ══════════════════════════════════════════════════
            #  LAYER 2.75: Rules Engine (parallel)
            # ══════════════════════════════════════════════════
            # Rules engine retired 2026-05-01; zero/empty stub.
            rule_score, rule_alerts = 0.0, []

            # ══════════════════════════════════════════════════
            #  LAYER 3: UEBA Long (learning-then-scoring)
            # ══════════════════════════════════════════════════
            #
            # UEBALong is always called. Gating happens INSIDE:
            #   - During the 14-day learning window it updates
            #     per-device and per-department baselines but
            #     returns should_alert=False regardless of what it
            #     observes. ML + Policy + Rules are doing all the
            #     detection in this window.
            #   - After activation it starts scoring every flow
            #     against its device baseline (or inheriting the
            #     department baseline for devices first seen
            #     post-activation).
            ueba_result = self.ueba.process_flow(
                flow,
                specialist_results=spec_detail,
                now=now,
            )

            # ══════════════════════════════════════════════════
            #  LAYER 3.5: Peer Group Deviation (cross-sectional)
            # ══════════════════════════════════════════════════
            # Maintain a per-src_ip rolling window, feed the peer
            # group baseline every PUSH_EVERY_N flows, and score
            # deviation every flow (cheap; 4 z-scores).
            peer_dev_score = 0.0
            peer_dev_reasons: List[str] = []
            src_ip_peer = flow.get("src_ip", "")
            # Gate on internal-only: external src_ips (inbound flows
            # from public internet, e.g. scanners) never seed the
            # per-entity rolling window or peer group baseline.
            if src_ip_peer and self.ip_classifier.is_internal(src_ip_peer):
                self.peer_metrics.record(src_ip_peer, flow, now)
                cur = self.peer_metrics.compute(src_ip_peer)
                if cur is not None:
                    if self.peer_metrics.should_push(src_ip_peer):
                        self.entity_ctx.update_peer_group(
                            src_ip_peer,
                            fpm=cur["fpm"],
                            unique_dst=cur["unique_dst"],
                            bytes_per_flow=cur["bytes_per_flow"],
                            send_ratio=cur["send_ratio"],
                            ports=cur["ports"],
                            protocols=cur["protocols"],
                        )
                    peer_dev_score, peer_dev_reasons = \
                        self.entity_ctx.score_peer_deviation(
                            src_ip_peer,
                            current_fpm=cur["fpm"],
                            current_unique_dst=cur["unique_dst"],
                            current_bytes_per_flow=cur["bytes_per_flow"],
                            current_send_ratio=cur["send_ratio"],
                        )

            # ══════════════════════════════════════════════════
            #  LAYER 4: Alert Decision + Dispatch
            # ══════════════════════════════════════════════════
            # Seven independent signals: policy, ueba, ml, rule,
            # threat-intel-soft, eta-tls-anomaly, peer-deviation.
            # Severity = highest-rank signal; any ≥2 signals bumps
            # one rank (flat; no double bump regardless of count).
            _SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2,
                         "LOW": 1, "BENIGN": 0, "": 0}
            signals = []

            if policy_result["violation"]:
                _sev = policy_result["severity"]
                signals.append((_SEV_RANK.get(_sev, 0), _sev,
                                "POLICY_" + policy_result["category"].upper()))

            if ueba_result["should_alert"]:
                _sev = ueba_result["alert_severity"]
                signals.append((_SEV_RANK.get(_sev, 0), _sev,
                                ueba_result["alert_tag"]))

            if ml_result["is_attack"]:
                _ml_thr = self.runtime_state.get_float("ml_threshold", 0.70)
                if ml_result.get("probability", 0) >= _ml_thr:
                    _sev = ml_result["severity"]
                    signals.append((_SEV_RANK.get(_sev, 0), _sev,
                                    "SPECIALIST"))

            if rule_score >= 0.85:
                _sev = "CRITICAL" if rule_score >= 1.0 else "HIGH"
                signals.append((_SEV_RANK[_sev], _sev, "RULE_MATCH"))

            # TI soft signal; medium/low TI hits that didn't
            # trip ALERT_IMMEDIATE still deserve a first-class
            # severity contribution, not just a boost bump.
            if ti_boost > 0 and ti_severity in ("MEDIUM", "LOW"):
                _sev = "MEDIUM" if ti_severity == "MEDIUM" else "LOW"
                signals.append((_SEV_RANK[_sev], _sev, "THREAT_INTEL_SOFT"))
                self.stats["layer1_ti_soft"] = \
                    self.stats.get("layer1_ti_soft", 0) + 1

            # ETA standalone signal; TLS anomalies (self-signed,
            # weak cipher, expired, SPLT) as a first-class detector.
            # Threshold: ≥2 anomalies to avoid single-flag noise.
            if eta_pure >= 0.20 and eta_anom_n >= 2:
                _sev = "HIGH" if eta_pure >= 0.35 else "MEDIUM"
                signals.append((_SEV_RANK[_sev], _sev, "ETA_TLS_ANOMALY"))
                self.stats["layer1_eta_signal"] = \
                    self.stats.get("layer1_eta_signal", 0) + 1

            # Peer group deviation; cross-sectional anomaly
            # (this device vs its department peers).
            if peer_dev_score >= 0.40:
                _sev = "HIGH" if peer_dev_score >= 0.70 else "MEDIUM"
                signals.append((_SEV_RANK[_sev], _sev, "PEER_DEVIATION"))
                self.stats["layer3_peer_deviation"] = \
                    self.stats.get("layer3_peer_deviation", 0) + 1

            should_alert = bool(signals)
            severity = "BENIGN"
            tag = ""
            if signals:
                signals.sort(key=lambda t: t[0], reverse=True)
                _, severity, tag = signals[0]
                if len(signals) >= 2:
                    _cur = _SEV_RANK.get(severity, 0)
                    _bump = {1: "MEDIUM", 2: "HIGH", 3: "CRITICAL",
                             4: "CRITICAL"}
                    if _cur in _bump:
                        severity = _bump[_cur]

            if should_alert:
                # Dashboard-controlled suppression; skip alert if
                # (src_ip, attack_type) is suppressed.
                _atype_for_sup = (ml_result.get("attack_type")
                                    or ueba_result.get("specialist_verdict")
                                    or tag)
                if self.runtime_state.is_suppressed(
                    flow.get("src_ip", ""), _atype_for_sup
                ):
                    continue

                self.stats["layer3_alerts"] += 1
                self.stats["total_alerts"] += 1

                alert = self._build_alert(
                    flow, ml_result, ueba_result, rule_score,
                    rule_alerts, verdict, severity, tag, now,
                    policy_result=policy_result,
                    peer_dev_score=peer_dev_score,
                    peer_dev_reasons=peer_dev_reasons)
                self.dispatcher.dispatch(alert)
                self._print_alert(alert)

            # Detection engine does NOT write to the training corpus.
            # scripts/capture_flows.py is a separate process that
            # tails Zeek directly and writes logs/flows.tsv without
            # any engine influence. This keeps retraining feedback-
            # loop-free.

            # Per-flow latency for /api/health
            try:
                self._latency_ms.append(
                    (time.perf_counter() - _t_flow_start) * 1000.0
                )
            except Exception:
                pass

            # Periodic stats
            if self.stats["flows_processed"] % 1000 == 0:
                self._print_stats()

    # ── Alert Building ────────────────────────────────────────

    def _dispatch_immediate_alert(self, flow: dict, verdict: dict,
                                   now: float):
        """Dispatch an immediate alert from Layer 1 (JA3/TI match)."""
        details = verdict.get("alert_details", {})
        identity = verdict.get("identity", {})
        sensitivity = verdict.get("sensitivity", {})

        alert = {
            "timestamp": datetime.fromtimestamp(now).isoformat(),
            "severity": verdict["severity"],
            "attack_type": details.get("attack_type", "Known_Threat"),
            "source": details.get("source", "intelligence_gate"),
            "src_ip": flow.get("src_ip", ""),
            "dst_ip": flow.get("dst_ip", ""),
            "dst_port": flow.get("dst_port", 0),
            "confidence": details.get("confidence", 0.99) * 100,
            "ml_score": 0.0,
            "ueba_score": 0.0,
            "rule_score": 0.0,
            "eta_score": verdict.get("eta_result", {}).get("eta_score", 0.0),
            "tag": "INTEL_GATE",
            "reasons": [verdict["reason"]],
            "identity": identity,
            "department": sensitivity.get("department", "") if sensitivity else "",
            "threat_intel": verdict.get("threat_hits", []),
            "ja3_match": details.get("ja3_hash", details.get("ioc_value", "")),
            "gates_passed": 0,
            "actual_label": "",
        }
        self.dispatcher.dispatch(alert)
        self._print_alert(alert)

    def _build_alert(self, flow, ml_result, ueba_result, rule_score,
                     rule_alerts, verdict, severity, tag, now,
                     policy_result=None,
                     peer_dev_score: float = 0.0,
                     peer_dev_reasons: Optional[List[str]] = None) -> dict:
        """Build enriched alert dict from all engine outputs."""
        identity = verdict.get("identity", {})
        sensitivity = verdict.get("sensitivity", {})
        eta_result = verdict.get("eta_result", {})

        reasons = list(ueba_result.get("reasons", []))
        for ra in rule_alerts:
            reasons.append(f"Rule: {ra.get('rule_name', '')}")
        if policy_result and policy_result.get("violation"):
            reasons = policy_result.get("reasons", []) + reasons
        if peer_dev_reasons:
            reasons = list(peer_dev_reasons) + reasons

        return {
            "timestamp": datetime.fromtimestamp(now).isoformat(),
            "severity": severity,
            "attack_type": ml_result.get("attack_type", ueba_result.get(
                "specialist_verdict", "Behavioral_Anomaly")),
            "source": ml_result.get("specialist_source", tag),
            "src_ip": flow.get("src_ip", ""),
            "dst_ip": flow.get("dst_ip", ""),
            "dst_port": flow.get("dst_port", 0),
            "confidence": ml_result.get("confidence", 0),
            "ml_score": ml_result.get("probability", 0),
            "ueba_score": ueba_result.get("anomaly_score", 0),
            "rule_score": rule_score,
            "eta_score": eta_result.get("eta_score", 0),
            "tag": tag,
            "reasons": reasons,
            "identity": identity,
            "department": sensitivity.get("department", "") if sensitivity else "",
            "threat_intel": verdict.get("threat_hits", []),
            "ja3_match": eta_result.get("ja3_match", {}).get("name", "") if eta_result.get("ja3_match") else "",
            "gates_passed": ueba_result.get("gates_passed", 0),
            "peer_deviation_score": round(peer_dev_score, 4),
            "actual_label": flow.get("actual_label", ""),
        }

    # ── Feature Extraction ────────────────────────────────────

    def _extract_features(self, flow: dict) -> List[float]:
        """Extract the full feature vector via FeatureNormalizer.

        Runs synonym mapping + derived-feature computation so Zeek flows
        get derived features (iat_cv, syn_ratio, bytes_per_packet, etc.)
        instead of zeros. Writes computed fields back into the flow dict;
        SentrixCascade re-derives its own 45-feature canonical vector from
        these raw fields using the frozen BaseIPFIXNormalizer math.
        """
        normalized = self.normalizer.normalize(flow)
        for k, v in normalized.items():
            if k not in flow:
                flow[k] = v
        return self.normalizer.to_vector(normalized)

    # ── Background Tasks ──────────────────────────────────────

    def _start_background_tasks(self):
        """Start periodic background tasks."""
        def ti_refresh():
            while self._running:
                time.sleep(3600)  # every hour
                if self._running:
                    try:
                        self.threat_intel.update_feeds()
                    except Exception as e:
                        log.error(f"TI refresh error: {e}")

        def save_state():
            while self._running:
                time.sleep(300)  # every 5 min
                if self._running:
                    try:
                        self.ueba.save_state()
                    except Exception as e:
                        log.error(f"State save error: {e}")

        def ueba_clock_tick():
            """
            Advance the UEBA observation counter by real elapsed time
            between ticks. Runs every 5 seconds. The counter is
            persistent in alerts.db → runtime_config, so restarts
            resume from where we left off (sans up to 5 seconds).

            Also: watch for a reset signal written by the dashboard
            (ueba_reset_signal config key). When a new value appears,
            wipe the UEBALong baselines; the counter itself was
            already zeroed by the dashboard, so this completes the
            "start over" action.
            """
            TICK = 5.0
            last = time.time()
            last_reset_signal = self.runtime_state.get_config(
                "ueba_reset_signal", ""
            ) or ""
            while self._running:
                time.sleep(TICK)
                if not self._running:
                    break
                try:
                    now_ts = time.time()
                    delta = max(0.0, now_ts - last)
                    last = now_ts
                    # Guard against huge deltas from wall-clock jumps
                    # (NTP sync, laptop sleep); cap at 2× the nominal
                    # tick so a resumed laptop can't vault the clock
                    # by an hour.
                    delta = min(delta, TICK * 2.0)
                    self.runtime_state.tick_ueba_clock(delta)

                    # Reset signal check; refresh the cache and
                    # compare against last observed value.
                    self.runtime_state.refresh()
                    sig = self.runtime_state.get_config(
                        "ueba_reset_signal", ""
                    ) or ""
                    if sig and sig != last_reset_signal:
                        log.info("UEBA reset signal received; wiping baselines")
                        self.ueba.reset_baselines()
                        last_reset_signal = sig
                except Exception as e:
                    log.error(f"UEBA clock tick error: {e}")

        def engine_stats_writer():
            """Every 10s, persist engine throughput / latency / counters to
            alerts.db::engine_stats. Dashboard /api/health reads the latest
            row. Creates the table lazily so older DBs are compatible."""
            import sqlite3 as _sq
            DB = str(_PROJECT / "alerts.db")
            try:
                _c = _sq.connect(DB, timeout=5)
                _c.execute("""
                    CREATE TABLE IF NOT EXISTS engine_stats (
                        timestamp             TEXT PRIMARY KEY,
                        flows_processed       INTEGER,
                        flows_per_sec         REAL,
                        layer1_immediate      INTEGER,
                        layer1_boosted        INTEGER,
                        layer2_attacks        INTEGER,
                        layer25_policy_violations INTEGER,
                        layer3_peer_deviation INTEGER,
                        total_alerts          INTEGER,
                        latency_p50_ms        REAL,
                        latency_p95_ms        REAL,
                        queue_depth           INTEGER,
                        uptime_seconds        REAL
                    )
                """)
                _c.execute("CREATE INDEX IF NOT EXISTS idx_engine_stats_ts "
                            "ON engine_stats(timestamp DESC)")
                _c.commit()
                _c.close()
            except Exception as e:
                log.error(f"engine_stats table init failed: {e}")

            TICK = 10.0
            while self._running:
                time.sleep(TICK)
                if not self._running:
                    break
                try:
                    s = self.stats
                    now_ts = time.time()
                    elapsed_since_last = max(now_ts - self._last_stats_write_ts, 0.001)
                    flows_delta = s.get("flows_processed", 0) - self._last_flows_processed
                    fps = flows_delta / elapsed_since_last
                    self._last_flows_processed = s.get("flows_processed", 0)
                    self._last_stats_write_ts = now_ts

                    # Latency percentiles from ring buffer
                    if len(self._latency_ms) > 0:
                        lats = sorted(self._latency_ms)
                        p50 = lats[len(lats) // 2]
                        p95 = lats[int(len(lats) * 0.95)]
                    else:
                        p50 = p95 = 0.0

                    # Queue depth; depends on capture source
                    q_depth = 0
                    try:
                        cap = getattr(self, "capture", None)
                        if cap is not None and hasattr(cap, "queue"):
                            q_depth = cap.queue.qsize()
                    except Exception:
                        pass

                    uptime = now_ts - self._start_time

                    _c = _sq.connect(DB, timeout=5)
                    _c.execute(
                        "INSERT OR REPLACE INTO engine_stats VALUES "
                        "(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            datetime.fromtimestamp(now_ts).isoformat(),
                            int(s.get("flows_processed", 0)),
                            round(fps, 2),
                            int(s.get("layer1_immediate", 0)),
                            int(s.get("layer1_boosted", 0)),
                            int(s.get("layer2_attacks", 0)),
                            int(s.get("layer25_policy_violations", 0)),
                            int(s.get("layer3_peer_deviation", 0)),
                            int(s.get("total_alerts", 0)),
                            round(p50, 3),
                            round(p95, 3),
                            int(q_depth),
                            round(uptime, 1),
                        ),
                    )
                    _c.commit()
                    # Prune; keep last ~24h of rows (1 row / 10s = ~8640/day)
                    _c.execute(
                        "DELETE FROM engine_stats WHERE timestamp < "
                        "datetime('now', '-2 days')"
                    )
                    _c.commit()
                    _c.close()
                except Exception as e:
                    log.warning(f"engine_stats writer: {e}")

        threading.Thread(target=ti_refresh, daemon=True).start()
        threading.Thread(target=save_state, daemon=True).start()
        threading.Thread(target=ueba_clock_tick, daemon=True,
                          name="ueba-clock-tick").start()
        threading.Thread(target=engine_stats_writer, daemon=True,
                          name="engine-stats").start()
        self.drift_monitor.start()

    # ── Console Output ────────────────────────────────────────

    def _print_alert(self, alert: dict):
        sev = alert["severity"]
        c = SEV_COLORS.get(sev, D)
        ts = alert["timestamp"][11:19] if len(alert["timestamp"]) > 11 else ""
        atype = alert.get("attack_type", "?")[:20]
        src = alert.get("src_ip", "?")
        tag = alert.get("tag", "")
        dept = alert.get("department", "")

        line = (f"  {col(ts, D):<20} "
                f"{col(f'[{sev}]', c):<22} "
                f"{col(atype, c):<24} "
                f"{src:<18} "
                f"{col(tag, c):<16} "
                f"{dept}")
        print(line)

        reasons = alert.get("reasons", [])
        if reasons:
            print(col(f"         > {reasons[0]}", D))
        ja3 = alert.get("ja3_match", "")
        if ja3:
            print(col(f"         > JA3: {ja3}", R))
        ti = alert.get("threat_intel", [])
        if ti:
            for h in ti[:2]:
                print(col(f"         > TI: {h.get('type','')} "
                         f"{h.get('value','')}", R))

    def _print_stats(self):
        s = self.stats
        elapsed = time.time() - self._start_time
        fps = s["flows_processed"] / max(elapsed, 1)
        print(col(f"\n  -- {s['flows_processed']:,} flows "
                  f"({fps:.0f}/s) | "
                  f"Alerts: {s['total_alerts']} "
                  f"(L1:{s['layer1_immediate']} "
                  f"ML:{s['layer2_attacks']} "
                  f"Policy:{s['layer25_policy_violations']} "
                  f"UEBA:{s['layer3_alerts']}) | "
                  f"WL:{s['layer1_whitelisted']} "
                  f"Boost:{s['layer1_boosted']} --\n", D))

    # ── Shutdown ──────────────────────────────────────────────

    def _shutdown(self):
        """Clean shutdown: save state, flush alerts, print summary."""
        print(col("\n  Shutting down...", Y))
        self._running = False
        self.capture.stop()
        self.dispatcher.flush()
        self.ueba.save_state()

        elapsed = time.time() - self._start_time
        s = self.stats
        fps = s["flows_processed"] / max(elapsed, 1)

        print(col(f"\n{'='*65}", G))
        print(col("  SENTRIX  -  SESSION COMPLETE", G))
        print(col(f"{'='*65}", G))
        print(f"  Flows processed    : {s['flows_processed']:,}")
        print(f"  Elapsed            : {elapsed:.1f}s ({fps:.0f} flows/sec)")
        print(f"  Total alerts       : {s['total_alerts']:,}")
        print(f"")
        print(f"  Layer 1 (Intel Gate):")
        print(f"    Whitelisted       : {s['layer1_whitelisted']:,}")
        print(f"    Immediate alerts  : {s['layer1_immediate']:,} (JA3/TI match)")
        print(f"    ETA boosted       : {s['layer1_boosted']:,}")
        print(f"  Layer 2 (ML Cascade):")
        print(f"    Attacks detected  : {s['layer2_attacks']:,}")
        print(f"  Layer 2.5 (Policy Engine):")
        print(f"    Policy violations : {s['layer25_policy_violations']:,}")
        print(f"  Layer 3 (UEBA v4):")
        print(f"    Alerts (7-gate)   : {s['layer3_alerts']:,}")
        print()

        self.intel_gate.print_summary()
        self.policy.print_summary()
        self.ueba.print_summary()
        self.dispatcher.print_summary()

        cap_stats = self.capture.get_stats()
        print(f"\n  Capture: mode={cap_stats['mode']}, "
              f"flows_read={cap_stats.get('flows_read', 0):,}")

        print(col(f"\n{'='*65}", G))
        print(col(f"  Alerts saved to: {self.dispatcher.db_path}", D))
        print(col(f"{'='*65}\n", G))

# ── Entry Point ───────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Sentrix Real-Time Detection Engine"
    )
    parser.add_argument("--mode", choices=["zeek", "csv"], default="csv",
                       help="Capture mode: zeek (live) or csv (replay)")
    parser.add_argument("--file", default="data/test.csv",
                       help="CSV file for replay mode")
    parser.add_argument("--rows", type=int, default=0,
                       help="Max rows to process (0=all)")
    parser.add_argument("--speed", type=float, default=0,
                       help="Flows/sec for replay (0=max)")
    parser.add_argument("--zeek-dir", default="/opt/zeek/logs/current",
                       help="Zeek log directory for live mode")
    args = parser.parse_args()

    if args.mode == "csv":
        engine = RealTimeEngine(
            capture_mode="csv",
            csv_file=args.file,
            max_rows=args.rows,
            speed=args.speed,
        )
    else:
        engine = RealTimeEngine(
            capture_mode="zeek",
            zeek_log_dir=args.zeek_dir,
        )

    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, lambda s, f: engine.stop())

    engine.start()

if __name__ == "__main__":
    main()
