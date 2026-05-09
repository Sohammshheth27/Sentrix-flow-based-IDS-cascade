"""Confidence Gating + FP Reduction"""
import os
import sys
import json
import time
import threading
import numpy as np
import joblib
from pathlib import Path
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ── Severity Thresholds (tuned for low FP) ────────────────────
# These are HIGHER than the old thresholds to reduce false positives
CONF_CRITICAL = 0.95   # was 0.92; only alert CRITICAL when very sure
CONF_HIGH     = 0.85   # was 0.80
CONF_MEDIUM   = 0.70   # was 0.65
CONF_LOW      = 0.55   # was 0.63
CONF_GATE     = 0.55   # below this → always BENIGN regardless of model output

class Whitelist:
    """Contextual whitelist; known-good flows skip ML entirely."""

    def __init__(self, config_path: str = None):
        if config_path is None:
            config_path = str(_PROJECT_ROOT / "config" / "whitelist.json")
        self._pairs = set()       # (dst_ip, dst_port) tuples
        self._ports = set()       # always-benign ports
        self._trusted_src = set() # trusted source IPs
        self._load(config_path)

    def _load(self, path: str):
        try:
            with open(path) as f:
                cfg = json.load(f)
            for entry in cfg.get("ip_port_pairs", []):
                self._pairs.add((entry["dst_ip"], int(entry["dst_port"])))
            self._ports = set(cfg.get("dst_ports_always_benign", []))
            self._trusted_src = set(cfg.get("src_ips_trusted", []))
            print(f"[Whitelist] Loaded: {len(self._pairs)} IP:port pairs, "
                  f"{len(self._ports)} ports, {len(self._trusted_src)} trusted IPs")
        except FileNotFoundError:
            print(f"[Whitelist] No config at {path}; empty whitelist")
        except Exception as e:
            print(f"[Whitelist] Load error: {e}")

    def is_whitelisted(self, flow: dict) -> bool:
        dst_ip = flow.get("dst_ip", "")
        dst_port = int(flow.get("dst_port", 0) or 0)
        src_ip = flow.get("src_ip", "")

        # Check IP:port pairs
        if (dst_ip, dst_port) in self._pairs:
            return True
        # Check always-benign ports
        if dst_port in self._ports:
            return True
        # Check trusted source (infrastructure generating traffic)
        if src_ip in self._trusted_src:
            return True
        return False

class TemporalAggregator:
    """
    Per-IP sliding window aggregator.
    Only fires alerts when attack ratio exceeds threshold over a window.

    Reduces alert noise: 1 suspicious flow among 100 benign → no alert.
    """

    def __init__(self, window_sec: int = 60, alert_ratio: float = 0.15):
        self._window = window_sec
        self._alert_ratio = alert_ratio
        self._flows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._lock = threading.Lock()

    def record(self, src_ip: str, is_attack: bool, confidence: float,
               severity: str, now: float = None) -> Tuple[bool, float, str]:
        """
        Record a flow classification and decide whether to alert.

        Returns: (should_alert, window_attack_ratio, effective_severity)
        """
        if now is None:
            now = time.time()

        with self._lock:
            q = self._flows[src_ip]
            q.append((now, is_attack, confidence, severity))

            # Prune old entries
            cutoff = now - self._window
            while q and q[0][0] < cutoff:
                q.popleft()

            if not q:
                return False, 0.0, "BENIGN"

            # Compute attack ratio in window
            total = len(q)
            attacks = sum(1 for _, a, _, _ in q if a)
            ratio = attacks / total

            # Find max severity and confidence in window
            max_sev_rank = 0
            max_conf = 0.0
            sev_map = {"BENIGN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            rev_map = {0: "BENIGN", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}

            for _, a, c, s in q:
                if a:
                    rank = sev_map.get(s, 0)
                    if rank > max_sev_rank:
                        max_sev_rank = rank
                    if c > max_conf:
                        max_conf = c

            # Decision logic
            if not is_attack:
                # Current flow is benign; only alert if window is overwhelmingly attack
                if ratio > 0.50 and max_sev_rank >= 3:
                    return True, ratio, rev_map[max_sev_rank]
                return False, ratio, "BENIGN"

            # Current flow is attack
            if severity == "CRITICAL" and confidence > CONF_CRITICAL:
                # CRITICAL with high confidence; always alert immediately
                return True, ratio, "CRITICAL"

            if ratio >= self._alert_ratio:
                # Enough attack flows in window; alert
                return True, ratio, severity

            if total < 5:
                # Too few flows to judge; let it through if confident
                return confidence > CONF_HIGH, ratio, severity

            # Attack ratio too low; suppress (likely isolated FP)
            return False, ratio, "BENIGN"

    def get_ip_stats(self, src_ip: str) -> dict:
        with self._lock:
            q = self._flows.get(src_ip, deque())
            if not q:
                return {"flows": 0, "attack_ratio": 0.0}
            total = len(q)
            attacks = sum(1 for _, a, _, _ in q if a)
            return {
                "flows": total,
                "attack_ratio": round(attacks / total, 3),
                "attacks": attacks,
            }

class LiteModel:
    """
    Lightweight LightGBM specialist (Stage 1 binary + Stage 2 attack type).
    Loads the models trained by train_unified_v2.py.
    """

    def __init__(self, models_dir: str):
        self.loaded = False
        self._lock = threading.Lock()
        md = Path(models_dir)

        try:
            meta_path = md / "lite_metadata.json"
            if not meta_path.exists():
                print("[LiteModel] No lite_metadata.json; skipping")
                return

            with open(meta_path) as f:
                self.meta = json.load(f)

            self.binary_model = joblib.load(md / "lite_binary.pkl")
            self.attack_model = joblib.load(md / "lite_attack.pkl")
            self.scaler = joblib.load(md / "lite_scaler.pkl")
            self.label_encoder = joblib.load(md / "lite_label_encoder.pkl")
            self.feature_names = self.meta["feature_names"]
            self.n_features = self.meta["n_features"]
            self.attack_classes = list(self.label_encoder.classes_)
            self.loaded = True
            print(f"[LiteModel] Loaded: {self.n_features} features, "
                  f"{len(self.attack_classes)} attack classes")
            print(f"[LiteModel] Attacks: {self.attack_classes}")
        except Exception as e:
            print(f"[LiteModel] Load failed: {e}")

    def predict(self, features: np.ndarray) -> List[dict]:
        """
        Predict on a batch of feature vectors (already in unified 31-feature format).
        Returns list of {prediction, confidence, is_attack, severity, source}.
        """
        if not self.loaded:
            return [{"prediction": "BENIGN", "confidence": 0.0,
                     "is_attack": False, "severity": "BENIGN",
                     "source": "lite"}] * len(features)

        with self._lock:
            X = self.scaler.transform(features).astype(np.float32)

            # Stage 1: Binary
            bin_proba = self.binary_model.predict_proba(X)
            bin_pred = (bin_proba[:, 1] > 0.5).astype(int)

            results = []
            # Stage 2: Attack type (only on predicted attacks)
            attack_idx = np.where(bin_pred == 1)[0]
            atk_pred = None
            atk_proba = None
            if len(attack_idx) > 0:
                atk_proba_full = self.attack_model.predict_proba(X[attack_idx])
                atk_pred = self.attack_model.predict(X[attack_idx])

            atk_i = 0
            for i in range(len(features)):
                if bin_pred[i] == 0:
                    # Benign
                    conf = float(bin_proba[i, 0])
                    results.append({
                        "prediction": "BENIGN",
                        "confidence": round(conf, 4),
                        "is_attack": False,
                        "severity": "BENIGN",
                        "source": "lite",
                    })
                else:
                    # Attack
                    if atk_pred is not None and atk_i < len(atk_pred):
                        label = str(self.label_encoder.inverse_transform([atk_pred[atk_i]])[0])
                        conf_atk = float(atk_proba_full[atk_i].max())
                        conf_bin = float(bin_proba[i, 1])
                        # Combined confidence = binary confidence * attack confidence
                        conf = conf_bin * conf_atk
                        atk_i += 1
                    else:
                        label = "Unknown"
                        conf = float(bin_proba[i, 1])

                    severity = self._conf_to_severity(conf)
                    results.append({
                        "prediction": label,
                        "confidence": round(conf, 4),
                        "is_attack": True,
                        "severity": severity,
                        "source": "lite",
                    })

            return results

    def _conf_to_severity(self, conf: float) -> str:
        if conf >= CONF_CRITICAL: return "CRITICAL"
        if conf >= CONF_HIGH:     return "HIGH"
        if conf >= CONF_MEDIUM:   return "MEDIUM"
        if conf >= CONF_LOW:      return "LOW"
        return "BENIGN"

class ConfidenceEngine:
    """
    Main confidence-gated ensemble engine.

    Combines outputs from multiple specialists using confidence-based
    arbitration. The most confident specialist wins.

    Integrates whitelist and temporal aggregation for FP reduction.
    """

    def __init__(self, models_dir: str = None):
        if models_dir is None:
            models_dir = str(_PROJECT_ROOT / "models")

        self.whitelist = Whitelist()
        self.aggregator = TemporalAggregator(window_sec=60, alert_ratio=0.15)
        self.lite = LiteModel(models_dir)

        self._sev_rank = {"BENIGN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

        # Stats
        self.stats = {
            "total_flows": 0,
            "whitelisted": 0,
            "gated_benign": 0,     # below confidence gate
            "aggregator_suppressed": 0,
            "alerts_fired": 0,
            "by_source": defaultdict(int),
        }
        self._lock = threading.Lock()

        print("[ConfEngine] Initialized")
        print(f"[ConfEngine] Thresholds: CRIT>{CONF_CRITICAL} HIGH>{CONF_HIGH} "
              f"MED>{CONF_MEDIUM} LOW>{CONF_LOW} GATE>{CONF_GATE}")

    def classify(self, flow: dict, ml_result: dict,
                 ueba_score: float = 0.0, ueba_ready: bool = False,
                 rule_score: float = 0.0) -> dict:
        """
        Confidence-gated classification of a single flow.

        Args:
            flow: Raw flow dict (src_ip, dst_ip, dst_port, bytes, etc.)
            ml_result: Output from existing InProcessML (probability, attack_type, severity, is_attack)
            ueba_score: UEBA anomaly score (0-1)
            ueba_ready: Whether UEBA has baseline for this device
            rule_score: Rules engine score (0-1)

        Returns:
            dict with: severity, confidence, attack_type, is_attack,
                       source, gated, whitelisted, window_ratio
        """
        self.stats["total_flows"] += 1
        src_ip = flow.get("src_ip", "")
        now = time.time()

        # ── Step 1: Whitelist check ────────────────────────────
        if self.whitelist.is_whitelisted(flow):
            self.stats["whitelisted"] += 1
            # Schema v2 (2026-04-27): attack_type=None when verdict is benign.
            # `attack_type` is reserved for the model's CLASS LABEL when an
            # attack is identified; benign verdicts don't have a class.
            return {
                "severity": "BENIGN", "confidence": 1.0,
                "attack_type": None, "verdict": "benign-whitelist",
                "is_attack": False, "source": "whitelist", "gated": False,
                "whitelisted": True, "window_ratio": 0.0,
            }

        # ── Step 2: Collect specialist opinions ────────────────
        opinions = []

        # Opinion 1: Existing ML ensemble (Original + UNSW)
        ml_conf = float(ml_result.get("probability", 0))
        ml_type = ml_result.get("attack_type", "BENIGN")
        ml_is_attack = ml_result.get("is_attack", False)
        if ml_is_attack and ml_conf >= CONF_GATE:
            opinions.append({
                "prediction": ml_type,
                "confidence": ml_conf,
                "severity": self._conf_to_severity(ml_conf),
                "source": "ml_ensemble",
            })

        # Opinion 2: Lite model (if loaded)
        # Note: Lite model needs unified features which aren't available here
        # In full integration, you'd pass unified features. For now, skip.

        # Opinion 3: UEBA behavioral score
        if ueba_ready and ueba_score > 0.5:
            ueba_conf = min(ueba_score, 0.95)
            opinions.append({
                "prediction": "Behavioral_Anomaly",
                "confidence": ueba_conf,
                "severity": self._conf_to_severity(ueba_conf),
                "source": "ueba",
            })

        # Opinion 4: Rules engine
        if rule_score >= 0.65:
            opinions.append({
                "prediction": "Rule_Match",
                "confidence": min(rule_score, 1.0),
                "severity": "CRITICAL" if rule_score >= 0.85 else "HIGH",
                "source": "rules",
            })

        # ── Step 3: Confidence arbitration ─────────────────────
        if not opinions:
            # No specialist thinks it's an attack
            self.aggregator.record(src_ip, False, 0.0, "BENIGN", now)
            return {
                "severity": "BENIGN", "confidence": 1.0 - ml_conf,
                "attack_type": None, "verdict": "benign-consensus",
                "is_attack": False, "source": "consensus", "gated": False,
                "whitelisted": False, "window_ratio": 0.0,
            }

        # Pick the most confident specialist
        best = max(opinions, key=lambda o: o["confidence"])

        # ── Step 4: Confidence gate ────────────────────────────
        if best["confidence"] < CONF_GATE:
            self.stats["gated_benign"] += 1
            self.aggregator.record(src_ip, False, best["confidence"], "BENIGN", now)
            return {
                "severity": "BENIGN", "confidence": best["confidence"],
                "attack_type": None, "verdict": "benign-gated",
                "is_attack": False, "source": f"gated({best['source']})",
                "gated": True, "whitelisted": False, "window_ratio": 0.0,
            }

        # ── Step 5: Multi-engine agreement boost ───────────────
        # If multiple specialists agree, boost confidence
        agreeing = sum(1 for o in opinions if o["severity"] != "BENIGN")
        if agreeing >= 2:
            # Two or more engines agree → boost
            best["confidence"] = min(best["confidence"] * 1.1, 1.0)
            best["severity"] = self._conf_to_severity(best["confidence"])

        if agreeing >= 3:
            # All three agree → high confidence
            best["confidence"] = min(best["confidence"] * 1.15, 1.0)
            best["severity"] = self._conf_to_severity(best["confidence"])

        # ── Step 6: Temporal aggregation ───────────────────────
        should_alert, ratio, eff_severity = self.aggregator.record(
            src_ip, True, best["confidence"], best["severity"], now
        )

        if not should_alert:
            self.stats["aggregator_suppressed"] += 1
            # Suppressed by aggregator; flow had specialist agreement but
            # was rate-limited. Verdict = benign because we're choosing not
            # to alert; the prediction (best["prediction"]) is informational.
            return {
                "severity": "BENIGN",
                "confidence": best["confidence"],
                "attack_type": None,                         # suppressed → no class
                "verdict": "benign-suppressed",
                "predicted_class": best["prediction"],       # what model said
                "is_attack": False,
                "source": f"suppressed({best['source']})",
                "gated": False, "whitelisted": False,
                "window_ratio": ratio,
            }

        # ── Step 7: Fire alert ─────────────────────────────────
        self.stats["alerts_fired"] += 1
        self.stats["by_source"][best["source"]] += 1

        return {
            "severity": eff_severity,
            "confidence": best["confidence"],
            "attack_type": best["prediction"],         # the model's class label
            "verdict": "attack",
            "is_attack": True,
            "source": best["source"],
            "gated": False, "whitelisted": False,
            "window_ratio": ratio,
            "agreeing_engines": agreeing,
        }

    def _conf_to_severity(self, conf: float) -> str:
        if conf >= CONF_CRITICAL: return "CRITICAL"
        if conf >= CONF_HIGH:     return "HIGH"
        if conf >= CONF_MEDIUM:   return "MEDIUM"
        if conf >= CONF_LOW:      return "LOW"
        return "BENIGN"

    def get_stats(self) -> dict:
        return {
            **self.stats,
            "by_source": dict(self.stats["by_source"]),
            "whitelist_entries": len(self.whitelist._pairs),
            "fp_reduction_rate": round(
                (self.stats["whitelisted"] + self.stats["gated_benign"] +
                 self.stats["aggregator_suppressed"]) /
                max(self.stats["total_flows"], 1) * 100, 1
            ),
        }

    def print_summary(self):
        s = self.get_stats()
        print("\n" + "=" * 60)
        print("  CONFIDENCE ENGINE SUMMARY")
        print("=" * 60)
        print(f"  Total flows       : {s['total_flows']:,}")
        print(f"  Whitelisted       : {s['whitelisted']:,}")
        print(f"  Gated (low conf)  : {s['gated_benign']:,}")
        print(f"  Suppressed (agg)  : {s['aggregator_suppressed']:,}")
        print(f"  Alerts fired      : {s['alerts_fired']:,}")
        print(f"  FP reduction      : {s['fp_reduction_rate']}%")
        if s["by_source"]:
            print(f"  Alert sources:")
            for src, cnt in sorted(s["by_source"].items(), key=lambda x: -x[1]):
                print(f"    {src:<20} {cnt:>6,}")
        print("=" * 60)
