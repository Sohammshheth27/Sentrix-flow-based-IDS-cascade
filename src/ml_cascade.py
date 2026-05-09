"""ML cascade for realtime_engine"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

_SRC = Path(__file__).resolve().parent
_PROJECT = _SRC.parent
from feature_helpers import extract_48, apply_temperature
from feature_normalizer import NUMERIC_FEATURES, N_NUMERIC

log = logging.getLogger("ml_cascade")

# Severity cutoffs on the fused final probability.
# Matches dashboard/alert_dispatch expectations.
SEV_THRESHOLDS = {
    "CRITICAL": 0.90,
    "HIGH":     0.75,
    "MEDIUM":   0.55,
    "LOW":      0.35,
}

def _prob_to_severity(p: float) -> str:
    if p >= SEV_THRESHOLDS["CRITICAL"]: return "CRITICAL"
    if p >= SEV_THRESHOLDS["HIGH"]:     return "HIGH"
    if p >= SEV_THRESHOLDS["MEDIUM"]:   return "MEDIUM"
    if p >= SEV_THRESHOLDS["LOW"]:      return "LOW"
    return "BENIGN"

class Phase3Cascade:
    """
    Phase-3 binary ensemble wrapped in the SpecialistCascade interface.
    """

    def __init__(self, models_dir: Path):
        self.models_dir = Path(models_dir)
        self.feature_names: List[str] = []   # sentinel: we self-extract
        self.n_features = N_NUMERIC

        self.ready = False
        self.scaler = None
        self.lgb = None
        self.xgb = None
        self.rf = None
        self.weights = {"lgb": 1 / 3, "xgb": 1 / 3, "rf": 1 / 3}
        self.temperature = 1.0
        self.apply_temp = False

        log.info("Loading Phase3Cascade ...")
        self._load()

    def _load(self) -> None:
        md = self.models_dir
        required = [
            "phase3_scaler.pkl",
            "phase3_bin_lgb.pkl",
            "phase3_bin_xgb.pkl",
            "phase3_bin_rf.pkl",
            "phase3_metadata.json",
            "phase3_temperature.json",
        ]
        for f in required:
            if not (md / f).exists():
                log.error(f"  Missing {f}; Phase3Cascade disabled")
                return

        try:
            self.scaler = joblib.load(md / "phase3_scaler.pkl")
            self.lgb = joblib.load(md / "phase3_bin_lgb.pkl")
            self.xgb = joblib.load(md / "phase3_bin_xgb.pkl")
            self.rf = joblib.load(md / "phase3_bin_rf.pkl")
            with open(md / "phase3_metadata.json") as f:
                meta = json.load(f)
            self.weights = meta["ensemble_weights"]
            with open(md / "phase3_temperature.json") as f:
                tmeta = json.load(f)
            self.temperature = float(tmeta["temperature"])
            self.apply_temp = bool(tmeta.get("apply_at_inference", False))
            self.ready = True
            log.info(
                f"  Phase3Cascade ready: "
                f"weights LGB={self.weights['lgb']:.2f} "
                f"XGB={self.weights['xgb']:.2f} RF={self.weights['rf']:.2f}  "
                f"T={self.temperature:.3f}  "
                f"apply_temp={self.apply_temp}"
            )
        except Exception as e:
            log.error(f"  Phase3Cascade load error: {e}")
            self.ready = False

    # ── Internal: vectorised inference ──────────────────────────────

    def _predict_proba(self, raw_flows: List[Dict]) -> np.ndarray:
        """Run the full Stage 1 ensemble on a batch of raw flow dicts."""
        if not self.ready or not raw_flows:
            return np.zeros(len(raw_flows), dtype=np.float32)

        df = pd.DataFrame(raw_flows)
        try:
            X = extract_48(df)
        except Exception as e:
            log.warning(f"extract_48 failed: {e}")
            return np.zeros(len(raw_flows), dtype=np.float32)
        X_sc = self.scaler.transform(X).astype(np.float32)

        p_lgb = self.lgb.predict_proba(X_sc)[:, 1]
        p_xgb = self.xgb.predict_proba(X_sc)[:, 1]
        p_rf = self.rf.predict_proba(X_sc)[:, 1]
        # Logit-space weighted average; matches retrain_phase3 training
        eps = 1e-7
        l_lgb = np.log(np.clip(p_lgb, eps, 1-eps) / (1 - np.clip(p_lgb, eps, 1-eps)))
        l_xgb = np.log(np.clip(p_xgb, eps, 1-eps) / (1 - np.clip(p_xgb, eps, 1-eps)))
        l_rf  = np.log(np.clip(p_rf,  eps, 1-eps) / (1 - np.clip(p_rf,  eps, 1-eps)))
        logit_avg = (self.weights["lgb"] * l_lgb
                     + self.weights["xgb"] * l_xgb
                     + self.weights["rf"] * l_rf)
        ens = 1.0 / (1.0 + np.exp(-logit_avg))

        if self.apply_temp:
            ens = apply_temperature(ens, self.temperature)
        return ens.astype(np.float32)

    # ── Public predict (SpecialistCascade-compatible) ───────────────

    def predict(
        self,
        features_batch: List[List[float]],
        raw_features_batch: Optional[List[Dict]] = None,
    ) -> Tuple[List[Dict], List[List[Dict]]]:
        """
        features_batch is ignored; the cascade re-extracts features from raw flows
        to guarantee train/infer parity.

        Returns (ml_results, specialist_results_per_flow).
        """
        n = len(features_batch) if features_batch else len(raw_features_batch or [])
        if n == 0:
            return [], []

        if not raw_features_batch:
            # No raw flows → return all-benign fallback.
            return [self._benign_result() for _ in range(n)], [[] for _ in range(n)]

        if not self.ready:
            return [self._benign_result() for _ in range(n)], [[] for _ in range(n)]

        probs = self._predict_proba(raw_features_batch)
        ml_results: List[Dict] = []
        spec_results: List[List[Dict]] = []

        for i, prob in enumerate(probs):
            p = float(prob)
            is_attack = p >= 0.50
            severity = _prob_to_severity(p) if is_attack else "BENIGN"
            attack_type = "Unclassified" if is_attack else "BENIGN"

            ml_results.append({
                "is_attack":          is_attack,
                "severity":           severity,
                "attack_type":        attack_type,
                "probability":        round(p, 6),
                "confidence":         round(p * 100 if is_attack else (1 - p) * 100, 2),
                "pred_class":         attack_type,
                "threshold":          0.50,
                "specialist_source":  "phase3_binary",
                "specialist_details": [],
            })
            # No specialist verdicts; binary detector only.
            spec_results.append([])

        return ml_results, spec_results

    def _benign_result(self) -> Dict:
        return {
            "is_attack":          False,
            "severity":           "BENIGN",
            "attack_type":        "BENIGN",
            "probability":        0.0,
            "confidence":         100.0,
            "pred_class":         "Benign",
            "threshold":          0.50,
            "specialist_source":  "phase3_binary",
            "specialist_details": [],
        }
