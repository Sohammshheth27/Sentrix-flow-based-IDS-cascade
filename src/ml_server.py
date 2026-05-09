"""v4  (Binary Gate + Specialist Routing)"""
import os
import sys
import io
import json
import time
import logging
import threading
import numpy as np

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

import joblib
import onnxruntime as ort
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s; %(message)s"
)
log = logging.getLogger("ml_server")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = Path(os.environ.get("MODELS_DIR", str(_PROJECT_ROOT / "models")))

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "BENIGN": 0}

def _prob_to_severity(prob: float) -> str:
    if prob >= 0.95: return "CRITICAL"
    if prob >= 0.85: return "HIGH"
    if prob >= 0.70: return "MEDIUM"
    if prob >= 0.55: return "LOW"
    return "BENIGN"

# ═══════════════════════════════════════════════════════════════
#  ONNX SPECIALIST MODEL
# ═══════════════════════════════════════════════════════════════

class ONNXSpecialist:
    """Single ONNX specialist with scaler and metadata."""

    def __init__(self, name: str, onnx_path: Path, meta_path: Path,
                 scaler_path: Path):
        self.name = name
        self.loaded = False
        self.session = None
        self.scaler = None
        self.meta = {}
        self.features: List[str] = []
        self.classes: List[str] = []
        self.n_features = 0
        self.benign_idx = 0
        self.input_name = ""
        self._lock = threading.Lock()

        try:
            with open(meta_path) as f:
                self.meta = json.load(f)
            self.features = self.meta["features"]
            self.n_features = self.meta["n_features"]
            self.classes = self.meta["classes"]
            self.benign_idx = self.meta.get("benign_idx", 0)

            self.scaler = joblib.load(scaler_path)

            opts = ort.SessionOptions()
            opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            opts.intra_op_num_threads = 2
            opts.inter_op_num_threads = 1
            self.session = ort.InferenceSession(str(onnx_path), opts)
            self.input_name = self.session.get_inputs()[0].name

            self.loaded = True
            size_mb = onnx_path.stat().st_size / (1024 * 1024)
            log.info(f"  [{name}] Loaded: {self.n_features} feat, "
                     f"{len(self.classes)} classes, {size_mb:.1f}MB")
        except Exception as e:
            log.warning(f"  [{name}] Load failed: {e}")

    def predict_batch(self, X: np.ndarray) -> List[dict]:
        """Predict on batch of RAW (unscaled) feature vectors."""
        if not self.loaded:
            return [self._benign()] * len(X)

        with self._lock:
            X_sc = self.scaler.transform(X).astype(np.float32)
            onnx_out = self.session.run(None, {self.input_name: X_sc})
            labels = np.array(onnx_out[0])
            proba_maps = onnx_out[1]

            results = []
            for i in range(len(X)):
                proba_dict = proba_maps[i]
                probs = np.array([proba_dict.get(c, 0.0)
                                  for c in range(len(self.classes))],
                                 dtype=np.float32)
                pred_idx = int(np.argmax(probs))
                pred_label = self.classes[pred_idx]
                confidence = float(probs[pred_idx])
                benign_prob = float(probs[self.benign_idx])
                attack_prob = 1.0 - benign_prob
                is_attack = pred_label != "Benign"

                results.append({
                    "label": pred_label,
                    "confidence": confidence,
                    "attack_prob": attack_prob,
                    "benign_prob": benign_prob,
                    "is_attack": is_attack,
                    "severity": _prob_to_severity(attack_prob) if is_attack else "BENIGN",
                    "source": self.name,
                    "probabilities": probs.tolist(),
                })
            return results

    def predict_single(self, X: np.ndarray) -> dict:
        """Predict on single sample (1, n_features)."""
        return self.predict_batch(X)[0]

    def _benign(self) -> dict:
        return {"label": "Benign", "confidence": 1.0, "attack_prob": 0.0,
                "benign_prob": 1.0, "is_attack": False, "severity": "BENIGN",
                "source": self.name, "probabilities": []}

# ═══════════════════════════════════════════════════════════════
#  SPECIALIST CASCADE: Binary Gate → Specialist Routing
# ═══════════════════════════════════════════════════════════════

class SpecialistCascade:
    """
    Two-stage cascade:
      Stage 1: Binary LightGBM (Benign/Attack); fast gate
      Stage 2: Route to best specialist ONNX for attack classification

    This replaces the old lite_attack.pkl Stage 2 with domain-specific
    specialist models that have higher precision per attack type.
    """

    # Feature aliases for routing flows to the right specialist
    _CIC_KEYS = {"Dst Port", "Flow Duration", "Tot Fwd Pkts",
                 "Flow Byts/s", "SYN Flag Cnt", "Pkt Len Mean"}
    _BOTNET_KEYS = {"Dur", "TotPkts", "TotBytes", "SrcBytes"}
    _IOT_KEYS = {"tcp.flags", "tcp.dstport", "tcp.len", "udp.port"}

    _ALIASES = {
        "Dst Port": ["dst_port", "Dport", "tcp.dstport"],
        "Protocol": ["protocol", "Proto_num"],
        "Flow Duration": ["duration", "Dur"],
        "Tot Fwd Pkts": ["TotPkts", "total_pkts"],
        "TotLen Fwd Pkts": ["fwd_bytes", "SrcBytes", "total_bytes"],
        "Flow Byts/s": ["bytes_per_sec", "BytesPerSec"],
        "SYN Flag Cnt": ["syn_flag", "tcp.connection.syn"],
        "RST Flag Cnt": ["rst_flag", "tcp.connection.rst"],
        "ACK Flag Cnt": ["ack_flag", "tcp.flags.ack"],
        "Pkt Len Mean": ["pkt_size_avg", "BytesPerPkt"],
        "Pkt Size Avg": ["pkt_size_avg", "BytesPerPkt"],
        "Dur": ["duration", "Flow Duration"],
        "Dport": ["dst_port", "Dst Port", "tcp.dstport"],
        "TotPkts": ["Tot Fwd Pkts", "total_pkts"],
        "TotBytes": ["total_bytes", "TotLen Fwd Pkts"],
        "SrcBytes": ["fwd_bytes", "TotLen Fwd Pkts"],
        "BytesPerPkt": ["pkt_size_avg", "Pkt Len Mean"],
        "BytesPerSec": ["bytes_per_sec", "Flow Byts/s"],
        "tcp.dstport": ["dst_port", "Dst Port", "Dport"],
        "tcp.flags.ack": ["ack_flag", "ACK Flag Cnt"],
        "tcp.len": ["pkt_size_avg"],
        "udp.port": ["dst_port"],
    }

    def __init__(self, models_dir: Path):
        log.info("Loading SpecialistCascade...")

        # Stage 1: Binary gate
        self.binary_model = None
        self.scaler = None
        self.binary_loaded = False
        self.feature_names: List[str] = []
        self.n_features = 0

        try:
            meta_path = models_dir / "lite_metadata.json"
            with open(meta_path) as f:
                meta = json.load(f)
            self.feature_names = meta["feature_names"]
            self.n_features = meta["n_features"]
            self.binary_model = joblib.load(models_dir / "lite_binary.pkl")
            self.scaler = joblib.load(models_dir / "lite_scaler.pkl")
            self.binary_loaded = True
            log.info(f"  [Binary Gate] Loaded: {self.n_features} features")
        except Exception as e:
            log.warning(f"  [Binary Gate] Load failed: {e}")

        # Stage 2: Specialist models
        self.specialists: Dict[str, ONNXSpecialist] = {}
        spec_configs = [
            # spec1/spec2: universal-32 variants; measurably better F1 and
            # eliminate the Argus/Zeek train/infer schema mismatch on spec2.
            # spec3: native-41 retained; its IoT protocol features (mqtt.*,
            # mbtcp.*, tcp.flags.*) cannot be reconstructed from the universal
            # flow schema and the uni variant loses ~22pts F1.
            ("spec1_cic", "spec1_cic_uni.onnx", "spec1_cic_uni_meta.json", "spec1_cic_uni_scaler.pkl"),
            ("spec2_botnet", "spec2_botnet_uni.onnx", "spec2_botnet_uni_meta.json", "spec2_botnet_uni_scaler.pkl"),
            ("spec3_iot", "spec3_iot.onnx", "spec3_meta.json", "spec3_scaler.pkl"),
        ]
        for name, onnx, meta, scaler in spec_configs:
            self.specialists[name] = ONNXSpecialist(
                name, models_dir / onnx, models_dir / meta, models_dir / scaler)

        loaded = sum(1 for s in self.specialists.values() if s.loaded)
        log.info(f"  [Specialists] {loaded}/3 loaded")

        # Collect all attack classes
        all_classes = set()
        for s in self.specialists.values():
            if s.loaded:
                all_classes.update(c for c in s.classes if c != "Benign")
        self.all_attack_classes = sorted(all_classes)
        log.info(f"  [Cascade] Total attack classes: {len(self.all_attack_classes)}")
        log.info(f"  [Cascade] Ready: Binary Gate -> 3 Specialist Routing")

    def predict(self, features_batch: List[List[float]],
                raw_features_batch: List[dict] = None
                ) -> Tuple[List[dict], List[List[dict]]]:
        """
        Classify a batch of flows through the full cascade.

        Args:
            features_batch: List of 31-dim feature vectors (for binary gate)
            raw_features_batch: Optional list of raw flow dicts (for specialist routing).
                               If None, specialists are skipped for attack type :
                               binary gate still classifies benign/attack.

        Returns:
            (ml_results, specialist_results_per_flow)

            ml_results: List of pipeline-compatible dicts:
                {is_attack, severity, attack_type, probability, confidence,
                 pred_class, threshold, specialist_source, specialist_details}

            specialist_results_per_flow: List of lists; each inner list contains
                the raw specialist verdicts for that flow (passed to UEBA v4).
                Empty list for benign flows.
        """
        if not self.binary_loaded:
            n = len(features_batch)
            return ([self._benign_result()] * n, [[]] * n)

        X = np.array(features_batch, dtype=np.float32)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        X_sc = self.scaler.transform(X).astype(np.float32)

        # ── Stage 1: Binary gate ──────────────────────────────
        bin_proba = self.binary_model.predict_proba(X_sc)
        bin_pred = (bin_proba[:, 1] > 0.50).astype(int)

        ml_results = []
        specialist_results = []

        # ── Stage 2: Route attacks to specialists ─────────────
        for i in range(len(X)):
            if bin_pred[i] == 0:
                # BENIGN; fast path, no specialist needed
                conf = float(bin_proba[i, 0])
                ml_results.append({
                    "is_attack": False,
                    "severity": "BENIGN",
                    "attack_type": "BENIGN",
                    "probability": round(1.0 - conf, 6),
                    "confidence": round(conf * 100, 2),
                    "pred_class": "Benign",
                    "threshold": 0.50,
                    "specialist_source": "",
                    "specialist_details": [],
                })
                specialist_results.append([])
            else:
                # ATTACK; route to specialists
                bin_conf = float(bin_proba[i, 1])
                raw_flow = raw_features_batch[i] if raw_features_batch else None
                spec_verdicts = self._route_to_specialists(X[i], raw_flow)
                specialist_results.append(spec_verdicts)

                if spec_verdicts:
                    result = self._weighted_consensus(
                        bin_conf, spec_verdicts)
                    result["specialist_details"] = spec_verdicts
                    ml_results.append(result)
                else:
                    # No specialist could run (missing features)
                    severity = _prob_to_severity(bin_conf)
                    ml_results.append({
                        "is_attack": True,
                        "severity": severity,
                        "attack_type": "Unclassified",
                        "probability": round(bin_conf, 6),
                        "confidence": round(bin_conf * 100, 2),
                        "pred_class": "Unclassified",
                        "threshold": 0.50,
                        "specialist_source": "binary_only",
                        "specialist_details": [],
                    })

        return ml_results, specialist_results

    def _weighted_consensus(self, bin_conf: float,
                            spec_verdicts: List[dict]) -> dict:
        """
        Weighted consensus across specialist verdicts.

        4 cases:
          1. Multiple specialists agree on SAME attack type  → BOOST
          2. Multiple specialists say ATTACK, DIFFERENT types → DAMPEN
          3. One specialist says ATTACK, others say BENIGN    → cautious
          4. ALL specialists say BENIGN despite binary ATTACK → downgrade
        """
        attacking = [v for v in spec_verdicts
                     if v["is_attack"] and v["confidence"] >= 0.50]
        n_attacking = len(attacking)
        n_total = len(spec_verdicts)

        # ── CASE 4: All specialists say BENIGN ───────────────
        if n_attacking == 0:
            # Specialists unanimously disagree with binary gate
            # Trust specialists; strong downgrade
            return {
                "is_attack": True,
                "severity": "LOW",
                "attack_type": "Unknown",
                "probability": round(bin_conf * 0.40, 6),
                "confidence": round(bin_conf * 40, 2),
                "pred_class": "Unknown",
                "threshold": 0.50,
                "specialist_source": "none_agreed",
            }

        best = max(attacking, key=lambda v: v["confidence"])

        # ── CASE 3: Single attacker, others benign ───────────
        if n_attacking == 1:
            n_benign = sum(1 for v in spec_verdicts if not v["is_attack"])
            if n_benign >= 1:
                # One attack vs one+ benign; cautious, slight dampen
                combined = bin_conf * best["confidence"] * 0.90
            else:
                # Only one specialist ran and it says attack
                combined = bin_conf * best["confidence"]

            severity = _prob_to_severity(combined)
            return {
                "is_attack": True,
                "severity": severity,
                "attack_type": best["label"],
                "probability": round(combined, 6),
                "confidence": round(combined * 100, 2),
                "pred_class": best["label"],
                "threshold": 0.50,
                "specialist_source": best["source"],
            }

        # Multiple specialists say ATTACK; check agreement
        attack_labels = [v["label"] for v in attacking]
        unique_labels = set(attack_labels)

        # ── CASE 1: Multiple agree on SAME attack type ───────
        if len(unique_labels) == 1:
            # Full consensus; strong boost
            avg_conf = sum(v["confidence"] for v in attacking) / n_attacking
            # Use max confidence × consensus boost
            # 2 agree → ×1.15, 3 agree → ×1.25
            boost = 1.0 + (n_attacking * 0.10) + 0.05
            combined = bin_conf * min(best["confidence"] * boost, 1.0)
            severity = _prob_to_severity(combined)
            sources = "+".join(v["source"] for v in attacking)
            return {
                "is_attack": True,
                "severity": severity,
                "attack_type": best["label"],
                "probability": round(combined, 6),
                "confidence": round(combined * 100, 2),
                "pred_class": best["label"],
                "threshold": 0.50,
                "specialist_source": f"consensus({sources})",
            }

        # ── CASE 2: Multiple attack, DIFFERENT types ─────────
        # Disagreement; use highest confidence but dampen
        combined = bin_conf * best["confidence"] * 0.85
        severity = _prob_to_severity(combined)
        return {
            "is_attack": True,
            "severity": severity,
            "attack_type": best["label"],
            "probability": round(combined, 6),
            "confidence": round(combined * 100, 2),
            "pred_class": best["label"],
            "threshold": 0.50,
            "specialist_source": f"split({best['source']})",
        }

    def _route_to_specialists(self, feature_vec: np.ndarray,
                               raw_flow: dict = None) -> List[dict]:
        """Route a single flow to applicable specialists."""
        results = []
        available = set(raw_flow.keys()) if raw_flow else set()

        for name, model in self.specialists.items():
            if not model.loaded:
                continue

            X = self._extract_specialist_features(model, raw_flow, available)
            if X is not None:
                pred = model.predict_single(X)
                results.append(pred)

        # Fallback: if no specialist matched on raw features,
        # try all specialists with zero-padded features
        if not results:
            for name, model in self.specialists.items():
                if model.loaded:
                    zeros = np.zeros((1, model.n_features), dtype=np.float32)
                    pred = model.predict_single(zeros)
                    results.append(pred)

        return results

    def _extract_specialist_features(self, model: ONNXSpecialist,
                                      raw_flow: dict,
                                      available: set) -> Optional[np.ndarray]:
        """Extract features for a specialist from raw flow dict."""
        if raw_flow is None:
            return None

        features = []
        missing = 0
        for feat_name in model.features:
            val = raw_flow.get(feat_name)
            if val is None:
                # Try aliases
                for alias in self._ALIASES.get(feat_name, []):
                    val = raw_flow.get(alias)
                    if val is not None:
                        break
            if val is None:
                features.append(0.0)
                missing += 1
            else:
                try:
                    features.append(float(val))
                except (ValueError, TypeError):
                    features.append(0.0)
                    missing += 1

        if missing > model.n_features * 0.5:
            return None

        return np.array(features, dtype=np.float32).reshape(1, -1)

    def _benign_result(self) -> dict:
        return {
            "is_attack": False, "severity": "BENIGN",
            "attack_type": "BENIGN", "probability": 0.0,
            "confidence": 100.0, "pred_class": "Benign",
            "threshold": 0.50, "specialist_source": "",
            "specialist_details": [],
        }

    def get_info(self) -> dict:
        specs = {n: s.loaded for n, s in self.specialists.items()}
        return {
            "binary_loaded": self.binary_loaded,
            "n_features": self.n_features,
            "feature_names": self.feature_names,
            "specialists": specs,
            "total_attack_classes": len(self.all_attack_classes),
            "all_attack_classes": self.all_attack_classes,
        }

# ═══════════════════════════════════════════════════════════════
#  GLOBALS + FASTAPI
# ═══════════════════════════════════════════════════════════════

ENGINE: Optional[SpecialistCascade] = None

class FlowFeatures(BaseModel):
    features: List[float] = Field(..., min_length=1, max_length=200)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    flow_id: Optional[str] = None
    timestamp: Optional[str] = None

class BatchRequest(BaseModel):
    flows: List[FlowFeatures] = Field(..., min_length=1, max_length=256)

class PredictionResult(BaseModel):
    is_attack: bool
    severity: str
    attack_type: str
    probability: float
    confidence: float
    pred_class: str
    threshold: float
    specialist_source: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    flow_id: Optional[str] = None
    latency_ms: Optional[float] = None

class BatchResult(BaseModel):
    predictions: List[PredictionResult]
    batch_size: int
    total_attacks: int
    latency_ms: float
    attacks_found: List[PredictionResult]

class HealthResponse(BaseModel):
    status: str
    models_loaded: dict
    config: dict
    server_time: str
    uptime_s: float

_start_time = time.time()

def _align_features(features: List[float], n: int) -> np.ndarray:
    arr = np.array(features, dtype=np.float32)
    if len(arr) < n:
        arr = np.pad(arr, (0, n - len(arr)))
    elif len(arr) > n:
        arr = arr[:n]
    return arr

@asynccontextmanager
async def lifespan(app: FastAPI):
    global ENGINE
    log.info("=" * 60)
    log.info("  IDS ML SERVER v4.0; Binary Gate + Specialist Routing")
    log.info("=" * 60)
    ENGINE = SpecialistCascade(MODELS_DIR)
    log.info("Server ready")
    yield
    log.info("Server shutting down")

app = FastAPI(
    title="Sentrix ML Server v4 (Specialist Cascade)",
    description=(
        "Binary LightGBM gate + 3 Specialist ONNX routing.\n"
        "No TensorFlow, no sklearn RF, no lite_attack."
    ),
    version="4.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

@app.get("/health", response_model=HealthResponse)
async def health():
    if ENGINE is None:
        raise HTTPException(503, "Models not loaded yet")
    info = ENGINE.get_info()
    return HealthResponse(
        status="ready",
        models_loaded={
            "binary_gate": info["binary_loaded"],
            **info["specialists"],
        },
        config={
            "n_features": info["n_features"],
            "total_attack_classes": info["total_attack_classes"],
            "threshold": 0.50,
            "architecture": "Binary Gate -> 3 Specialist ONNX Routing",
        },
        server_time=datetime.utcnow().isoformat() + "Z",
        uptime_s=round(time.time() - _start_time, 1),
    )

@app.post("/predict", response_model=PredictionResult)
async def predict_single(flow: FlowFeatures):
    if ENGINE is None:
        raise HTTPException(503, "Models not loaded")
    t0 = time.perf_counter()
    n = ENGINE.n_features
    feat = np.nan_to_num(_align_features(flow.features, n),
                         nan=0.0, posinf=0.0, neginf=0.0)
    ml_results, _ = ENGINE.predict([feat.tolist()])
    result = ml_results[0]
    latency = round((time.perf_counter() - t0) * 1000, 3)
    return PredictionResult(
        **{k: v for k, v in result.items() if k != "specialist_details"},
        src_ip=flow.src_ip, dst_ip=flow.dst_ip,
        src_port=flow.src_port, dst_port=flow.dst_port,
        protocol=flow.protocol, flow_id=flow.flow_id,
        latency_ms=latency,
    )

@app.post("/predict/batch", response_model=BatchResult)
async def predict_batch(request: BatchRequest):
    if ENGINE is None:
        raise HTTPException(503, "Models not loaded")
    t0 = time.perf_counter()
    n_feat = ENGINE.n_features
    features = [
        np.nan_to_num(_align_features(f.features, n_feat),
                      nan=0.0, posinf=0.0, neginf=0.0).tolist()
        for f in request.flows
    ]
    ml_results, _ = ENGINE.predict(features)
    predictions = []
    attacks_found = []
    for i, flow in enumerate(request.flows):
        r = ml_results[i]
        pred = PredictionResult(
            **{k: v for k, v in r.items() if k != "specialist_details"},
            src_ip=flow.src_ip, dst_ip=flow.dst_ip,
            src_port=flow.src_port, dst_port=flow.dst_port,
            protocol=flow.protocol, flow_id=flow.flow_id,
        )
        predictions.append(pred)
        if r["is_attack"]:
            attacks_found.append(pred)
    latency = round((time.perf_counter() - t0) * 1000, 3)
    return BatchResult(
        predictions=predictions, batch_size=len(request.flows),
        total_attacks=len(attacks_found), latency_ms=latency,
        attacks_found=attacks_found,
    )

@app.get("/feature-names")
async def get_feature_names():
    if ENGINE is None:
        raise HTTPException(503, "Not ready")
    return {"feature_names": ENGINE.feature_names, "n_features": ENGINE.n_features}

@app.get("/classes")
async def get_classes():
    if ENGINE is None:
        raise HTTPException(503, "Not ready")
    specs = {}
    for name, s in ENGINE.specialists.items():
        if s.loaded:
            specs[name] = [c for c in s.classes if c != "Benign"]
    return {
        "specialist_classes": specs,
        "total_unique": len(ENGINE.all_attack_classes),
        "all_attacks": ENGINE.all_attack_classes,
    }

if __name__ == "__main__":
    print("=" * 60)
    print("  SENTRIX ML SERVER v4.0")
    print("  Binary Gate + 3 Specialist ONNX Routing")
    print("=" * 60)
    print(f"  Models dir : {MODELS_DIR}")
    print(f"  API docs   : http://localhost:8001/docs")
    print("=" * 60)
    uvicorn.run("ml_server:app", host="0.0.0.0", port=8001,
                reload=False, log_level="info", workers=1)
