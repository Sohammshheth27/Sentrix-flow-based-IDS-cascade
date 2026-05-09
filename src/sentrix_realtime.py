"""Sentrix real-time IPFIX inference engine."""
from __future__ import annotations

import argparse, gc, gzip, json, math, os, sys, time
from collections import Counter, deque
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd

# File lives in src/; go up one level to find project root + models/ + normalizers/
_PROJECT = Path(__file__).resolve().parents[1]
if str(_PROJECT) not in sys.path:
    sys.path.insert(0, str(_PROJECT))

from normalizers.base_ipfix_normalizer import CANONICAL_FEATURES, EPS
from normalizers.ctuiot_ipfix_normalizer import CtuIotIPFIXNormalizer
from sentrix_host_aggregator import HOST_AGG_FEATURES

MODELS = _PROJECT / "models"
FEATURE_COLS = list(CANONICAL_FEATURES) + list(HOST_AGG_FEATURES)
N_FEATURES = len(FEATURE_COLS)

# ── Streaming host aggregator (O(1) amortised per flow) ──────────────

class StreamingHostAggregator:
    """Incremental 60-second rolling aggregator. One call per flow, in
    timestamp order. Returns the 8 HOST_AGG_FEATURES values for the flow
    and updates internal state with the flow's own data."""

    def __init__(self, window_seconds: float = 60.0,
                 cold_start: Optional[Dict[str, float]] = None):
        self.window = float(window_seconds)
        self.cold_start = cold_start or {}
        # state[src_ip] = dict of running values
        self.state: Dict[str, Dict[str, Any]] = {}

    def _new_state(self) -> Dict[str, Any]:
        return {
            "dq": deque(),           # (ts, dst_ip, dst_port, syn_no_ack, bytes_out)
            "sum_syn_na": 0,
            "sum_bytes": 0.0,
            "dst_counter": Counter(),
            "port_counter": Counter(),
            "iat_dq": deque(),       # differences between consecutive flow timestamps
            "iat_sum": 0.0,
            "iat_sq": 0.0,
        }

    def update_and_query(self, ts: float, src_ip: str, dst_ip: str,
                         dst_port: int, syn_no_ack: int,
                         total_bytes: float) -> np.ndarray:
        st = self.state.get(src_ip)
        if st is None:
            st = self._new_state()
            self.state[src_ip] = st
        cutoff = ts - self.window

        # Evict expired
        while st["dq"] and st["dq"][0][0] < cutoff:
            _, ed, ep, esna, ebo = st["dq"].popleft()
            st["sum_syn_na"] -= esna
            st["sum_bytes"] -= ebo
            c = st["dst_counter"][ed] - 1
            if c == 0: del st["dst_counter"][ed]
            else:      st["dst_counter"][ed] = c
            c = st["port_counter"][ep] - 1
            if c == 0: del st["port_counter"][ep]
            else:      st["port_counter"][ep] = c
            if st["iat_dq"]:
                expired = st["iat_dq"].popleft()
                st["iat_sum"] -= expired
                st["iat_sq"] -= expired * expired

        # Compute aggregate BEFORE inserting this flow
        count = len(st["dq"])
        if count == 0:
            # Cold-start row; use peer-group baseline
            agg = np.array([
                self.cold_start.get(f, 0.0) for f in HOST_AGG_FEATURES
            ], dtype=np.float32)
        else:
            n_iat = len(st["iat_dq"])
            if n_iat > 0:
                iat_mean = st["iat_sum"] / n_iat
                iat_var = (st["iat_sq"] / n_iat) - (iat_mean * iat_mean)
                iat_std = math.sqrt(max(iat_var, 0.0))
            else:
                iat_mean = 0.0; iat_std = 0.0
            agg = np.array([
                count,
                len(st["dst_counter"]),
                len(st["port_counter"]),
                st["sum_syn_na"],
                count / self.window,
                st["sum_bytes"],
                iat_mean,
                iat_std,
            ], dtype=np.float32)

        # Insert this flow
        if st["dq"]:
            new_iat = ts - st["dq"][-1][0]
            st["iat_dq"].append(new_iat)
            st["iat_sum"] += new_iat
            st["iat_sq"] += new_iat * new_iat
        st["dq"].append((ts, dst_ip, int(dst_port), syn_no_ack, total_bytes))
        st["sum_syn_na"] += syn_no_ack
        st["sum_bytes"] += total_bytes
        st["dst_counter"][dst_ip] = st["dst_counter"].get(dst_ip, 0) + 1
        st["port_counter"][int(dst_port)] = st["port_counter"].get(int(dst_port), 0) + 1
        return agg

# ── Sentrix live engine ──────────────────────────────────────────────

def _logit(p: np.ndarray) -> np.ndarray:
    p = np.clip(p, EPS, 1 - EPS)
    return np.log(p / (1 - p))

class SentrixLiveEngine:

    def __init__(self, models_dir: Path = MODELS, use_onnx_for_stage2: bool = True):
        self.scaler = joblib.load(models_dir / "sentrix_scaler.pkl")
        self.lgb_clf = joblib.load(models_dir / "sentrix_binary_lgb.pkl")
        self.xgb_clf = joblib.load(models_dir / "sentrix_binary_xgb.pkl")
        self.rf_clf  = joblib.load(models_dir / "sentrix_binary_rf.pkl")
        w = json.loads((models_dir / "sentrix_ensemble_weights.json").read_text())
        self.W_LGB, self.W_XGB, self.W_RF = w["lgb"], w["xgb"], w["rf"]
        self.T = json.loads((models_dir / "sentrix_temperature.json").read_text())["temperature"]
        thr = json.loads((models_dir / "sentrix_thresholds.json").read_text())
        self.TAU_LOW, self.TAU_HIGH = thr["TAU_LOW"], thr["TAU_HIGH"]
        cb_path = models_dir / "sentrix_cold_start_baseline.json"
        cold = json.loads(cb_path.read_text()) if cb_path.exists() else {}
        self.aggregator = StreamingHostAggregator(window_seconds=60.0, cold_start=cold)

        # Stage 2
        self.stage2 = None
        self.stage2_classes: List[str] = []
        cm_path = models_dir / "sentrix_class_mapping.json"
        if cm_path.exists():
            mapping = json.loads(cm_path.read_text())
            self.stage2_classes = mapping["classes"]
        if use_onnx_for_stage2:
            onnx_path = models_dir / "sentrix_multiclass.onnx"
            if onnx_path.exists():
                try:
                    import onnxruntime as ort
                    self.stage2 = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
                    self.stage2_kind = "onnx"
                except Exception as e:
                    print(f"[warn] ONNX stage2 load failed ({e}); falling back to joblib.", file=sys.stderr)
        if self.stage2 is None:
            pkl_path = models_dir / "sentrix_multiclass.pkl"
            if pkl_path.exists():
                self.stage2 = joblib.load(pkl_path)
                self.stage2_kind = "joblib"
            else:
                self.stage2_kind = "none"

    # ── Prediction primitives ───────────────────────────────────────

    def _stage1_prob(self, x_scaled: np.ndarray) -> float:
        """Return calibrated p(attack) for a single 1×53 scaled feature vector."""
        p1 = self.lgb_clf.predict_proba(x_scaled)[:, 1]
        p2 = self.xgb_clf.predict_proba(x_scaled)[:, 1]
        p3 = self.rf_clf.predict_proba(x_scaled)[:, 1]
        logit = self.W_LGB * _logit(p1) + self.W_XGB * _logit(p2) + self.W_RF * _logit(p3)
        ens = 1.0 / (1.0 + np.exp(-logit))
        # Temperature
        ens = np.clip(ens, EPS, 1 - EPS)
        cal = 1.0 / (1.0 + np.exp(-_logit(ens) / self.T))
        return float(cal[0])

    def _stage2_family(self, x_scaled: np.ndarray):
        """Return (family_name, confidence) for a single 1×53 scaled vector."""
        if self.stage2 is None or not self.stage2_classes:
            return None, None
        if self.stage2_kind == "onnx":
            out = self.stage2.run(None, {"input": x_scaled.astype(np.float32)})
            # onnxmltools LightGBM multiclass: out[0]=labels, out[1]=list[dict{class->prob}]
            probs_raw = out[1][0]
            if isinstance(probs_raw, dict):
                idxs = sorted(probs_raw.keys())
                probs = np.array([probs_raw[k] for k in idxs], dtype=np.float32)
            else:
                probs = np.asarray(probs_raw, dtype=np.float32)
        else:  # joblib
            probs = self.stage2.predict_proba(x_scaled)[0]
        top = int(np.argmax(probs))
        return self.stage2_classes[top], float(probs[top])

    # ── Per-flow pipeline ───────────────────────────────────────────

    def process_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Process one flow dict with 45 canonical + metadata keys.
        Returns the alert dict + stage latencies."""
        t_start = time.perf_counter()

        # Identity for aggregator
        ts = float(row.get("timestamp", 0.0) or 0.0)
        src = str(row.get("src_ip", "") or "")
        dst = str(row.get("dst_ip", "") or "")
        t_norm = time.perf_counter()

        # Aggregate
        syn = int(row.get("syn_flag", 0))
        ack = int(row.get("ack_flag", 0))
        syn_no_ack = int(syn == 1 and ack == 0)
        tb = float(row.get("total_bytes", 0.0))
        dp = int(row.get("dst_port", 0))
        agg_vec = self.aggregator.update_and_query(ts, src, dst, dp, syn_no_ack, tb)
        t_agg = time.perf_counter()

        # Assemble 53-feature vector (canonical + aggregates)
        canon = np.array([float(row.get(c, 0.0)) for c in CANONICAL_FEATURES],
                         dtype=np.float32)
        x = np.concatenate([canon, agg_vec]).reshape(1, -1).astype(np.float32)
        x_scaled = self.scaler.transform(x).astype(np.float32)
        t_scale = time.perf_counter()

        # Stage 1
        p_attack = self._stage1_prob(x_scaled)
        t_stage1 = time.perf_counter()

        # Routing + optional Stage 2
        family, family_conf = None, None
        label = "benign" if p_attack < self.TAU_LOW else "attack"
        if p_attack >= self.TAU_LOW:
            family, family_conf = self._stage2_family(x_scaled)
        t_stage2 = time.perf_counter()

        def ms(a, b): return round((b - a) * 1000.0, 3)
        return {
            "ts": ts,
            "src_ip": src, "dst_ip": dst,
            "label": label,
            "confidence": round(float(p_attack if label == "attack" else (1.0 - p_attack)), 6),
            "p_attack": round(float(p_attack), 6),
            "attack_family": family,
            "family_confidence": round(float(family_conf), 6) if family_conf is not None else None,
            "stage_latencies_ms": {
                "norm":   ms(t_start, t_norm),
                "agg":    ms(t_norm, t_agg),
                "scale":  ms(t_agg, t_scale),
                "stage1": ms(t_scale, t_stage1),
                "stage2": ms(t_stage1, t_stage2),
                "total":  ms(t_start, t_stage2),
            },
        }

# ── Validation: replay parquet, compare to batch predictions ──────────

def validate_against_parquet(parquet_path: Path, n_per_source: int = 100,
                              out_json: Path = MODELS / "sentrix_realtime_validation.json"):
    """Replay the last n_per_source rows per source_dataset through the live
    engine, also compute batch predictions on the same rows, check that live
    and batch agree within numerical tolerance."""
    eng = SentrixLiveEngine()
    df = pd.read_parquet(parquet_path)
    # Pick rows: n per source_dataset, timestamp-sorted
    keep = []
    for src, grp in df.groupby("source_dataset"):
        grp = grp.sort_values("timestamp").tail(n_per_source)
        keep.append(grp)
    sample = pd.concat(keep, ignore_index=True).sort_values("timestamp").reset_index(drop=True)
    print(f"validation sample: {len(sample):,} rows from "
          f"{sample['source_dataset'].nunique()} sources")

    # Batch predictions (using an INDEPENDENT aggregator state identical to the
    # live one that will process the sample; we recompute both in parallel).
    canon = sample[list(CANONICAL_FEATURES)].to_numpy(dtype=np.float32)
    batch_aggregator = StreamingHostAggregator(window_seconds=60.0,
                                                cold_start=eng.aggregator.cold_start)
    batch_agg = np.zeros((len(sample), len(HOST_AGG_FEATURES)), dtype=np.float32)
    for i, r in enumerate(sample.itertuples(index=False)):
        batch_agg[i] = batch_aggregator.update_and_query(
            float(getattr(r, "timestamp", 0.0) or 0.0),
            str(getattr(r, "src_ip", "") or ""),
            str(getattr(r, "dst_ip", "") or ""),
            int(getattr(r, "dst_port", 0)),
            int(int(getattr(r, "syn_flag", 0)) == 1 and int(getattr(r, "ack_flag", 0)) == 0),
            float(getattr(r, "total_bytes", 0.0)),
        )
    X_batch = np.concatenate([canon, batch_agg], axis=1).astype(np.float32)
    Xs_batch = eng.scaler.transform(X_batch).astype(np.float32)
    p1 = eng.lgb_clf.predict_proba(Xs_batch)[:, 1]
    p2 = eng.xgb_clf.predict_proba(Xs_batch)[:, 1]
    p3 = eng.rf_clf.predict_proba(Xs_batch)[:, 1]
    ens = 1.0 / (1.0 + np.exp(-(eng.W_LGB*_logit(p1) + eng.W_XGB*_logit(p2) + eng.W_RF*_logit(p3))))
    ens = np.clip(ens, EPS, 1-EPS)
    batch_cal = 1.0 / (1.0 + np.exp(-_logit(ens) / eng.T))

    # Live predictions (one row at a time)
    eng.aggregator = StreamingHostAggregator(window_seconds=60.0,
                                             cold_start=eng.aggregator.cold_start)
    live_p = np.zeros(len(sample), dtype=np.float32)
    live_labels = []
    live_families = []
    latencies = []
    t0 = time.perf_counter()
    for i, r in enumerate(sample.itertuples(index=False)):
        row_dict = {c: getattr(r, c, 0.0) for c in CANONICAL_FEATURES}
        row_dict.update({
            "timestamp": float(getattr(r, "timestamp", 0.0) or 0.0),
            "src_ip":    str(getattr(r, "src_ip", "") or ""),
            "dst_ip":    str(getattr(r, "dst_ip", "") or ""),
        })
        alert = eng.process_row(row_dict)
        live_p[i] = alert["p_attack"]
        live_labels.append(alert["label"])
        live_families.append(alert["attack_family"])
        latencies.append(alert["stage_latencies_ms"]["total"])
    elapsed = time.perf_counter() - t0
    throughput = len(sample) / max(elapsed, 1e-6)

    # Compare batch vs live
    max_diff = float(np.max(np.abs(live_p - batch_cal.astype(np.float32))))
    mean_diff = float(np.mean(np.abs(live_p - batch_cal.astype(np.float32))))
    tolerance_ok = max_diff < 1e-4  # float32 scaler+ensemble rounding budget

    # Agreement vs ground truth
    y_true = sample["label"].astype(np.int8).to_numpy()
    live_attack = np.array([1 if l == "attack" else 0 for l in live_labels], dtype=np.int8)
    live_P = float(((live_attack == 1) & (y_true == 1)).sum() / max((live_attack == 1).sum(), 1))
    live_R = float(((live_attack == 1) & (y_true == 1)).sum() / max((y_true == 1).sum(), 1))
    live_F1 = 2 * live_P * live_R / max(live_P + live_R, 1e-9)

    lat = np.array(latencies, dtype=np.float32)

    out = {
        "parquet_path": str(parquet_path),
        "n_per_source": n_per_source,
        "n_total": int(len(sample)),
        "sources": sorted(sample["source_dataset"].unique().tolist()),
        "live_vs_batch": {
            "max_abs_diff": max_diff,
            "mean_abs_diff": mean_diff,
            "tolerance_ok": tolerance_ok,
        },
        "live_metrics_at_threshold_0.50": {
            "precision": round(live_P, 4),
            "recall":    round(live_R, 4),
            "f1":        round(live_F1, 4),
            "n_attack_pred": int((live_attack == 1).sum()),
            "n_attack_true": int((y_true == 1).sum()),
        },
        "latency_ms": {
            "p50": round(float(np.percentile(lat, 50)), 3),
            "p95": round(float(np.percentile(lat, 95)), 3),
            "p99": round(float(np.percentile(lat, 99)), 3),
            "max": round(float(lat.max()), 3),
            "mean": round(float(lat.mean()), 3),
        },
        "throughput_fps": int(throughput),
        "stage2_kind": eng.stage2_kind,
    }
    out_json.write_text(json.dumps(out, indent=2, default=str))
    print(json.dumps(out, indent=2, default=str))
    return out

# ── Streaming from Zeek conn.log(.gz) ─────────────────────────────────

def stream_from_conn_log(path: Path, follow: bool = False,
                          max_rows: Optional[int] = None):
    """Yield normalized flow dicts from a Zeek conn.log.labeled[.gz] file.
    `follow=True` tails the file (stdin-like streaming). Reuses the CtuIot
    normalizer because MTA / CTU-IoT / live Zeek all share the same format."""
    norm = CtuIotIPFIXNormalizer(device_profile="live")
    eng = SentrixLiveEngine()
    total = 0; t0 = time.perf_counter()

    if path.suffix == ".gz":
        df = norm.normalize(path, max_rows=max_rows, scenario_id="live")
    else:
        df = norm.normalize(path, max_rows=max_rows, scenario_id="live")

    for r in df.itertuples(index=False):
        row = {c: getattr(r, c, 0.0) for c in CANONICAL_FEATURES}
        row.update({
            "timestamp": float(getattr(r, "timestamp", 0.0) or 0.0),
            "src_ip":    str(getattr(r, "src_ip", "") or ""),
            "dst_ip":    str(getattr(r, "dst_ip", "") or ""),
        })
        alert = eng.process_row(row)
        print(json.dumps(alert), flush=True)
        total += 1
    elapsed = time.perf_counter() - t0
    print(json.dumps({"summary": {"rows": total,
                                   "elapsed_s": round(elapsed, 3),
                                   "throughput_fps": int(total / max(elapsed, 1e-6))}}),
          flush=True)

# ── CLI ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    v = sub.add_parser("validate-parquet", help="Validate against a saved splits parquet")
    v.add_argument("parquet", type=Path)
    v.add_argument("--n-per-source", type=int, default=100)
    v.add_argument("--out", type=Path, default=MODELS / "sentrix_realtime_validation.json")
    s = sub.add_parser("stream-conn-log", help="Process a Zeek conn.log.labeled[.gz]")
    s.add_argument("conn_log", type=Path)
    s.add_argument("--max-rows", type=int, default=None)
    args = ap.parse_args()

    if args.mode == "validate-parquet":
        validate_against_parquet(args.parquet, args.n_per_source, args.out)
    elif args.mode == "stream-conn-log":
        stream_from_conn_log(args.conn_log, max_rows=args.max_rows)
