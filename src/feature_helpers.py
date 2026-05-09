"""Inference-side feature engineering helpers.

Contains the two functions used by the runtime ML cascade
(``ml_cascade.py``) to keep the train/infer feature pipeline identical:

  * ``extract_48`` derives the 48-feature input vector from a raw flow
    DataFrame.
  * ``apply_temperature`` applies post-hoc temperature scaling to a
    calibrated probability vector.

Both originate from the model-retraining pipeline; copying them here
removes the runtime dependency on the training script.
"""
from __future__ import annotations
import numpy as np
import pandas as pd

from feature_normalizer import FeatureNormalizer, NUMERIC_FEATURES, N_NUMERIC

norm = FeatureNormalizer()


def extract_48(df: pd.DataFrame) -> np.ndarray:
    """Same engineering as retrain_v3.py but dataset_id removed."""
    mapping = norm.map_columns(list(df.columns))
    df_r = df.rename(columns={c: u for c, u in mapping.items()})

    X = np.zeros((len(df_r), N_NUMERIC), dtype=np.float32)
    for i, feat in enumerate(NUMERIC_FEATURES):
        if feat in df_r.columns:
            cd = df_r[feat]
            if isinstance(cd, pd.DataFrame):
                cd = cd.iloc[:, 0]
            X[:, i] = pd.to_numeric(cd, errors="coerce").fillna(0).values
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    ti = {f: i for i, f in enumerate(NUMERIC_FEATURES)}
    m = X[:, ti["total_bytes"]] == 0
    X[m, ti["total_bytes"]] = X[m, ti["fwd_bytes"]] + X[m, ti["bwd_bytes"]]
    m = X[:, ti["total_packets"]] == 0
    X[m, ti["total_packets"]] = X[m, ti["fwd_packets"]] + X[m, ti["bwd_packets"]]

    tp = X[:, ti["total_packets"]].clip(min=1)
    tb = X[:, ti["total_bytes"]]
    dur = X[:, ti["duration"]].clip(min=0.001)
    fb = X[:, ti["fwd_bytes"]]; bb = X[:, ti["bwd_bytes"]]
    fp = X[:, ti["fwd_packets"]]; bp = X[:, ti["bwd_packets"]]

    m = X[:, ti["bytes_per_sec"]] == 0; X[m, ti["bytes_per_sec"]] = tb[m] / dur[m]
    m = X[:, ti["packets_per_sec"]] == 0; X[m, ti["packets_per_sec"]] = X[m, ti["total_packets"]] / dur[m]
    m = X[:, ti["pkt_size_mean"]] == 0; X[m, ti["pkt_size_mean"]] = tb[m] / tp[m]
    m = X[:, ti["fwd_byte_ratio"]] == 0; X[m, ti["fwd_byte_ratio"]] = fb[m] / tb[m].clip(min=1)

    X[:, ti["bytes_per_packet"]] = tb / tp
    X[:, ti["fwd_bwd_pkt_ratio"]] = fp / bp.clip(min=1)
    X[:, ti["fwd_bwd_byte_ratio"]] = fb / bb.clip(min=1)
    X[:, ti["header_payload_ratio"]] = X[:, ti["header_len"]] / tb.clip(min=1)
    X[:, ti["iat_cv"]] = X[:, ti["iat_std"]] / X[:, ti["iat_mean"]].clip(min=0.001)
    X[:, ti["pkt_size_cv"]] = X[:, ti["pkt_size_std"]] / X[:, ti["pkt_size_mean"]].clip(min=1)
    X[:, ti["duration_per_packet"]] = X[:, ti["duration"]] / tp

    dp = X[:, ti["dst_port"]].astype(int)
    X[:, ti["is_well_known_port"]] = ((dp > 0) & (dp < 1024)).astype(np.float32)
    X[:, ti["is_http"]] = np.isin(dp, [80, 8080]).astype(np.float32)
    X[:, ti["is_https"]] = np.isin(dp, [443, 8443]).astype(np.float32)
    X[:, ti["is_dns"]] = (dp == 53).astype(np.float32)
    X[:, ti["is_ssh"]] = (dp == 22).astype(np.float32)
    X[:, ti["is_threat_port"]] = np.isin(
        dp, [4444, 4445, 5555, 23, 2323, 6667, 31337, 1234, 9999, 48101, 3333, 8545]
    ).astype(np.float32)

    X[:, ti["syn_ratio"]] = X[:, ti["syn_flag"]] / tp
    X[:, ti["rst_ratio"]] = X[:, ti["rst_flag"]] / tp
    X[:, ti["fin_ratio"]] = X[:, ti["fin_flag"]] / tp

    return np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)


def apply_temperature(probs: np.ndarray, T: float) -> np.ndarray:
    p = np.clip(probs, 1e-7, 1 - 1e-7)
    logits = np.log(p / (1 - p))
    return 1.0 / (1.0 + np.exp(-logits / T))
