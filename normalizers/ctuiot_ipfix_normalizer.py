"""ctuiot_ipfix_normalizer.py — CTU-IoT-23 (Aposemat) Zeek conn.log.labeled normalizer.

conn.log.labeled format = standard Zeek conn.log + two appended columns:
  `label`           ∈ {"Benign", "Malicious", "Background"}
  `detailed-label`  ∈ family/behavior descriptor ("Mirai", "Okiru", "C&C",
                      "PartOfAHorizontalPortScan", etc.) or "-"/"(empty)"

Our scenario-level labeling (step2 pipeline) populates:
  `label` ← "Benign" for the Amazon Echo scenario, "Malicious" for attack
  `detailed-label` ← the family name ("Mirai", "Okiru", "Hajime", etc.)
Stratosphere's native per-flow labels use the same format with more granular
detailed-label values; this normalizer handles both.
"""
from __future__ import annotations

from pathlib import Path
import numpy as np
import pandas as pd

from normalizers.base_ipfix_normalizer import (
    BaseIPFIXNormalizer, parse_zeek_tsv, numeric_col,
)

_PROTO_MAP = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "gre": 47, "esp": 50}


class CtuIotIPFIXNormalizer(BaseIPFIXNormalizer):
    SOURCE_DATASET = "CTU-IoT-23"
    EXTRA_METADATA = ("device_profile",)

    def __init__(self, device_profile: str = ""):
        # Free-text tag describing the IoT device category. Informational only
        # (IP camera, smart speaker, router, etc.) — not a feature.
        self.device_profile = device_profile

    def load_raw(self, path: Path, max_rows: int | None = None) -> pd.DataFrame:
        return parse_zeek_tsv(path, max_rows=max_rows)

    def extract_group_a(self, raw: pd.DataFrame, out: pd.DataFrame) -> pd.DataFrame:
        out["src_port"] = numeric_col(raw, "id.orig_p").astype(np.int32)
        out["dst_port"] = numeric_col(raw, "id.resp_p").astype(np.int32)

        proto = raw.get("proto", pd.Series([""] * len(raw))).fillna("").astype(str).str.lower()
        out["protocol"] = proto.map(_PROTO_MAP).fillna(0).astype(np.int8)

        out["duration"] = numeric_col(raw, "duration").astype(np.float32)

        fp = numeric_col(raw, "orig_pkts").astype(np.int64)
        bp = numeric_col(raw, "resp_pkts").astype(np.int64)
        out["fwd_packets"] = fp
        out["bwd_packets"] = bp
        out["total_packets"] = fp + bp

        fb = numeric_col(raw, "orig_ip_bytes")
        bb = numeric_col(raw, "resp_ip_bytes")
        if (fb == 0).all() and "orig_bytes" in raw.columns:
            fb = numeric_col(raw, "orig_bytes")
        if (bb == 0).all() and "resp_bytes" in raw.columns:
            bb = numeric_col(raw, "resp_bytes")
        out["fwd_bytes"] = fb.astype(np.float64)
        out["bwd_bytes"] = bb.astype(np.float64)
        out["total_bytes"] = (fb + bb).astype(np.float64)

        out["pkt_size_min"] = 0.0
        out["pkt_size_max"] = 0.0

        hist = raw.get("history", pd.Series([""] * len(raw))).fillna("").astype(str).str.upper()
        out["syn_flag"] = hist.str.contains("S|H", regex=True, na=False).astype(np.int8)
        out["fin_flag"] = hist.str.contains("F", na=False).astype(np.int8)
        out["rst_flag"] = hist.str.contains("R", na=False).astype(np.int8)
        out["ack_flag"] = hist.str.contains("A|H", regex=True, na=False).astype(np.int8)
        out["psh_flag"] = np.int8(0)
        return out

    def extract_labels(self, raw: pd.DataFrame) -> pd.DataFrame:
        n = len(raw)
        labels = pd.DataFrame(index=raw.index)
        labels["label"] = np.int8(-1)
        labels["attack_family"] = pd.Series([None] * n, index=raw.index, dtype="object")

        if "label" not in raw.columns:
            # Unlabeled conn.log (raw Zeek output) — treat as all-benign with no family.
            labels["label"] = np.int8(0)
            return labels

        lbl = raw["label"].fillna("").astype(str).str.strip()
        benign = lbl.str.casefold() == "benign"
        malicious = lbl.str.casefold() == "malicious"

        labels.loc[benign, "label"] = 0
        labels.loc[malicious, "label"] = 1

        # Attack family from detailed-label. Stratosphere uses values like
        # "Mirai", "C&C", "PartOfAHorizontalPortScan", "Attack", "-"/"(empty)".
        if "detailed-label" in raw.columns:
            detail = raw["detailed-label"].fillna("").astype(str).str.strip()
            # Treat placeholder values as None
            detail = detail.where(~detail.isin(["-", "(empty)", ""]), other=None)
            labels.loc[malicious, "attack_family"] = detail[malicious]

        # label=-1 (Background, unexpected strings) drops downstream.
        return labels

    def extract_identity(self, raw: pd.DataFrame) -> pd.DataFrame:
        df = pd.DataFrame(index=raw.index)
        df["timestamp"] = numeric_col(raw, "ts").astype(np.float64)
        df["src_ip"] = raw.get("id.orig_h", pd.Series([""] * len(raw))).fillna("").astype(str)
        df["dst_ip"] = raw.get("id.resp_h", pd.Series([""] * len(raw))).fillna("").astype(str)
        return df

    def detect_flag_ratio_mode(self, raw: pd.DataFrame) -> str:
        return "binary"

    def add_metadata(self, out, raw, *, mode, scenario_id):
        out = super().add_metadata(out, raw, mode=mode, scenario_id=scenario_id)
        out["device_profile"] = self.device_profile
        return out
