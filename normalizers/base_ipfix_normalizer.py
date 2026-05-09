"""base_ipfix_normalizer.py — Phase 4 IPFIX-native abstract base class.

Defines the frozen 45-feature canonical schema and the shared derivation math
used by every dataset-specific normalizer (MAWI, CTU-13, CTU-IoT-23). Every
subclass MUST return exactly `CANONICAL_FEATURES` in order + the metadata
columns. Adding a 46th feature or reordering is a violation.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Tuple, Union

import numpy as np
import pandas as pd

# ──────────────────────────────────────────────────────────────────────
#  CANONICAL 45-FEATURE SCHEMA — frozen, do not edit
# ──────────────────────────────────────────────────────────────────────

EPS = 1e-6

CANONICAL_FEATURES: Tuple[str, ...] = (
    # Group A — 17 direct IPFIX IEs
    "src_port", "dst_port", "protocol", "duration",
    "fwd_packets", "bwd_packets", "total_packets",
    "fwd_bytes", "bwd_bytes", "total_bytes",
    "pkt_size_min", "pkt_size_max",
    "syn_flag", "fin_flag", "rst_flag", "ack_flag", "psh_flag",
    # Group B — 10 simple derived
    "bytes_per_sec", "packets_per_sec",
    "fwd_packets_per_sec", "bwd_packets_per_sec",
    "pkt_size_mean", "fwd_byte_ratio",
    "bytes_per_packet", "fwd_bwd_pkt_ratio", "fwd_bwd_byte_ratio",
    "duration_per_packet",
    # Group C — 6 port/protocol booleans
    "is_well_known_port", "is_http", "is_https",
    "is_dns", "is_ssh", "is_threat_port",
    # Group D — 3 flag ratios (mode-dependent; see detect_flag_ratio_mode)
    "syn_ratio", "rst_ratio", "fin_ratio",
    # Group E — 9 engineered IPFIX-derivable
    "syn_without_ack", "rst_without_established",
    "flag_entropy", "traffic_asymmetry", "protocol_port_mismatch",
    "short_session_flag", "long_session_flag",
    "small_packet_flag", "large_packet_flag",
)
N_CANONICAL = len(CANONICAL_FEATURES)
assert N_CANONICAL == 45, f"canonical schema must be exactly 45 features, got {N_CANONICAL}"

METADATA_COLUMNS: Tuple[str, ...] = (
    "label",             # 0 benign, 1 attack; rows with label=-1 are dropped before return
    "attack_family",     # str or None; None for benign
    "source_dataset",    # MAWI / CTU-13 / CTU-IoT-23
    "scenario_id",       # scenario name or capture date
    "flag_ratio_mode",   # 'rate' or 'binary' — which mode produced syn/rst/fin_ratio
    "timestamp",         # epoch seconds, used by host aggregator; NOT a feature
    "src_ip",            # source IP string, used by host aggregator; NOT a feature
    "dst_ip",            # destination IP string, used by host aggregator; NOT a feature
)

# Port tables — these are final. is_http is locked by spec.
_HTTP_PORTS = frozenset({80, 8080, 8000, 8008})
_HTTPS_PORTS = frozenset({443, 8443})
_DNS_PORT = 53
_SSH_PORT = 22
# Threat port list — classic malware C2 / backdoor ports commonly cited in TI feeds.
_THREAT_PORTS = frozenset({1337, 4444, 4445, 5555, 6667, 6697, 9999, 31337, 48101})
# Common-TCP ports for protocol_port_mismatch detection
_COMMON_TCP_PORTS = frozenset({
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587,
    993, 995, 3306, 3389, 5432, 5900, 8080, 8443,
})


# ──────────────────────────────────────────────────────────────────────
#  BaseIPFIXNormalizer
# ──────────────────────────────────────────────────────────────────────

class BaseIPFIXNormalizer(ABC):
    """Abstract base class.

    Subclasses must:
      - set SOURCE_DATASET
      - implement load_raw(path, max_rows)
      - implement extract_group_a(raw) -> DataFrame with 17 Group A columns
      - implement extract_labels(raw) -> DataFrame with ['label', 'attack_family']
      - implement detect_flag_ratio_mode(raw) -> 'rate' or 'binary'
      - optionally override compute_flag_ratios for rate-mode computation

    The template method `.normalize()` runs the full pipeline. Output is
    exactly 45 canonical columns in order + metadata columns.
    """

    SOURCE_DATASET: str = ""   # must override
    EXTRA_METADATA: Tuple[str, ...] = ()  # per-dataset extras

    # ── Public entry point ───────────────────────────────────────────

    def normalize(
        self,
        source: Union[str, Path, pd.DataFrame],
        *,
        max_rows: int | None = None,
        scenario_id: str = "",
    ) -> pd.DataFrame:
        """Template method. source = file path OR a raw DataFrame."""
        if isinstance(source, (str, Path)):
            raw = self.load_raw(Path(source), max_rows=max_rows)
        else:
            raw = source.head(max_rows).copy() if max_rows else source.copy()

        if len(raw) == 0:
            return self._empty_output(scenario_id, "binary")

        # Build output stepwise — always using primitives from raw/GroupA.
        out = pd.DataFrame(index=raw.index)
        out = self.extract_group_a(raw, out)
        self._assert_group_a(out)

        labels = self.extract_labels(raw)
        out = out.join(labels)

        identity = self.extract_identity(raw)
        out = out.join(identity)

        mode = self.detect_flag_ratio_mode(raw)
        if mode not in ("rate", "binary"):
            raise ValueError(f"detect_flag_ratio_mode must return 'rate' or 'binary', got {mode!r}")

        out = self.compute_group_b(out)
        out = self.compute_group_c(out)
        out = self.compute_flag_ratios(raw, out, mode)
        out = self.compute_group_e(out)
        out = self.add_metadata(out, raw, mode=mode, scenario_id=scenario_id)

        # Drop label=-1 rows (per spec: Background → drop)
        n_before = len(out)
        out = out[out["label"] != -1].copy().reset_index(drop=True)
        self._last_dropped = n_before - len(out)

        # Final column order: 45 canonical + METADATA_COLUMNS + EXTRA_METADATA
        final_cols = list(CANONICAL_FEATURES) + list(METADATA_COLUMNS) + list(self.EXTRA_METADATA)
        for c in final_cols:
            if c not in out.columns:
                raise RuntimeError(f"{self.__class__.__name__}: missing output column {c!r}")
        out = out[final_cols]

        # Downcast numerics for memory
        for c in CANONICAL_FEATURES:
            out[c] = pd.to_numeric(out[c], errors="coerce").fillna(0).astype(np.float32)
        out["label"] = out["label"].astype(np.int8)

        self.validate_output_schema(out)
        return out

    # ── Abstract methods ─────────────────────────────────────────────

    @abstractmethod
    def load_raw(self, path: Path, max_rows: int | None = None) -> pd.DataFrame:
        """Read the raw dataset file into a DataFrame."""

    @abstractmethod
    def extract_group_a(self, raw: pd.DataFrame, out: pd.DataFrame) -> pd.DataFrame:
        """Populate the 17 Group A direct IPFIX IE columns on `out` and return it."""

    @abstractmethod
    def extract_labels(self, raw: pd.DataFrame) -> pd.DataFrame:
        """Return a DataFrame with columns ['label', 'attack_family'].
        label ∈ {-1, 0, 1}. Rows with -1 are dropped."""

    def extract_identity(self, raw: pd.DataFrame) -> pd.DataFrame:
        """Return DataFrame with timestamp, src_ip, dst_ip columns for host
        aggregation. Default returns zeros/empty; subclasses override if they
        have these fields in the raw data (MAWI, CTU-IoT via Zeek; CTU-13 via Argus).
        These are metadata, not features — they never reach the scaler or model."""
        df = pd.DataFrame(index=raw.index)
        df["timestamp"] = 0.0
        df["src_ip"] = ""
        df["dst_ip"] = ""
        return df

    @abstractmethod
    def detect_flag_ratio_mode(self, raw: pd.DataFrame) -> str:
        """Return 'rate' when per-flag counter IEs (IANA 218/219/220) are available,
        otherwise 'binary' when only tcpControlBits (IE 6) presence is available.
        All three current datasets return 'binary'; keeps the code future-proof
        for nProbe/Cisco-IPFIX exports with counter IEs."""

    # ── Group B — 10 simple derived features ─────────────────────────

    def compute_group_b(self, out: pd.DataFrame) -> pd.DataFrame:
        dur = out["duration"].clip(lower=EPS)
        tp = out["total_packets"].clip(lower=1)
        tb = out["total_bytes"].clip(lower=0)
        fp = out["fwd_packets"].clip(lower=0)
        bp = out["bwd_packets"].clip(lower=0)
        fb = out["fwd_bytes"].clip(lower=0)
        bb = out["bwd_bytes"].clip(lower=0)

        out["bytes_per_sec"] = tb / dur
        out["packets_per_sec"] = out["total_packets"] / dur
        out["fwd_packets_per_sec"] = fp / dur
        out["bwd_packets_per_sec"] = bp / dur
        out["pkt_size_mean"] = tb / tp
        out["fwd_byte_ratio"] = fb / tb.clip(lower=1)
        out["bytes_per_packet"] = tb / tp                # alias of pkt_size_mean
        out["fwd_bwd_pkt_ratio"] = fp / bp.clip(lower=1)
        out["fwd_bwd_byte_ratio"] = fb / bb.clip(lower=1)
        out["duration_per_packet"] = out["duration"] / tp
        return out

    # ── Group C — 6 port/protocol booleans ──────────────────────────

    def compute_group_c(self, out: pd.DataFrame) -> pd.DataFrame:
        dp = pd.to_numeric(out["dst_port"], errors="coerce").fillna(0).astype(int)
        sp = pd.to_numeric(out["src_port"], errors="coerce").fillna(0).astype(int)

        out["is_well_known_port"] = ((dp > 0) & (dp < 1024)).astype(np.int8)
        out["is_http"] = dp.isin(_HTTP_PORTS).astype(np.int8)
        out["is_https"] = dp.isin(_HTTPS_PORTS).astype(np.int8)
        out["is_dns"] = ((dp == _DNS_PORT) | (sp == _DNS_PORT)).astype(np.int8)
        out["is_ssh"] = (dp == _SSH_PORT).astype(np.int8)
        out["is_threat_port"] = dp.isin(_THREAT_PORTS).astype(np.int8)
        return out

    # ── Group D — flag ratios (mode-dependent) ──────────────────────

    def compute_flag_ratios(
        self, raw: pd.DataFrame, out: pd.DataFrame, mode: str,
    ) -> pd.DataFrame:
        """Default: binary mode uses flag presence directly. Subclasses
        override for 'rate' mode when per-flag IPFIX counter IEs are available."""
        if mode == "binary":
            out["syn_ratio"] = out["syn_flag"].astype(np.float32)
            out["rst_ratio"] = out["rst_flag"].astype(np.float32)
            out["fin_ratio"] = out["fin_flag"].astype(np.float32)
        else:
            # Rate mode must be implemented by subclasses that see IEs 218/219/220.
            raise NotImplementedError(
                f"{self.__class__.__name__}.compute_flag_ratios: mode='rate' requires "
                f"per-flag counter IEs. Subclass must override."
            )
        return out

    # ── Group E — 9 engineered IPFIX-derivable features ──────────────

    def compute_group_e(self, out: pd.DataFrame) -> pd.DataFrame:
        s = out["syn_flag"].astype(np.int8)
        f = out["fin_flag"].astype(np.int8)
        r = out["rst_flag"].astype(np.int8)
        a = out["ack_flag"].astype(np.int8)
        p = out["psh_flag"].astype(np.int8)

        out["syn_without_ack"] = ((s == 1) & (a == 0)).astype(np.int8)
        out["rst_without_established"] = ((r == 1) & ((s + a) == 0)).astype(np.int8)

        # Shannon entropy of flag distribution [s,f,r,a,p]. Vectorized.
        flags = np.stack([s.values, f.values, r.values, a.values, p.values], axis=1).astype(np.float32)
        flag_sum = flags.sum(axis=1, keepdims=True)
        # Rows with no flags → entropy 0 (uniform over zero support is degenerate).
        safe = np.where(flag_sum > 0, flag_sum, 1.0)
        probs = flags / safe
        with np.errstate(divide="ignore", invalid="ignore"):
            log_probs = np.where(probs > 0, np.log(probs), 0.0)
        ent = -(probs * log_probs).sum(axis=1)
        ent = np.where(flag_sum.flatten() > 0, ent, 0.0)
        out["flag_entropy"] = ent.astype(np.float32)

        # Traffic asymmetry: |fwd_bytes - bwd_bytes| / max(total_bytes, EPS).
        asym_denom = out["total_bytes"].clip(lower=EPS)
        out["traffic_asymmetry"] = (out["fwd_bytes"] - out["bwd_bytes"]).abs() / asym_denom

        # protocol_port_mismatch: 1 if protocol==TCP(6) and dst_port not in COMMON_TCP_PORTS.
        is_tcp = (out["protocol"] == 6)
        dp = pd.to_numeric(out["dst_port"], errors="coerce").fillna(0).astype(int)
        out["protocol_port_mismatch"] = (is_tcp & ~dp.isin(_COMMON_TCP_PORTS)).astype(np.int8)

        # Session length / packet-size signatures.
        out["short_session_flag"] = (out["duration"] < 1.0).astype(np.int8)
        out["long_session_flag"] = (out["duration"] > 600.0).astype(np.int8)
        out["small_packet_flag"] = (out["pkt_size_mean"] < 64).astype(np.int8)
        out["large_packet_flag"] = (out["pkt_size_mean"] > 1400).astype(np.int8)
        return out

    # ── Metadata + schema validation ─────────────────────────────────

    def add_metadata(
        self, out: pd.DataFrame, raw: pd.DataFrame, *,
        mode: str, scenario_id: str,
    ) -> pd.DataFrame:
        out["source_dataset"] = self.SOURCE_DATASET
        out["scenario_id"] = scenario_id or ""
        out["flag_ratio_mode"] = mode
        return out

    def validate_output_schema(self, df: pd.DataFrame) -> None:
        """Assert exact column order and required metadata columns."""
        first_n = list(df.columns[:N_CANONICAL])
        if first_n != list(CANONICAL_FEATURES):
            # Surface the first diff for fast diagnosis
            diffs = [(i, a, b) for i, (a, b) in enumerate(zip(first_n, CANONICAL_FEATURES)) if a != b]
            raise RuntimeError(
                f"Canonical schema mismatch. First diff at idx {diffs[0] if diffs else 'N/A'}. "
                f"Got {first_n[:5]}...{first_n[-3:]}, expected {CANONICAL_FEATURES[:5]}...{CANONICAL_FEATURES[-3:]}"
            )
        for c in METADATA_COLUMNS:
            if c not in df.columns:
                raise RuntimeError(f"Missing metadata column {c!r}")
        # No additional canonical columns beyond position 45
        tail = list(df.columns[N_CANONICAL:])
        expected_tail = list(METADATA_COLUMNS) + list(self.EXTRA_METADATA)
        if tail != expected_tail:
            raise RuntimeError(
                f"Unexpected tail columns. Got {tail}, expected {expected_tail}"
            )

    # ── Internal helpers ─────────────────────────────────────────────

    def _assert_group_a(self, out: pd.DataFrame) -> None:
        group_a = [c for c in CANONICAL_FEATURES[:17]]
        missing = [c for c in group_a if c not in out.columns]
        if missing:
            raise RuntimeError(f"{self.__class__.__name__}.extract_group_a missing: {missing}")

    def _empty_output(self, scenario_id: str, mode: str) -> pd.DataFrame:
        cols = list(CANONICAL_FEATURES) + list(METADATA_COLUMNS) + list(self.EXTRA_METADATA)
        return pd.DataFrame({c: pd.Series([], dtype="float32") for c in CANONICAL_FEATURES}
                           ).reindex(columns=cols)


# ── Small shared parser for Zeek TSV files ──────────────────────────
# Used by MAWI and CTU-IoT normalizers. Kept here to avoid duplication.

def parse_zeek_tsv(
    path: Path,
    max_rows: int | None = None,
    extra_label_columns: int = 0,
) -> pd.DataFrame:
    """Parse a Zeek TSV file (optionally .gz) into a DataFrame.

    Zeek TSV has `#fields` / `#types` header lines and `-` / `(empty)` sentinels.
    `extra_label_columns` = 2 for Stratosphere conn.log.labeled (appends
    'label' and 'detailed-label' columns after standard Zeek schema).
    """
    import gzip, io

    fields: list[str] | None = None
    opener = gzip.open if str(path).endswith(".gz") else open
    rows: list[list[str]] = []

    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if fields is None:
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) != len(fields):
                continue
            rows.append(parts)
            if max_rows is not None and len(rows) >= max_rows:
                break

    if fields is None or not rows:
        return pd.DataFrame(columns=fields or [])

    df = pd.DataFrame(rows, columns=fields)
    # Zeek uses '-' for unset and '(empty)' for empty set
    df = df.replace({"-": None, "(empty)": None})
    return df


def numeric_col(df: pd.DataFrame, col: str, default: float = 0.0) -> pd.Series:
    """Coerce a column to numeric, filling NaN/None with default."""
    if col not in df.columns:
        return pd.Series([default] * len(df), index=df.index, dtype=np.float64)
    return pd.to_numeric(df[col], errors="coerce").fillna(default)
