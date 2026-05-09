"""Universal Feature Schema (IPFIX-Inspired)"""
import sys
import io
import re
import logging
from typing import Dict, List, Optional, Tuple
from collections import OrderedDict

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

log = logging.getLogger("normalizer")

# ═══════════════════════════════════════════════════════════════
#  UNIVERSAL SCHEMA DEFINITION
# ═══════════════════════════════════════════════════════════════

# Each entry: (feature_name, default_value, list_of_synonyms)
# Synonyms cover: CIC-IDS, CICIoT2023, HIKARI, UNSW-NB15, CTU-13,
#                 Edge-IIoTset, Zeek, NetFlow, LUFlow, NF-UQ-NIDS-v2

UNIVERSAL_SCHEMA = OrderedDict([

    # ── Identity ──────────────────────────────────────────────
    ("src_ip", ("", [
        "src_ip", "originh", "SrcAddr", "srcip", "Src IP",
        "id.orig_h", "IPV4_SRC_ADDR", "sa", "src_addr", "Source IP",
    ])),
    ("dst_ip", ("", [
        "dst_ip", "responh", "DstAddr", "dstip", "Dst IP",
        "id.resp_h", "IPV4_DST_ADDR", "da", "dst_addr", "Destination IP",
    ])),
    ("src_port", (0, [
        "src_port", "originp", "Sport", "srcport", "Src Port",
        "id.orig_p", "L4_SRC_PORT", "sp", "src_port_number", "Source Port",
    ])),
    ("dst_port", (0, [
        "dst_port", "responp", "Dport", "dstport", "Dst Port",
        "id.resp_p", "L4_DST_PORT", "dp", "dst_port_number", "Destination Port",
        "tcp.dstport", "udp.port", "dsport",
    ])),
    ("protocol", (6, [
        "protocol", "Protocol", "Proto", "proto", "Protocol Type",
        "Proto_num", "PROTOCOL", "pr", "ip_protocol", "L4_PROTOCOL",
    ])),

    # ── Duration ──────────────────────────────────────────────
    ("duration", (0.0, [
        "duration", "Duration", "Dur", "dur", "flow_duration",
        "Flow Duration", "DURATION", "conn_duration", "td",
        "duration_sec", "FlowDuration",
    ])),

    # ── Volume: Packets ───────────────────────────────────────
    ("fwd_packets", (0, [
        "fwd_packets", "Tot Fwd Pkts", "fwd_pkts_tot", "TotPkts",
        "Spkts", "orig_pkts", "IN_PKTS", "fpkts", "fwd_pkts",
        "src_pkts", "dpkts", "Total Fwd Packets", "fwd_data_pkts_tot",
        "Total Fwd Packet", "Subflow Fwd Packets",
        "fwd_packets_count", "subflow_fwd_packets",
    ])),
    ("bwd_packets", (0, [
        "bwd_packets", "Tot Bwd Pkts", "bwd_pkts_tot",
        "Dpkts", "resp_pkts", "OUT_PKTS", "bpkts", "bwd_pkts",
        "dst_pkts", "Total Backward Packets", "bwd_data_pkts_tot",
        "Total Bwd packets", "Subflow Bwd Packets",
        "bwd_packets_count", "subflow_bwd_packets",
    ])),
    ("total_packets", (0, [
        "total_packets", "TotPkts", "total_pkts", "Number",
        "Pkts", "pkts", "TOTAL_PKTS", "flow_pkts_tot",
        "Total Packets", "num_pkts", "packets_count",
    ])),

    # ── Volume: Bytes ─────────────────────────────────────────
    ("fwd_bytes", (0.0, [
        "fwd_bytes", "TotLen Fwd Pkts", "fwd_pkts_payload.tot",
        "SrcBytes", "Sbytes", "orig_bytes", "IN_BYTES",
        "fbytes", "src_bytes", "fwd_subflow_bytes",
        "Total Length of Fwd Packets", "fwd_payload_bytes",
        "Total Length of Fwd Packet", "Subflow Fwd Bytes",
        "fwd_total_payload_bytes", "subflow_fwd_bytes",
    ])),
    ("bwd_bytes", (0.0, [
        "bwd_bytes", "TotLen Bwd Pkts", "bwd_pkts_payload.tot",
        "DstBytes", "Dbytes", "resp_bytes", "OUT_BYTES",
        "bbytes", "dst_bytes", "bwd_subflow_bytes",
        "Total Length of Bwd Packets", "bwd_payload_bytes",
        "Total Length of Bwd Packet", "Subflow Bwd Bytes",
        "bwd_total_payload_bytes", "subflow_bwd_bytes",
    ])),
    ("total_bytes", (0.0, [
        "total_bytes", "TotBytes", "Tot size", "Tot sum",
        "Bytes", "bytes", "TOTAL_BYTES", "flow_bytes_tot",
        "Total Bytes", "total_payload", "flow_pkts_payload.tot",
        "total_payload_bytes",
    ])),

    # ── Rates ─────────────────────────────────────────────────
    ("bytes_per_sec", (0.0, [
        "bytes_per_sec", "Flow Byts/s", "Flow Bytes/s", "BytesPerSec", "Rate",
        "Bps", "bps", "BYTES_PER_SEC", "payload_bytes_per_second",
        "flow_bytes_per_sec", "Byte Rate",
    ])),
    ("packets_per_sec", (0.0, [
        "packets_per_sec", "Flow Pkts/s", "Flow Packets/s", "flow_pkts_per_sec",
        "Pps", "pps", "PKTS_PER_SEC", "PacketRate",
        "flow_packets_per_sec", "Packet Rate",
    ])),
    ("fwd_packets_per_sec", (0.0, [
        "fwd_packets_per_sec", "fwd_pkts_per_sec", "Srate",
        "Fwd Pkts/s", "Fwd Packets/s", "fwd_pps", "src_rate",
    ])),
    ("bwd_packets_per_sec", (0.0, [
        "bwd_packets_per_sec", "bwd_pkts_per_sec", "Drate",
        "Bwd Pkts/s", "Bwd Packets/s", "bwd_pps", "dst_rate",
    ])),

    # ── Packet Sizes ──────────────────────────────────────────
    ("pkt_size_min", (0.0, [
        "pkt_size_min", "Min", "flow_pkts_payload.min", "min_pkt",
        "Pkt Len Min", "Packet Length Min", "pkt_len_min", "MIN_PKT_SIZE",
        "fwd_pkts_payload.min", "Packet Min", "Fwd Packet Length Min",
        "payload_bytes_min",
    ])),
    ("pkt_size_max", (0.0, [
        "pkt_size_max", "Max", "flow_pkts_payload.max", "max_pkt",
        "Pkt Len Max", "Packet Length Max", "Fwd Pkt Len Max", "Bwd Pkt Len Max",
        "pkt_len_max", "MAX_PKT_SIZE", "Packet Max",
        "Fwd Packet Length Max", "Bwd Packet Length Max",
        "payload_bytes_max",
    ])),
    ("pkt_size_mean", (0.0, [
        "pkt_size_mean", "AVG", "flow_pkts_payload.avg",
        "Pkt Len Mean", "Packet Length Mean", "Pkt Size Avg",
        "Fwd Pkt Len Mean", "Fwd Packet Length Mean",
        "Average Packet Size", "BytesPerPkt", "pkt_len_mean",
        "MEAN_PKT_SIZE", "avg_pkt_size", "bytes_per_pkt", "Packet Mean",
        "payload_bytes_mean",
    ])),
    ("pkt_size_std", (0.0, [
        "pkt_size_std", "Std", "flow_pkts_payload.std",
        "Pkt Len Std", "Packet Length Std", "Packet Length Variance",
        "pkt_len_std", "STD_PKT_SIZE", "Variance", "Packet Std",
        "payload_bytes_std",
    ])),

    # ── Inter-Arrival Times ───────────────────────────────────
    ("iat_min", (0.0, [
        "iat_min", "Flow IAT Min", "flow_iat.min", "min_iat",
        "IAT_MIN", "Sintpkt", "min_flowiat",
    ])),
    ("iat_max", (0.0, [
        "iat_max", "Flow IAT Max", "flow_iat.max", "max_iat",
        "IAT_MAX", "max_flowiat", "IAT",
    ])),
    ("iat_mean", (0.0, [
        "iat_mean", "Flow IAT Mean", "flow_iat.avg", "mean_iat",
        "IAT_MEAN", "avg_flowiat", "Dintpkt",
    ])),
    ("iat_std", (0.0, [
        "iat_std", "Flow IAT Std", "flow_iat.std", "std_iat",
        "IAT_STD", "std_flowiat",
    ])),
    ("fwd_iat_mean", (0.0, [
        "fwd_iat_mean", "Fwd IAT Mean", "fwd_iat.avg",
        "fwd_iat_avg", "src_iat_mean",
    ])),
    ("fwd_iat_total", (0.0, [
        "fwd_iat_total", "Fwd IAT Tot", "fwd_iat.tot",
        "fwd_iat_sum", "src_iat_total",
    ])),

    # ── TCP Flags ─────────────────────────────────────────────
    ("syn_flag", (0, [
        "syn_flag", "SYN Flag Cnt", "SYN Flag Count", "syn_flag_number", "syn_count",
        "flow_SYN_flag_count", "SYN", "tcp.connection.syn",
        "SYN_FLAG", "Syn",
    ])),
    ("fin_flag", (0, [
        "fin_flag", "FIN Flag Cnt", "FIN Flag Count", "fin_flag_number", "fin_count",
        "flow_FIN_flag_count", "FIN", "tcp.connection.fin",
        "FIN_FLAG", "Fin",
    ])),
    ("rst_flag", (0, [
        "rst_flag", "RST Flag Cnt", "RST Flag Count", "rst_flag_number", "rst_count",
        "flow_RST_flag_count", "RST", "tcp.connection.rst",
        "RST_FLAG", "Rst",
    ])),
    ("ack_flag", (0, [
        "ack_flag", "ACK Flag Cnt", "ACK Flag Count", "ack_flag_number", "ack_count",
        "flow_ACK_flag_count", "ACK", "tcp.flags.ack",
        "ACK_FLAG", "Ack",
    ])),
    ("psh_flag", (0, [
        "psh_flag", "PSH Flag Cnt", "PSH Flag Count", "psh_flag_number",
        "fwd_PSH_flag_count", "Fwd PSH Flags", "PSH", "PSH_FLAG", "Psh",
    ])),

    # ── Derived Features ──────────────────────────────────────
    ("fwd_byte_ratio", (0.0, [
        "fwd_byte_ratio", "down_up_ratio", "fwd_bwd_ratio",
        "upload_ratio", "src_ratio",
    ])),
    ("header_len", (0, [
        "header_len", "Header_Length", "fwd_header_size_tot",
        "header_length", "hdr_len", "HEADER_LEN",
        "Fwd Header Length", "Fwd Header Len",
        "total_header_bytes", "fwd_total_header_bytes",
    ])),
    ("init_fwd_win", (0, [
        "init_fwd_win", "Init Fwd Win Byts", "fwd_init_window_size",
        "init_win_bytes_forward", "TCP_WIN_INIT_FWD",
        "FWD Init Win Bytes",
    ])),

    # ── Derived Features (computed, not mapped) ─────────────────
    ("bytes_per_packet", (0.0, ["bytes_per_packet", "BytesPerPkt"])),
    ("fwd_bwd_pkt_ratio", (0.0, ["fwd_bwd_pkt_ratio"])),
    ("fwd_bwd_byte_ratio", (0.0, ["fwd_bwd_byte_ratio"])),
    ("header_payload_ratio", (0.0, ["header_payload_ratio"])),
    ("iat_cv", (0.0, ["iat_cv"])),
    ("pkt_size_cv", (0.0, ["pkt_size_cv"])),
    ("duration_per_packet", (0.0, ["duration_per_packet"])),
    ("is_well_known_port", (0, ["is_well_known_port"])),
    ("is_http", (0, ["is_http", "HTTP"])),
    ("is_https", (0, ["is_https", "HTTPS"])),
    ("is_dns", (0, ["is_dns", "DNS"])),
    ("is_ssh", (0, ["is_ssh", "SSH"])),
    ("syn_ratio", (0.0, ["syn_ratio"])),
    ("rst_ratio", (0.0, ["rst_ratio"])),
    ("fin_ratio", (0.0, ["fin_ratio"])),
    ("is_threat_port", (0, ["is_threat_port"])),
    # is_multicast; explicit signal for multicast/broadcast destinations.
    # Added in schema but NOT included in N_NUMERIC until models are
    # retrained to expect 49 features. Computed in _compute_derived
    # and available for the next retrain's extract_48 to pick up.
    # NOTE: currently excluded from NUMERIC_FEATURES via the guard below.
    ("is_multicast", (0, ["is_multicast"])),

    # ── TLS Metadata (if available) ───────────────────────────
    ("ja3", ("", [
        "ja3", "ja3_hash", "JA3", "tls_ja3",
    ])),
    ("ja3s", ("", [
        "ja3s", "ja3s_hash", "JA3S", "tls_ja3s",
    ])),
    ("sni", ("", [
        "sni", "server_name", "SNI", "tls_sni",
        "ssl_server_name", "ServerName",
    ])),
])

# Feature names list (ordered)
UNIVERSAL_FEATURES = list(UNIVERSAL_SCHEMA.keys())
N_UNIVERSAL = len(UNIVERSAL_FEATURES)

# Numeric features (for ML vector extraction; excludes string fields
# and retrain-gated features that current models don't expect).
_RETRAIN_GATED = {"is_multicast"}
NUMERIC_FEATURES = [f for f in UNIVERSAL_FEATURES
                    if f not in ("src_ip", "dst_ip", "ja3", "ja3s", "sni")
                    and f not in _RETRAIN_GATED]
N_NUMERIC = len(NUMERIC_FEATURES)

# ═══════════════════════════════════════════════════════════════
#  NORMALIZER
# ═══════════════════════════════════════════════════════════════

class FeatureNormalizer:
    """
    Universal feature normalizer.
    Maps ANY dataset column names to the universal 35-feature schema.
    """

    def __init__(self):
        # Build reverse lookup: synonym → universal_name
        self._synonym_map: Dict[str, str] = {}
        for uni_name, (default, synonyms) in UNIVERSAL_SCHEMA.items():
            # Add the universal name itself
            self._synonym_map[uni_name] = uni_name
            self._synonym_map[uni_name.lower()] = uni_name
            # Add all synonyms (case-insensitive)
            for syn in synonyms:
                self._synonym_map[syn] = uni_name
                self._synonym_map[syn.lower()] = uni_name
                # Also strip spaces/dots/underscores for fuzzy match
                clean = syn.lower().replace(" ", "").replace(".", "").replace("_", "").replace("/", "")
                self._synonym_map[clean] = uni_name

        # Cache: maps (dataset column name → universal name) per dataset
        self._column_cache: Dict[str, str] = {}

        # Stats
        self.stats = {
            "flows_normalized": 0,
            "columns_matched": 0,
            "columns_unmatched": 0,
        }

        print(f"[Normalizer] Universal schema: {N_UNIVERSAL} features, "
              f"{N_NUMERIC} numeric, {len(self._synonym_map)} synonyms")

    def map_column(self, col_name: str) -> Optional[str]:
        """Map a single column name to universal schema name."""
        # Check cache first
        if col_name in self._column_cache:
            return self._column_cache[col_name]

        # Exact match
        if col_name in self._synonym_map:
            self._column_cache[col_name] = self._synonym_map[col_name]
            return self._synonym_map[col_name]

        # Case-insensitive
        lower = col_name.lower()
        if lower in self._synonym_map:
            self._column_cache[col_name] = self._synonym_map[lower]
            return self._synonym_map[lower]

        # Stripped match (remove spaces, dots, underscores)
        clean = lower.replace(" ", "").replace(".", "").replace("_", "").replace("/", "")
        if clean in self._synonym_map:
            self._column_cache[col_name] = self._synonym_map[clean]
            return self._synonym_map[clean]

        # Not found
        self._column_cache[col_name] = None
        return None

    def map_columns(self, columns: List[str]) -> Dict[str, str]:
        """Map a list of dataset columns to universal schema.
        Returns {dataset_col: universal_name} for matched columns."""
        mapping = {}
        matched = 0
        unmatched = 0
        for col in columns:
            uni = self.map_column(col)
            if uni:
                mapping[col] = uni
                matched += 1
            else:
                unmatched += 1

        self.stats["columns_matched"] += matched
        self.stats["columns_unmatched"] += unmatched
        return mapping

    def normalize(self, flow: dict) -> dict:
        """
        Normalize a raw flow dict to universal schema.
        Any recognized column names are mapped. Unknown columns preserved as-is.
        """
        self.stats["flows_normalized"] += 1
        result = {}

        # Set defaults for all universal features
        for uni_name, (default, _) in UNIVERSAL_SCHEMA.items():
            result[uni_name] = default

        # Map recognized fields
        for key, value in flow.items():
            uni = self.map_column(key)
            if uni:
                result[uni] = value
            else:
                # Preserve unknown fields (might be dataset-specific)
                result[key] = value

        # ── Compute derived features if missing ───────────────
        self._compute_derived(result)

        return result

    def _compute_derived(self, flow: dict):
        """Compute derived features from available base features."""

        # total_packets from fwd + bwd if missing
        if _is_zero(flow.get("total_packets")):
            fwd = _to_float(flow.get("fwd_packets", 0))
            bwd = _to_float(flow.get("bwd_packets", 0))
            if fwd + bwd > 0:
                flow["total_packets"] = fwd + bwd

        # total_bytes from fwd + bwd if missing
        if _is_zero(flow.get("total_bytes")):
            fwd = _to_float(flow.get("fwd_bytes", 0))
            bwd = _to_float(flow.get("bwd_bytes", 0))
            if fwd + bwd > 0:
                flow["total_bytes"] = fwd + bwd

        # bytes_per_sec from total_bytes / duration if missing
        if _is_zero(flow.get("bytes_per_sec")):
            dur = _to_float(flow.get("duration", 0))
            total = _to_float(flow.get("total_bytes", 0))
            if dur > 0.001:
                flow["bytes_per_sec"] = total / dur

        # packets_per_sec from total_packets / duration if missing
        if _is_zero(flow.get("packets_per_sec")):
            dur = _to_float(flow.get("duration", 0))
            total = _to_float(flow.get("total_packets", 0))
            if dur > 0.001:
                flow["packets_per_sec"] = total / dur

        # pkt_size_mean from total_bytes / total_packets if missing
        if _is_zero(flow.get("pkt_size_mean")):
            total_b = _to_float(flow.get("total_bytes", 0))
            total_p = _to_float(flow.get("total_packets", 0))
            if total_p > 0:
                flow["pkt_size_mean"] = total_b / total_p

        # fwd_byte_ratio from fwd_bytes / total_bytes if missing
        if _is_zero(flow.get("fwd_byte_ratio")):
            fwd = _to_float(flow.get("fwd_bytes", 0))
            total = _to_float(flow.get("total_bytes", 0))
            if total > 0:
                flow["fwd_byte_ratio"] = fwd / total

        # Protocol string → number
        proto = flow.get("protocol", 6)
        if isinstance(proto, str):
            proto_map = {"tcp": 6, "udp": 17, "icmp": 1,
                        "TCP": 6, "UDP": 17, "ICMP": 1}
            flow["protocol"] = proto_map.get(proto, 0)

        # ── 16 Derived Features ───────────────────────────────
        total_b = _to_float(flow.get("total_bytes", 0))
        total_p = _to_float(flow.get("total_packets", 0))
        fwd_p = _to_float(flow.get("fwd_packets", 0))
        bwd_p = _to_float(flow.get("bwd_packets", 0))
        fwd_b = _to_float(flow.get("fwd_bytes", 0))
        bwd_b = _to_float(flow.get("bwd_bytes", 0))
        dur = _to_float(flow.get("duration", 0))
        dst_port = int(_to_float(flow.get("dst_port", 0)))
        syn = _to_float(flow.get("syn_flag", 0))
        rst = _to_float(flow.get("rst_flag", 0))
        fin = _to_float(flow.get("fin_flag", 0))
        hdr = _to_float(flow.get("header_len", 0))
        iat_m = _to_float(flow.get("iat_mean", 0))
        iat_s = _to_float(flow.get("iat_std", 0))
        ps_m = _to_float(flow.get("pkt_size_mean", 0))
        ps_s = _to_float(flow.get("pkt_size_std", 0))

        # Ratio features
        flow["bytes_per_packet"] = total_b / max(total_p, 1)
        flow["fwd_bwd_pkt_ratio"] = fwd_p / max(bwd_p, 1)
        flow["fwd_bwd_byte_ratio"] = fwd_b / max(bwd_b, 1)
        flow["header_payload_ratio"] = hdr / max(total_b, 1)

        # Statistical features
        flow["iat_cv"] = iat_s / max(iat_m, 0.001)
        flow["pkt_size_cv"] = ps_s / max(ps_m, 1)
        flow["duration_per_packet"] = dur / max(total_p, 1)

        # Port intelligence
        flow["is_well_known_port"] = 1 if 0 < dst_port < 1024 else 0
        flow["is_http"] = 1 if dst_port in (80, 8080, 8000) else 0
        flow["is_https"] = 1 if dst_port in (443, 8443) else 0
        flow["is_dns"] = 1 if dst_port == 53 else 0
        flow["is_ssh"] = 1 if dst_port == 22 else 0

        _THREAT_PORTS = {4444, 4445, 5555, 23, 2323, 6667, 31337, 1234,
                         9999, 48101, 3333, 3334, 3335, 8333, 8545}
        flow["is_threat_port"] = 1 if dst_port in _THREAT_PORTS else 0

        # Connection behavior ratios
        flow["syn_ratio"] = syn / max(total_p, 1)
        flow["rst_ratio"] = rst / max(total_p, 1)
        flow["fin_ratio"] = fin / max(total_p, 1)

        # is_multicast; checks dst_ip against RFC multicast ranges
        import ipaddress as _ipa
        try:
            _dst = flow.get("dst_ip", "")
            flow["is_multicast"] = (
                1 if _dst and _ipa.ip_address(str(_dst)).is_multicast else 0)
        except (ValueError, TypeError):
            flow["is_multicast"] = 0

    def to_vector(self, flow: dict) -> List[float]:
        """Extract numeric feature vector from normalized flow.
        Returns N_NUMERIC-dimensional float vector for ML models."""
        vec = []
        for feat in NUMERIC_FEATURES:
            val = flow.get(feat, 0.0)
            try:
                v = float(val)
                if v != v or abs(v) == float('inf'):
                    v = 0.0
            except (ValueError, TypeError):
                v = 0.0
            vec.append(v)
        return vec

    def normalize_dataframe(self, df, label_col: str = None):
        """
        Normalize an entire pandas DataFrame.
        Returns (normalized_df, column_mapping, unmapped_columns).
        """
        import pandas as pd

        # Map columns
        mapping = self.map_columns(list(df.columns))

        # Rename matched columns
        rename_map = {}
        unmapped = []
        for col in df.columns:
            if col in mapping:
                rename_map[col] = mapping[col]
            elif col == label_col:
                rename_map[col] = col  # preserve label column
            else:
                unmapped.append(col)

        df_norm = df.rename(columns=rename_map)

        # Add missing universal features with defaults
        for uni_name, (default, _) in UNIVERSAL_SCHEMA.items():
            if uni_name not in df_norm.columns and uni_name not in ("src_ip", "dst_ip", "ja3", "ja3s", "sni"):
                df_norm[uni_name] = default

        return df_norm, mapping, unmapped

    def print_mapping_report(self, columns: List[str]):
        """Print detailed mapping report for a dataset's columns."""
        mapping = self.map_columns(columns)
        matched = [(c, mapping[c]) for c in columns if c in mapping]
        unmatched = [c for c in columns if c not in mapping]

        print(f"\n  Feature Mapping Report")
        print(f"  {'='*55}")
        print(f"  Matched: {len(matched)}/{len(columns)} columns")
        print(f"\n  MATCHED:")
        for orig, uni in matched:
            marker = " " if orig.lower() == uni.lower() else "*"
            print(f"  {marker} {orig:<35} -> {uni}")
        if unmatched:
            print(f"\n  UNMATCHED ({len(unmatched)}):")
            for c in unmatched:
                print(f"    ? {c}")
        print(f"  {'='*55}")

    def get_stats(self) -> dict:
        return dict(self.stats)

def _to_float(val) -> float:
    try:
        v = float(val)
        return v if v == v and abs(v) != float('inf') else 0.0
    except (ValueError, TypeError):
        return 0.0

def _is_zero(val) -> bool:
    if val is None:
        return True
    try:
        return float(val) == 0.0
    except (ValueError, TypeError):
        return True
