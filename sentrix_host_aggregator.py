"""phase4_host_aggregator.py — compute the 8 per-flow host-level aggregates.

Each flow picks up 8 extra features describing its source host's behaviour in
the preceding 60 seconds. This compensates for the Phase 4 schema dropping
packet-level IAT / size-variance features; host-level context recovers the
scanning / beaconing / flood signal without per-packet inspection.

The 8 aggregates (exact names — used downstream by the scaler, Stage 1, and
live inference):
  host_flow_count_60s          flows initiated from src_ip in last 60s
  host_distinct_dst_60s        distinct destination IPs
  host_distinct_port_60s       distinct destination ports (scan width)
  host_syn_no_ack_count_60s    SYN-without-ACK flow count (scan signature)
  host_flow_rate_60s           flows/second
  host_bytes_out_60s           total outbound bytes in window
  host_inter_flow_mean_60s     mean time between flow initiations (beaconing)
  host_inter_flow_std_60s      std of inter-flow timing (regularity)

Implementation: single O(n) pass over timestamp-sorted flows with a per-src_ip
deque. Entries older than the window are evicted as we advance. Cold-start
hosts (no prior history in window) get zeros by default, or a peer-group
baseline vector if one is supplied via `cold_start_baseline`.
"""
from __future__ import annotations

import sys, time
from collections import Counter, defaultdict, deque
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd


HOST_AGG_FEATURES: Tuple[str, ...] = (
    "host_flow_count_60s",
    "host_distinct_dst_60s",
    "host_distinct_port_60s",
    "host_syn_no_ack_count_60s",
    "host_flow_rate_60s",
    "host_bytes_out_60s",
    "host_inter_flow_mean_60s",
    "host_inter_flow_std_60s",
)
N_HOST_AGG = len(HOST_AGG_FEATURES)
assert N_HOST_AGG == 8


class PhaseFourHostAggregator:
    """Stream-efficient per-source 60-second rolling aggregator.

    Usage:
        agg = PhaseFourHostAggregator(window_seconds=60.0)
        out_df = agg.aggregate(normalized_df)
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        cold_start_baseline: Optional[Dict[str, float]] = None,
    ):
        self.window = float(window_seconds)
        # Peer-group baseline for new hosts. Keys: HOST_AGG_FEATURES names.
        # Hook for UEBA cold-start inheritance — pass the department median
        # when available. Default None → zero-impute for cold-start rows.
        self.cold_start_baseline = cold_start_baseline

    # ── Main entry point ────────────────────────────────────────────

    def aggregate(self, df: pd.DataFrame) -> pd.DataFrame:
        """Return a new DataFrame with the 8 aggregate columns appended.

        Input must have columns: timestamp, src_ip, dst_ip, dst_port,
        syn_flag, ack_flag, total_bytes. (These are all present in the
        Phase 4 normalizer output — timestamp/src_ip/dst_ip as metadata,
        the rest as canonical features.)
        """
        required = ["timestamp", "src_ip", "dst_ip", "dst_port",
                    "syn_flag", "ack_flag", "total_bytes"]
        missing = [c for c in required if c not in df.columns]
        if missing:
            raise ValueError(
                f"PhaseFourHostAggregator.aggregate: missing columns {missing}. "
                f"Run through a Phase 4 normalizer first."
            )

        if len(df) == 0:
            empty = {c: pd.Series([], dtype="float32") for c in HOST_AGG_FEATURES}
            return pd.concat([df.reset_index(drop=True), pd.DataFrame(empty)], axis=1)

        # Sort chronologically — this is the key invariant for the sliding window.
        # We record the original index so callers can map rows back.
        order = df["timestamp"].to_numpy().argsort(kind="stable")
        df_sorted = df.iloc[order].reset_index(drop=True)

        # Extract arrays once for tight loop
        ts      = df_sorted["timestamp"].to_numpy(dtype=np.float64)
        src_ip  = df_sorted["src_ip"].to_numpy()
        dst_ip  = df_sorted["dst_ip"].to_numpy()
        dst_pt  = df_sorted["dst_port"].to_numpy(dtype=np.int32)
        syn     = df_sorted["syn_flag"].to_numpy(dtype=np.int8)
        ack     = df_sorted["ack_flag"].to_numpy(dtype=np.int8)
        tb      = df_sorted["total_bytes"].to_numpy(dtype=np.float64)

        n = len(df_sorted)
        out = np.zeros((n, N_HOST_AGG), dtype=np.float64)

        # Per-host incremental state. Running sums + Counters make evict and
        # add each O(1) amortized — total aggregation is O(n), not O(n×window).
        #
        # state[src_ip] = [
        #   deque of (ts, dst_ip, dst_port, syn_na, bytes_out),
        #   sum_syn_na, sum_bytes,
        #   Counter[dst_ip], Counter[dst_port],
        #   deque of iat values (len = len(flow_dq) - 1),
        #   iat_sum, iat_sq_sum,
        # ]
        hist: Dict[str, list] = {}
        window = self.window
        cold = self.cold_start_baseline

        PROGRESS_EVERY = max(n // 20, 50_000)
        t_start = time.time()

        for i in range(n):
            t = ts[i]
            s = src_ip[i]
            st = hist.get(s)
            if st is None:
                st = [deque(), 0, 0.0, Counter(), Counter(), deque(), 0.0, 0.0]
                hist[s] = st
            flow_dq, sum_syn_na, sum_bytes, dst_c, port_c, iat_dq, iat_sum, iat_sq = st
            cutoff = t - window

            # ── Evict expired entries, subtract their contribution ────────
            while flow_dq and flow_dq[0][0] < cutoff:
                _, ed, ep, esna, ebo = flow_dq.popleft()
                sum_syn_na -= esna
                sum_bytes -= ebo
                # Decrement Counter — delete key when hitting zero
                c = dst_c[ed] - 1
                if c == 0: del dst_c[ed]
                else:      dst_c[ed] = c
                c = port_c[ep] - 1
                if c == 0: del port_c[ep]
                else:      port_c[ep] = c
                # Evict corresponding iat value (one per evicted flow, except
                # when evicting the very first flow — no iat was ever created).
                if iat_dq:
                    expired = iat_dq.popleft()
                    iat_sum -= expired
                    iat_sq -= expired * expired

            count = len(flow_dq)
            if count > 0:
                n_iat = len(iat_dq)
                if n_iat > 0:
                    iat_mean = iat_sum / n_iat
                    iat_var = (iat_sq / n_iat) - (iat_mean * iat_mean)
                    iat_std = (iat_var ** 0.5) if iat_var > 0 else 0.0
                else:
                    iat_mean = 0.0
                    iat_std = 0.0
                out[i, 0] = count
                out[i, 1] = len(dst_c)
                out[i, 2] = len(port_c)
                out[i, 3] = sum_syn_na
                out[i, 4] = count / window
                out[i, 5] = sum_bytes
                out[i, 6] = iat_mean
                out[i, 7] = iat_std
            else:
                # Cold-start row — first flow ever from this source in window
                if cold is not None:
                    for j, f in enumerate(HOST_AGG_FEATURES):
                        out[i, j] = float(cold.get(f, 0.0))
                # else: zeros (already initialized)

            # ── Append current row, incrementally update running state ────
            syn_no_ack_this = int(syn[i] == 1 and ack[i] == 0)
            # IAT: diff with previous in-window flow (if any)
            if flow_dq:
                new_iat = t - flow_dq[-1][0]
                iat_dq.append(new_iat)
                iat_sum += new_iat
                iat_sq += new_iat * new_iat
            d_ip, d_pt, bt = dst_ip[i], int(dst_pt[i]), tb[i]
            flow_dq.append((t, d_ip, d_pt, syn_no_ack_this, bt))
            sum_syn_na += syn_no_ack_this
            sum_bytes += bt
            dst_c[d_ip] = dst_c.get(d_ip, 0) + 1
            port_c[d_pt] = port_c.get(d_pt, 0) + 1

            # Store updated running state back
            st[1] = sum_syn_na
            st[2] = sum_bytes
            st[6] = iat_sum
            st[7] = iat_sq

            if (i + 1) % PROGRESS_EVERY == 0:
                elapsed = time.time() - t_start
                rate = (i + 1) / max(elapsed, 1e-6)
                eta = (n - i - 1) / rate
                print(f"    [aggregator] {i+1:,}/{n:,} ({100*(i+1)/n:.1f}%) "
                      f"rate={rate:,.0f} rows/s  eta={eta:.0f}s  "
                      f"hosts={len(hist):,}", flush=True)

        # Assemble output DataFrame
        agg_df = pd.DataFrame(out, columns=list(HOST_AGG_FEATURES))
        # float32 to match the rest of the feature schema
        for c in HOST_AGG_FEATURES:
            agg_df[c] = agg_df[c].astype(np.float32)

        merged = pd.concat([df_sorted, agg_df], axis=1)
        # Preserve insertion order: re-sort back to caller's original order
        merged = merged.iloc[np.argsort(order, kind="stable")].reset_index(drop=True)
        return merged

    # ── Peer-group baseline helper ──────────────────────────────────

    @staticmethod
    def compute_peer_baseline(df_with_aggregates: pd.DataFrame) -> Dict[str, float]:
        """Compute a median-based cold-start baseline from a labeled corpus.
        Pass the training split (post-aggregate) here, then provide the
        resulting dict back to the aggregator for inference on new hosts."""
        baseline: Dict[str, float] = {}
        for f in HOST_AGG_FEATURES:
            if f in df_with_aggregates.columns:
                baseline[f] = float(df_with_aggregates[f].median())
            else:
                baseline[f] = 0.0
        return baseline
