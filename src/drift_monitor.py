"""Population Stability Index (PSI) concept drift detection."""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

log = logging.getLogger("drift_monitor")

PSI_THRESHOLD = 0.20
PSI_CHECK_INTERVAL = 3600.0   # check every hour
N_BINS = 10                    # decile-based PSI

class DriftMonitor:

    def __init__(self, scaler_path: Path, feature_names: List[str],
                 window_seconds: float = 86400.0):
        self._feature_names = feature_names
        self._n_features = len(feature_names)
        self._window = window_seconds
        self._lock = threading.Lock()
        self._buffer: deque = deque(maxlen=200_000)
        self._running = False
        self._thread: Optional[threading.Thread] = None

        self._train_mean: Optional[np.ndarray] = None
        self._train_std: Optional[np.ndarray] = None
        self._ready = False

        try:
            import joblib
            scaler = joblib.load(scaler_path)
            self._train_mean = np.array(scaler.mean_, dtype=np.float64)
            self._train_std = np.array(scaler.scale_, dtype=np.float64)
            if len(self._train_mean) == self._n_features:
                self._ready = True
                log.info(f"  DriftMonitor: loaded training distribution "
                         f"({self._n_features} features)")
            else:
                log.warning(f"  DriftMonitor: scaler has {len(self._train_mean)} "
                            f"features, expected {self._n_features}")
        except Exception as e:
            log.warning(f"  DriftMonitor: failed to load scaler: {e}")

    def record(self, feature_vector: List[float]) -> None:
        if not self._ready:
            return
        with self._lock:
            self._buffer.append((time.time(), np.array(feature_vector, dtype=np.float64)))

    def start(self) -> None:
        if not self._ready:
            return
        self._running = True
        self._thread = threading.Thread(target=self._check_loop, daemon=True,
                                         name="drift-monitor")
        self._thread.start()
        log.info("  DriftMonitor: background check started "
                 f"(interval={PSI_CHECK_INTERVAL:.0f}s)")

    def stop(self) -> None:
        self._running = False

    def _check_loop(self) -> None:
        while self._running:
            time.sleep(PSI_CHECK_INTERVAL)
            if not self._running:
                break
            try:
                self._compute_psi()
            except Exception as e:
                log.error(f"DriftMonitor check failed: {e}")

    def _compute_psi(self) -> None:
        now = time.time()
        cutoff = now - self._window
        with self._lock:
            recent = [v for t, v in self._buffer if t > cutoff]
        if len(recent) < 1000:
            return

        X = np.vstack(recent)
        drifted = []
        for i in range(self._n_features):
            col = X[:, i]
            mu, sigma = self._train_mean[i], max(self._train_std[i], 1e-10)
            standardized = (col - mu) / sigma

            # Build expected distribution (standard normal deciles)
            expected_edges = np.percentile(
                np.random.standard_normal(100_000), np.linspace(0, 100, N_BINS + 1))
            expected_counts = np.ones(N_BINS) / N_BINS

            actual_counts = np.histogram(standardized, bins=expected_edges)[0]
            actual_pct = actual_counts / max(actual_counts.sum(), 1)
            actual_pct = np.clip(actual_pct, 1e-6, None)
            exp_pct = np.clip(expected_counts, 1e-6, None)

            psi = float(np.sum((actual_pct - exp_pct) * np.log(actual_pct / exp_pct)))
            if psi > PSI_THRESHOLD:
                drifted.append((self._feature_names[i], psi))

        if drifted:
            drifted.sort(key=lambda x: x[1], reverse=True)
            top = drifted[:5]
            names = ", ".join(f"{n}={v:.3f}" for n, v in top)
            log.warning(f"CONCEPT DRIFT DETECTED; {len(drifted)} features "
                        f"above PSI {PSI_THRESHOLD}: {names}. "
                        f"Consider retraining.")
        else:
            log.info(f"DriftMonitor: all {self._n_features} features stable "
                     f"(n={len(recent):,} flows in 24h window)")
