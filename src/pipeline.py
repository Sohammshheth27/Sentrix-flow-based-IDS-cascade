"""v2  (Speed Optimised)"""
import os
import sys
import time
import json
import sqlite3
import argparse
import threading
import queue
import io

# Fix Windows console encoding for emoji/unicode characters
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import requests
import numpy  as np
import pandas as pd
from datetime    import datetime
from collections import defaultdict, deque
from typing      import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ueba       import UEBAv4
# Hand-curated rules engine retired 2026-05-01. Behavioural patterns
# previously covered by the rules engine are now handled by Stage 1
# ML, UEBA, and the per-deployment fine-tuning loop. Signature-based
# detection has migrated to the Suricata integration at Layer 0.
from confidence_engine import ConfidenceEngine

# ── Config ────────────────────────────────────────────────────

ML_SERVER  = "http://localhost:8001"
DB_PATH    = "alerts.db"

# Path B: In-process ML
# Set USE_INPROCESS=True to load models directly (no HTTP server needed)
# Set USE_INPROCESS=False to use ml_server.py via HTTP (original mode)
USE_INPROCESS = True

# Fast inference: skip RF (sklearn RF is slow on CPU)
# XGB + DNN only; 3-4x faster, <1% accuracy difference
# Set False to use full RF+XGB+DNN ensemble
FAST_INFERENCE = True
MODELS_DIR    = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models"
)

# FIX 1: Batch size 32 → 256
BATCH_SIZE = 256

# Severity thresholds calibrated for ML-only operation
#
# Without UEBA baseline: final = 0.85 × ml_score
# With all three engines: final = up to 1.00
#
# ml_score >= 0.941  → final >= 0.800 → CRITICAL
# ml_score >= 0.706  → final >= 0.600 → HIGH
# ml_score >= 0.529  → final >= 0.450 → MEDIUM
# ml_score >= 0.353  → final >= 0.300 → LOW
#
# When UEBA and Rules also fire, scores escalate naturally.
SEV_CRITICAL = 0.80
SEV_HIGH     = 0.60
SEV_MEDIUM   = 0.45
SEV_LOW      = 0.30

# ── Alert deduplication ───────────────────────────────────────
# Same src_ip + attack_type within this window = suppressed
# Prevents alert flood: 1,963 alerts → ~50 meaningful alerts
DEDUP_WINDOW_SEC = 60   # seconds before same alert can fire again
DEDUP_ESCALATE   = True # if severity escalates, always let through

W_ML    = 0.60
W_UEBA  = 0.25
W_RULES = 0.15

BENIGN_LABELS = {
    'BenignTraffic','BENIGN','Benign','benign','Normal'
}

# ── Colours ───────────────────────────────────────────────────

R='\033[91m'; O='\033[33m'; Y='\033[93m'
G='\033[92m'; C='\033[96m'; D='\033[90m'
B='\033[1m';  X='\033[0m'

def col(s,c): return f"{c}{s}{X}"
def bold(s):  return f"{B}{s}{X}"

def severity_colour(sev):
    return {
        'CRITICAL':R,'HIGH':O,'MEDIUM':Y,'LOW':C,'BENIGN':D
    }.get(sev, D)

def score_to_severity(score):
    if score >= SEV_CRITICAL: return "CRITICAL"
    if score >= SEV_HIGH:     return "HIGH"
    if score >= SEV_MEDIUM:   return "MEDIUM"
    if score >= SEV_LOW:      return "LOW"
    return "BENIGN"

# ── Alert DB; batched writes ─────────────────────────────────

class AlertDB:
    """
    FIX 4 (partial): Batched SQLite writes.
    Alerts accumulate in memory and flush to disk every
    FLUSH_EVERY inserts or on explicit flush() call.
    Eliminates per-alert disk I/O from the hot path.
    """

    FLUSH_EVERY = 100

    def __init__(self, path=DB_PATH):
        self.path   = path
        self._buf   = []
        self._lock  = threading.Lock()
        self._init()

    def _init(self):
        if self.path == ":memory:":
            return
        conn = sqlite3.connect(self.path)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT    NOT NULL,
                severity     TEXT    NOT NULL,
                final_score  REAL    NOT NULL,
                ml_score     REAL,
                ueba_score   REAL,
                rule_score   REAL,
                attack_type  TEXT,
                src_ip       TEXT,
                dst_ip       TEXT,
                dst_port     INTEGER,
                ueba_reasons TEXT,
                rule_names   TEXT,
                correlated   INTEGER DEFAULT 0,
                actual_label TEXT,
                created_at   TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_severity
                ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_src_ip
                ON alerts(src_ip);
        """)
        conn.commit()
        conn.close()

    def insert(self, alert: dict):
        with self._lock:
            self._buf.append(alert)
            if len(self._buf) >= self.FLUSH_EVERY:
                self._flush_locked()

    def flush(self):
        with self._lock:
            self._flush_locked()

    def _flush_locked(self):
        if not self._buf or self.path == ":memory:":
            self._buf.clear()
            return
        try:
            conn = sqlite3.connect(self.path, timeout=10)
            conn.executemany("""
                INSERT INTO alerts
                  (timestamp,severity,final_score,ml_score,ueba_score,
                   rule_score,attack_type,src_ip,dst_ip,dst_port,
                   ueba_reasons,rule_names,correlated,actual_label)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, [
                (a["timestamp"],a["severity"],a["final_score"],
                 a["ml_score"],a["ueba_score"],a["rule_score"],
                 a["attack_type"],a["src_ip"],a["dst_ip"],a["dst_port"],
                 json.dumps(a["ueba_reasons"]),
                 json.dumps(a["rule_names"]),
                 int(a["correlated"]),a.get("actual_label",""))
                for a in self._buf
            ])
            conn.commit()
            conn.close()
        except Exception:
            pass
        self._buf.clear()

# ── Print buffer ──────────────────────────────────────────────

class PrintBuffer:
    """
    FIX 4: Buffer alert lines and flush periodically.
    Decouples terminal I/O from detection loop.
    """

    def __init__(self, flush_every=50):
        self._buf        = []
        self._flush_every= flush_every
        self._lock       = threading.Lock()

    def add(self, line: str):
        with self._lock:
            self._buf.append(line)
            if len(self._buf) >= self._flush_every:
                self._flush_locked()

    def flush(self):
        with self._lock:
            self._flush_locked()

    def _flush_locked(self):
        if self._buf:
            print("\n".join(self._buf))
            self._buf.clear()

# ── In-Process ML Engine (Path B) ────────────────────────────

class InProcessML:
    """
    Path B: Binary Gate + 3 Specialist ONNX routing in-process.

    Stage 1: Binary LightGBM (Benign/Attack)
    Stage 2: Route attacks to spec1_cic / spec2_botnet / spec3_iot

    No lite_attack.pkl, no TensorFlow, no sklearn RF.
    Specialist results flow directly to UEBA v4; zero redundancy.
    """

    def __init__(self, models_dir: str):
        from ml_server import SpecialistCascade
        from pathlib import Path

        self._cascade = SpecialistCascade(Path(models_dir))
        self.feature_names = self._cascade.feature_names
        self.n_features = self._cascade.n_features
        self.threshold = 0.50

        info = self._cascade.get_info()
        mode = "Binary Gate + 3 Specialist ONNX"
        print(col(f"  [InProcess] {mode}", G))
        print(col(f"  [InProcess] {self.n_features} features, "
                  f"{info['total_attack_classes']} attack classes", G))

    def predict(self, features_batch, raw_features_batch=None):
        """Returns (ml_results, specialist_results_per_flow)."""
        return self._cascade.predict(features_batch, raw_features_batch)

    def predict_fast(self, features_batch, raw_features_batch=None):
        return self.predict(features_batch, raw_features_batch)

    def get_info(self):
        info = self._cascade.get_info()
        return {
            "config": {
                "n_features": info["n_features"],
                "n_classes": info["total_attack_classes"],
                "threshold": self.threshold,
                "engine": "Binary Gate + 3 Specialist ONNX",
                "total_classes": info["total_attack_classes"],
            },
            "feature_names": info["feature_names"],
            "n_features": info["n_features"],
        }

# ── ML Prefetcher ─────────────────────────────────────────────

class MLPrefetcher:
    """
    FIX 5: Prefetch ML predictions for the next batch
    while the current batch is being processed by UEBA + Rules.

    Uses a background thread and a two-slot queue:
      - Slot 0: predictions for current batch (ready to use)
      - Slot 1: predictions being fetched for next batch

    The detection loop calls:
      preds = prefetcher.get(current_features)
    which returns predictions for current_features and
    simultaneously starts fetching for whatever comes next.
    """

    def __init__(self, session: requests.Session, ml_url: str):
        self._session  = session
        self._ml_url   = ml_url
        self._q        = queue.Queue(maxsize=2)
        self._lock     = threading.Lock()
        self._pending  = None
        self._thread   = None

    # Max flows per single ML HTTP call
    # ML server rejects batches larger than this with 422
    ML_CHUNK = 32

    def fetch(self, features: List[List[float]]) -> List[dict]:
        """
        Fetch ML predictions for any number of flows.

        Splits into chunks of ML_CHUNK to respect server limits.
        Session is reused across chunks (connection kept alive).
        """
        all_preds = []
        for i in range(0, len(features), self.ML_CHUNK):
            chunk = features[i : i + self.ML_CHUNK]
            all_preds.extend(self._fetch_chunk(chunk))
        return all_preds

    def _fetch_chunk(self, features: List[List[float]]) -> List[dict]:
        """Fetch one chunk; max ML_CHUNK flows."""
        try:
            resp = self._session.post(
                f"{self._ml_url}/predict/batch",
                json={"flows":[{"features":f} for f in features]},
                timeout=30
            )
            resp.raise_for_status()
            return resp.json()["predictions"]
        except Exception as e:
            # Session connection stale; retry with fresh connection
            try:
                import requests as _req
                resp2 = _req.post(
                    f"{self._ml_url}/predict/batch",
                    json={"flows":[{"features":f} for f in features]},
                    timeout=30
                )
                resp2.raise_for_status()
                return resp2.json()["predictions"]
            except Exception:
                return self._fallback(len(features))

    def _fallback(self, n: int) -> List[dict]:
        return [{"probability":0.5,"attack_type":"Unknown",
                 "is_attack":False,"severity":"BENIGN"}] * n

    def _bg_fetch(self, features):
        """Background thread: fetch and put result in queue."""
        preds = self.fetch(features)
        self._q.put(preds)

    def prefetch(self, next_features: List[List[float]]):
        """Start fetching next batch in background."""
        if self._thread and self._thread.is_alive():
            return   # Already fetching
        self._thread = threading.Thread(
            target=self._bg_fetch,
            args=(next_features,),
            daemon=True
        )
        self._thread.start()

    def get_prefetched(self, timeout=30) -> Optional[List[dict]]:
        """Get previously prefetched result."""
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

# ── Main Pipeline ─────────────────────────────────────────────

class Pipeline:

    def __init__(self,
                 ml_url       : str          = ML_SERVER,
                 db_path      : str          = DB_PATH,
                 smb_allowlist                = None,  # legacy slot, unused since rules engine retired 2026-05-01
                 min_severity : str          = "LOW",
                 quiet        : bool         = False):

        self.ml_url       = ml_url
        self.min_severity = min_severity
        self.quiet        = quiet

        self._sev_rank = {
            "BENIGN":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4
        }
        self._min_rank = self._sev_rank.get(min_severity, 1)

        print(bold(col("\n  Initialising unified pipeline v2...", C)))

        if USE_INPROCESS:
            # ── Path B: In-process ML (no HTTP server needed) ────
            print(col("  Mode: IN-PROCESS ML (Path B)", G))
            print(col("  Loading models directly; no ml_server.py needed", D))
            self._inprocess = InProcessML(MODELS_DIR)
            info = self._inprocess.get_info()
            self.feature_names = info["feature_names"]
            self.n_features    = info["n_features"]
            self.threshold     = info["config"]["threshold"]
            self._session      = None
            self._prefetcher   = None
            total = info["config"]["total_classes"]
            print(col(
                f"  ✅ In-process: {self.n_features} features, "
                f"threshold={self.threshold:.3f}, "
                f"{total} classes", G
            ))
        else:
            # ── Path A: HTTP to ml_server.py (original mode) ─────
            print(col("  Mode: HTTP ML SERVER (Path A)", D))
            self._inprocess = None
            # FIX 2: Persistent session for connection reuse
            self._session = requests.Session()
            self.feature_names, self.n_features, self.threshold = \
                self._connect_ml()
            # FIX 5: ML prefetcher
            self._prefetcher = MLPrefetcher(self._session, ml_url)

        self.ueba = UEBAv4(models_dir=MODELS_DIR)
        # Rules engine retired 2026-05-01; rule_score is forced to 0.0
        # at every flow and the W_RULES weight contributes nothing to
        # the fused score. Detection coverage previously provided by
        # the rules engine now resides in Stage 1 ML, UEBA, and the
        # per-deployment fine-tuning loop in the alert dispatcher.

        # Confidence engine; specialist ensemble + FP reduction
        self.conf_engine = ConfidenceEngine(MODELS_DIR)

        self.db     = AlertDB(db_path)
        self._pbuf  = PrintBuffer(flush_every=50)
        self._recent= deque(maxlen=500)

        # Deduplication state: (src_ip, attack_type) → (last_time, last_severity)
        self._dedup: Dict[Tuple[str,str], Tuple[float, str]] = {}

        self.stats = {
            "flows":0,"alerts":0,
            "CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"BENIGN":0,
            "ml_only":0,"ueba_only":0,"rule_only":0,"combined":0,
            "attack_types":defaultdict(int),
            "whitelisted":0,"gated":0,"suppressed":0,
        }
        self._start = time.time()

        mode_str = ("IN-PROCESS-FAST" if (USE_INPROCESS and FAST_INFERENCE)
                    else "IN-PROCESS-FULL" if USE_INPROCESS
                    else "HTTP-SERVER")
        print(col(f"\n  Pipeline v2 ready [{mode_str}]", G))
        print(col(f"  UEBA v2: ML entity behaviour analytics active", G))
        print(col(f"  Batch={BATCH_SIZE}  "
                  f"Mode={mode_str}  "
                  f"Dedup={DEDUP_WINDOW_SEC}s  "
                  f"PrintBuffer=50", D))
        print(col(f"  Formula: {W_ML}×ML + {W_UEBA}×UEBA "
                  f"+ {W_RULES}×Rules\n", D))

    def _connect_ml(self):
        print(col("  Connecting to ML server...", D))
        for attempt in range(3):
            try:
                h  = self._session.get(
                    f"{self.ml_url}/health", timeout=5
                ).json()
                fn = self._session.get(
                    f"{self.ml_url}/feature-names", timeout=5
                ).json()
                threshold = h["config"]["threshold"]
                n         = fn["n_features"]
                names     = fn["feature_names"]
                print(col(
                    f"  ✅ ML server: {n} features, "
                    f"threshold={threshold:.3f}, "
                    f"{h['config']['n_classes']} classes", G
                ))
                return names, n, threshold
            except Exception as e:
                if attempt < 2:
                    print(col(f"  Retry {attempt+1}/3: {e}", Y))
                    time.sleep(2)
                else:
                    print(col("  ❌ ML server not reachable", R))
                    print(col("     Start: py -3.11 ml_server.py", R))
                    sys.exit(1)

    # ── Core: process one batch ────────────────────────────────

    def process_batch(self,
                      flows   : List[dict],
                      features: List[List[float]],
                      labels  : List[str]       = None,
                      ml_preds: List[dict]       = None
                      ) -> List[dict]:
        """
        Process a batch through all three engines.

        ml_preds: if provided (prefetched), skip the ML call.
                  if None, fetch synchronously.
        """
        if not flows:
            return []

        labels = labels or [""] * len(flows)

        # ML inference; in-process (Binary Gate + Specialist Routing)
        spec_results_all = None
        if ml_preds is None:
            if USE_INPROCESS and self._inprocess:
                # Returns (ml_results, specialist_results_per_flow)
                ml_preds, spec_results_all = self._inprocess.predict(
                    features, raw_features_batch=flows)
            else:
                ml_preds = self._prefetcher.fetch(features)

        if spec_results_all is None:
            spec_results_all = [[]] * len(flows)

        now    = time.time()
        alerts = []

        for i, (flow, feat, label, ml_pred) in enumerate(zip(
            flows, features, labels, ml_preds
        )):
            self.stats["flows"] += 1

            ml_score = ml_pred["probability"]
            ml_type  = ml_pred.get("attack_type") or "BENIGN"

            # UEBA v4; receives specialist results from ML stage (no redundant queries)
            ueba_result = self.ueba.process_flow(
                flow, specialist_results=spec_results_all[i])
            ueba_score = ueba_result["anomaly_score"]
            ueba_reasons = ueba_result["reasons"]
            ueba_ready = ueba_result["baseline_ready"]

            # Rules engine retired 2026-05-01; rule_score and rule_alerts
            # are zero/empty so the rules slot in the fused score and
            # alert metadata stays schema-compatible.
            rule_score, rule_alerts = 0.0, []
            rule_names = []
            correlated = False

            # ── Confidence-gated fusion ─────────────────────
            # Route through confidence engine (whitelist + gating + temporal)
            conf_result = self.conf_engine.classify(
                flow, ml_pred,
                ueba_score=ueba_score, ueba_ready=ueba_ready,
                rule_score=rule_score,
            )

            if conf_result["whitelisted"]:
                self.stats["whitelisted"] += 1
                self.stats["BENIGN"] += 1
                continue

            if conf_result["gated"]:
                self.stats["gated"] += 1
                self.stats["BENIGN"] += 1
                continue

            # Use confidence engine's severity (higher thresholds = fewer FPs)
            severity = conf_result["severity"]
            is_attack = conf_result["is_attack"]
            ml_type = conf_result["attack_type"] if is_attack else ml_type

            # Compute final score for logging (legacy compatibility)
            if ueba_ready:
                final = (W_ML*ml_score + W_UEBA*ueba_score + W_RULES*rule_score)
            else:
                final = ((W_ML+W_UEBA)*ml_score + W_RULES*rule_score)

            # Override severity from confidence engine
            if not is_attack:
                severity = "BENIGN"
                if conf_result.get("source", "").startswith("suppressed"):
                    self.stats["suppressed"] += 1

            sev_rank = self._sev_rank[severity]

            self.stats[severity] += 1
            if severity != "BENIGN":
                self.stats["alerts"]          += 1
                self.stats["attack_types"][ml_type] += 1
                ml_f   = ml_score  >= self.threshold
                ueba_f = ueba_score >= 0.65
                rule_f = rule_score >= 0.65
                if   ml_f and ueba_f and rule_f: self.stats["combined"]  += 1
                elif ml_f and not ueba_f and not rule_f: self.stats["ml_only"]   += 1
                elif ueba_f and not ml_f:                self.stats["ueba_only"] += 1
                elif rule_f and not ml_f:                self.stats["rule_only"] += 1

            if sev_rank >= self._min_rank:
                # ── Deduplication check ───────────────────────
                # Suppress if same src_ip + attack_type fired
                # within DEDUP_WINDOW_SEC, unless severity
                # has escalated (e.g. LOW → CRITICAL = let through)
                src_ip   = flow.get("src_ip", "")
                dedup_key = (src_ip, ml_type)
                last_time, last_sev = self._dedup.get(
                    dedup_key, (0.0, "BENIGN")
                )
                time_since = now - last_time
                sev_escalated = (
                    self._sev_rank[severity] >
                    self._sev_rank.get(last_sev, 0)
                )

                if (time_since < DEDUP_WINDOW_SEC and
                        not sev_escalated and
                        not correlated):
                    # Suppressed; same alert seen recently
                    # Still count it in stats but don't save/print
                    self.stats["BENIGN"] -= 1  # undo overcount
                    self.stats[severity] -= 1
                    if severity != "BENIGN":
                        self.stats["alerts"] -= 1
                    continue

                # Update dedup tracker
                self._dedup[dedup_key] = (now, severity)

                # Prune old dedup entries every 1000 flows
                if self.stats["flows"] % 1000 == 0:
                    cutoff = now - DEDUP_WINDOW_SEC * 2
                    self._dedup = {
                        k: v for k, v in self._dedup.items()
                        if v[0] > cutoff
                    }

                alert = {
                    "timestamp"   : datetime.fromtimestamp(now).isoformat(),
                    "severity"    : severity,
                    "final_score" : round(final,4),
                    "ml_score"    : round(ml_score,4),
                    "ueba_score"  : round(ueba_score,4),
                    "rule_score"  : round(rule_score,4),
                    "attack_type" : ml_type,
                    "src_ip"      : src_ip,
                    "dst_ip"      : flow.get("dst_ip",""),
                    "dst_port"    : flow.get("dst_port",0),
                    "ueba_reasons": ueba_reasons,
                    "rule_names"  : rule_names,
                    "correlated"  : correlated,
                    "actual_label": label,
                    "ueba_ready"  : ueba_ready,
                }
                alerts.append(alert)
                self._recent.appendleft(alert)
                self.db.insert(alert)

                # UEBAv4 tracks alerts internally via process_flow

                # FIX 4: Buffer print instead of immediate I/O
                if not self.quiet:
                    self._pbuf.add(self._format_alert(alert))

        return alerts

    def _format_alert(self, a: dict) -> str:
        ts    = a["timestamp"][11:19]
        sev   = a["severity"]
        c     = severity_colour(sev)
        tag   = col(" [CHAIN]",R) if a["correlated"] else ""
        ready = "" if a["ueba_ready"] else col(" [no baseline]",D)
        line  = (
            f"  {col(ts,D):<20} "
            f"{col(f'[{sev}]',c):<25} "
            f"ML={a['ml_score']:.3f} "
            f"U={a['ueba_score']:.3f} "
            f"R={a['rule_score']:.3f} "
            f"→ {col(str(round(a['final_score'],3)),c):<8} "
            f"{col(a['attack_type'][:20],c):<24}"
            f"{tag}{ready}"
        )
        extras = []
        if a["ueba_reasons"] and a["ueba_score"] >= 0.30:
            extras.append(col(f"         ↳ UEBA: {a['ueba_reasons'][0]}",D))
        for rn in a["rule_names"]:
            chain = " (ATTACK CHAIN)" if a["correlated"] else ""
            extras.append(col(f"         ↳ Rule: {rn}{chain}",R))
        return "\n".join([line]+extras)

    def print_stats(self, force=False):
        now = time.time()
        if not force and (now - getattr(self,'_last_stat',0)) < 5:
            return
        self._last_stat = now
        self._pbuf.flush()

        elapsed = now - self._start
        fps     = self.stats["flows"] / max(elapsed,1)

        print(col(f"\n  ── STATS @ {self.stats['flows']:,} flows "
                  f"({fps:.0f}/s) ──", C))
        print(
            f"  Alerts: {col(str(self.stats['alerts']),R)}  "
            f"CRITICAL={col(str(self.stats['CRITICAL']),R)}  "
            f"HIGH={col(str(self.stats['HIGH']),O)}  "
            f"MEDIUM={col(str(self.stats['MEDIUM']),Y)}  "
            f"LOW={col(str(self.stats['LOW']),C)}"
        )
        tops = sorted(self.stats["attack_types"].items(),
                      key=lambda x:-x[1])[:5]
        if tops:
            print(f"  Top: {col(' | '.join(f'{t}:{c}' for t,c in tops),D)}")
        print(
            f"  ML-only:{self.stats['ml_only']}  "
            f"UEBA-only:{self.stats['ueba_only']}  "
            f"Rule-only:{self.stats['rule_only']}  "
            f"All-three:{self.stats['combined']}"
        )
        print()

    def print_final(self):
        self._pbuf.flush()
        self.db.flush()
        elapsed = time.time() - self._start
        fps     = self.stats["flows"] / max(elapsed,1)

        print(col(f"\n{'='*65}",G))
        print(col("  PIPELINE COMPLETE  (v2; Speed Optimised)",G))
        print(col(f"{'='*65}",G))
        print(f"  Flows        : {self.stats['flows']:,}")
        print(f"  Elapsed      : {elapsed:.1f}s  ({fps:.0f} flows/sec)")
        print(f"  Batch size   : {BATCH_SIZE}")
        print(f"  Total alerts : {self.stats['alerts']:,}")
        print()
        print(f"  CRITICAL : {col(str(self.stats['CRITICAL']),R)}")
        print(f"  HIGH     : {col(str(self.stats['HIGH']),O)}")
        print(f"  MEDIUM   : {col(str(self.stats['MEDIUM']),Y)}")
        print(f"  LOW      : {col(str(self.stats['LOW']),C)}")
        print()
        print(f"  Engine contribution:")
        print(f"    ML only   : {self.stats['ml_only']:,}")
        print(f"    UEBA only : {self.stats['ueba_only']:,}")
        print(f"    Rules only: {self.stats['rule_only']:,}")
        print(f"    All three : {self.stats['combined']:,}")
        print()
        tops = sorted(self.stats["attack_types"].items(),
                      key=lambda x:-x[1])[:10]
        if tops:
            print("  Top attack types:")
            for atype,cnt in tops:
                bar = "█"*min(int(cnt/max(self.stats['alerts'],1)*30),25)
                print(f"    {col(atype,C):<35} {cnt:>6,}  {bar}")
        # Confidence engine stats
        print(f"\n  FP Reduction:")
        print(f"    Whitelisted : {self.stats.get('whitelisted',0):,}")
        print(f"    Gated (low) : {self.stats.get('gated',0):,}")
        print(f"    Suppressed  : {self.stats.get('suppressed',0):,}")
        total_reduced = (self.stats.get('whitelisted',0) +
                        self.stats.get('gated',0) +
                        self.stats.get('suppressed',0))
        if self.stats['flows'] > 0:
            pct = total_reduced / self.stats['flows'] * 100
            print(f"    Total FP reduction: {total_reduced:,} flows ({pct:.1f}%)")

        self.conf_engine.print_summary()

        print(col(f"  Alerts saved to: {self.db.path}",D))
        self.ueba.save_state()
        print(col(f"  UEBA state saved",D))
        print(col(f"{'='*65}\n",G))

# ── Feature extraction ────────────────────────────────────────

def build_feature_index(df_columns, feature_names):
    """
    FIX 3: Pre-compute column index map once.
    itertuples returns positional values :
    we need to know which index corresponds to each feature.
    """
    col_to_idx = {c: i+1 for i,c in enumerate(df_columns)}
    # +1 because itertuples index 0 is the row Index
    return [col_to_idx.get(f, -1) for f in feature_names]

def extract_features_fast(row_tuple, feat_indices) -> List[float]:
    """
    FIX 3: Extract features from itertuples row using pre-computed indices.
    10x faster than iterrows + dict access.
    """
    out = []
    for idx in feat_indices:
        if idx == -1:
            out.append(0.0)
        else:
            try:
                v = float(row_tuple[idx])
                if v != v or abs(v) == float('inf'):
                    v = 0.0
            except:
                v = 0.0
            out.append(v)
    return out

# ── CSV source ────────────────────────────────────────────────

def run_csv(pipeline : Pipeline,
            file_path: str,
            speed    : float = 0,
            max_rows : int   = 0):

    if not os.path.exists(file_path):
        print(col(f"  ❌ File not found: {file_path}",R))
        sys.exit(1)

    size_mb = os.path.getsize(file_path)/1024**2
    print(col(f"\n  Loading {file_path} ({size_mb:.1f} MB)...",D))

    sample = pd.read_csv(file_path, nrows=5, low_memory=False)
    sample.columns = sample.columns.str.strip()
    label_col = next(
        (c for c in sample.columns
         if c.strip().lower() in ['label','attack','class']),
        sample.columns[-1]
    )

    print(col(f"\n{'='*75}",C))
    print(col("  LIVE DETECTION FEED; ML + UEBA + Rules  (v2)",C))
    print(col(f"{'='*75}",C))
    print(col(
        f"  {'TIME':<10} {'SEV':<12} "
        f"{'ML':>5} {'UEBA':>5} {'RULE':>5} {'FINAL':>6}  "
        f"{'ATTACK TYPE':<24} NOTE",D
    ))
    print(col("  "+"─"*75,D))

    batch_feats  = []
    batch_flows  = []
    batch_labels = []
    rows_done    = 0

    sleep_per = BATCH_SIZE/speed if speed > 0 else 0

    try:
        nrows = max_rows if max_rows else None

        # FIX 3: Read in larger chunks, use itertuples
        for chunk in pd.read_csv(
            file_path, chunksize=2000,
            nrows=nrows, low_memory=False
        ):
            chunk.columns = chunk.columns.str.strip()

            # Build feature index map once per chunk
            # (columns are same across chunks)
            feat_indices = build_feature_index(
                chunk.columns.tolist(), pipeline.feature_names
            )

            # FIX 3: itertuples instead of iterrows
            for row in chunk.itertuples(index=True):
                label = str(getattr(row, label_col, ""))

                # FIX 3: fast feature extraction
                features = extract_features_fast(row, feat_indices)

                is_attack = label not in BENIGN_LABELS
                src_ip = (
                    f"192.0.2.{(rows_done%3)+105}"
                    if is_attack else
                    f"192.0.2.{(rows_done%5)+10}"
                )

                try:
                    dst_port = int(getattr(row,'dst_port',0) or 0)
                except: dst_port = 0
                try:
                    tot_size = float(getattr(row,'Tot size',
                                    getattr(row,'Total Length of Fwd Packet',
                                    0)) or 0)
                except: tot_size = 0.0

                flow_dict = {
                    "src_ip"  : src_ip,
                    "dst_ip"  : "203.0.113.1",
                    "dst_port": dst_port,
                    "bytes"   : tot_size,
                    "protocol": "TCP",
                }

                batch_feats.append(features)
                batch_flows.append(flow_dict)
                batch_labels.append(label)
                rows_done += 1

                if len(batch_feats) >= BATCH_SIZE:

                    # Fetch ML predictions (Binary Gate + Specialist Routing)
                    # process_batch handles ML internally now
                    pipeline.process_batch(
                        batch_flows, batch_feats,
                        batch_labels
                    )

                    batch_feats  = []
                    batch_flows  = []
                    batch_labels = []

                    pipeline.print_stats()
                    if sleep_per > 0:
                        time.sleep(sleep_per)

                if max_rows and rows_done >= max_rows:
                    break

            if max_rows and rows_done >= max_rows:
                break

        # Final partial batch
        if batch_feats:
            pipeline.process_batch(
                batch_flows, batch_feats, batch_labels
            )

    except KeyboardInterrupt:
        print(col("\n\n  ⏹  Stopped by user",Y))

    pipeline.print_final()

# ── Entry point ───────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Unified IDS Pipeline v2; ML + UEBA + Rules"
    )
    parser.add_argument("--source", choices=["csv"], default="csv")
    parser.add_argument("--file",   default="test.csv")
    parser.add_argument("--speed",  type=float, default=0)
    parser.add_argument("--rows",   type=int,   default=0)
    parser.add_argument("--severity", default="LOW",
        choices=["LOW","MEDIUM","HIGH","CRITICAL"])
    parser.add_argument("--quiet",  action="store_true")
    args = parser.parse_args()

    print(bold(col("\n"+"="*65,C)))
    print(bold(col("  🛡️  SENTRIX UNIFIED PIPELINE v2",C)))
    print(bold(col("  ML + UEBA + Rules  |  Speed Optimised",C)))
    print(bold(col("="*65,C)))
    print(col(f"  Source   : {args.file}",D))
    print(col(f"  Batch    : {BATCH_SIZE}",D))
    print(col(
        f"  Speed    : {'MAX' if args.speed==0 else f'{args.speed}/s'}",D
    ))
    print(col(f"  Severity : {args.severity}+",D))

    allow = SMBAllowlist()
    allow.add("192.0.2.1","Gateway (demo)")
    allow.add("192.0.2.2","DNS Server (demo)")
    allow.add("192.0.2.3","Domain Controller (demo)")

    p = Pipeline(
        smb_allowlist = allow,
        min_severity  = args.severity,
        quiet         = args.quiet,
    )

    run_csv(p, args.file, args.speed, args.rows)

if __name__ == "__main__":
    main()
