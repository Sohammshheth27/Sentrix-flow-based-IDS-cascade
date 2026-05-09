"""Network Capture Service (Layer 0)"""
import os
import sys
import io
import csv
import json
import time
import hashlib
import logging
import threading
import queue
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

log = logging.getLogger("capture")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ═══════════════════════════════════════════════════════════════
#  JA3 COMPUTATION
# ═══════════════════════════════════════════════════════════════

def compute_ja3(tls_version: int, cipher_suites: List[int],
                extensions: List[int], elliptic_curves: List[int],
                ec_point_formats: List[int]) -> str:
    """
    Compute JA3 fingerprint from TLS ClientHello fields.
    JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)
    """
    # Filter GREASE values (0x?a?a pattern); these are randomized and should be excluded
    grease = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
              0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
              0xcaca, 0xdada, 0xeaea, 0xfafa}

    ciphers = [c for c in cipher_suites if c not in grease]
    exts = [e for e in extensions if e not in grease]
    curves = [c for c in elliptic_curves if c not in grease]
    formats = [f for f in ec_point_formats if f not in grease]

    ja3_str = (f"{tls_version},"
               f"{'-'.join(str(c) for c in ciphers)},"
               f"{'-'.join(str(e) for e in exts)},"
               f"{'-'.join(str(c) for c in curves)},"
               f"{'-'.join(str(f) for f in formats)}")

    return hashlib.md5(ja3_str.encode()).hexdigest()

def compute_ja3s(tls_version: int, cipher_suite: int,
                 extensions: List[int]) -> str:
    """Compute JA3S fingerprint from TLS ServerHello."""
    exts = "-".join(str(e) for e in extensions) if extensions else ""
    ja3s_str = f"{tls_version},{cipher_suite},{exts}"
    return hashlib.md5(ja3s_str.encode()).hexdigest()

# ═══════════════════════════════════════════════════════════════
#  ZEEK LOG READER (Production Mode)
# ═══════════════════════════════════════════════════════════════

class ZeekLogReader:
    """
    Reads Zeek conn.log + ssl.log + dns.log and merges into enriched flows.

    Zeek outputs tab-separated log files. This reader:
    1. Tails conn.log for new flows (inotify or polling)
    2. Correlates with ssl.log for JA3/TLS metadata
    3. Correlates with dns.log for domain names
    4. Outputs enriched flow dicts to the queue
    """

    def __init__(self, log_dir: str = "/opt/zeek/logs/current",
                 flow_queue: queue.Queue = None):
        self.log_dir = Path(log_dir)
        self.queue = flow_queue or queue.Queue(maxsize=50000)
        self._running = False
        self._thread = None

        # Correlation tables: uid → metadata
        self._ssl_cache: Dict[str, dict] = {}   # uid → {ja3, ja3s, sni, ...}
        self._dns_cache: Dict[str, str] = {}     # query_ip → domain
        self._ssl_cache_lock = threading.Lock()

        # File positions (for tailing)
        self._file_pos: Dict[str, int] = {}

        self.stats = {
            "flows_read": 0,
            "ssl_records": 0,
            "dns_records": 0,
            "enriched_flows": 0,
        }

    def start(self):
        """Start reading Zeek logs in background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log.info(f"[ZeekReader] Started, watching {self.log_dir}")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        """Main loop: poll Zeek logs for new entries."""
        while self._running:
            try:
                # Read ssl.log first (build correlation cache)
                self._read_ssl_log()
                # Read dns.log
                self._read_dns_log()
                # Read conn.log and enrich flows
                self._read_conn_log()
                time.sleep(0.5)  # poll interval
            except Exception as e:
                log.error(f"[ZeekReader] Error: {e}")
                time.sleep(2)

    def _read_zeek_log(self, filename: str) -> List[dict]:
        """Read new lines from a Zeek log file."""
        path = self.log_dir / filename
        if not path.exists():
            return []

        pos = self._file_pos.get(filename, 0)
        entries = []

        try:
            with open(path, 'r') as f:
                f.seek(pos)
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        # Parse header for field names
                        if line.startswith('#fields'):
                            self._fields = line.split('\t')[1:]
                        continue
                    fields = line.split('\t')
                    if hasattr(self, '_fields') and len(fields) == len(self._fields):
                        entry = dict(zip(self._fields, fields))
                        entries.append(entry)
                self._file_pos[filename] = f.tell()
        except Exception as e:
            log.debug(f"[ZeekReader] Read error {filename}: {e}")

        return entries

    def _read_ssl_log(self):
        """Read ssl.log for JA3/TLS metadata."""
        entries = self._read_zeek_log("ssl.log")
        for entry in entries:
            uid = entry.get("uid", "")
            if not uid:
                continue

            with self._ssl_cache_lock:
                self._ssl_cache[uid] = {
                    "ja3": entry.get("ja3", ""),
                    "ja3s": entry.get("ja3s", ""),
                    "sni": entry.get("server_name", ""),
                    "tls_version": entry.get("version", ""),
                    "cipher_suite": entry.get("cipher", ""),
                    "cert_subject": entry.get("subject", ""),
                    "cert_issuer": entry.get("issuer", ""),
                    "validation_status": entry.get("validation_status", ""),
                }
                self.stats["ssl_records"] += 1

        # Prune old SSL cache entries (keep last 50K)
        if len(self._ssl_cache) > 50000:
            with self._ssl_cache_lock:
                keys = list(self._ssl_cache.keys())
                for k in keys[:10000]:
                    del self._ssl_cache[k]

    def _read_dns_log(self):
        """Read dns.log for domain name resolution."""
        entries = self._read_zeek_log("dns.log")
        for entry in entries:
            query = entry.get("query", "")
            answers = entry.get("answers", "")
            if query and answers:
                for ip in answers.split(","):
                    ip = ip.strip()
                    if ip and ip != "-":
                        self._dns_cache[ip] = query
                        self.stats["dns_records"] += 1

        # Prune DNS cache
        if len(self._dns_cache) > 100000:
            keys = list(self._dns_cache.keys())
            for k in keys[:20000]:
                del self._dns_cache[k]

    def _read_conn_log(self):
        """Read conn.log and produce enriched flow dicts."""
        entries = self._read_zeek_log("conn.log")
        for entry in entries:
            self.stats["flows_read"] += 1
            flow = self._zeek_to_flow(entry)
            if flow:
                self.stats["enriched_flows"] += 1
                try:
                    self.queue.put_nowait(flow)
                except queue.Full:
                    pass  # drop flow if queue full (backpressure)

    def _zeek_to_flow(self, entry: dict) -> Optional[dict]:
        """Convert Zeek conn.log entry to our enriched flow dict."""
        src_ip = entry.get("id.orig_h", "")
        dst_ip = entry.get("id.resp_h", "")
        if not src_ip or not dst_ip:
            return None

        uid = entry.get("uid", "")
        proto = entry.get("proto", "tcp").lower()
        proto_num = {"tcp": 6, "udp": 17, "icmp": 1}.get(proto, 0)

        def safe_float(v, default=0.0):
            try:
                return float(v) if v and v != "-" else default
            except (ValueError, TypeError):
                return default

        def safe_int(v, default=0):
            try:
                return int(v) if v and v != "-" else default
            except (ValueError, TypeError):
                return default

        duration = safe_float(entry.get("duration", "0"))
        orig_bytes = safe_float(entry.get("orig_bytes", "0"))
        resp_bytes = safe_float(entry.get("resp_bytes", "0"))
        orig_pkts = safe_int(entry.get("orig_pkts", "0"))
        resp_pkts = safe_int(entry.get("resp_pkts", "0"))
        total_bytes = orig_bytes + resp_bytes
        total_pkts = orig_pkts + resp_pkts

        # Connection state → flags
        conn_state = entry.get("conn_state", "")
        syn_flag = 1 if conn_state in ("S0", "S1", "SF", "SH", "SHR", "RSTO", "RSTOS0") else 0
        ack_flag = 1 if conn_state in ("SF", "S1") else 0
        rst_flag = 1 if "R" in conn_state else 0
        fin_flag = 1 if "F" in conn_state else 0

        flow = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": safe_int(entry.get("id.orig_p", "0")),
            "dst_port": safe_int(entry.get("id.resp_p", "0")),
            "protocol": proto_num,
            "duration": duration,
            "total_bytes": total_bytes,
            "total_pkts": total_pkts,
            "fwd_bytes": orig_bytes,
            "bwd_bytes": resp_bytes,
            "bytes": total_bytes,
            "syn_flag": syn_flag,
            "ack_flag": ack_flag,
            "rst_flag": rst_flag,
            "fin_flag": fin_flag,
            "psh_flag": 0,
            "bytes_per_sec": total_bytes / max(duration, 0.001),
            "pkts_per_sec": total_pkts / max(duration, 0.001),
            "pkt_size_avg": total_bytes / max(total_pkts, 1),
            "capture_time": safe_float(entry.get("ts", str(time.time()))),
            "flow_id": uid,
            # Keep raw Zeek conn_state so rules can distinguish successful
            # connections (SF) from scans (S0, REJ) and failed auth (RSTR,
            # RSTO). Rule 7 (Direct-to-IP) and future brute-force rules
            # depend on this.
            "conn_state": conn_state,
        }

        # Enrich with SSL/TLS metadata
        with self._ssl_cache_lock:
            ssl = self._ssl_cache.get(uid, {})

        if ssl:
            flow["ja3"] = ssl.get("ja3", "")
            flow["ja3s"] = ssl.get("ja3s", "")
            flow["sni"] = ssl.get("sni", "")
            flow["tls_version"] = ssl.get("tls_version", "")
            flow["cipher_suite"] = ssl.get("cipher_suite", "")
            flow["cert_subject"] = ssl.get("cert_subject", "")
            cert_issuer = ssl.get("cert_issuer", "")
            cert_subject = ssl.get("cert_subject", "")
            flow["cert_self_signed"] = (cert_subject == cert_issuer and cert_subject != "")
            flow["cert_expired"] = ssl.get("validation_status", "") == "expired"

        # Enrich with DNS (reverse lookup)
        domain = self._dns_cache.get(dst_ip, "")
        if domain:
            flow["dns_query"] = domain
        elif ssl.get("sni"):
            flow["dns_query"] = ssl["sni"]

        return flow

# ═══════════════════════════════════════════════════════════════
#  CSV REPLAY SOURCE (Testing/Offline Mode)
# ═══════════════════════════════════════════════════════════════

class CSVReplaySource:
    """
    Reads CSV files (CICFlowMeter output or test.csv) and produces flows.
    Adds simulated src_ips and timestamps for UEBA baseline building.
    """

    BENIGN_LABELS = {'BenignTraffic', 'BENIGN', 'Benign', 'benign', 'Normal'}

    def __init__(self, file_path: str, flow_queue: queue.Queue = None,
                 max_rows: int = 0, speed: float = 0):
        self.file_path = file_path
        self.queue = flow_queue or queue.Queue(maxsize=50000)
        self.max_rows = max_rows
        self.speed = speed  # flows/sec, 0 = max speed
        self._running = False
        self._thread = None
        self.stats = {"flows_read": 0, "enriched_flows": 0}

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log.info(f"[CSVReplay] Started: {self.file_path}")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        import pandas as pd

        try:
            nrows = self.max_rows if self.max_rows else None
            for chunk in pd.read_csv(self.file_path, chunksize=2000,
                                     nrows=nrows, low_memory=False):
                if not self._running:
                    break

                chunk.columns = chunk.columns.str.strip()
                label_col = next(
                    (c for c in chunk.columns
                     if c.strip().lower() in ('label', 'attack', 'class')),
                    chunk.columns[-1]
                )

                for row in chunk.itertuples():
                    if not self._running:
                        break

                    self.stats["flows_read"] += 1
                    label = str(getattr(row, label_col, ""))
                    is_attack = label not in self.BENIGN_LABELS
                    idx = self.stats["flows_read"]

                    # Simulate different IPs for attack vs benign
                    if is_attack:
                        src_ip = f"192.0.2.{(idx % 3) + 105}"
                    else:
                        src_ip = f"192.168.1.{(idx % 5) + 10}"

                    flow = self._row_to_flow(row, chunk.columns, src_ip, label)
                    if flow:
                        self.stats["enriched_flows"] += 1
                        try:
                            self.queue.put(flow, timeout=5)
                        except queue.Full:
                            pass

                    if self.speed > 0:
                        time.sleep(1.0 / self.speed)

        except Exception as e:
            log.error(f"[CSVReplay] Error: {e}")
        finally:
            # Signal end of stream
            try:
                self.queue.put(None, timeout=2)
            except queue.Full:
                pass

    def _row_to_flow(self, row, columns, src_ip: str, label: str) -> dict:
        def get_val(names, default=0.0):
            for name in names:
                safe = name.replace(' ', '_').replace('.', '_').replace('/', '_')
                val = getattr(row, safe, None)
                if val is not None:
                    try:
                        return float(val)
                    except (ValueError, TypeError):
                        pass
            return default

        dst_port = int(get_val(["Dst Port", "dst_port", "Dport"], 0))
        duration = get_val(["Flow Duration", "duration", "Dur"], 0)
        total_bytes = get_val(["Tot size", "total_bytes", "TotBytes"], 0)

        flow = {
            "src_ip": src_ip,
            "dst_ip"  : "203.0.113.1",
            "src_port": int(get_val(["Src Port", "src_port"], 0)),
            "dst_port": dst_port,
            "protocol": int(get_val(["Protocol", "protocol", "Proto_num"], 6)),
            "duration": duration,
            "total_bytes": total_bytes,
            "total_pkts": get_val(["Tot Fwd Pkts", "TotPkts", "total_pkts"], 0),
            "fwd_bytes": get_val(["TotLen Fwd Pkts", "fwd_bytes", "SrcBytes"], 0),
            "bwd_bytes": get_val(["TotLen Bwd Pkts", "bwd_bytes"], 0),
            "bytes": total_bytes,
            "syn_flag": int(get_val(["SYN Flag Cnt", "syn_flag"], 0)),
            "ack_flag": int(get_val(["ACK Flag Cnt", "ack_flag"], 0)),
            "rst_flag": int(get_val(["RST Flag Cnt", "rst_flag"], 0)),
            "fin_flag": int(get_val(["FIN Flag Cnt", "fin_flag"], 0)),
            "psh_flag": int(get_val(["PSH Flag Cnt", "psh_flag"], 0)),
            "bytes_per_sec": get_val(["Flow Byts/s", "bytes_per_sec"], 0),
            "pkts_per_sec": get_val(["Flow Pkts/s", "pkts_per_sec"], 0),
            "pkt_size_avg": get_val(["Pkt Size Avg", "pkt_size_avg", "Pkt Len Mean"], 0),
            "capture_time": time.time(),
            "flow_id": f"csv-{self.stats['flows_read']}",
            "actual_label": label,
        }

        # Copy all raw features for specialist routing
        for col in columns:
            safe = col.replace(' ', '_').replace('.', '_').replace('/', '_')
            val = getattr(row, safe, None)
            if val is not None and col not in flow:
                try:
                    flow[col] = float(val)
                except (ValueError, TypeError):
                    pass

        return flow

# ═══════════════════════════════════════════════════════════════
#  CAPTURE SERVICE (Unified Interface)
# ═══════════════════════════════════════════════════════════════

class CaptureService:
    """
    Unified capture interface. Wraps Zeek, CSV, or scapy source.

    Usage:
        cap = CaptureService(mode="zeek", zeek_log_dir="/opt/zeek/logs/current")
        cap = CaptureService(mode="csv", csv_file="test.csv", max_rows=5000)
        cap.start()
        flow = cap.get_flow(timeout=1.0)
    """

    def __init__(self, mode: str = "csv", **kwargs):
        self.mode = mode
        self.flow_queue = queue.Queue(maxsize=kwargs.get("queue_size", 50000))
        self._source = None

        if mode == "zeek":
            self._source = ZeekLogReader(
                log_dir=kwargs.get("zeek_log_dir", "/opt/zeek/logs/current"),
                flow_queue=self.flow_queue,
            )
        elif mode == "csv":
            self._source = CSVReplaySource(
                file_path=kwargs.get("csv_file", "test.csv"),
                flow_queue=self.flow_queue,
                max_rows=kwargs.get("max_rows", 0),
                speed=kwargs.get("speed", 0),
            )
        else:
            raise ValueError(f"Unknown capture mode: {mode}. Use 'zeek' or 'csv'.")

        log.info(f"[Capture] Mode: {mode}")

    def start(self):
        """Start capture in background thread."""
        self._source.start()

    def stop(self):
        """Stop capture."""
        self._source.stop()

    def get_flow(self, timeout: float = 1.0) -> Optional[dict]:
        """Get next flow from queue. Returns None on timeout or end-of-stream."""
        try:
            flow = self.flow_queue.get(timeout=timeout)
            return flow  # None = end of stream
        except queue.Empty:
            return None

    def get_batch(self, batch_size: int = 256, timeout: float = 1.0) -> List[dict]:
        """Get up to batch_size flows. Returns partial batch on timeout."""
        batch = []
        deadline = time.time() + timeout
        while len(batch) < batch_size and time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            try:
                flow = self.flow_queue.get(timeout=min(remaining, 0.1))
                if flow is None:
                    break  # end of stream
                batch.append(flow)
            except queue.Empty:
                break
        return batch

    @property
    def queue_size(self) -> int:
        return self.flow_queue.qsize()

    def get_stats(self) -> dict:
        return {
            "mode": self.mode,
            "queue_depth": self.flow_queue.qsize(),
            **self._source.stats,
        }
