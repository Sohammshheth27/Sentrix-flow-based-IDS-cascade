"""Encrypted Traffic Analytics"""
import os
import sys
import io
import hashlib
import ipaddress
import math
import re
import time
import logging
from typing import Dict, List, Optional, Tuple
from collections import Counter

# ── Direct-to-IP detection helpers ─────────────────────────────
# Regex to test whether an SNI field contains a raw IPv4/IPv6 literal
# rather than a hostname. Legit browsers never put an IP in SNI; some
# hardcoded-C2 malware does (to look like "it has an SNI") but also
# often just leaves it empty.
_IP_LITERAL_RE = re.compile(
    r"^(\d{1,3}(\.\d{1,3}){3})$"                # IPv4
    r"|^\[?[0-9a-fA-F:]+\]?$"                   # IPv6 (loose)
)

def _sni_looks_like_ip(sni: str) -> bool:
    """True if SNI is empty, a raw IP literal, or a pseudo-placeholder
    like 'localhost' that should never appear for external traffic."""
    if not sni:
        return True
    s = sni.strip().lower()
    if s in {"localhost", "none", "null"}:
        return True
    return bool(_IP_LITERAL_RE.match(s))

def _dst_is_external(dst_ip: str) -> bool:
    """True if dst_ip is a routable public address (not private/loopback/
    link-local/multicast). Unresolvable strings default to False (safe)."""
    if not dst_ip:
        return False
    try:
        a = ipaddress.ip_address(dst_ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_reserved or a.is_unspecified)

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

log = logging.getLogger("eta")

# Known suspicious JA3 fingerprints (hardcoded fallback if threat_intel DB is empty)
# These are the most common malware JA3s from SSLBL as of 2024
_BUILTIN_BAD_JA3 = {
    "51c64c77e60f3980eea90869b68c58a8": "Tofsee",
    "ec74a5c51106f0419184d0dd08fb05bc": "Emotet",
    "4d7a28d6f2263ed61de88ca66eb011e3": "Emotet",
    "6734f37431670b3ab4292b8f60f29984": "Trickbot",
    "72a589da586844d7f0818ce684948eea": "CobaltStrike",
    "a0e9f5d64349fb13191bc781f81f42e1": "CobaltStrike",
    "b62e3f7b521b4d0f5b7b042f6b567c50": "Metasploit",
    "e7d705a3286e19ea42f587b344ee6865": "Generic Malware",
    "3b5074b1b5d032e5620f69f9f700ff0e": "AsyncRAT",
    "f436b9416f37d134cadd04886327d3e8": "IcedID",
}

# Normal browser JA3s (should NOT be flagged)
_KNOWN_BROWSER_JA3 = {
    "b32309a26951912be7dba376398abc3b": "Chrome",
    "37f463bf4616ecd445d4a1937da06e19": "Firefox",
    "cd08e31494f9531f560d64c695473da9": "Safari",
    "d5a62e6e8e4e3b4e0e5b5e5e5e5e5e5e": "Edge",
}

# TLS cipher suites that are considered weak/dangerous
_WEAK_CIPHERS = {
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
}

class EncryptedTrafficAnalyzer:
    """
    Analyze encrypted TLS traffic without decryption.

    Extracts behavioral features from the TLS envelope and
    flow metadata to detect malware C2, exfiltration, and
    TLS-based attacks.
    """

    def __init__(self, threat_intel=None):
        """
        Args:
            threat_intel: Optional ThreatIntelEngine for JA3 lookup.
                         If None, uses builtin JA3 database only.
        """
        self.threat_intel = threat_intel
        self.stats = {
            "flows_analyzed": 0,
            "tls_flows": 0,
            "ja3_matches": 0,
            "tls_anomalies": 0,
            "splt_anomalies": 0,
            "direct_to_ip": 0,
        }
        print(f"[ETA] Encrypted Traffic Analyzer ready")
        print(f"[ETA] Builtin bad JA3: {len(_BUILTIN_BAD_JA3)}, "
              f"Threat intel: {'connected' if threat_intel else 'standalone'}")

    def analyze_flow(self, flow: dict) -> dict:
        """
        Analyze a single flow for encrypted traffic anomalies.

        Args:
            flow: dict with optional TLS/SSL fields:
                ja3, ja3s, tls_version, cipher_suite, sni,
                cert_self_signed, cert_expired, cert_subject,
                splt_lengths, splt_times, byte_distribution

        Returns:
            {
                "is_tls": bool,
                "eta_score": float (0-1),
                "eta_reasons": list[str],
                "ja3_match": dict or None,
                "tls_anomalies": list[str],
                "risk_factors": list[str],
            }
        """
        self.stats["flows_analyzed"] += 1

        result = {
            "is_tls": False,
            "eta_score": 0.0,
            "eta_reasons": [],
            "ja3_match": None,
            "tls_anomalies": [],
            "risk_factors": [],
        }

        # Detect if this is a TLS flow
        dst_port = int(flow.get("dst_port", 0) or 0)
        has_tls_fields = any(flow.get(k) for k in [
            "ja3", "ja3s", "tls_version", "cipher_suite", "sni",
            "ssl_version", "cert_subject"])
        is_tls = has_tls_fields or dst_port in (443, 8443, 993, 995, 465, 636)

        if not is_tls:
            return result

        result["is_tls"] = True
        self.stats["tls_flows"] += 1
        score = 0.0
        reasons = []
        anomalies = []
        risk = []

        # ── JA3 Fingerprint Check ─────────────────────────────
        ja3 = flow.get("ja3", flow.get("ja3_hash", ""))
        if ja3:
            match = self._check_ja3(ja3)
            if match:
                result["ja3_match"] = match
                self.stats["ja3_matches"] += 1

                if match.get("severity") == "CRITICAL":
                    score += 0.60
                    reasons.append(f"JA3 MATCH: {match.get('name', 'Unknown')} "
                                 f"malware ({ja3[:16]}...)")
                    risk.append("known_malware_ja3")
                else:
                    score += 0.40
                    reasons.append(f"JA3 suspicious: {match.get('name', 'Unknown')}")
                    risk.append("suspicious_ja3")

        # ── JA3S Check (Server fingerprint) ────────────────────
        ja3s = flow.get("ja3s", "")
        if ja3s:
            match_s = self._check_ja3(ja3s)
            if match_s:
                score += 0.20
                reasons.append(f"JA3S match: server fingerprint suspicious")

        # ── TLS Version Check ──────────────────────────────────
        tls_version = flow.get("tls_version", flow.get("ssl_version", ""))
        if tls_version:
            version_score, version_reason = self._check_tls_version(tls_version)
            if version_score > 0:
                score += version_score
                anomalies.append(version_reason)

        # ── Certificate Anomalies ──────────────────────────────
        if flow.get("cert_self_signed"):
            score += 0.25
            anomalies.append("Self-signed certificate (internal CA or malware)")
            risk.append("self_signed_cert")

        if flow.get("cert_expired"):
            score += 0.15
            anomalies.append("Expired certificate")
            risk.append("expired_cert")

        cert_subject = flow.get("cert_subject", "")
        sni = flow.get("sni", "")
        if cert_subject and sni and cert_subject.lower() != sni.lower():
            score += 0.20
            anomalies.append(f"Cert/SNI mismatch: cert={cert_subject}, sni={sni}")
            risk.append("cert_sni_mismatch")

        # ── Direct-to-IP (missing/IP-literal SNI to external) ─
        # Legit browsers always populate SNI with a hostname. Malware
        # with a hardcoded C2 IP often has empty SNI or stuffs the IP
        # into SNI. Only fire on external destinations; internal
        # services (office LAN 192.168/10/172.16) often legitimately
        # skip SNI.
        #
        # Score is modest on its own; Layer-4 fusion already requires
        # eta_anom_n >= 2 to fire ETA_TLS_ANOMALY, so this signal
        # needs to pair with a self-signed cert, JA3 hit, or similar
        # to produce an alert. That's the correct FP defense against
        # IoT devices that legitimately hardcode IPs.
        if dst_port in (443, 8443, 465, 993, 995, 636):
            dst_ip_v = flow.get("dst_ip", "")
            if _dst_is_external(dst_ip_v) and _sni_looks_like_ip(sni):
                score += 0.15
                if not sni:
                    anomalies.append(
                        f"Direct-to-IP: TLS handshake to external "
                        f"{dst_ip_v}:{dst_port} with no SNI"
                    )
                else:
                    anomalies.append(
                        f"Direct-to-IP: SNI is IP literal '{sni}' "
                        f"(to {dst_ip_v}:{dst_port})"
                    )
                risk.append("direct_to_ip_no_sni")
                self.stats["direct_to_ip"] += 1

        # ── Cipher Suite Check ─────────────────────────────────
        cipher = flow.get("cipher_suite", 0)
        if cipher and isinstance(cipher, int) and cipher in _WEAK_CIPHERS:
            score += 0.15
            anomalies.append(f"Weak cipher: {_WEAK_CIPHERS[cipher]}")
            risk.append("weak_cipher")

        # ── SPLT Analysis ──────────────────────────────────────
        splt_lengths = flow.get("splt_lengths", [])
        splt_times = flow.get("splt_times", [])
        if splt_lengths and len(splt_lengths) >= 5:
            splt_score, splt_reasons = self._analyze_splt(
                splt_lengths, splt_times)
            if splt_score > 0:
                score += splt_score
                reasons.extend(splt_reasons)
                self.stats["splt_anomalies"] += 1

        # ── Byte Distribution Entropy ──────────────────────────
        byte_dist = flow.get("byte_distribution", [])
        if byte_dist and len(byte_dist) == 256:
            entropy = self._byte_entropy(byte_dist)
            if entropy < 6.0:
                # Normal encrypted traffic has entropy ~7.5-8.0
                # Low entropy in "encrypted" traffic = not actually encrypted
                # or poorly encrypted malware
                score += 0.20
                reasons.append(f"Low byte entropy: {entropy:.2f} "
                             f"(expected >7.0 for encrypted)")
                risk.append("low_entropy")

        if anomalies:
            self.stats["tls_anomalies"] += 1

        result["eta_score"] = round(min(score, 1.0), 4)
        result["eta_reasons"] = reasons
        result["tls_anomalies"] = anomalies
        result["risk_factors"] = risk

        return result

    def _check_ja3(self, ja3_hash: str) -> Optional[dict]:
        """Check JA3 against threat intel + builtin database."""
        # Skip known browsers
        if ja3_hash in _KNOWN_BROWSER_JA3:
            return None

        # Check threat intel engine first (has live feed data)
        if self.threat_intel:
            hit = self.threat_intel.lookup_ja3(ja3_hash)
            if hit:
                return hit

        # Fall back to builtin
        if ja3_hash in _BUILTIN_BAD_JA3:
            return {
                "type": "ja3",
                "value": ja3_hash,
                "name": _BUILTIN_BAD_JA3[ja3_hash],
                "category": "malware_tls",
                "severity": "HIGH",
            }

        return None

    def _check_tls_version(self, version: str) -> Tuple[float, str]:
        """Check for TLS downgrade attacks."""
        v = str(version).lower().strip()

        # Map various representations
        if v in ("ssl3", "sslv3", "3.0", "0x0300"):
            return 0.40, "SSLv3 detected (POODLE vulnerable, obsolete since 2015)"
        if v in ("tls1.0", "tlsv1", "1.0", "0x0301"):
            return 0.25, "TLS 1.0 detected (deprecated, possible downgrade attack)"
        if v in ("tls1.1", "tlsv1.1", "1.1", "0x0302"):
            return 0.15, "TLS 1.1 detected (deprecated since 2021)"
        # TLS 1.2 and 1.3 are fine
        return 0.0, ""

    def _analyze_splt(self, lengths: List[int],
                      times: List[float]) -> Tuple[float, List[str]]:
        """
        Analyze Sequence of Packet Lengths and Times.

        C2 beaconing has characteristic SPLT patterns:
        - Regular small packets (check-in)
        - Alternating small/large (command/response)
        - Very consistent lengths and timings
        """
        score = 0.0
        reasons = []

        # Length regularity (low std = uniform packet sizes = suspicious)
        if len(lengths) >= 5:
            mean_len = sum(lengths) / len(lengths)
            if mean_len > 0:
                std_len = (sum((x - mean_len) ** 2 for x in lengths)
                          / len(lengths)) ** 0.5
                cv_len = std_len / mean_len

                if cv_len < 0.05 and mean_len < 500:
                    # Very uniform small packets; classic C2 beacon
                    score += 0.35
                    reasons.append(f"SPLT: uniform packets ({mean_len:.0f}B, "
                                 f"CV={cv_len:.3f}); C2 beacon pattern")
                elif cv_len < 0.10 and mean_len < 200:
                    score += 0.20
                    reasons.append(f"SPLT: regular small packets "
                                 f"({mean_len:.0f}B avg)")

        # Timing regularity
        if times and len(times) >= 5:
            intervals = [times[i+1] - times[i]
                        for i in range(len(times)-1) if times[i+1] > times[i]]
            if len(intervals) >= 4:
                mean_t = sum(intervals) / len(intervals)
                if mean_t > 0.1:
                    std_t = (sum((x - mean_t) ** 2 for x in intervals)
                            / len(intervals)) ** 0.5
                    cv_t = std_t / mean_t

                    if cv_t < 0.05 and mean_t > 5:
                        score += 0.30
                        reasons.append(f"SPLT timing: periodic "
                                     f"({mean_t:.1f}s, CV={cv_t:.3f})")
                    elif cv_t < 0.15 and mean_t > 10:
                        score += 0.15
                        reasons.append(f"SPLT timing: semi-regular "
                                     f"(~{mean_t:.0f}s intervals)")

        # Asymmetry (large out, small in = exfil; large in, small out = download)
        if len(lengths) >= 6:
            # Separate likely client→server (odd indices) and server→client (even)
            out_lens = [lengths[i] for i in range(0, len(lengths), 2)]
            in_lens = [lengths[i] for i in range(1, len(lengths), 2)]
            if out_lens and in_lens:
                out_avg = sum(out_lens) / len(out_lens)
                in_avg = sum(in_lens) / len(in_lens)
                if out_avg > 0 and in_avg > 0:
                    ratio = out_avg / in_avg
                    if ratio > 10 and out_avg > 1000:
                        score += 0.25
                        reasons.append(f"SPLT asymmetry: {ratio:.0f}x "
                                     f"outbound heavy (exfiltration pattern)")

        return min(score, 0.50), reasons

    def _byte_entropy(self, distribution: List[int]) -> float:
        """Calculate Shannon entropy of byte distribution."""
        total = sum(distribution)
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in distribution:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy

    # ── JA3 Generation ────────────────────────────────────────

    @staticmethod
    def generate_ja3(tls_hello: dict) -> str:
        """
        Generate JA3 fingerprint from TLS ClientHello fields.

        Args:
            tls_hello: dict with:
                tls_version: int (e.g., 771 for TLS 1.2)
                cipher_suites: list[int]
                extensions: list[int]
                elliptic_curves: list[int]
                ec_point_formats: list[int]

        Returns: JA3 hash (MD5 hex string)
        """
        version = str(tls_hello.get("tls_version", ""))
        ciphers = "-".join(str(c) for c in tls_hello.get("cipher_suites", []))
        extensions = "-".join(str(e) for e in tls_hello.get("extensions", []))
        curves = "-".join(str(c) for c in tls_hello.get("elliptic_curves", []))
        formats = "-".join(str(f) for f in tls_hello.get("ec_point_formats", []))

        ja3_raw = f"{version},{ciphers},{extensions},{curves},{formats}"
        return hashlib.md5(ja3_raw.encode()).hexdigest()

    def get_stats(self) -> dict:
        return dict(self.stats)

    def print_summary(self):
        s = self.stats
        print(f"\n{'='*55}")
        print(f"  ENCRYPTED TRAFFIC ANALYTICS SUMMARY")
        print(f"{'='*55}")
        print(f"  Flows analyzed   : {s['flows_analyzed']:,}")
        print(f"  TLS flows        : {s['tls_flows']:,}")
        print(f"  JA3 matches      : {s['ja3_matches']:,}")
        print(f"  TLS anomalies    : {s['tls_anomalies']:,}")
        print(f"  SPLT anomalies   : {s['splt_anomalies']:,}")
        print(f"{'='*55}")
