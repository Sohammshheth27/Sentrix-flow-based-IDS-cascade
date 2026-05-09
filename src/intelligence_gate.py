"""Layer 1: Pre-Model Intelligence Gate (Tier 1)"""
import sys
import io
import time
import logging
from typing import Dict, List, Optional

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

log = logging.getLogger("intel_gate")

class IntelligenceGate:
    """
    Pre-model intelligence gate with full Tier 1 ETA capabilities.
    JA3 profiling + DNS-TLS correlation + threat intel + ETA + identity.
    """

    def __init__(self, threat_intel=None, eta_engine=None,
                 entity_context=None, whitelist=None,
                 ja3_profiler=None, dns_tls_correlator=None):
        self.ti = threat_intel
        self.eta = eta_engine
        self.ctx = entity_context
        self.whitelist = whitelist
        self.ja3_prof = ja3_profiler
        self.dns_corr = dns_tls_correlator

        self.stats = {
            "flows_evaluated": 0,
            "immediate_alerts": 0,
            "ti_hits": 0,
            "ja3_malware_hits": 0,
            "ja3_pair_hits": 0,
            "ja3_new_entity": 0,
            "ja3_rare_network": 0,
            "dns_fronting": 0,
            "dns_hardcoded": 0,
            "whitelisted": 0,
            "eta_boosted": 0,
            "passed_to_ml": 0,
        }

        components = []
        if self.ti:         components.append("ThreatIntel")
        if self.eta:        components.append("ETA")
        if self.ctx:        components.append("Identity")
        if self.whitelist:  components.append("Whitelist")
        if self.ja3_prof:   components.append("JA3Profiler")
        if self.dns_corr:   components.append("DNS-TLS")

        print(f"[IntelGate] Tier 1 initialized: {', '.join(components)}")

    def evaluate(self, flow: dict, now: float = None) -> dict:
        """Evaluate a single flow through all Layer 1 checks."""
        self.stats["flows_evaluated"] += 1
        if now is None:
            now = time.time()

        src_ip = flow.get("src_ip", "")

        result = {
            "action": "CONTINUE",
            "severity": "BENIGN",
            "reason": "",
            # Decomposed boosts (each contributes provenance for fusion):
            #   ti_boost    ; medium/low threat-intel hit bump
            #   ja3_boost   ; JA3 per-entity rarity / category softness
            #   dns_boost   ; soft DNS-TLS correlation (not fronting-immediate)
            #   eta_pure    ; TLS anomalies only (self-signed, weak, expired)
            #   intel_boost ; sum of all four, capped at 0.50
            #   eta_boost   ; back-compat alias = intel_boost
            "ti_boost": 0.0,
            "ti_severity": "",
            "ja3_boost": 0.0,
            "dns_boost": 0.0,
            "eta_pure": 0.0,
            "eta_anomaly_count": 0,
            "intel_boost": 0.0,
            "eta_boost": 0.0,
            "threat_hits": [],
            "eta_result": {},
            "ja3_result": {},
            "dns_tls_result": {},
            "identity": None,
            "sensitivity": None,
            "alert_details": {},
        }

        # ── 1a. WHITELIST (cheapest; do first) ──────────────
        if self.whitelist and self.whitelist.is_whitelisted(flow):
            self.stats["whitelisted"] += 1
            result["action"] = "SKIP_BENIGN"
            result["reason"] = "whitelisted"
            return result

        # ── 1f. IDENTITY (needed by all subsequent checks) ───
        if self.ctx:
            identity = self.ctx.get_identity(src_ip)
            result["identity"] = identity.to_dict() if identity else None
            result["sensitivity"] = self.ctx.get_sensitivity(src_ip)

        ti_boost = 0.0
        ja3_boost = 0.0
        dns_boost = 0.0
        eta_pure = 0.0
        all_reasons = []

        # ── 1b. THREAT INTEL LOOKUP ──────────────────────────
        if self.ti:
            hits = self.ti.lookup_flow(flow)
            if hits:
                result["threat_hits"] = hits
                self.stats["ti_hits"] += 1

                best_hit = max(hits, key=lambda h: {
                    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1
                }.get(h.get("severity", "LOW"), 0))

                if best_hit.get("severity") in ("CRITICAL", "HIGH"):
                    self.stats["immediate_alerts"] += 1
                    result["action"] = "ALERT_IMMEDIATE"
                    result["severity"] = best_hit["severity"]
                    result["reason"] = (f"ThreatIntel: {best_hit['type']} "
                                       f"{best_hit['value']} "
                                       f"[{best_hit.get('category', '')}]")
                    result["alert_details"] = {
                        "source": "threat_intel",
                        "attack_type": best_hit.get("category", "Known_Threat"),
                        "confidence": 0.99,
                        "ioc_type": best_hit["type"],
                        "ioc_value": best_hit["value"],
                        "feed": best_hit.get("feed", ""),
                    }
                    return result
                else:
                    # MEDIUM/LOW TI hit; boost ML *and* surface as
                    # first-class signal for fusion (ti_severity).
                    ti_boost = 0.15
                    result["ti_severity"] = best_hit.get("severity", "LOW")
                    all_reasons.append(f"TI: {best_hit['type']} "
                                      f"{best_hit['value']} ({best_hit.get('severity','')})")

        # ── 1c. JA3 PROFILER (pair + entity + network) ───────
        if self.ja3_prof:
            ja3_result = self.ja3_prof.analyze(flow, entity_ip=src_ip, now=now)
            result["ja3_result"] = ja3_result

            if ja3_result.get("is_tls"):
                # Check 1: JA3+JA3S pair match → IMMEDIATE CRITICAL
                pair = ja3_result.get("ja3_pair_match")
                if pair and pair.get("confidence", 0) >= 0.95:
                    self.stats["ja3_pair_hits"] += 1
                    self.stats["immediate_alerts"] += 1
                    result["action"] = "ALERT_IMMEDIATE"
                    result["severity"] = "CRITICAL"
                    result["reason"] = (f"JA3+JA3S PAIR: {pair['name']} "
                                       f"(client+server fingerprint confirmed)")
                    result["alert_details"] = {
                        "source": "ja3_pair_match",
                        "attack_type": pair["name"],
                        "confidence": pair["confidence"],
                        "ja3_hash": flow.get("ja3", ""),
                        "malware_family": pair["name"],
                    }
                    return result

                # Check 2: Known malware JA3 (without pair confirmation)
                malware = ja3_result.get("ja3_known_malware")
                if malware and not malware.get("pair_mismatch"):
                    if malware.get("severity") == "CRITICAL":
                        self.stats["ja3_malware_hits"] += 1
                        self.stats["immediate_alerts"] += 1
                        result["action"] = "ALERT_IMMEDIATE"
                        result["severity"] = "CRITICAL"
                        result["reason"] = (f"JA3 Match: {malware['name']} "
                                           f"({malware.get('family', '')})")
                        result["alert_details"] = {
                            "source": "ja3_match",
                            "attack_type": malware["name"],
                            "confidence": 0.95,
                            "ja3_hash": flow.get("ja3", ""),
                            "malware_family": malware.get("family", ""),
                        }
                        return result

                # Check 3: Accumulate JA3 boost (new entity + rare + category)
                _ja3_soft = ja3_result.get("ja3_boost", 0.0)
                if _ja3_soft > 0:
                    ja3_boost += _ja3_soft
                    all_reasons.extend(ja3_result.get("ja3_reasons", []))

                    if ja3_result.get("ja3_entity_new"):
                        self.stats["ja3_new_entity"] += 1
                    if ja3_result.get("ja3_network_rare"):
                        self.stats["ja3_rare_network"] += 1

        # ── 1d. DNS-TLS CORRELATION ──────────────────────────
        if self.dns_corr:
            # First record any DNS from this flow
            self.dns_corr.record_dns_from_flow(flow, now)

            dns_result = self.dns_corr.check_tls_flow(flow, now)
            result["dns_tls_result"] = dns_result

            if dns_result.get("is_tls"):
                dns_boost = dns_result.get("boost", 0.0)

                if dns_result.get("domain_fronting"):
                    self.stats["dns_fronting"] += 1
                    # Domain fronting with high boost = immediate alert
                    if dns_boost >= 0.35:
                        self.stats["immediate_alerts"] += 1
                        result["action"] = "ALERT_IMMEDIATE"
                        result["severity"] = "HIGH"
                        result["reason"] = dns_result["reasons"][0]
                        result["alert_details"] = {
                            "source": "domain_fronting",
                            "attack_type": "Domain_Fronting",
                            "confidence": 0.90,
                            "dns_domain": dns_result.get("dns_domain", ""),
                            "sni": dns_result.get("sni", ""),
                        }
                        return result

                if dns_result.get("hardcoded_ip"):
                    self.stats["dns_hardcoded"] += 1

                if dns_boost > 0:
                    all_reasons.extend(dns_result.get("reasons", []))

        # ── 1e. ETA ANALYSIS (TLS anomalies) ─────────────────
        if self.eta:
            eta_result = self.eta.analyze_flow(flow)
            result["eta_result"] = eta_result

            if eta_result.get("is_tls"):
                eta_score = eta_result.get("eta_score", 0.0)

                # Skip JA3 match here (already handled by JA3 profiler above)
                # Only add TLS anomaly boost (self-signed, expired, weak cipher, etc.)
                tls_anomalies = eta_result.get("tls_anomalies", [])
                if tls_anomalies and eta_score > 0:
                    # Only add TLS-anomaly portion (not JA3 which is already counted)
                    eta_pure = min(len(tls_anomalies) * 0.10, 0.25)
                    result["eta_anomaly_count"] = len(tls_anomalies)
                    all_reasons.extend(tls_anomalies)

        # ── Finalize decomposed boosts ────────────────────────
        intel_boost = min(ti_boost + ja3_boost + dns_boost + eta_pure, 0.50)

        if intel_boost > 0:
            self.stats["eta_boosted"] += 1

        result["ti_boost"]    = round(ti_boost,    4)
        result["ja3_boost"]   = round(ja3_boost,   4)
        result["dns_boost"]   = round(dns_boost,   4)
        result["eta_pure"]    = round(eta_pure,    4)
        result["intel_boost"] = round(intel_boost, 4)
        # Back-compat alias; consumers still reading eta_boost
        # (e.g., older tests) get the total here.
        result["eta_boost"]   = round(intel_boost, 4)
        if all_reasons:
            result["reason"] = " | ".join(all_reasons[:5])

        self.stats["passed_to_ml"] += 1
        return result

    # ── Stats ─────────────────────────────────────────────────

    def get_stats(self) -> dict:
        s = self.stats
        total = max(s["flows_evaluated"], 1)
        return {
            **s,
            "immediate_rate": f"{s['immediate_alerts']/total*100:.3f}%",
            "whitelist_rate": f"{s['whitelisted']/total*100:.1f}%",
            "boost_rate": f"{s['eta_boosted']/total*100:.2f}%",
        }

    def print_summary(self):
        s = self.get_stats()
        print(f"\n{'='*60}")
        print(f"  INTELLIGENCE GATE SUMMARY (Layer 1; Tier 1)")
        print(f"{'='*60}")
        print(f"  Flows evaluated     : {s['flows_evaluated']:,}")
        print(f"  Whitelisted         : {s['whitelisted']:,} ({s['whitelist_rate']})")
        print(f"  Threat intel hits   : {s['ti_hits']:,}")
        print(f"  JA3 malware matches : {s['ja3_malware_hits']:,}")
        print(f"  JA3+JA3S pairs      : {s['ja3_pair_hits']:,}")
        print(f"  JA3 new on entity   : {s['ja3_new_entity']:,}")
        print(f"  JA3 rare on network : {s['ja3_rare_network']:,}")
        print(f"  Domain fronting     : {s['dns_fronting']:,}")
        print(f"  Hardcoded C2 IP     : {s['dns_hardcoded']:,}")
        print(f"  Immediate alerts    : {s['immediate_alerts']:,} ({s['immediate_rate']})")
        print(f"  ETA boosted         : {s['eta_boosted']:,} ({s['boost_rate']})")
        print(f"  Passed to ML        : {s['passed_to_ml']:,}")
        print(f"{'='*60}")
