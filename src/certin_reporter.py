"""CERT-In incident report formatter."""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger("certin")

CERTIN_INCIDENT_TYPES = {
    "DDoS": "denial-of-service",
    "DoS": "denial-of-service",
    "BruteForce": "unauthorised-access-attempts",
    "Botnet": "malicious-code",
    "Infiltration": "unauthorised-access",
    "Injection": "unauthorised-access",
    "Recon": "scanning-probing",
    "Backdoor": "malicious-code",
    "Ransomware": "ransomware",
    "Known_Threat": "malicious-code",
    "TLS_Suspicious": "suspicious-network-traffic",
    "Behavioral_Anomaly": "suspicious-network-traffic",
    "Unclassified": "suspicious-network-traffic",
    "CRYPTO_MINING": "unauthorised-access",
    "DNS_Tunneling": "data-exfiltration",
    "credential_harvesting": "phishing",
}

class CERTInReporter:

    def __init__(self, org_name: str = "", org_sector: str = "",
                 contact_email: str = "", contact_phone: str = "",
                 submit_url: str = ""):
        self.org_name = org_name
        self.org_sector = org_sector
        self.contact_email = contact_email
        self.contact_phone = contact_phone
        self.submit_url = submit_url

    def format_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        attack_type = alert.get("attack_type", "Unclassified")
        incident_type = CERTIN_INCIDENT_TYPES.get(
            attack_type, "suspicious-network-traffic")

        now_utc = datetime.now(timezone.utc).isoformat()
        detection_time = alert.get("timestamp", now_utc)

        return {
            "certin_schema_version": "1.0",
            "reporting_entity": {
                "organization": self.org_name,
                "sector": self.org_sector,
                "contact_email": self.contact_email,
                "contact_phone": self.contact_phone,
            },
            "incident": {
                "type": incident_type,
                "severity": alert.get("severity", "MEDIUM"),
                "detection_timestamp": detection_time,
                "reporting_timestamp": now_utc,
                "description": (
                    f"{attack_type} detected by Sentrix. "
                    f"Source: {alert.get('src_ip', 'unknown')} -> "
                    f"Destination: {alert.get('dst_ip', 'unknown')}:"
                    f"{alert.get('dst_port', 0)}. "
                    f"Confidence: {alert.get('confidence', 0):.1f}%."
                ),
            },
            "affected_systems": [
                {
                    "ip": alert.get("src_ip", ""),
                    "role": "source",
                    "department": alert.get("department", ""),
                },
                {
                    "ip": alert.get("dst_ip", ""),
                    "role": "destination",
                    "port": alert.get("dst_port", 0),
                },
            ],
            "indicators": {
                "attack_type": attack_type,
                "ml_score": alert.get("ml_score", 0),
                "ueba_score": alert.get("ueba_score", 0),
                "rule_score": alert.get("rule_score", 0),
                "ja3_hash": alert.get("ja3_match", ""),
                "threat_intel_hits": alert.get("threat_intel", []),
                "reasons": alert.get("reasons", []),
            },
            "recommended_action": self._recommend_action(attack_type,
                                                          alert.get("severity", "")),
        }

    def _recommend_action(self, attack_type: str, severity: str) -> str:
        if severity == "CRITICAL":
            return (f"IMMEDIATE: Isolate affected systems. "
                    f"Block source IP at perimeter firewall. "
                    f"Preserve forensic evidence. "
                    f"Report to CERT-In within 6 hours.")
        if attack_type in ("Ransomware",):
            return ("Isolate affected host. Disconnect from network. "
                    "Do NOT pay ransom. Engage incident response team. "
                    "Report to CERT-In within 6 hours.")
        if severity == "HIGH":
            return ("Investigate source IP. Check for lateral movement. "
                    "Block if confirmed malicious. Report to CERT-In "
                    "within 6 hours if confirmed.")
        return ("Monitor and investigate. Collect additional evidence. "
                "Report to CERT-In if incident confirmed.")

    def submit(self, report: Dict) -> bool:
        if not self.submit_url:
            log.info("CERT-In report generated (no submit URL configured)")
            return False
        try:
            import urllib.request
            data = json.dumps(report).encode("utf-8")
            req = urllib.request.Request(
                self.submit_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status in (200, 201, 202):
                    log.info(f"CERT-In report submitted (HTTP {resp.status})")
                    return True
                log.warning(f"CERT-In submit returned HTTP {resp.status}")
                return False
        except Exception as e:
            log.error(f"CERT-In submit failed: {e}")
            return False
