"""Sentrix attack_type ↔ MITRE ATT&CK mapping."""
from __future__ import annotations
from typing import Dict, List, Tuple

# Canonical MITRE ATT&CK tactics (Enterprise matrix). Order = column order
# on the heatmap. Every Sentrix detection maps to at least one of these.
TACTICS: List[Tuple[str, str]] = [
    ("TA0043", "Reconnaissance"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

# attack_type → list of (tactic_id, tactic_name, technique_id, technique_name)
ATTACK_TYPE_TO_MITRE: Dict[str, List[Tuple[str, str, str, str]]] = {

    # ── Stage 2 ML attack families ───────────────
    # All IoT botnet families fit Command and Control + Discovery
    # (scanning before C2). Mirai family variants also involve Impact
    # via DDoS but we stick with C2 as primary.
    "Hajime": [
        ("TA0011", "Command and Control", "T1071.001", "Application Layer Protocol: Web"),
        ("TA0007", "Discovery",           "T1046",     "Network Service Discovery"),
    ],
    "Hakai": [
        ("TA0011", "Command and Control", "T1071",     "Application Layer Protocol"),
        ("TA0040", "Impact",              "T1498",     "Network Denial of Service"),
    ],
    "Mirai": [
        ("TA0011", "Command and Control", "T1071",     "Application Layer Protocol"),
        ("TA0007", "Discovery",           "T1046",     "Network Service Discovery"),
        ("TA0040", "Impact",              "T1498",     "Network Denial of Service"),
    ],
    "Muhstik": [
        ("TA0011", "Command and Control", "T1071.001", "Application Layer Protocol: Web"),
        ("TA0040", "Impact",              "T1496",     "Resource Hijacking"),
    ],
    "Neris": [
        ("TA0011", "Command and Control", "T1071",     "Application Layer Protocol"),
        ("TA0009", "Collection",          "T1005",     "Data from Local System"),
    ],
    "Okiru": [
        ("TA0011", "Command and Control", "T1071",     "Application Layer Protocol"),
        ("TA0007", "Discovery",           "T1046",     "Network Service Discovery"),
    ],

    # ── Rule-based detections ──────────────────────────────────────
    "RDP Brute Force": [
        ("TA0006", "Credential Access",   "T1110.001", "Password Guessing"),
        ("TA0001", "Initial Access",      "T1133",     "External Remote Services"),
    ],
    "SSH Brute Force": [
        ("TA0006", "Credential Access",   "T1110.001", "Password Guessing"),
        ("TA0001", "Initial Access",      "T1133",     "External Remote Services"),
    ],
    "SMB Lateral Movement": [
        ("TA0008", "Lateral Movement",    "T1021.002", "SMB/Windows Admin Shares"),
    ],
    "Large Outbound Transfer": [
        ("TA0010", "Exfiltration",        "T1041",     "Exfiltration Over C2 Channel"),
    ],
    "Cryptomining Detected": [
        ("TA0040", "Impact",              "T1496",     "Resource Hijacking"),
    ],
    "DNS Tunneling Suspected": [
        ("TA0011", "Command and Control", "T1071.004", "DNS"),
        ("TA0010", "Exfiltration",        "T1048.003", "Exfil Over Unencrypted Non-C2"),
    ],
    "Ransomware SMB Fan-out": [
        ("TA0040", "Impact",              "T1486",     "Data Encrypted for Impact"),
        ("TA0008", "Lateral Movement",    "T1021.002", "SMB/Windows Admin Shares"),
    ],
    "Direct-to-IP (No DNS)": [
        ("TA0011", "Command and Control", "T1071",     "Application Layer Protocol"),
        ("TA0005", "Defense Evasion",     "T1095",     "Non-Application Layer Protocol"),
    ],
    "Port Sweep": [
        ("TA0007", "Discovery",           "T1046",     "Network Service Discovery"),
    ],
    "Horizontal Scan": [
        ("TA0007", "Discovery",           "T1018",     "Remote System Discovery"),
    ],

    # Alias fallbacks; capture common ML "attack_type" strings the
    # engine may emit that we haven't otherwise categorised.
    "Unclassified": [("TA0011", "Command and Control", "T1071", "Application Layer Protocol")],
    "TLS_Suspicious": [
        ("TA0011", "Command and Control", "T1573",     "Encrypted Channel"),
        ("TA0005", "Defense Evasion",     "T1027",     "Obfuscated Files or Information"),
    ],
    "Known_Threat": [("TA0011", "Command and Control", "T1071", "Application Layer Protocol")],
}

def tactic_ids() -> List[str]:
    """Return MITRE tactic IDs in canonical order."""
    return [t[0] for t in TACTICS]

def tactic_names() -> List[str]:
    """Return MITRE tactic display names in canonical order."""
    return [t[1] for t in TACTICS]

def lookup(attack_type: str) -> List[Tuple[str, str, str, str]]:
    """Return MITRE entries for a given attack_type, or empty list if unknown."""
    if not attack_type:
        return []
    # Try exact match, then best-effort fallback
    if attack_type in ATTACK_TYPE_TO_MITRE:
        return ATTACK_TYPE_TO_MITRE[attack_type]
    # Partial: match any key that's contained in the string
    for k, v in ATTACK_TYPE_TO_MITRE.items():
        if k in attack_type or attack_type in k:
            return v
    return []

def tactics_for(attack_type: str) -> List[str]:
    """Return the set of tactic IDs an attack_type maps to."""
    return [e[0] for e in lookup(attack_type)]
