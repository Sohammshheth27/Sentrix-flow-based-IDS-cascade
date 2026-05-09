"""Security Policy Enforcement Layer"""
import sys
import io
import json
import time
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set
from collections import defaultdict

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

log = logging.getLogger("policy")
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Severity ranking
_SEV = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "BENIGN": 0}

class PolicyEngine:
    """
    Security Policy Enforcement.
    Evaluates every flow against organizational security policies.
    """

    def __init__(self, config_path: str = None, threat_intel=None):
        if config_path is None:
            config_path = str(_PROJECT_ROOT / "config" / "security_policies.json")

        self.config = {}
        self.ti = threat_intel

        # Anonymizer port sets (built from config)
        self._anon_ports: Dict[str, Set[int]] = {}
        self._anon_severity: Dict[str, str] = {}
        self._all_anon_ports: Set[int] = set()

        # Device restriction rules
        self._device_rules: List[dict] = []

        # Department rules
        self._dept_rules: Dict[str, dict] = {}

        # Authorized VPN
        self._authorized_vpn_ips: Set[str] = set()
        self._authorized_vpn_depts: Set[str] = set()
        self._vpn_server_ips: Set[str] = set()

        # Time policy
        self._biz_start = 8
        self._biz_end = 19
        self._weekend_mult = 1.5
        self._offhours_mult = 1.3

        # Tor exit nodes (from threat intel feed)
        self._tor_exits: Set[str] = set()

        self._load_config(config_path)

        # Indian domain whitelist + UPI lookalike patterns
        self._trusted_domain_suffixes: List[str] = []
        self._bank_lookalike_patterns: List[str] = []
        _india_cfg = _PROJECT_ROOT / "config" / "india_whitelist.yaml"
        if _india_cfg.exists():
            try:
                import yaml
                with open(_india_cfg, "r", encoding="utf-8") as _fh:
                    _icfg = yaml.safe_load(_fh) or {}
                self._trusted_domain_suffixes = list(
                    _icfg.get("trusted_domain_suffixes") or [])
                self._bank_lookalike_patterns = list(
                    _icfg.get("bank_lookalike_patterns") or [])
                print(f"[Policy] India whitelist: {len(self._trusted_domain_suffixes)} "
                      f"trusted suffixes, {len(self._bank_lookalike_patterns)} "
                      f"lookalike patterns")
            except Exception as e:
                print(f"[Policy] India whitelist load failed: {e}")

        self.stats = {
            "flows_evaluated": 0,
            "violations": 0,
            "anonymizer_detected": 0,
            "device_violations": 0,
            "department_violations": 0,
            "time_escalated": 0,
            "exfil_indicators": 0,
            "by_category": defaultdict(int),
            "by_severity": defaultdict(int),
        }

        n_anon = len(self._all_anon_ports)
        n_dev = len(self._device_rules)
        n_dept = len(self._dept_rules)
        print(f"[Policy] Loaded: {n_anon} anonymizer ports, "
              f"{n_dev} device rules, {n_dept} department rules")

    def _load_config(self, path: str):
        try:
            with open(path) as f:
                self.config = json.load(f)
        except FileNotFoundError:
            print(f"[Policy] No config at {path}; policies disabled")
            return
        except Exception as e:
            print(f"[Policy] Config error: {e}")
            return

        # Parse anonymizer detection
        anon_cfg = self.config.get("anonymizer_detection", {})
        if anon_cfg.get("enabled"):
            for name in ["tor", "i2p", "vpn_unauthorized", "proxy", "zeronet", "freenet"]:
                acfg = anon_cfg.get(name, {})
                if acfg.get("enabled", True):
                    ports = set(acfg.get("dst_ports", []))
                    self._anon_ports[name] = ports
                    self._anon_severity[name] = acfg.get("default_severity", "MEDIUM")
                    self._all_anon_ports.update(ports)

        # Parse device restrictions
        dev_cfg = self.config.get("device_restrictions", {})
        if dev_cfg.get("enabled"):
            self._device_rules = dev_cfg.get("rules", [])

        # Parse department policies
        dept_cfg = self.config.get("department_policies", {})
        if dept_cfg.get("enabled"):
            self._dept_rules = dept_cfg.get("rules", {})

        # Parse time policies
        time_cfg = self.config.get("time_based_policies", {})
        if time_cfg.get("enabled"):
            biz = time_cfg.get("business_hours", {})
            self._biz_start = biz.get("start", 8)
            self._biz_end = biz.get("end", 19)
            self._weekend_mult = time_cfg.get("weekend_multiplier", 1.5)
            self._offhours_mult = time_cfg.get("off_hours_multiplier", 1.3)

        # Parse authorized VPN
        vpn_cfg = self.config.get("authorized_vpn", {})
        self._authorized_vpn_ips = set(vpn_cfg.get("authorized_ips", []))
        self._authorized_vpn_depts = set(vpn_cfg.get("authorized_departments", []))
        self._vpn_server_ips = set(vpn_cfg.get("authorized_server_ips", []))

    # ── Main Evaluation ───────────────────────────────────────

    def evaluate(self, flow: dict, identity: dict = None,
                 now: float = None) -> dict:
        """
        Evaluate a flow against security policies.

        Args:
            flow: flow dict with src_ip, dst_ip, dst_port, etc.
            identity: identity dict from EntityContextEngine (department, device_type, etc.)
            now: timestamp (default: time.time())

        Returns:
            {
                "violation": bool,
                "severity": str,
                "category": str,       # anonymizer/device/department/exfiltration
                "reasons": list[str],
                "policy_boost": float,  # added to ML/UEBA scoring
            }
        """
        if now is None:
            now = time.time()

        self.stats["flows_evaluated"] += 1

        result = {
            "violation": False,
            "severity": "BENIGN",
            "category": "",
            "reasons": [],
            "policy_boost": 0.0,
        }

        src_ip = flow.get("src_ip", "")
        dst_ip = flow.get("dst_ip", "")
        dst_port = int(flow.get("dst_port", 0) or 0)
        fwd_bytes = float(flow.get("fwd_bytes", flow.get("total_bytes", 0)) or 0)

        # Extract identity info
        device_type = ""
        department = ""
        hostname = ""
        if identity:
            device_type = identity.get("device_type", identity.get("type", ""))
            department = identity.get("department", "")
            hostname = identity.get("hostname", "")

        violations = []  # list of (severity, category, reason)

        # ── 1. ANONYMIZER DETECTION ───────────────────────────
        anon_detected = self._check_anonymizer(dst_port, dst_ip, flow)
        if anon_detected:
            for anon_name, base_severity in anon_detected:
                self.stats["anonymizer_detected"] += 1
                self.stats["by_category"][anon_name] += 1

                # Check if authorized
                if anon_name == "vpn_unauthorized":
                    if self._is_vpn_authorized(src_ip, dst_ip, department):
                        continue  # authorized VPN; skip

                violations.append((
                    base_severity,
                    anon_name,
                    f"Anonymizer detected: {anon_name.upper()} "
                    f"(dst_port={dst_port}, dst={dst_ip})"
                ))

        # ── 2. DEVICE RESTRICTIONS ────────────────────────────
        if device_type:
            for rule in self._device_rules:
                dev_types = rule.get("device_types", [])
                if device_type.lower() in [d.lower() for d in dev_types]:
                    # Check forbidden categories (only if anonymizer was detected)
                    if violations:
                        for _, cat, _ in list(violations):
                            forbidden = [c.lower() for c in rule.get("forbidden_categories", [])]
                            if cat.lower() in forbidden or "anonymizer" in forbidden:
                                sev = rule.get("severity", "CRITICAL")
                                reason = rule.get("reason", "Device policy violation")
                                violations.append((
                                    sev, "device_restriction",
                                    f"DEVICE VIOLATION: {device_type} ({hostname or src_ip}) "
                                    f"using {cat}; {reason}"
                                ))
                                self.stats["device_violations"] += 1
                                break

                    # Check forbidden ports (ALWAYS; independent of anonymizer)
                    forbidden_ports = set(rule.get("forbidden_ports", []))
                    if dst_port in forbidden_ports:
                        violations.append((
                            rule.get("severity", "CRITICAL"),
                            "device_port_violation",
                            f"DEVICE PORT: {device_type} ({hostname or src_ip}) "
                            f"connecting to port {dst_port}; "
                            f"{rule.get('reason', 'forbidden port')}"
                        ))
                        self.stats["device_violations"] += 1

        # ── 3. DEPARTMENT RESTRICTIONS ────────────────────────
        if department and violations:
            dept_rule = self._dept_rules.get(department, {})
            if dept_rule:
                forbidden = [c.lower() for c in dept_rule.get("forbidden_categories", [])]
                allowed = [c.lower() for c in dept_rule.get("allowed_categories", [])]

                for _, cat, _ in violations:
                    cat_lower = cat.lower()
                    if cat_lower in allowed:
                        continue  # explicitly allowed for this department
                    if cat_lower in forbidden or "anonymizer" in forbidden:
                        sev = dept_rule.get("severity_boost", "HIGH")
                        reason = dept_rule.get("reason", "Department policy violation")
                        violations.append((
                            sev, "department_restriction",
                            f"DEPT VIOLATION: {department} department; "
                            f"{cat} usage; {reason}"
                        ))
                        self.stats["department_violations"] += 1
                        break

        # ── 4. TIME-BASED ESCALATION ──────────────────────────
        if violations:
            dt = datetime.fromtimestamp(now)
            hour = dt.hour
            is_weekend = dt.weekday() >= 5
            is_offhours = hour < self._biz_start or hour > self._biz_end

            if is_weekend or is_offhours:
                self.stats["time_escalated"] += 1
                time_label = "weekend" if is_weekend else f"off-hours ({hour:02d}:00)"
                violations.append((
                    "MEDIUM", "time_escalation",
                    f"TIME: {time_label}; anonymizer/violation activity "
                    f"outside business hours increases severity"
                ))

        # ── 5. DATA EXFILTRATION INDICATORS ───────────────────
        if anon_detected and fwd_bytes > 10_000_000:  # >10MB through anonymizer
            violations.append((
                "CRITICAL", "exfiltration",
                f"EXFIL: {fwd_bytes/1e6:.1f}MB uploaded through anonymizer; "
                f"data exfiltration indicator"
            ))
            self.stats["exfil_indicators"] += 1

        # ── 6. TOR EXIT NODE CHECK (if threat intel available) ─
        if self.ti and dst_ip:
            ti_hit = self.ti.lookup_ip(dst_ip)
            if ti_hit and ti_hit.get("category") == "anonymizer":
                violations.append((
                    "HIGH", "tor_exit_node",
                    f"TI: dst_ip {dst_ip} is a known Tor exit node"
                ))

        # ── 7. UPI / BANK LOOKALIKE DOMAIN CHECK ──────────────
        sni = flow.get("sni", "") or flow.get("server_name", "") or ""
        if sni and self._bank_lookalike_patterns:
            sni_lower = sni.lower()
            for pattern in self._bank_lookalike_patterns:
                if pattern in sni_lower:
                    violations.append((
                        "HIGH", "credential_harvesting",
                        f"UPI/BANK PHISHING: SNI '{sni}' matches lookalike "
                        f"pattern '{pattern}'; likely credential harvesting"
                    ))
                    break

        # ── Compute final result ──────────────────────────────
        if not violations:
            return result

        self.stats["violations"] += 1

        # Take highest severity
        best_sev = max(violations, key=lambda v: _SEV.get(v[0], 0))
        result["violation"] = True
        result["severity"] = best_sev[0]
        result["category"] = best_sev[1]
        result["reasons"] = [v[2] for v in violations]

        # Compute policy boost for ML/UEBA integration
        sev_boost = {"CRITICAL": 0.50, "HIGH": 0.40, "MEDIUM": 0.25, "LOW": 0.10}
        result["policy_boost"] = sev_boost.get(best_sev[0], 0.0)

        self.stats["by_severity"][best_sev[0]] += 1

        return result

    # ── Anonymizer Detection ──────────────────────────────────

    def _check_anonymizer(self, dst_port: int, dst_ip: str,
                          flow: dict) -> List[tuple]:
        """Check if flow uses an anonymization network. Returns list of (name, severity).

        Skips port-based checks when dst is private (RFC1918/link-local/
        loopback). Anonymization bypasses EXTERNAL content filtering,
        so an internal→internal flow cannot "anonymize" anything. This
        exemption cuts 95%+ of false positives on office LANs where
        internal services use ports that overlap with proxy/VPN ranges
        (e.g., internal Jenkins on 8080, dev SOCKS on 1080).

        JA3 / Tor-exit-IP checks below still run regardless of direction
       ; those are always malicious.
        """
        detections = []

        import ipaddress as _ipa
        dst_is_internal = False
        try:
            _a = _ipa.ip_address(dst_ip)
            dst_is_internal = (_a.is_private or _a.is_loopback or _a.is_link_local)
        except (ValueError, TypeError):
            pass

        if not dst_is_internal:
            for anon_name, ports in self._anon_ports.items():
                if dst_port in ports:
                    severity = self._anon_severity.get(anon_name, "MEDIUM")
                    detections.append((anon_name, severity))

        # Also check JA3 for Tor (if available)
        ja3 = flow.get("ja3", "")
        if ja3:
            # Known Tor Browser JA3 hashes
            tor_ja3 = {
                "e7d705a3286e19ea42f587b344ee6865",
                "839bbe3ed786119b7b0a09c57a3b8d6e",
            }
            if ja3 in tor_ja3:
                detections.append(("tor", "HIGH"))

        # Check if destination is known Tor exit node
        if dst_ip in self._tor_exits:
            detections.append(("tor", "HIGH"))

        return detections

    # ── VPN Authorization ─────────────────────────────────────

    def _is_vpn_authorized(self, src_ip: str, dst_ip: str,
                           department: str) -> bool:
        """Check if this VPN usage is authorized."""
        # Connecting TO a corporate VPN server = always OK
        if dst_ip in self._vpn_server_ips:
            return True

        # Authorized IPs
        if src_ip in self._authorized_vpn_ips:
            return True

        # Authorized departments
        if department in self._authorized_vpn_depts:
            return True

        return False

    # ── Bulk Evaluation ───────────────────────────────────────

    def evaluate_batch(self, flows: List[dict],
                       identities: List[dict] = None,
                       now: float = None) -> List[dict]:
        """Evaluate a batch of flows."""
        if identities is None:
            identities = [None] * len(flows)
        return [self.evaluate(f, i, now) for f, i in zip(flows, identities)]

    # ── Feed Integration ──────────────────────────────────────

    def load_tor_exits(self, ips: List[str]):
        """Load Tor exit node IPs (from threat intel feed)."""
        self._tor_exits = set(ips)
        print(f"[Policy] Loaded {len(self._tor_exits)} Tor exit nodes")

    # ── Stats ─────────────────────────────────────────────────

    def get_stats(self) -> dict:
        return {
            **{k: v for k, v in self.stats.items() if not isinstance(v, defaultdict)},
            "by_category": dict(self.stats["by_category"]),
            "by_severity": dict(self.stats["by_severity"]),
        }

    def print_summary(self):
        s = self.get_stats()
        print(f"\n{'='*55}")
        print(f"  SECURITY POLICY ENGINE SUMMARY")
        print(f"{'='*55}")
        print(f"  Flows evaluated      : {s['flows_evaluated']:,}")
        print(f"  Violations detected  : {s['violations']:,}")
        print(f"    Anonymizer         : {s['anonymizer_detected']:,}")
        print(f"    Device violations  : {s['device_violations']:,}")
        print(f"    Dept violations    : {s['department_violations']:,}")
        print(f"    Time escalated     : {s['time_escalated']:,}")
        print(f"    Exfil indicators   : {s['exfil_indicators']:,}")
        if s["by_category"]:
            print(f"\n  By category:")
            for cat, cnt in sorted(s["by_category"].items(), key=lambda x: -x[1]):
                print(f"    {cat:<25} {cnt:>6,}")
        if s["by_severity"]:
            print(f"\n  By severity:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                cnt = s["by_severity"].get(sev, 0)
                if cnt:
                    print(f"    {sev:<12} {cnt:>6,}")
        print(f"{'='*55}")
