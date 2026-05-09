"""Peer Group Analysis + Identity Engine"""
import os
import sys
import io
import json
import time
import math
import ipaddress
import threading
import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Set

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

log = logging.getLogger("entity_context")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Shared identity returned for every external (public) IP. Reusing one
# instance prevents _identities from growing unbounded when the office
# talks to Google, Cloudflare, YouTube, etc.
_EXTERNAL_IDENTITY: Optional["DeviceIdentity"] = None

def _external_identity() -> "DeviceIdentity":
    global _EXTERNAL_IDENTITY
    if _EXTERNAL_IDENTITY is None:
        _EXTERNAL_IDENTITY = DeviceIdentity(
            ip="",
            hostname="",
            type="external",
            department="External",
            priority="low",
            trusted=False,
            sensitivity="low",
            data_class="external",
        )
    return _EXTERNAL_IDENTITY

class DeviceIdentity:
    """Identity record for a single device."""

    __slots__ = ['ip', 'hostname', 'mac', 'device_type', 'department',
                 'owner', 'priority', 'trusted', 'sensitivity',
                 'data_class', 'first_seen', 'last_seen']

    def __init__(self, ip: str, **kwargs):
        self.ip = ip
        self.hostname = kwargs.get("hostname", "")
        self.mac = kwargs.get("mac", "")
        self.device_type = kwargs.get("type", "unknown")
        self.department = kwargs.get("department", "Unknown")
        self.owner = kwargs.get("owner", "")
        self.priority = kwargs.get("priority", "medium")
        self.trusted = kwargs.get("trusted", False)
        self.sensitivity = kwargs.get("sensitivity", "medium")
        self.data_class = kwargs.get("data_class", "internal")
        self.first_seen = time.time()
        self.last_seen = time.time()

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "hostname": self.hostname, "mac": self.mac,
            "device_type": self.device_type, "department": self.department,
            "owner": self.owner, "priority": self.priority,
            "trusted": self.trusted, "sensitivity": self.sensitivity,
            "data_class": self.data_class,
        }

class PeerGroupBaseline:
    """
    Behavioral baseline for a group of peer entities.

    Tracks mean + std of key metrics across all entities in the group.
    New entities inherit this baseline immediately (zero cold start).
    """

    def __init__(self, name: str):
        self.name = name
        self.members: Set[str] = set()
        self._lock = threading.Lock()

        # Per-metric aggregates: list of recent values from all members
        # Updated hourly from each member's current metrics
        self._fpm_samples: List[float] = []
        self._unique_dst_samples: List[float] = []
        self._bytes_per_flow_samples: List[float] = []
        self._send_ratio_samples: List[float] = []

        # Computed baselines
        self.mean_fpm = 0.0
        self.std_fpm = 0.0
        self.mean_unique_dst = 0.0
        self.std_unique_dst = 0.0
        self.mean_bytes_per_flow = 0.0
        self.std_bytes_per_flow = 0.0
        self.mean_send_ratio = 0.5
        self.std_send_ratio = 0.0

        # Group-level port and protocol norms
        self.common_ports: Dict[int, int] = defaultdict(int)  # port → member_count
        self.common_protocols: Dict[int, int] = defaultdict(int)

        self.n_samples = 0
        self.last_computed = 0.0

    def add_member(self, ip: str):
        with self._lock:
            self.members.add(ip)

    def remove_member(self, ip: str):
        with self._lock:
            self.members.discard(ip)

    def update_from_entity(self, ip: str, fpm: float, unique_dst: float,
                           bytes_per_flow: float, send_ratio: float,
                           ports: Set[int] = None, protocols: Set[int] = None):
        """Record a member's current metrics into the group baseline."""
        with self._lock:
            self.members.add(ip)
            self._fpm_samples.append(fpm)
            self._unique_dst_samples.append(unique_dst)
            self._bytes_per_flow_samples.append(bytes_per_flow)
            self._send_ratio_samples.append(send_ratio)

            if ports:
                for p in ports:
                    self.common_ports[p] += 1
            if protocols:
                for pr in protocols:
                    self.common_protocols[pr] += 1

            # Keep last 500 samples per metric (rolling)
            max_samples = 500
            if len(self._fpm_samples) > max_samples:
                self._fpm_samples = self._fpm_samples[-max_samples:]
                self._unique_dst_samples = self._unique_dst_samples[-max_samples:]
                self._bytes_per_flow_samples = self._bytes_per_flow_samples[-max_samples:]
                self._send_ratio_samples = self._send_ratio_samples[-max_samples:]

            self._recompute()

    def _recompute(self):
        """Recompute mean and std from samples."""
        if len(self._fpm_samples) < 3:
            return

        self.n_samples = len(self._fpm_samples)

        self.mean_fpm = sum(self._fpm_samples) / self.n_samples
        self.std_fpm = self._std(self._fpm_samples, self.mean_fpm)

        self.mean_unique_dst = sum(self._unique_dst_samples) / self.n_samples
        self.std_unique_dst = self._std(self._unique_dst_samples, self.mean_unique_dst)

        self.mean_bytes_per_flow = sum(self._bytes_per_flow_samples) / self.n_samples
        self.std_bytes_per_flow = self._std(self._bytes_per_flow_samples,
                                            self.mean_bytes_per_flow)

        self.mean_send_ratio = sum(self._send_ratio_samples) / self.n_samples
        self.std_send_ratio = self._std(self._send_ratio_samples, self.mean_send_ratio)

        self.last_computed = time.time()

    @staticmethod
    def _std(samples: List[float], mean: float) -> float:
        if len(samples) < 2:
            return 0.0
        return max((sum((x - mean) ** 2 for x in samples) / len(samples)) ** 0.5, 0.01)

    def get_baseline(self) -> dict:
        return {
            "group": self.name,
            "members": len(self.members),
            "n_samples": self.n_samples,
            "mean_fpm": round(self.mean_fpm, 2),
            "std_fpm": round(self.std_fpm, 2),
            "mean_unique_dst": round(self.mean_unique_dst, 2),
            "std_unique_dst": round(self.std_unique_dst, 2),
            "mean_bytes_per_flow": round(self.mean_bytes_per_flow, 2),
            "std_bytes_per_flow": round(self.std_bytes_per_flow, 2),
            "mean_send_ratio": round(self.mean_send_ratio, 4),
            "top_ports": sorted(self.common_ports.items(),
                               key=lambda x: -x[1])[:10],
        }

    @property
    def is_ready(self) -> bool:
        return self.n_samples >= 10 and len(self.members) >= 2

class EntityContextEngine:
    """
    Identity + Peer Group engine.

    Provides:
      - Who is this IP? (identity lookup)
      - What department? (subnet → department mapping)
      - How sensitive? (department → sensitivity level)
      - What do peers do? (group baseline for zero cold start)
      - Is this entity deviating from its peer group?
    """

    def __init__(self, config_path: str = None):
        if config_path is None:
            config_path = str(_PROJECT_ROOT / "config" / "identity_registry.json")

        self._identities: Dict[str, DeviceIdentity] = {}
        self._subnets: List[Tuple[ipaddress.IPv4Network, str]] = []
        self._dept_sensitivity: Dict[str, dict] = {}
        self._peer_groups: Dict[str, PeerGroupBaseline] = {}
        self._lock = threading.Lock()

        # IP classifier; single source of truth for internal vs
        # external. External IPs never get cached as identities or
        # seeded into peer groups.
        from ip_classifier import get_classifier
        self._ip_classifier = get_classifier()

        self.stats = {
            "identity_lookups": 0,
            "identity_hits": 0,
            "peer_deviations": 0,
            "cold_starts_avoided": 0,
            "external_skipped": 0,
        }

        self._load_config(config_path)

        print(f"[EntityCtx] Loaded: {len(self._identities)} devices, "
              f"{len(self._subnets)} subnets, "
              f"{len(self._dept_sensitivity)} departments")

    def _load_config(self, path: str):
        try:
            with open(path) as f:
                cfg = json.load(f)

            # Load device identities
            for ip, info in cfg.get("devices", {}).items():
                dept = info.get("department", "Unknown")
                sens = cfg.get("department_sensitivity", {}).get(dept, {})
                identity = DeviceIdentity(
                    ip,
                    hostname=info.get("hostname", ""),
                    mac=info.get("mac", ""),
                    type=info.get("type", "unknown"),
                    department=dept,
                    owner=info.get("owner", ""),
                    priority=info.get("priority", "medium"),
                    trusted=info.get("trusted", False),
                    sensitivity=sens.get("level", "medium"),
                    data_class=sens.get("data_class", "internal"),
                )
                self._identities[ip] = identity

            # Load subnet → department mapping
            for subnet_str, dept in cfg.get("subnet_to_department", {}).items():
                try:
                    net = ipaddress.IPv4Network(subnet_str, strict=False)
                    self._subnets.append((net, dept))
                except ValueError:
                    pass
            # Sort subnets by prefix length (most specific first)
            self._subnets.sort(key=lambda x: -x[0].prefixlen)

            # Load department sensitivity
            self._dept_sensitivity = cfg.get("department_sensitivity", {})

            # Initialize peer groups
            for dept in self._dept_sensitivity:
                self._peer_groups[dept] = PeerGroupBaseline(dept)

            # Assign known devices to peer groups
            for ip, identity in self._identities.items():
                dept = identity.department
                if dept in self._peer_groups:
                    self._peer_groups[dept].add_member(ip)

        except FileNotFoundError:
            print(f"[EntityCtx] No config at {path}")
        except Exception as e:
            print(f"[EntityCtx] Config error: {e}")

    # ── Identity Lookup ───────────────────────────────────────

    def get_identity(self, ip: str) -> DeviceIdentity:
        """
        Look up identity for an IP.
        Returns known identity or auto-generates from subnet mapping.

        External IPs (Google, Cloudflare, YouTube CDNs, etc.) return a
        shared sentinel identity and are NOT cached or added to peer
        groups; they are not office devices.
        """
        self.stats["identity_lookups"] += 1

        # External IPs short-circuit to the shared sentinel. Gate flows
        # may still reference this for alert metadata but nothing is
        # persisted and the peer group membership stays clean.
        if self._ip_classifier.is_external(ip):
            self.stats["external_skipped"] += 1
            return _external_identity()

        # Check known devices first
        identity = self._identities.get(ip)
        if identity:
            identity.last_seen = time.time()
            self.stats["identity_hits"] += 1
            return identity

        # Auto-assign department from subnet
        dept = self._subnet_to_dept(ip)
        sens = self._dept_sensitivity.get(dept, {})

        identity = DeviceIdentity(
            ip,
            department=dept,
            sensitivity=sens.get("level", "medium"),
            data_class=sens.get("data_class", "unknown"),
        )

        # Cache for future lookups
        with self._lock:
            self._identities[ip] = identity

        # Add to peer group
        if dept in self._peer_groups:
            self._peer_groups[dept].add_member(ip)

        return identity

    def _subnet_to_dept(self, ip: str) -> str:
        """Map IP to department via subnet matching."""
        try:
            addr = ipaddress.IPv4Address(ip)
            for net, dept in self._subnets:
                if addr in net:
                    return dept
        except ValueError:
            pass
        return "Unknown"

    # ── Peer Group Analysis ───────────────────────────────────

    def get_peer_group(self, department: str) -> Optional[PeerGroupBaseline]:
        """Get the peer group baseline for a department."""
        return self._peer_groups.get(department)

    def update_peer_group(self, ip: str, fpm: float, unique_dst: float,
                          bytes_per_flow: float, send_ratio: float,
                          ports: Set[int] = None, protocols: Set[int] = None):
        """
        Feed an entity's current metrics into its peer group.
        Called periodically (e.g., every 100 flows) by UEBA v4.

        Skips external IPs; they never contribute to a peer baseline.
        """
        if self._ip_classifier.is_external(ip):
            return
        identity = self.get_identity(ip)
        dept = identity.department
        group = self._peer_groups.get(dept)
        if group:
            group.update_from_entity(ip, fpm, unique_dst,
                                     bytes_per_flow, send_ratio,
                                     ports, protocols)

    def score_peer_deviation(self, ip: str, current_fpm: float,
                             current_unique_dst: float,
                             current_bytes_per_flow: float,
                             current_send_ratio: float
                             ) -> Tuple[float, List[str]]:
        """
        Score how much this entity deviates from its peer group.

        Returns (deviation_score, reasons).
        Score 0.0 = perfectly normal for the group.
        Score 1.0 = extreme outlier.

        External IPs are never scored; they have no peer group.
        """
        if self._ip_classifier.is_external(ip):
            return 0.0, []

        identity = self.get_identity(ip)
        dept = identity.department
        group = self._peer_groups.get(dept)

        if not group or not group.is_ready:
            return 0.0, []

        score = 0.0
        reasons = []

        # Z-score for each metric against peer group
        z_fpm = self._z_score(current_fpm, group.mean_fpm, group.std_fpm)
        z_dst = self._z_score(current_unique_dst, group.mean_unique_dst,
                              group.std_unique_dst)
        z_bytes = self._z_score(current_bytes_per_flow,
                                group.mean_bytes_per_flow,
                                group.std_bytes_per_flow)
        z_ratio = self._z_score(current_send_ratio, group.mean_send_ratio,
                                group.std_send_ratio)

        # Rate deviation from peers
        if z_fpm >= 5.0:
            score += 0.35
            reasons.append(f"Peer deviation: rate {current_fpm:.0f} fpm vs "
                         f"group {group.mean_fpm:.0f}+/-{group.std_fpm:.0f} "
                         f"(z={z_fpm:.1f}, dept={dept})")
        elif z_fpm >= 3.0:
            score += 0.20
            reasons.append(f"Peer rate elevated: z={z_fpm:.1f} vs {dept} group")

        # Destination diversity deviation
        if z_dst >= 5.0:
            score += 0.30
            reasons.append(f"Peer deviation: {current_unique_dst:.0f} unique dsts vs "
                         f"group {group.mean_unique_dst:.0f}+/-{group.std_unique_dst:.0f}")
        elif z_dst >= 3.0:
            score += 0.15
            reasons.append(f"Peer dst diversity elevated: z={z_dst:.1f}")

        # Volume deviation
        if z_bytes >= 5.0:
            score += 0.25
            reasons.append(f"Peer deviation: {current_bytes_per_flow:.0f} bytes/flow vs "
                         f"group {group.mean_bytes_per_flow:.0f}")
        elif z_bytes >= 3.0:
            score += 0.10

        # Send ratio deviation (exfiltration detection across peer group)
        if z_ratio >= 4.0 and current_send_ratio > 0.80:
            score += 0.30
            reasons.append(f"Peer deviation: {current_send_ratio*100:.0f}% outbound vs "
                         f"group {group.mean_send_ratio*100:.0f}% "
                         f"(possible exfiltration)")
        elif z_ratio >= 3.0:
            score += 0.10

        if score > 0:
            self.stats["peer_deviations"] += 1

        return min(score, 1.0), reasons

    def get_group_baseline_for_cold_start(self, ip: str) -> Optional[dict]:
        """
        Get peer group baseline for an entity that hasn't built
        its own baseline yet. Eliminates cold start blindness.
        """
        identity = self.get_identity(ip)
        group = self._peer_groups.get(identity.department)
        if group and group.is_ready:
            self.stats["cold_starts_avoided"] += 1
            return group.get_baseline()
        return None

    def get_sensitivity(self, ip: str) -> dict:
        """Get sensitivity context for alert prioritization."""
        identity = self.get_identity(ip)
        dept_info = self._dept_sensitivity.get(identity.department, {})
        return {
            "department": identity.department,
            "sensitivity": identity.sensitivity,
            "data_class": identity.data_class,
            "priority": identity.priority,
            "alert_escalation": dept_info.get("alert_escalation", False),
            "owner": identity.owner,
            "hostname": identity.hostname,
            "trusted": identity.trusted,
        }

    @staticmethod
    def _z_score(value: float, mean: float, std: float) -> float:
        if std < 0.01:
            return 0.0 if abs(value - mean) < 0.01 else 10.0
        return abs(value - mean) / std

    # ── Utilities ─────────────────────────────────────────────

    def get_all_groups(self) -> Dict[str, dict]:
        return {name: g.get_baseline()
                for name, g in self._peer_groups.items()}

    def get_stats(self) -> dict:
        return {
            **self.stats,
            "known_devices": len(self._identities),
            "peer_groups": len(self._peer_groups),
            "groups_ready": sum(1 for g in self._peer_groups.values()
                               if g.is_ready),
        }

    def print_summary(self):
        s = self.get_stats()
        print(f"\n{'='*55}")
        print(f"  ENTITY CONTEXT SUMMARY")
        print(f"{'='*55}")
        print(f"  Known devices      : {s['known_devices']}")
        print(f"  Identity lookups   : {s['identity_lookups']:,}")
        print(f"  Identity hits      : {s['identity_hits']:,}")
        print(f"  Peer groups        : {s['peer_groups']}")
        print(f"  Groups ready       : {s['groups_ready']}")
        print(f"  Peer deviations    : {s['peer_deviations']:,}")
        print(f"  Cold starts avoided: {s['cold_starts_avoided']:,}")

        for name, group in self._peer_groups.items():
            if group.is_ready:
                b = group.get_baseline()
                print(f"\n  [{name}] ({b['members']} members, "
                      f"{b['n_samples']} samples)")
                print(f"    fpm: {b['mean_fpm']}+/-{b['std_fpm']}")
                print(f"    dst: {b['mean_unique_dst']}+/-{b['std_unique_dst']}")
                print(f"    bytes: {b['mean_bytes_per_flow']}+/-{b['std_bytes_per_flow']}")

        print(f"{'='*55}")
