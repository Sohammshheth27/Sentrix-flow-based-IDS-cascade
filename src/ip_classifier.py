"""Internal vs External IP classification."""
import ipaddress
from pathlib import Path
from typing import List, Optional, Union

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

_DEFAULT_INTERNAL_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",    # CGNAT; RFC 6598
    "169.254.0.0/16",   # link-local
    "127.0.0.0/8",      # loopback
    "::1/128",
    "fc00::/7",         # IPv6 ULA
    "fe80::/10",        # IPv6 link-local
]

IPNet = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

class IPClassifier:
    """Classifies IPs as internal (office) or external (public)."""

    def __init__(self, config_path: Optional[Path] = None):
        self._nets: List[IPNet] = []
        self._extra_count = 0
        self._public_office_count = 0

        for cidr in _DEFAULT_INTERNAL_CIDRS:
            try:
                self._nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass

        if config_path is None:
            config_path = _PROJECT_ROOT / "config" / "internal_networks.yaml"

        if Path(config_path).exists():
            self._load_extra(Path(config_path))

        print(f"[IPClassifier] {len(self._nets)} internal networks "
              f"(extra={self._extra_count}, "
              f"public_office={self._public_office_count})")

    def _load_extra(self, path: Path) -> None:
        try:
            import yaml  # deferred import; yaml is already a project dep
        except ImportError:
            print(f"[IPClassifier] PyYAML not installed, skipping {path}")
            return
        try:
            with open(path, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"[IPClassifier] Failed to read {path}: {e}")
            return

        for cidr in (cfg.get("extra_internal") or []):
            try:
                self._nets.append(ipaddress.ip_network(cidr, strict=False))
                self._extra_count += 1
            except ValueError:
                print(f"[IPClassifier] skipping bad CIDR in "
                      f"extra_internal: {cidr!r}")

        for ip_str in (cfg.get("public_office_ips") or []):
            try:
                addr = ipaddress.ip_address(ip_str)
                host_bits = "/32" if addr.version == 4 else "/128"
                self._nets.append(
                    ipaddress.ip_network(f"{ip_str}{host_bits}",
                                          strict=False))
                self._public_office_count += 1
            except ValueError:
                print(f"[IPClassifier] skipping bad public_office_ip: "
                      f"{ip_str!r}")

    def is_internal(self, ip: str) -> bool:
        """True if ip is RFC1918/CGNAT/link-local/loopback or listed
        in internal_networks.yaml. False for public IPs and invalid
        strings (fail-closed: unknown → treated as external)."""
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(str(ip))
        except (ValueError, TypeError):
            return False
        for net in self._nets:
            if addr.version == net.version and addr in net:
                return True
        return False

    def is_external(self, ip: str) -> bool:
        """True if ip is a valid public IP not in any internal net."""
        if not ip:
            return False
        try:
            ipaddress.ip_address(str(ip))
        except (ValueError, TypeError):
            return False
        return not self.is_internal(ip)

    def classify(self, ip: str) -> str:
        """Returns 'internal', 'external', or 'invalid'."""
        if not ip:
            return "invalid"
        try:
            ipaddress.ip_address(str(ip))
        except (ValueError, TypeError):
            return "invalid"
        return "internal" if self.is_internal(ip) else "external"

# Module-level singleton; loaded once at engine start.
_CLASSIFIER: Optional[IPClassifier] = None

def get_classifier(config_path: Optional[Path] = None) -> IPClassifier:
    """Return the process-wide IPClassifier singleton.

    First call loads config/internal_networks.yaml; subsequent calls
    return the same instance. Pass a config_path to force reload with
    a different config (mainly for tests)."""
    global _CLASSIFIER
    if _CLASSIFIER is None or config_path is not None:
        _CLASSIFIER = IPClassifier(config_path)
    return _CLASSIFIER
