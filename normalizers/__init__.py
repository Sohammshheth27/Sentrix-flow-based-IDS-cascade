"""Phase 4 IPFIX-native normalizers.

Every dataset is loaded through a BaseIPFIXNormalizer subclass and emits exactly
the 45-column canonical schema (frozen in base_ipfix_normalizer.CANONICAL_FEATURES)
plus a fixed set of metadata columns. Never extend the 45-feature tuple.
"""
from normalizers.base_ipfix_normalizer import (
    BaseIPFIXNormalizer,
    CANONICAL_FEATURES,
    N_CANONICAL,
    METADATA_COLUMNS,
    EPS,
)

__all__ = [
    "BaseIPFIXNormalizer",
    "CANONICAL_FEATURES",
    "N_CANONICAL",
    "METADATA_COLUMNS",
    "EPS",
]
