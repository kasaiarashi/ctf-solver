"""
Common Utilities

Shared utilities for CTF solving.
"""

from .flag_extractor import (
    extract_flag,
    find_flags,
    FLAG_PATTERNS,
)
from .encoding_utils import (
    to_base64,
    from_base64,
    to_hex,
    from_hex,
    to_binary,
    from_binary,
    rot13,
    url_encode,
    url_decode,
    detect_encoding,
)

__all__ = [
    # Flag extractor
    "extract_flag",
    "find_flags",
    "FLAG_PATTERNS",
    # Encoding utils
    "to_base64",
    "from_base64",
    "to_hex",
    "from_hex",
    "to_binary",
    "from_binary",
    "rot13",
    "url_encode",
    "url_decode",
    "detect_encoding",
]
