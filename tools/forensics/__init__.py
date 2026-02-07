"""
Forensics Tools

Utilities for digital forensics and steganography.
"""

from .stego_utils import (
    extract_lsb,
    check_file_signature,
    analyze_metadata,
    find_hidden_data,
)
from .file_carver import (
    find_embedded_files,
    carve_file,
    get_file_type,
    MAGIC_BYTES,
)

__all__ = [
    # Stego utils
    "extract_lsb",
    "check_file_signature",
    "analyze_metadata",
    "find_hidden_data",
    # File carver
    "find_embedded_files",
    "carve_file",
    "get_file_type",
    "MAGIC_BYTES",
]
