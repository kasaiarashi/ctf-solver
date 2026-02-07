"""
CTF Solver Tools

A collection of Python utilities for solving CTF challenges.

Modules:
    binary - Binary analysis tools (checksec, gadgets, ELF analysis)
    crypto - Cryptography utilities (ciphers, hashes, RSA)
    web - Web exploitation helpers (SQLi, XSS, requests)
    forensics - Forensics tools (steganography, file carving)
    common - Shared utilities (encoding, flag extraction)
"""

from . import binary
from . import crypto
from . import web
from . import forensics
from . import common

__version__ = "1.0.0"
__all__ = ["binary", "crypto", "web", "forensics", "common"]
