"""
Hash Utilities

Tools for hash identification, cracking hints, and common operations.
"""

import hashlib
import re
from typing import Optional, List, Tuple


# Hash patterns for identification
HASH_PATTERNS = [
    (r'^[a-fA-F0-9]{32}$', 'MD5', 128),
    (r'^[a-fA-F0-9]{40}$', 'SHA-1', 160),
    (r'^[a-fA-F0-9]{56}$', 'SHA-224', 224),
    (r'^[a-fA-F0-9]{64}$', 'SHA-256', 256),
    (r'^[a-fA-F0-9]{96}$', 'SHA-384', 384),
    (r'^[a-fA-F0-9]{128}$', 'SHA-512', 512),
    (r'^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$', 'MD5-crypt', None),
    (r'^\$2[aby]?\$\d{2}\$[a-zA-Z0-9./]{53}$', 'bcrypt', None),
    (r'^\$5\$[a-zA-Z0-9./]{16}\$[a-zA-Z0-9./]{43}$', 'SHA-256-crypt', None),
    (r'^\$6\$[a-zA-Z0-9./]{16}\$[a-zA-Z0-9./]{86}$', 'SHA-512-crypt', None),
    (r'^[a-fA-F0-9]{16}$', 'MySQL323/Half-MD5', 64),
    (r'^\*[A-F0-9]{40}$', 'MySQL5', 160),
]


def identify_hash(hash_string: str) -> List[Tuple[str, int]]:
    """
    Identify the type of hash based on format.

    Args:
        hash_string: The hash to identify

    Returns:
        List of (hash_type, bit_length) tuples, sorted by likelihood
    """
    matches = []
    hash_string = hash_string.strip()

    for pattern, name, bits in HASH_PATTERNS:
        if re.match(pattern, hash_string):
            matches.append((name, bits))

    return matches


def hash_string(text: str, algorithm: str = 'md5') -> str:
    """
    Hash a string with the specified algorithm.

    Args:
        text: String to hash
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)

    Returns:
        Hex digest of the hash
    """
    algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
        'sha224': hashlib.sha224,
        'sha384': hashlib.sha384,
    }

    if algorithm.lower() not in algorithms:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    hasher = algorithms[algorithm.lower()]()
    hasher.update(text.encode())
    return hasher.hexdigest()


def hash_bytes(data: bytes, algorithm: str = 'md5') -> str:
    """Hash bytes with the specified algorithm."""
    algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
    }

    if algorithm.lower() not in algorithms:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    hasher = algorithms[algorithm.lower()]()
    hasher.update(data)
    return hasher.hexdigest()


def check_common_hashes(hash_to_check: str) -> Optional[str]:
    """
    Check if hash matches common passwords/values.

    Args:
        hash_to_check: Hash to check

    Returns:
        Plaintext if found, None otherwise
    """
    common_values = [
        "", "password", "123456", "admin", "root", "flag",
        "test", "guest", "qwerty", "letmein", "password123",
        "abc123", "monkey", "master", "dragon", "111111",
        "1234567890", "12345678", "12345", "1234",
    ]

    hash_to_check = hash_to_check.lower().strip()
    hash_type = identify_hash(hash_to_check)

    if not hash_type:
        return None

    for value in common_values:
        for algo in ['md5', 'sha1', 'sha256', 'sha512']:
            if hash_string(value, algo).lower() == hash_to_check:
                return value

    return None


def crack_md5_numeric(target_hash: str, max_length: int = 8) -> Optional[str]:
    """
    Brute force numeric MD5 hash.

    Args:
        target_hash: Target MD5 hash
        max_length: Maximum number length

    Returns:
        Plaintext if found, None otherwise
    """
    target_hash = target_hash.lower()

    for length in range(1, max_length + 1):
        for i in range(10 ** length):
            candidate = str(i).zfill(length)
            if hashlib.md5(candidate.encode()).hexdigest() == target_hash:
                return candidate

    return None


def length_extension_check(hash_value: str) -> bool:
    """
    Check if a hash algorithm is vulnerable to length extension.

    Returns True for MD5, SHA-1, SHA-256, SHA-512.
    """
    hash_types = identify_hash(hash_value)
    vulnerable = {'MD5', 'SHA-1', 'SHA-256', 'SHA-512'}

    for hash_type, _ in hash_types:
        if hash_type in vulnerable:
            return True
    return False


def generate_rainbow_lookup_url(hash_value: str) -> str:
    """Generate URL for online rainbow table lookup."""
    return f"https://crackstation.net/ (paste: {hash_value})"


if __name__ == "__main__":
    # Example usage
    test_hash = "5d41402abc4b2a76b9719d911017c592"
    print(f"Hash: {test_hash}")
    print(f"Identified as: {identify_hash(test_hash)}")

    result = check_common_hashes(test_hash)
    if result:
        print(f"Cracked: {result}")

    print(f"\nMD5('test'): {hash_string('test', 'md5')}")
    print(f"SHA256('test'): {hash_string('test', 'sha256')}")
