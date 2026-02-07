"""
Flag Extractor

Tools for finding and extracting CTF flags.
"""

import re
from typing import List, Optional, Tuple


# Common CTF flag patterns
FLAG_PATTERNS = [
    # Generic
    r'flag\{[^\}]+\}',
    r'FLAG\{[^\}]+\}',
    r'Flag\{[^\}]+\}',

    # CTF-specific
    r'CTF\{[^\}]+\}',
    r'ctf\{[^\}]+\}',

    # picoCTF
    r'picoCTF\{[^\}]+\}',
    r'picoGym\{[^\}]+\}',

    # HackTheBox
    r'HTB\{[^\}]+\}',
    r'htb\{[^\}]+\}',

    # TryHackMe
    r'THM\{[^\}]+\}',
    r'thm\{[^\}]+\}',

    # Google CTF
    r'CTF\{[^\}]+\}',

    # DEF CON
    r'OOO\{[^\}]+\}',

    # PlaidCTF
    r'PCTF\{[^\}]+\}',

    # DragonCTF
    r'DrgnS\{[^\}]+\}',

    # CSAW
    r'flag\{[^\}]+\}',

    # redpwn
    r'flag\{[^\}]+\}',

    # Hack.lu
    r'fluxfingers\{[^\}]+\}',

    # ASIS
    r'ASIS\{[^\}]+\}',

    # HITCON
    r'hitcon\{[^\}]+\}',

    # Square CTF
    r'flag-[a-zA-Z0-9]+',

    # Underscored variants
    r'flag_[a-zA-Z0-9_]+',

    # UUID-like
    r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
]


def extract_flag(text: str, pattern: Optional[str] = None) -> Optional[str]:
    """
    Extract a flag from text.

    Args:
        text: Text to search
        pattern: Optional specific pattern (uses common patterns if None)

    Returns:
        Flag string if found, None otherwise
    """
    if pattern:
        match = re.search(pattern, text)
        return match.group(0) if match else None

    # Try all common patterns
    for pat in FLAG_PATTERNS:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            return match.group(0)

    return None


def find_flags(text: str, pattern: Optional[str] = None) -> List[str]:
    """
    Find all flags in text.

    Args:
        text: Text to search
        pattern: Optional specific pattern

    Returns:
        List of found flags
    """
    flags = []

    if pattern:
        flags = re.findall(pattern, text)
    else:
        for pat in FLAG_PATTERNS:
            matches = re.findall(pat, text, re.IGNORECASE)
            flags.extend(matches)

    # Remove duplicates while preserving order
    seen = set()
    unique = []
    for f in flags:
        if f not in seen:
            seen.add(f)
            unique.append(f)

    return unique


def extract_flag_from_file(file_path: str, binary: bool = False) -> List[str]:
    """
    Search for flags in a file.

    Args:
        file_path: Path to the file
        binary: Whether to treat as binary file

    Returns:
        List of found flags
    """
    mode = 'rb' if binary else 'r'

    try:
        with open(file_path, mode) as f:
            content = f.read()

        if binary:
            # Try to decode as various encodings
            for encoding in ['utf-8', 'latin-1', 'ascii']:
                try:
                    text = content.decode(encoding, errors='ignore')
                    flags = find_flags(text)
                    if flags:
                        return flags
                except:
                    continue
            return []
        else:
            return find_flags(content)

    except Exception as e:
        print(f"Error reading file: {e}")
        return []


def validate_flag_format(flag: str, expected_prefix: str = "flag") -> bool:
    """
    Validate that a flag matches expected format.

    Args:
        flag: Flag to validate
        expected_prefix: Expected flag prefix

    Returns:
        True if valid format
    """
    pattern = rf'^{re.escape(expected_prefix)}\{{[^\}}]+\}}$'
    return bool(re.match(pattern, flag, re.IGNORECASE))


def create_flag_pattern(prefix: str) -> str:
    """
    Create a regex pattern for a specific CTF.

    Args:
        prefix: CTF prefix (e.g., "picoCTF", "HTB")

    Returns:
        Regex pattern string
    """
    return rf'{re.escape(prefix)}\{{[^\}}]+\}}'


def decode_and_find_flag(encoded: str) -> List[Tuple[str, str]]:
    """
    Try common decodings and search for flags.

    Args:
        encoded: Encoded string

    Returns:
        List of (encoding_type, flag) tuples
    """
    import base64
    from urllib.parse import unquote

    results = []

    # Plain text
    flags = find_flags(encoded)
    for f in flags:
        results.append(('plain', f))

    # Base64
    try:
        decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
        flags = find_flags(decoded)
        for f in flags:
            results.append(('base64', f))
    except:
        pass

    # URL encoding
    try:
        decoded = unquote(encoded)
        if decoded != encoded:
            flags = find_flags(decoded)
            for f in flags:
                results.append(('url', f))
    except:
        pass

    # Hex
    try:
        decoded = bytes.fromhex(encoded.replace(' ', '')).decode('utf-8', errors='ignore')
        flags = find_flags(decoded)
        for f in flags:
            results.append(('hex', f))
    except:
        pass

    # ROT13
    import codecs
    try:
        decoded = codecs.decode(encoded, 'rot_13')
        flags = find_flags(decoded)
        for f in flags:
            results.append(('rot13', f))
    except:
        pass

    return results


if __name__ == "__main__":
    # Example usage
    test_strings = [
        "Congratulations! Your flag is flag{this_is_a_test}",
        "picoCTF{base64_is_easy_12345}",
        "The answer is HTB{h4ck_th3_b0x}",
        "SGVsbG8gZmxhZ3t0ZXN0fQ==",  # Base64 encoded "Hello flag{test}"
    ]

    for s in test_strings:
        found = find_flags(s)
        if found:
            print(f"Found in '{s[:30]}...': {found}")

        # Try decoding
        decoded = decode_and_find_flag(s)
        for enc, flag in decoded:
            print(f"  [{enc}] {flag}")
