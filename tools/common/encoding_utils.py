"""
Encoding Utilities

Tools for encoding and decoding various formats.
"""

import base64
import codecs
from typing import Union, Optional, List, Tuple
from urllib.parse import quote, unquote


def to_base64(data: Union[str, bytes]) -> str:
    """
    Encode data to base64.

    Args:
        data: String or bytes to encode

    Returns:
        Base64 encoded string
    """
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


def from_base64(data: str) -> bytes:
    """
    Decode base64 data.

    Args:
        data: Base64 encoded string

    Returns:
        Decoded bytes
    """
    # Handle URL-safe base64
    data = data.replace('-', '+').replace('_', '/')

    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding

    return base64.b64decode(data)


def to_hex(data: Union[str, bytes]) -> str:
    """
    Encode data to hexadecimal.

    Args:
        data: String or bytes to encode

    Returns:
        Hex encoded string
    """
    if isinstance(data, str):
        data = data.encode()
    return data.hex()


def from_hex(data: str) -> bytes:
    """
    Decode hexadecimal data.

    Args:
        data: Hex encoded string

    Returns:
        Decoded bytes
    """
    # Remove common prefixes and separators
    data = data.replace('0x', '').replace(' ', '').replace(':', '').replace('-', '')
    return bytes.fromhex(data)


def to_binary(data: Union[str, bytes]) -> str:
    """
    Encode data to binary representation.

    Args:
        data: String or bytes to encode

    Returns:
        Binary string (space-separated bytes)
    """
    if isinstance(data, str):
        data = data.encode()
    return ' '.join(format(byte, '08b') for byte in data)


def from_binary(data: str) -> bytes:
    """
    Decode binary representation.

    Args:
        data: Binary string

    Returns:
        Decoded bytes
    """
    # Remove spaces and split into 8-bit chunks
    data = data.replace(' ', '')
    chunks = [data[i:i+8] for i in range(0, len(data), 8)]
    return bytes(int(chunk, 2) for chunk in chunks)


def rot13(text: str) -> str:
    """Apply ROT13 transformation."""
    return codecs.decode(text, 'rot_13')


def rot(text: str, n: int) -> str:
    """
    Apply ROT-N transformation.

    Args:
        text: Text to transform
        n: Rotation amount (1-25)

    Returns:
        Transformed text
    """
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            rotated = chr((ord(char) - base + n) % 26 + base)
            result.append(rotated)
        else:
            result.append(char)
    return ''.join(result)


def url_encode(text: str, safe: str = '') -> str:
    """
    URL encode a string.

    Args:
        text: String to encode
        safe: Characters to not encode

    Returns:
        URL encoded string
    """
    return quote(text, safe=safe)


def url_decode(text: str) -> str:
    """
    URL decode a string.

    Args:
        text: URL encoded string

    Returns:
        Decoded string
    """
    return unquote(text)


def to_octal(data: Union[str, bytes]) -> str:
    """
    Encode data to octal representation.

    Args:
        data: String or bytes to encode

    Returns:
        Octal string
    """
    if isinstance(data, str):
        data = data.encode()
    return ' '.join(format(byte, '03o') for byte in data)


def from_octal(data: str) -> bytes:
    """
    Decode octal representation.

    Args:
        data: Octal string

    Returns:
        Decoded bytes
    """
    chunks = data.split()
    return bytes(int(chunk, 8) for chunk in chunks)


def to_decimal(data: Union[str, bytes]) -> str:
    """
    Encode data to decimal representation.

    Args:
        data: String or bytes to encode

    Returns:
        Decimal string (space-separated)
    """
    if isinstance(data, str):
        data = data.encode()
    return ' '.join(str(byte) for byte in data)


def from_decimal(data: str) -> bytes:
    """
    Decode decimal representation.

    Args:
        data: Decimal string

    Returns:
        Decoded bytes
    """
    chunks = data.split()
    return bytes(int(chunk) for chunk in chunks)


def detect_encoding(data: str) -> List[Tuple[str, float]]:
    """
    Attempt to detect the encoding of data.

    Args:
        data: Potentially encoded string

    Returns:
        List of (encoding_type, confidence) tuples
    """
    results = []
    data = data.strip()

    # Check for Base64
    if len(data) % 4 == 0 or data.endswith('='):
        try:
            decoded = from_base64(data)
            # Check if result is printable
            try:
                text = decoded.decode('utf-8')
                if all(c.isprintable() or c.isspace() for c in text):
                    results.append(('base64', 0.9))
            except:
                results.append(('base64', 0.5))
        except:
            pass

    # Check for Hex
    hex_chars = set('0123456789abcdefABCDEF ')
    if all(c in hex_chars for c in data):
        try:
            decoded = from_hex(data)
            try:
                text = decoded.decode('utf-8')
                if all(c.isprintable() or c.isspace() for c in text):
                    results.append(('hex', 0.9))
            except:
                results.append(('hex', 0.5))
        except:
            pass

    # Check for Binary
    if all(c in '01 ' for c in data):
        try:
            decoded = from_binary(data)
            try:
                text = decoded.decode('utf-8')
                if all(c.isprintable() or c.isspace() for c in text):
                    results.append(('binary', 0.9))
            except:
                pass
        except:
            pass

    # Check for URL encoding
    if '%' in data:
        try:
            decoded = url_decode(data)
            if decoded != data:
                results.append(('url', 0.9))
        except:
            pass

    # Check for ROT13 (look for common patterns)
    rot13_decoded = rot13(data)
    common_words = ['the', 'and', 'flag', 'key', 'password']
    for word in common_words:
        if word in rot13_decoded.lower():
            results.append(('rot13', 0.7))
            break

    # Sort by confidence
    return sorted(results, key=lambda x: x[1], reverse=True)


def multi_decode(data: str, max_depth: int = 5) -> List[Tuple[str, str]]:
    """
    Attempt multiple layers of decoding.

    Args:
        data: Potentially encoded string
        max_depth: Maximum decoding depth

    Returns:
        List of (decoding_chain, result) tuples
    """
    results = []

    def recursive_decode(current: str, chain: str, depth: int):
        if depth >= max_depth:
            return

        # Try each encoding
        encodings = detect_encoding(current)
        for enc_type, confidence in encodings:
            if confidence < 0.5:
                continue

            try:
                if enc_type == 'base64':
                    decoded = from_base64(current).decode('utf-8', errors='ignore')
                elif enc_type == 'hex':
                    decoded = from_hex(current).decode('utf-8', errors='ignore')
                elif enc_type == 'binary':
                    decoded = from_binary(current).decode('utf-8', errors='ignore')
                elif enc_type == 'url':
                    decoded = url_decode(current)
                elif enc_type == 'rot13':
                    decoded = rot13(current)
                else:
                    continue

                new_chain = f"{chain} -> {enc_type}" if chain else enc_type
                results.append((new_chain, decoded))
                recursive_decode(decoded, new_chain, depth + 1)
            except:
                pass

    recursive_decode(data, "", 0)
    return results


if __name__ == "__main__":
    # Example usage
    original = "flag{test_encoding}"
    print(f"Original: {original}")
    print(f"Base64:   {to_base64(original)}")
    print(f"Hex:      {to_hex(original)}")
    print(f"Binary:   {to_binary(original)}")
    print(f"ROT13:    {rot13(original)}")
    print(f"URL:      {url_encode(original)}")

    # Multi-layer encoding
    encoded = to_base64(to_hex(original))
    print(f"\nDouble encoded: {encoded}")
    print("Detected encodings:", detect_encoding(encoded))
    print("Multi-decode results:")
    for chain, result in multi_decode(encoded):
        print(f"  {chain}: {result[:50]}...")
