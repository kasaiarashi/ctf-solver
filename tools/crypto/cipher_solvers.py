"""
Classical Cipher Solvers

Tools for solving classical ciphers and encoding challenges.
"""

from typing import List, Tuple, Optional, Dict
from collections import Counter
import string

# English letter frequency (most to least common)
ENGLISH_FREQ = "etaoinshrdlcumwfgypbvkjxqz"


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """
    Decrypt Caesar cipher with known shift.

    Args:
        ciphertext: Encrypted text
        shift: Shift value (1-25)

    Returns:
        Decrypted text
    """
    result = []
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            decrypted = chr((ord(char) - base - shift) % 26 + base)
            result.append(decrypted)
        else:
            result.append(char)
    return ''.join(result)


def caesar_bruteforce(ciphertext: str) -> List[Tuple[int, str]]:
    """
    Try all Caesar cipher shifts.

    Args:
        ciphertext: Encrypted text

    Returns:
        List of (shift, decrypted_text) tuples
    """
    results = []
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        results.append((shift, decrypted))
    return results


def rot13(text: str) -> str:
    """Apply ROT13 transformation."""
    return caesar_decrypt(text, 13)


def atbash(text: str) -> str:
    """Apply Atbash cipher (reverse alphabet)."""
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            decrypted = chr(25 - (ord(char) - base) + base)
            result.append(decrypted)
        else:
            result.append(char)
    return ''.join(result)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """
    Decrypt Vigenere cipher with known key.

    Args:
        ciphertext: Encrypted text
        key: Encryption key

    Returns:
        Decrypted text
    """
    result = []
    key = key.upper()
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            decrypted = chr((ord(char) - base - shift) % 26 + base)
            result.append(decrypted)
            key_index += 1
        else:
            result.append(char)

    return ''.join(result)


def xor_single_byte(data: bytes, key: int) -> bytes:
    """
    XOR data with a single byte key.

    Args:
        data: Input bytes
        key: Single byte key (0-255)

    Returns:
        XORed bytes
    """
    return bytes([b ^ key for b in data])


def xor_single_byte_bruteforce(data: bytes) -> List[Tuple[int, bytes, float]]:
    """
    Bruteforce single-byte XOR and score by printability.

    Returns:
        List of (key, decrypted, score) sorted by score
    """
    results = []
    for key in range(256):
        decrypted = xor_single_byte(data, key)
        score = _score_printable(decrypted)
        results.append((key, decrypted, score))

    return sorted(results, key=lambda x: x[2], reverse=True)


def xor_repeating_key(data: bytes, key: bytes) -> bytes:
    """
    XOR data with a repeating key.

    Args:
        data: Input bytes
        key: Key bytes

    Returns:
        XORed bytes
    """
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])


def _score_printable(data: bytes) -> float:
    """Score how printable/English-like the data is."""
    try:
        text = data.decode('utf-8', errors='replace')
        printable = sum(1 for c in text if c.isprintable() or c in '\n\t ')
        english = sum(1 for c in text.lower() if c in ENGLISH_FREQ[:10])
        return printable / len(text) + english / len(text)
    except:
        return 0.0


def frequency_analysis(text: str) -> Dict[str, float]:
    """
    Perform frequency analysis on text.

    Args:
        text: Text to analyze

    Returns:
        Dictionary of character frequencies (as percentages)
    """
    # Filter to letters only
    letters = [c.upper() for c in text if c.isalpha()]
    total = len(letters)

    if total == 0:
        return {}

    counter = Counter(letters)
    return {char: (count / total) * 100 for char, count in counter.most_common()}


def substitution_hints(ciphertext: str) -> Dict[str, str]:
    """
    Suggest substitution cipher mappings based on frequency.

    Args:
        ciphertext: Encrypted text

    Returns:
        Dictionary mapping cipher letters to suggested plaintext letters
    """
    freq = frequency_analysis(ciphertext)
    sorted_cipher = sorted(freq.keys(), key=lambda x: freq[x], reverse=True)

    hints = {}
    for i, cipher_char in enumerate(sorted_cipher):
        if i < len(ENGLISH_FREQ):
            hints[cipher_char] = ENGLISH_FREQ[i].upper()

    return hints


def find_key_length_kasiski(ciphertext: str, max_length: int = 20) -> List[int]:
    """
    Use Kasiski examination to find probable Vigenere key lengths.

    Args:
        ciphertext: Encrypted text (letters only)
        max_length: Maximum key length to consider

    Returns:
        List of probable key lengths
    """
    text = ''.join(c.upper() for c in ciphertext if c.isalpha())
    distances = []

    # Find repeated trigrams and their distances
    for i in range(len(text) - 3):
        trigram = text[i:i+3]
        for j in range(i + 3, len(text) - 3):
            if text[j:j+3] == trigram:
                distances.append(j - i)

    if not distances:
        return list(range(2, max_length + 1))

    # Find common factors
    from math import gcd
    from functools import reduce

    factors = Counter()
    for d in distances:
        for f in range(2, min(d + 1, max_length + 1)):
            if d % f == 0:
                factors[f] += 1

    return [k for k, v in factors.most_common(5)]


if __name__ == "__main__":
    # Example usage
    ct = "KHOOR ZRUOG"
    print(f"Ciphertext: {ct}")
    print(f"ROT13: {rot13(ct)}")

    print("\nCaesar bruteforce:")
    for shift, pt in caesar_bruteforce(ct)[:5]:
        print(f"  Shift {shift}: {pt}")
