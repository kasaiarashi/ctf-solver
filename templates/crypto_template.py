#!/usr/bin/env python3
"""
Crypto Solve Template

Usage:
    python solve.py
    python solve.py --file data.txt
"""

import argparse
from typing import Optional

# Crypto imports (install with: pip install pycryptodome gmpy2 z3-solver)
try:
    from Crypto.Util.number import long_to_bytes, bytes_to_long, GCD, inverse
    PYCRYPTO = True
except ImportError:
    PYCRYPTO = False
    print("[!] PyCryptodome not installed")

try:
    import gmpy2
    from gmpy2 import iroot, mpz
    GMPY2 = True
except ImportError:
    GMPY2 = False
    print("[!] gmpy2 not installed")

try:
    from z3 import *
    Z3 = True
except ImportError:
    Z3 = False
    print("[!] z3-solver not installed")


# =============================================================================
# Given Values (fill in from challenge)
# =============================================================================

# RSA
n = None  # Modulus
e = None  # Public exponent
c = None  # Ciphertext
p = None  # Factor (if known)
q = None  # Factor (if known)
d = None  # Private exponent (if known)

# AES
key = None
iv = None
ciphertext = None


# =============================================================================
# Helper Functions
# =============================================================================

def int_to_bytes(n: int) -> bytes:
    """Convert integer to bytes."""
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def bytes_to_int(b: bytes) -> int:
    """Convert bytes to integer."""
    return int.from_bytes(b, 'big')


def egcd(a: int, b: int) -> tuple:
    """Extended Euclidean Algorithm."""
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x


def modinv(a: int, m: int) -> int:
    """Modular multiplicative inverse."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m


def isqrt(n: int) -> int:
    """Integer square root."""
    if n < 0:
        raise ValueError("Negative number")
    if n == 0:
        return 0
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


# =============================================================================
# RSA Attacks
# =============================================================================

def rsa_decrypt(c: int, d: int, n: int) -> bytes:
    """Standard RSA decryption."""
    m = pow(c, d, n)
    return int_to_bytes(m)


def small_e_attack(c: int, e: int) -> Optional[bytes]:
    """Attack when m^e < n (cube root attack for e=3)."""
    if GMPY2:
        m, exact = iroot(mpz(c), e)
        if exact:
            return int_to_bytes(int(m))
    else:
        # Simple integer root
        low, high = 0, c
        while low < high:
            mid = (low + high) // 2
            if pow(mid, e) < c:
                low = mid + 1
            else:
                high = mid
        if pow(low, e) == c:
            return int_to_bytes(low)
    return None


def fermat_factor(n: int, iterations: int = 1000000) -> Optional[tuple]:
    """Fermat factorization (when p and q are close)."""
    a = isqrt(n) + 1
    for _ in range(iterations):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def wiener_attack(e: int, n: int) -> Optional[int]:
    """Wiener's attack for small d."""

    def continued_fraction(num, denom):
        while denom:
            q = num // denom
            yield q
            num, denom = denom, num - q * denom

    def convergents(cf):
        n0, n1 = 0, 1
        d0, d1 = 1, 0
        for q in cf:
            n0, n1 = n1, q * n1 + n0
            d0, d1 = d1, q * d1 + d0
            yield n1, d1

    for k, d in convergents(continued_fraction(e, n)):
        if k == 0:
            continue

        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n

        if disc >= 0:
            sqrt_disc = isqrt(disc)
            if sqrt_disc * sqrt_disc == disc:
                p = (s + sqrt_disc) // 2
                if n % p == 0:
                    return d

    return None


# =============================================================================
# Classical Ciphers
# =============================================================================

def caesar(text: str, shift: int) -> str:
    """Caesar cipher."""
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    return ''.join(result)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR with repeating key."""
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))


# =============================================================================
# Main Solve
# =============================================================================

def solve():
    """
    Main solving logic.

    Challenge: [CHALLENGE NAME]
    Type: [RSA / AES / Classical / Custom]
    Vulnerability: [DESCRIBE WEAKNESS]
    """

    print("[*] Starting solve...")

    # -------------------------------------------------------------------------
    # Analysis
    # -------------------------------------------------------------------------

    # Print given values
    # print(f"[*] n = {n}")
    # print(f"[*] e = {e}")
    # print(f"[*] c = {c}")

    # -------------------------------------------------------------------------
    # Attack
    # -------------------------------------------------------------------------

    # Example: Small e attack
    # flag = small_e_attack(c, e)

    # Example: Factor and decrypt
    # factors = fermat_factor(n)
    # if factors:
    #     p, q = factors
    #     phi = (p - 1) * (q - 1)
    #     d = modinv(e, phi)
    #     flag = rsa_decrypt(c, d, n)

    # -------------------------------------------------------------------------
    # Output
    # -------------------------------------------------------------------------

    # if flag:
    #     print(f"[+] Flag: {flag.decode()}")
    # else:
    #     print("[-] Solve failed")

    pass


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Crypto Solve')
    parser.add_argument('--file', help='Input file')
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            data = f.read()
            print(f"[*] Loaded {len(data)} bytes from {args.file}")

    solve()
