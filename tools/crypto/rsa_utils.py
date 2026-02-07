"""
RSA Utilities

Tools for RSA cryptanalysis and attacks.
"""

from typing import Optional, Tuple, List
from math import gcd, isqrt


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm."""
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x


def modinv(a: int, m: int) -> int:
    """Modular multiplicative inverse."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def rsa_decrypt(c: int, d: int, n: int) -> int:
    """
    Decrypt RSA ciphertext.

    Args:
        c: Ciphertext
        d: Private exponent
        n: Modulus

    Returns:
        Plaintext as integer
    """
    return pow(c, d, n)


def rsa_encrypt(m: int, e: int, n: int) -> int:
    """
    Encrypt RSA plaintext.

    Args:
        m: Plaintext as integer
        e: Public exponent
        n: Modulus

    Returns:
        Ciphertext
    """
    return pow(m, e, n)


def factor_small(n: int, limit: int = 1000000) -> Optional[Tuple[int, int]]:
    """
    Try to factor n using trial division.

    Args:
        n: Number to factor
        limit: Maximum factor to try

    Returns:
        (p, q) if successful, None otherwise
    """
    if n % 2 == 0:
        return 2, n // 2

    for i in range(3, min(limit, isqrt(n) + 1), 2):
        if n % i == 0:
            return i, n // i

    return None


def fermat_factor(n: int, iterations: int = 1000000) -> Optional[Tuple[int, int]]:
    """
    Fermat's factorization method.
    Works when p and q are close together.

    Args:
        n: Number to factor
        iterations: Maximum iterations

    Returns:
        (p, q) if successful, None otherwise
    """
    a = isqrt(n)
    if a * a == n:
        return a, a

    a += 1
    for _ in range(iterations):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1

    return None


def wiener_attack(e: int, n: int) -> Optional[int]:
    """
    Wiener's attack for small private exponent.
    Works when d < n^0.25 / 3.

    Args:
        e: Public exponent
        n: Modulus

    Returns:
        Private exponent d if successful, None otherwise
    """
    def continued_fraction(num: int, denom: int):
        """Generate continued fraction expansion."""
        while denom:
            q = num // denom
            yield q
            num, denom = denom, num - q * denom

    def convergents(cf):
        """Generate convergents from continued fraction."""
        n0, n1 = 0, 1
        d0, d1 = 1, 0
        for q in cf:
            n0, n1 = n1, q * n1 + n0
            d0, d1 = d1, q * d1 + d0
            yield n1, d1

    for k, d in convergents(continued_fraction(e, n)):
        if k == 0:
            continue

        # Check if d is the private exponent
        phi_candidate = (e * d - 1) // k

        # phi(n) = (p-1)(q-1) = n - p - q + 1
        # So p + q = n - phi + 1
        s = n - phi_candidate + 1
        # p and q are roots of x^2 - sx + n = 0
        discriminant = s * s - 4 * n

        if discriminant >= 0:
            sqrt_disc = isqrt(discriminant)
            if sqrt_disc * sqrt_disc == discriminant:
                p = (s + sqrt_disc) // 2
                q = (s - sqrt_disc) // 2
                if p * q == n:
                    return d

    return None


def common_modulus_attack(n: int, e1: int, e2: int, c1: int, c2: int) -> Optional[int]:
    """
    Common modulus attack.
    When same message encrypted with same n but different e.

    Args:
        n: Common modulus
        e1, e2: Different public exponents
        c1, c2: Corresponding ciphertexts

    Returns:
        Plaintext if successful, None otherwise
    """
    if gcd(e1, e2) != 1:
        return None

    # Find s1, s2 such that e1*s1 + e2*s2 = 1
    _, s1, s2 = egcd(e1, e2)

    # m = c1^s1 * c2^s2 mod n
    if s1 < 0:
        c1 = modinv(c1, n)
        s1 = -s1
    if s2 < 0:
        c2 = modinv(c2, n)
        s2 = -s2

    return (pow(c1, s1, n) * pow(c2, s2, n)) % n


def hastad_broadcast(ciphertexts: List[int], moduli: List[int], e: int = 3) -> Optional[int]:
    """
    Hastad's broadcast attack.
    When same message encrypted with same small e but different n.

    Args:
        ciphertexts: List of ciphertexts
        moduli: List of moduli
        e: Public exponent (default 3)

    Returns:
        Plaintext if successful, None otherwise
    """
    if len(ciphertexts) < e or len(moduli) < e:
        return None

    # Use Chinese Remainder Theorem
    def crt(remainders: List[int], moduli: List[int]) -> int:
        """Chinese Remainder Theorem."""
        N = 1
        for n in moduli:
            N *= n

        result = 0
        for r, n in zip(remainders, moduli):
            Ni = N // n
            result += r * Ni * modinv(Ni, n)

        return result % N

    # Combine using CRT
    m_e = crt(ciphertexts[:e], moduli[:e])

    # Take e-th root
    m = integer_nth_root(m_e, e)
    if m is not None and pow(m, e) == m_e:
        return m

    return None


def integer_nth_root(x: int, n: int) -> Optional[int]:
    """
    Compute integer n-th root of x.

    Returns:
        n-th root if x is a perfect n-th power, None otherwise
    """
    if x < 0 and n % 2 == 0:
        return None
    if x == 0:
        return 0

    sign = 1
    if x < 0:
        sign = -1
        x = -x

    # Newton's method
    guess = 1 << ((x.bit_length() + n - 1) // n)
    while True:
        new_guess = ((n - 1) * guess + x // pow(guess, n - 1)) // n
        if new_guess >= guess:
            break
        guess = new_guess

    if pow(guess, n) == x:
        return sign * guess
    return None


def small_e_attack(c: int, e: int, n: int) -> Optional[int]:
    """
    Attack for small e when m^e < n.

    Args:
        c: Ciphertext
        e: Public exponent
        n: Modulus

    Returns:
        Plaintext if m^e < n, None otherwise
    """
    m = integer_nth_root(c, e)
    if m is not None and pow(m, e) == c:
        return m
    return None


def int_to_bytes(n: int) -> bytes:
    """Convert integer to bytes."""
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def bytes_to_int(b: bytes) -> int:
    """Convert bytes to integer."""
    return int.from_bytes(b, 'big')


if __name__ == "__main__":
    # Example: small e attack
    print("Testing small e attack...")
    m = bytes_to_int(b"flag{test}")
    e = 3
    n = 0xffffffffffffffffffffffffffff  # Large n
    c = pow(m, e, n)  # Since m^3 < n, this is just m^3

    recovered = small_e_attack(c, e, n)
    if recovered:
        print(f"Recovered: {int_to_bytes(recovered)}")
