# Cryptography Cheatsheet

## First Things to Try (Any Crypto Challenge)

```bash
# Identify encoding/cipher
# Check: Is it base64? Hex? Binary? Some cipher?

# Base64 decode
echo "SGVsbG8gV29ybGQ=" | base64 -d

# Hex decode
echo "48656c6c6f" | xxd -r -p

# Try CyberChef for multi-layer decoding
# https://gchq.github.io/CyberChef/

# Check for known cipher patterns
# - Only uppercase letters? → Caesar/Substitution
# - Repeating patterns? → XOR/Vigenere
# - Large numbers? → RSA
# - Has IV/key/ciphertext? → AES/DES
```

---

## Encoding Detection

| Pattern | Likely Encoding |
|---------|-----------------|
| `=` or `==` at end, A-Za-z0-9+/ | Base64 |
| Only 0-9, a-f (lowercase hex) | Hex |
| Only 0-1 | Binary |
| `%20`, `%3D` | URL encoding |
| Starts with `0x` | Hex |
| `&#65;` or `&#x41;` | HTML entities |

### Decode Commands
```bash
# Base64
echo "dGVzdA==" | base64 -d
python3 -c "import base64; print(base64.b64decode('dGVzdA=='))"

# Hex
echo "74657374" | xxd -r -p
python3 -c "print(bytes.fromhex('74657374'))"

# Binary
python3 -c "print(''.join(chr(int(b,2)) for b in '01110100 01100101'.split()))"

# URL
python3 -c "from urllib.parse import unquote; print(unquote('%74%65%73%74'))"

# ROT13
echo "grfg" | tr 'a-zA-Z' 'n-za-mN-ZA-M'
python3 -c "import codecs; print(codecs.decode('grfg', 'rot_13'))"

# All ROT variations
for i in {1..25}; do echo "ROT$i: $(echo 'grfg' | tr "a-zA-Z" "$(echo {a..z}{A..Z} | cut -c$((i+1))-26,$((i+27))-52,1-$i,27-$((i+26)))")"; done
```

---

## Classical Ciphers

### Caesar Cipher
```python
# Bruteforce all shifts
ciphertext = "KHOOR"
for shift in range(26):
    plaintext = ''.join(
        chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
        if c.isalpha() else c
        for c in ciphertext
    )
    print(f"Shift {shift}: {plaintext}")
```

### Vigenere Cipher
```python
def vigenere_decrypt(ciphertext, key):
    result = []
    key = key.upper()
    key_idx = 0
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_idx % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base - shift) % 26 + base))
            key_idx += 1
        else:
            result.append(char)
    return ''.join(result)

# Find key length using Kasiski or Index of Coincidence
# Then frequency analysis for each position
```

### Substitution Cipher
```python
# Frequency analysis
from collections import Counter
ciphertext = "YOUR CIPHERTEXT HERE"
freq = Counter(c.upper() for c in ciphertext if c.isalpha())
print(freq.most_common())
# English frequency: ETAOINSHRDLU

# Use https://quipqiup.com/ for automatic solving
```

### XOR Cipher
```python
# Single-byte XOR bruteforce
ciphertext = bytes.fromhex("1b37373331363f78151b7f2b783431333d")
for key in range(256):
    plaintext = bytes([b ^ key for b in ciphertext])
    if all(32 <= b < 127 for b in plaintext):
        print(f"Key {key}: {plaintext}")

# Known plaintext XOR
def xor_known_plaintext(ciphertext, known_plaintext):
    key = bytes([c ^ p for c, p in zip(ciphertext, known_plaintext)])
    return key
```

### Rail Fence
```python
def rail_fence_decrypt(ciphertext, rails):
    fence = [[None] * len(ciphertext) for _ in range(rails)]
    rail, direction = 0, 1
    for i in range(len(ciphertext)):
        fence[rail][i] = True
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction *= -1

    idx = 0
    for r in range(rails):
        for c in range(len(ciphertext)):
            if fence[r][c]:
                fence[r][c] = ciphertext[idx]
                idx += 1

    rail, direction = 0, 1
    result = []
    for i in range(len(ciphertext)):
        result.append(fence[rail][i])
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction *= -1
    return ''.join(result)
```

---

## RSA

### Given Values Check
```
n = modulus (p * q)
e = public exponent (commonly 65537, 3, or 17)
c = ciphertext
d = private exponent (if given, just decrypt)
p, q = prime factors (if given, compute d)
```

### Basic Decryption (d known)
```python
m = pow(c, d, n)
plaintext = m.to_bytes((m.bit_length() + 7) // 8, 'big')
print(plaintext)
```

### Factor n → Get d → Decrypt
```python
from math import gcd

# If p and q known
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)  # Python 3.8+
m = pow(c, d, n)
```

### Common Attacks

#### Small e Attack (e=3, m^e < n)
```python
from gmpy2 import iroot
m, exact = iroot(c, e)
if exact:
    print(m.to_bytes((m.bit_length() + 7) // 8, 'big'))
```

#### Fermat Factorization (p ≈ q)
```python
from math import isqrt
def fermat_factor(n):
    a = isqrt(n) + 1
    b2 = a * a - n
    while isqrt(b2) ** 2 != b2:
        a += 1
        b2 = a * a - n
    b = isqrt(b2)
    return a - b, a + b

p, q = fermat_factor(n)
```

#### Wiener Attack (small d)
```python
# Use: https://github.com/pablocelayes/rsa-wiener-attack
# d < n^0.25 / 3
```

#### Common Modulus Attack
```python
# Same n, same m, different e1 and e2
from math import gcd

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = egcd(b % a, a)
    return g, y - (b // a) * x, x

_, s1, s2 = egcd(e1, e2)
if s1 < 0:
    s1 = -s1
    c1 = pow(c1, -1, n)
if s2 < 0:
    s2 = -s2
    c2 = pow(c2, -1, n)

m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
```

#### Hastad Broadcast Attack
```python
# Same m, same small e, different n
# Use CRT to recover m^e, then take e-th root
from functools import reduce

def crt(remainders, moduli):
    N = reduce(lambda a, b: a * b, moduli)
    result = 0
    for r, n in zip(remainders, moduli):
        Ni = N // n
        result += r * Ni * pow(Ni, -1, n)
    return result % N

m_e = crt([c1, c2, c3], [n1, n2, n3])
m = iroot(m_e, e)[0]
```

#### Factor with FactorDB
```python
# http://factordb.com/
# Or use:
import requests
def factordb(n):
    r = requests.get(f'http://factordb.com/api?query={n}')
    return r.json()
```

---

## AES

### ECB Mode (Detect)
```python
# If same plaintext block = same ciphertext block
# Look for repeating 16-byte blocks
```

### CBC Padding Oracle
```bash
# Use: https://github.com/AonCyberLabs/PadBuster
padbuster http://target/decrypt?cipher= CIPHERTEXT 16 -encoding 0
```

### CBC Bit Flipping
```python
# Flip bit in block N-1 to change plaintext in block N
# target_byte = original_byte ^ old_value ^ new_value
```

---

## Hashes

### Identify Hash
```python
# By length:
# 32 hex = MD5
# 40 hex = SHA1
# 64 hex = SHA256
# 128 hex = SHA512
```

### Crack Hashes
```bash
# Hashcat
hashcat -m 0 hash.txt wordlist.txt     # MD5
hashcat -m 100 hash.txt wordlist.txt   # SHA1
hashcat -m 1400 hash.txt wordlist.txt  # SHA256

# John
john --wordlist=rockyou.txt --format=raw-md5 hash.txt

# Online
# https://crackstation.net/
# https://hashes.com/
```

### Length Extension Attack
```bash
# MD5, SHA1, SHA256 vulnerable
# Use: https://github.com/iagox86/hash_extender
hash_extender -d "original" -s "HASH" -a "append" -f sha256 -l SECRET_LEN
```

---

## Useful Tools

```bash
# CyberChef - https://gchq.github.io/CyberChef/
# dCode - https://www.dcode.fr/
# Ciphey - auto-decode
pip install ciphey
ciphey -t "CIPHERTEXT"

# RsaCtfTool
git clone https://github.com/RsaCtfTool/RsaCtfTool
python3 RsaCtfTool.py --publickey pub.pem --uncipherfile cipher.txt

# FactorDB
http://factordb.com/
```

---

## Python Crypto Libraries

```python
# pycryptodome
from Crypto.Cipher import AES, DES
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime, inverse

# gmpy2 (fast math)
from gmpy2 import iroot, isqrt, mpz, invert

# z3 (constraint solving)
from z3 import *

# sympy (factoring)
from sympy import factorint, isprime
```

---

## One-Liners

```bash
# Quick base64 decode and check for flag
echo "BASE64STRING" | base64 -d | grep -i flag

# Hex to ASCII
python3 -c "print(bytes.fromhex('HEX_STRING'))"

# Check if number is prime
python3 -c "from sympy import isprime; print(isprime(NUMBER))"

# Factor small number
python3 -c "from sympy import factorint; print(factorint(NUMBER))"
```
