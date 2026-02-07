# CTF Solver Project

A comprehensive CTF-solving infrastructure for Claude Code with specialized skills, agents, and Python tools.

## Project Overview

This project provides a complete toolkit for solving Capture The Flag (CTF) challenges across all major categories:
- **PWN** - Binary exploitation
- **Crypto** - Cryptography challenges
- **Web** - Web application security
- **Forensics** - Digital forensics and steganography
- **Reverse Engineering** - Binary analysis and decompilation

## Workflow

Follow the standard CTF solving workflow:

```
RECON → ANALYSIS → EXPLOIT → VERIFY → WRITEUP
```

1. **RECON**: Gather initial information about the challenge
2. **ANALYSIS**: Deep dive into vulnerabilities and attack vectors
3. **EXPLOIT**: Develop and test the exploit
4. **VERIFY**: Confirm the flag is correct
5. **WRITEUP**: Document the solution

## Custom Skills (Commands)

| Skill | Description |
|-------|-------------|
| `/analyze <file>` | Analyze a challenge file and identify category/vulnerabilities |
| `/exploit <type>` | Generate exploit template for a vulnerability type |
| `/solve <challenge>` | Full autonomous solving workflow |
| `/recon <target>` | Reconnaissance on file or service |
| `/writeup <challenge>` | Generate professional writeup |

## Specialized Agents

Use the Task tool with these specialized agents:

| Agent | Use Case |
|-------|----------|
| `pwn-expert` | Buffer overflows, format strings, heap, ROP chains |
| `crypto-solver` | Classical ciphers, RSA, AES, encoding |
| `web-hacker` | SQLi, XSS, SSRF, auth bypass |
| `forensics-analyst` | Steganography, file carving, memory analysis |
| `reverse-engineer` | Disassembly, decompilation, algorithm recovery |

## Python Tools

Located in `tools/`:

```python
# Binary analysis
from tools.binary import checksec_wrapper, gadget_finder, elf_analyzer

# Cryptography
from tools.crypto import cipher_solvers, hash_utils, rsa_utils

# Web exploitation
from tools.web import sqli_helper, xss_payloads, request_utils

# Forensics
from tools.forensics import stego_utils, file_carver

# Common utilities
from tools.common import flag_extractor, encoding_utils
```

## Common Commands

```bash
# Binary analysis
checksec ./binary
file ./binary
strings ./binary | grep -i flag
objdump -d ./binary

# Network
nc host port
curl -v http://target

# Forensics
binwalk -e file
exiftool image.png
steghide extract -sf image.jpg

# Crypto
openssl rsa -in key.pem -text
```

## Directory Structure

```
challenges/     # Place challenge files here
exploits/       # Working exploit scripts
writeups/       # Solution documentation
tools/          # Python utility modules
templates/      # Exploit and writeup templates
```

## Flag Formats

Common CTF flag formats:
- `flag{...}`
- `CTF{...}`
- `picoCTF{...}`
- `HTB{...}`
- Custom formats specified per challenge

## Best Practices

1. **Always start with `/recon`** to understand what you're working with
2. **Check binary protections** before attempting pwn exploits
3. **Save working exploits** to `exploits/` directory
4. **Document solutions** using `/writeup` for future reference
5. **Use templates** from `templates/` as starting points

## External Tools

This project integrates with:
- **pwntools** - Exploit development framework
- **radare2/r2** - Reverse engineering
- **gdb/pwndbg** - Debugging
- **sqlmap** - SQL injection automation
- **binwalk** - Firmware/file analysis
- **z3** - SMT solver for crypto
