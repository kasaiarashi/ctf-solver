# /analyze - Challenge Analysis

Analyze a CTF challenge to identify its category, vulnerabilities, and attack vectors.

## Usage
```
/analyze <file_or_directory>
```

## Instructions

When the user invokes `/analyze`, perform comprehensive challenge analysis:

### 1. File Identification
```bash
file <target>
```

Identify the file type and categorize:
- **ELF binary** → PWN/Reverse Engineering
- **Python/JS/PHP** → Web or Crypto
- **Image files** → Forensics/Steganography
- **Archive files** → Extract and analyze contents
- **Network captures** → Forensics
- **Text/encoded data** → Crypto

### 2. Category-Specific Analysis

#### For Binaries (PWN/RE):
```bash
checksec --file=<binary>
file <binary>
strings <binary> | head -50
objdump -d <binary> | head -100
```

Report:
- Architecture (x86, x64, ARM)
- Protections (ASLR, NX, PIE, Canary, RELRO)
- Interesting strings (flag patterns, format strings, passwords)
- Dangerous functions (gets, strcpy, printf with user input)

#### For Web Challenges:
- Identify framework/language
- Check for common vulnerabilities (SQLi, XSS, SSTI)
- Look for authentication mechanisms
- Identify input points

#### For Crypto:
- Identify cipher type (classical, modern, custom)
- Look for weak implementations
- Check key sizes and parameters
- Identify encoding schemes

#### For Forensics:
```bash
binwalk <file>
exiftool <file>
xxd <file> | head -20
```

Check for:
- Hidden files
- Steganography indicators
- Metadata
- File carving opportunities

### 3. Output Format

Provide structured analysis:

```
## Challenge Analysis

**Category**: [PWN/Crypto/Web/Forensics/RE]
**Difficulty**: [Easy/Medium/Hard] (estimated)

### File Information
- Type: ...
- Size: ...
- Architecture: ... (if applicable)

### Security Features (if binary)
- ASLR: ...
- NX: ...
- PIE: ...
- Canary: ...

### Identified Vulnerabilities
1. ...
2. ...

### Recommended Approach
1. ...
2. ...

### Suggested Tools
- ...
```

### 4. Next Steps

After analysis, suggest:
- Specific `/exploit` command if vulnerability found
- Specialized agent to use (pwn-expert, crypto-solver, etc.)
- Additional reconnaissance needed
