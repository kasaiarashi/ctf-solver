# /recon - Reconnaissance

Perform initial reconnaissance on a challenge target.

## Usage
```
/recon <file>
/recon <url>
/recon <host:port>
```

## Instructions

When the user invokes `/recon`, gather comprehensive initial intelligence:

### File Reconnaissance

```bash
# Basic identification
file <target>
ls -la <target>

# Content preview
xxd <target> | head -30
strings <target> | head -50

# Archive inspection
binwalk <target>

# Metadata
exiftool <target> 2>/dev/null || true
```

### Binary Reconnaissance

```bash
# Security features
checksec --file=<binary>

# Architecture info
file <binary>
readelf -h <binary> 2>/dev/null || true

# Symbols and functions
nm <binary> 2>/dev/null | head -30 || true
objdump -t <binary> 2>/dev/null | grep -E "main|flag|win|shell|system" || true

# Dangerous functions
objdump -d <binary> 2>/dev/null | grep -E "gets|strcpy|sprintf|scanf" || true

# Strings of interest
strings <binary> | grep -iE "flag|password|secret|key|admin|root" || true
```

### Network Service Reconnaissance

```bash
# Banner grab
echo "" | nc -v <host> <port> -w 3 2>&1 | head -20

# HTTP service
curl -v <url> 2>&1 | head -50
```

For web services:
- Check response headers
- Identify server/framework
- Look for robots.txt, .git, common paths
- Note cookies and session handling

### Directory/Multi-file Reconnaissance

```bash
# List all files
find <directory> -type f

# Identify file types
file <directory>/*

# Look for interesting files
find <directory> -name "*.py" -o -name "*.php" -o -name "*.js" -o -name "flag*"
```

### Output Format

```
## Reconnaissance Report

**Target**: <target>
**Type**: <file/binary/service/directory>

### Basic Information
- File type: ...
- Size: ...
- Permissions: ...

### Key Findings
1. ...
2. ...
3. ...

### Strings of Interest
```
<relevant strings>
```

### Security Features (if binary)
| Feature | Status |
|---------|--------|
| ASLR    | ...    |
| NX      | ...    |
| PIE     | ...    |
| Canary  | ...    |
| RELRO   | ...    |

### Recommendations
- Suggested category: ...
- Next step: `/analyze <target>` or specific agent
- Tools to use: ...
```

### Quick Checks

Always check for:
1. **Flag in plaintext**: `strings <file> | grep -i flag`
2. **Embedded files**: `binwalk -e <file>`
3. **Hidden data**: Check file size vs expected
4. **Encoding**: Base64, hex, rot13 patterns
5. **Comments**: Source code comments, metadata

### Follow-up Suggestions

Based on findings, suggest:
- Specific vulnerability to investigate
- Agent to delegate to
- `/analyze` for deeper analysis
- `/exploit` if vulnerability is clear
