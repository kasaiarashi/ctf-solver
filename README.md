# CTF Solver

A comprehensive CTF-solving infrastructure for Claude Code with specialized skills, agents, and Python tools.

## Setup

0. Setup Python Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Install external tools (macOS):
```bash
brew install radare2 binwalk steghide exiftool
```

3. Run Claude Code in this directory:
```bash
claude
```

## Features

### Custom Skills
- `/analyze` - Analyze challenge files
- `/exploit` - Generate exploit templates
- `/solve` - Full solving workflow
- `/recon` - Reconnaissance
- `/writeup` - Generate writeups

### Specialized Agents
- `pwn-expert` - Binary exploitation
- `crypto-solver` - Cryptography
- `web-hacker` - Web security
- `forensics-analyst` - Digital forensics
- `reverse-engineer` - Reverse engineering

### Python Tools
- Binary analysis utilities
- Crypto solvers
- Web exploitation helpers
- Forensics tools
- Common utilities

## Usage

```bash
# Start Claude Code
claude

# Analyze a challenge
/analyze ./challenges/binary

# Generate exploit template
/exploit buffer-overflow

# Full solve attempt
/solve ./challenges/crypto_challenge
```

## Directory Structure

```
challenges/     # Challenge files
exploits/       # Working exploits
writeups/       # Solution writeups
tools/          # Python utilities
templates/      # Code templates
```

## License

MIT
