# /solve - Full Solve Workflow

Autonomously attempt to solve a CTF challenge through the complete workflow.

## Usage
```
/solve <challenge_path_or_url>
/solve <challenge_directory>
```

## Instructions

When the user invokes `/solve`, execute the full CTF solving workflow:

### Phase 1: RECON
1. Identify all challenge files
2. Read any README or description
3. Determine challenge category
4. Note flag format if specified

### Phase 2: ANALYSIS
Based on category, perform deep analysis:

**For PWN:**
- Run checksec
- Identify vulnerability class
- Find target functions/addresses
- Map out exploitation path

**For Crypto:**
- Identify cipher/algorithm
- Find weaknesses
- Gather parameters (n, e, c for RSA, etc.)

**For Web:**
- Map attack surface
- Identify injection points
- Check authentication/session handling

**For Forensics:**
- Extract hidden data
- Analyze file structure
- Check for steganography

**For RE:**
- Static analysis of key functions
- Identify algorithm/logic
- Find key validation routine

### Phase 3: EXPLOIT
1. Select appropriate agent if complex:
   - `pwn-expert` for binary exploitation
   - `crypto-solver` for cryptography
   - `web-hacker` for web challenges
   - `forensics-analyst` for forensics
   - `reverse-engineer` for reverse engineering

2. Generate exploit using Python tools in `tools/`

3. Create and test exploit script

### Phase 4: VERIFY
1. Execute exploit
2. Extract flag
3. Validate flag format
4. Report success or iterate

### Phase 5: ITERATE (if needed)
If initial approach fails:
1. Re-analyze with new information
2. Try alternative techniques
3. Adjust exploit parameters
4. Maximum 3 iteration attempts

### Phase 6: WRITEUP
On success, offer to generate writeup:
```
/writeup <challenge_name>
```

## Autonomous Decision Making

During `/solve`, make intelligent decisions:

1. **Tool Selection**: Choose appropriate tools based on challenge type
2. **Agent Delegation**: Use specialized agents for complex sub-tasks
3. **Error Recovery**: Adapt approach based on failures
4. **Resource Management**: Don't spend excessive time on dead ends

## Output Format

Provide status updates at each phase:

```
## Solving: <challenge_name>

### Phase 1: RECON ✓
- Found: binary, source code
- Category: PWN
- Flag format: flag{...}

### Phase 2: ANALYSIS ✓
- Vulnerability: Buffer overflow in read_input()
- Protection: NX enabled, no PIE
- Approach: ret2libc

### Phase 3: EXPLOIT
- Generating exploit...
- Testing locally...
- [status updates]

### Phase 4: VERIFY
- Flag captured: flag{...}

### Result: SUCCESS ✓
```

## Failure Handling

If solve fails after attempts:
1. Document what was tried
2. Explain blockers encountered
3. Suggest manual investigation points
4. Offer partial solution/analysis
