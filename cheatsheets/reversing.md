# Reverse Engineering Cheatsheet

## First Things to Run (Any Binary)

```bash
# Basic info
file ./binary                      # File type, architecture
strings ./binary | head -50        # Readable strings
strings ./binary | grep -i flag    # Quick flag search
strings ./binary | grep -i pass    # Password hints

# Dynamic info (Linux)
ltrace ./binary                    # Library calls
strace ./binary                    # System calls

# Static analysis
objdump -d ./binary | head -200    # Disassembly
nm ./binary                        # Symbol table
readelf -h ./binary                # ELF header
readelf -S ./binary                # Sections
```

---

## File Types

### Identify
```bash
file ./binary

# Common types:
# ELF 64-bit LSB executable      → Linux x64
# ELF 32-bit LSB executable      → Linux x86
# PE32 executable                → Windows x86
# PE32+ executable               → Windows x64
# Mach-O 64-bit executable       → macOS
# Python compiled                → .pyc file
# Java archive                   → .jar file
```

### Running Different Architectures
```bash
# 32-bit on 64-bit Linux
sudo dpkg --add-architecture i386
sudo apt install libc6:i386

# ARM
qemu-arm ./binary
qemu-aarch64 ./binary

# Windows on Linux
wine ./binary.exe
```

---

## Disassembly Tools

### Objdump
```bash
# Disassemble
objdump -d ./binary
objdump -d ./binary -M intel      # Intel syntax

# Specific function
objdump -d ./binary | grep -A 50 "<main>:"

# All sections
objdump -D ./binary
```

### Radare2
```bash
# Open with analysis
r2 -A ./binary

# Common commands
aaa                    # Analyze all
afl                    # List functions
pdf @ main             # Disassemble main
pdf @ sym.check        # Disassemble function
pdc @ main             # Pseudo-decompile
s main                 # Seek to main
VV                     # Visual graph mode
V                      # Visual mode

# Search
/ flag                 # Search string
/x 9090                # Search hex bytes
axt @ sym.flag         # Cross-references to

# Strings
iz                     # Strings in data section
izz                    # All strings

# Write mode (patching)
r2 -w ./binary
wx 9090 @ 0x401234     # Write bytes
```

### Ghidra
```bash
# Launch Ghidra
ghidraRun

# Key windows:
# - Decompiler (shows C-like code)
# - Listing (disassembly)
# - Symbol Tree (functions, variables)
# - Data Type Manager

# Shortcuts:
# G       - Go to address
# L       - Rename label/function
# Ctrl+L  - Retype variable
# ;       - Add comment
```

### IDA Free
```bash
# Views:
# - IDA View (disassembly)
# - Hex View
# - Strings window (Shift+F12)
# - Functions window
# - Cross-references (X)

# Shortcuts:
# G       - Go to address
# N       - Rename
# X       - Cross-references
# Space   - Toggle graph/text view
```

---

## Debugging

### GDB
```bash
gdb ./binary

# Basic commands
r                      # Run
r arg1 arg2            # Run with arguments
r < input.txt          # Run with input file
b main                 # Breakpoint at main
b *0x401234            # Breakpoint at address
c                      # Continue
si                     # Step instruction
ni                     # Next instruction (skip calls)
finish                 # Run until return
q                      # Quit

# Examine
info registers         # All registers
p $rax                 # Print register
x/20x $rsp             # 20 hex words at RSP
x/s 0x404000           # String at address
x/10i $rip             # 10 instructions at RIP
info functions         # List functions

# Modify
set $rax = 0x1234      # Set register
set {int}0x404000 = 0  # Set memory
```

### GDB with pwndbg/GEF
```bash
# Enhanced features
vmmap                  # Memory map
telescope $rsp 20      # Stack visualization
heap                   # Heap info
checksec               # Security features
context                # Show registers, stack, code
```

### Dynamic Analysis
```bash
# Trace library calls
ltrace ./binary
ltrace -f ./binary     # Follow forks
ltrace -s 100 ./binary # Longer string output

# Trace system calls
strace ./binary
strace -f ./binary     # Follow forks
strace -e open ./binary # Filter specific calls
```

---

## Common Patterns

### String Comparison
```asm
# Look for strcmp, strncmp, memcmp
call strcmp
test eax, eax
jne wrong_password

# Or character-by-character
cmp byte [rax], 0x41   # Compare with 'A'
jne fail
```
**Strategy**: Find the comparison and extract expected values.

### XOR Encryption
```asm
xor eax, ecx           # XOR with key
```
**Strategy**: XOR encrypted data with key.

### Loop-based Check
```asm
.loop:
    mov al, [rsi + rcx]    # Get input byte
    xor al, [rdi + rcx]    # XOR with key
    cmp al, [rdx + rcx]    # Compare with expected
    jne fail
    inc rcx
    cmp rcx, rax           # Check counter
    jl .loop
```
**Strategy**: Extract all expected values, reverse the transformation.

---

## Patching

### With Radare2
```bash
r2 -w ./binary
s 0x401234             # Seek to address
wx 9090                # Write NOP (0x90)
wx 7500                # JNZ (75) → JZ (74)
wx eb00                # JZ → JMP
```

### Common Patches
| Original | Patched | Effect |
|----------|---------|--------|
| `75 XX` (JNZ) | `74 XX` (JZ) | Invert branch |
| `74 XX` (JZ) | `75 XX` (JNZ) | Invert branch |
| `74 XX` (JZ) | `EB XX` (JMP) | Always jump |
| `75 XX` (JNZ) | `90 90` (NOP) | Never jump |
| `0F 84` (JZ long) | `0F 85` (JNZ) | Invert |
| `E8 XX` (CALL) | `90 90 90 90 90` | NOP call |

### With Python
```python
with open('binary', 'rb') as f:
    data = bytearray(f.read())

# Patch bytes at offset
data[0x1234] = 0x90
data[0x1235] = 0x90

with open('binary_patched', 'wb') as f:
    f.write(data)
```

---

## Anti-Debugging Bypass

### Common Techniques
```c
// ptrace check
if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
    exit(1);

// Timing checks
start = time();
// ... code ...
if (time() - start > threshold)
    exit(1);
```

### Bypass Methods
```bash
# LD_PRELOAD fake ptrace
cat > ptrace.c << 'EOF'
long ptrace(int request, ...) { return 0; }
EOF
gcc -shared -o ptrace.so ptrace.c
LD_PRELOAD=./ptrace.so ./binary

# GDB catch syscall
catch syscall ptrace
commands
set $rax = 0
continue
end
```

---

## Python Reversing (.pyc)

```bash
# Decompile
uncompyle6 file.pyc > file.py
pycdc file.pyc > file.py

# View bytecode
python3 -m dis file.pyc
```

---

## Java Reversing (.jar, .class)

```bash
# Extract JAR
unzip file.jar -d extracted/

# Decompile
jadx file.jar
jadx-gui file.jar      # GUI
cfr file.jar

# View bytecode
javap -c ClassName.class
```

---

## .NET Reversing (.exe, .dll)

```bash
# Decompile (Linux)
ilspycmd file.exe

# Decompile (Windows)
# dnSpy, ILSpy, dotPeek
```

---

## Algorithm Identification

### Constants to Look For
| Constant | Algorithm |
|----------|-----------|
| `0x67452301` | MD5/SHA1 init |
| `0x6a09e667` | SHA256 init |
| `0x9e3779b9` | TEA delta |
| `0x61707865` | ChaCha/Salsa |
| `0x63, 0x7c, 0x77, 0x7b` | AES S-box |

---

## Useful Scripts

### Extract Strings with Context
```bash
strings -t x ./binary | grep -i password
# Then in r2: s 0xOFFSET; pd 10
```

### Find Flag Validation
```bash
objdump -d ./binary | grep -E "cmp|strcmp|strncmp|memcmp" -A2 -B2
```

### Bruteforce Single Char
```python
import subprocess
import string

for c in string.printable:
    result = subprocess.run(['./binary'], input=c.encode(), capture_output=True)
    if b'Correct' in result.stdout:
        print(f"Found: {c}")
        break
```

---

## One-Liners

```bash
# All strings containing 'flag'
strings ./binary | grep -i flag

# Find main function offset
objdump -d ./binary | grep "<main>:" | cut -d' ' -f1

# Check for debug symbols
file ./binary | grep -i "not stripped"

# Run with fake library
LD_PRELOAD=./fake.so ./binary

# Trace specific function
ltrace -e strcmp ./binary
```
